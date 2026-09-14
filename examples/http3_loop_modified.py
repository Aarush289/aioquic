import argparse
import asyncio
import logging
import math
import os
import pickle
import ssl
import time
from collections import deque
from typing import BinaryIO, Callable, Deque, Dict, List, Optional, Union, cast
from urllib.parse import urlparse

import aioquic
import wsproto
import wsproto.events
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
    PushPromiseReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.quic.logger import QuicFileLogger
from aioquic.quic.packet import QuicProtocolVersion
from aioquic.tls import CipherSuite, SessionTicket

try:
    import uvloop
except ImportError:
    uvloop = None

logger = logging.getLogger("client")

HttpConnection = Union[H0Connection, H3Connection]
USER_AGENT = "aioquic/" + aioquic.__version__

# Pipeline fill target: we open enough concurrent streams so that total
# inflight data ≈ TARGET_BYTES at all times.
TARGET_BYTES = 100 * 1024 * 1024   # 100 MB default, overridable via --target-bytes


# ─────────────────────────────────────────────────────────────────────────────
# URL / Request / WebSocket helpers  (unchanged from original)
# ─────────────────────────────────────────────────────────────────────────────

class URL:
    def __init__(self, url: str) -> None:
        parsed = urlparse(url)
        self.authority = parsed.netloc
        self.full_path = parsed.path or "/"
        if parsed.query:
            self.full_path += "?" + parsed.query
        self.scheme = parsed.scheme


class HttpRequest:
    def __init__(
        self,
        method: str,
        url: URL,
        content: bytes = b"",
        headers: Optional[Dict] = None,
    ) -> None:
        if headers is None:
            headers = {}
        self.content = content
        self.headers = headers
        self.method = method
        self.url = url


class WebSocket:
    def __init__(
        self, http: HttpConnection, stream_id: int, transmit: Callable[[], None]
    ) -> None:
        self.http = http
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.stream_id = stream_id
        self.subprotocol: Optional[str] = None
        self.transmit = transmit
        self.websocket = wsproto.Connection(wsproto.ConnectionType.CLIENT)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        data = self.websocket.send(
            wsproto.events.CloseConnection(code=code, reason=reason)
        )
        self.http.send_data(stream_id=self.stream_id, data=data, end_stream=True)
        self.transmit()

    async def recv(self) -> str:
        return await self.queue.get()

    async def send(self, message: str) -> None:
        assert isinstance(message, str)
        data = self.websocket.send(wsproto.events.TextMessage(data=message))
        self.http.send_data(stream_id=self.stream_id, data=data, end_stream=False)
        self.transmit()

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            for header, value in event.headers:
                if header == b"sec-websocket-protocol":
                    self.subprotocol = value.decode()
        elif isinstance(event, DataReceived):
            self.websocket.receive_data(event.data)
        for ws_event in self.websocket.events():
            self.websocket_event_received(ws_event)

    def websocket_event_received(self, event: wsproto.events.Event) -> None:
        if isinstance(event, wsproto.events.TextMessage):
            self.queue.put_nowait(event.data)


# ─────────────────────────────────────────────────────────────────────────────
# HttpClient
# ─────────────────────────────────────────────────────────────────────────────

class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.pushes: Dict[int, Deque[H3Event]] = {}
        self._http: Optional[HttpConnection] = None
        self._request_events: Dict[int, Deque[H3Event]] = {}
        self._request_waiter: Dict[int, asyncio.Future[Deque[H3Event]]] = {}
        self._websockets: Dict[int, WebSocket] = {}

        if self._quic.configuration.alpn_protocols[0].startswith("hq-"):
            self._http = H0Connection(self._quic)
        else:
            self._http = H3Connection(self._quic)

    # ── public methods ────────────────────────────────────────────────────────

    async def get(self, url: str, headers: Optional[Dict] = None) -> Deque[H3Event]:
        return await self._request(HttpRequest(method="GET", url=URL(url), headers=headers))

    async def head(self, url: str, headers: Optional[Dict] = None) -> Deque[H3Event]:
        """HEAD request: server returns headers only, no body."""
        return await self._request(HttpRequest(method="HEAD", url=URL(url), headers=headers))

    async def post(self, url: str, data: bytes, headers: Optional[Dict] = None) -> Deque[H3Event]:
        return await self._request(
            HttpRequest(method="POST", url=URL(url), content=data, headers=headers)
        )

    async def websocket(self, url: str, subprotocols: Optional[List[str]] = None) -> WebSocket:
        request = HttpRequest(method="CONNECT", url=URL(url))
        stream_id = self._quic.get_next_available_stream_id()
        websocket = WebSocket(http=self._http, stream_id=stream_id, transmit=self.transmit)
        self._websockets[stream_id] = websocket
        headers = [
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", request.url.authority.encode()),
            (b":path", request.url.full_path.encode()),
            (b":protocol", b"websocket"),
            (b"user-agent", USER_AGENT.encode()),
            (b"sec-websocket-version", b"13"),
        ]
        if subprotocols:
            headers.append((b"sec-websocket-protocol", ", ".join(subprotocols).encode()))
        self._http.send_headers(stream_id=stream_id, headers=headers)
        self.transmit()
        return websocket

    # ── stream availability ───────────────────────────────────────────────────

    def get_available_streams(self) -> int:
        """
        How many more client-initiated bidi streams can we open right now?
        Client bidi stream IDs: 0, 4, 8, ... so used = next_id // 4.
        Falls back to 100 if QUIC internals aren't accessible.
        """
        try:
            quic = self._quic
            max_streams = quic._remote_max_streams_bidi
            next_id = quic.get_next_available_stream_id(is_unidirectional=False)
            used = next_id // 4
            available = max(1, max_streams - used)
            logger.debug("Stream limits: remote_max=%d used=%d available=%d",
                         max_streams, used, available)
            return available
        except Exception as e:
            logger.debug("Could not read stream limits (%s), defaulting to 100", e)
            return 100

    # ── event routing ─────────────────────────────────────────────────────────

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._request_events:
                self._request_events[stream_id].append(event)
                if event.stream_ended:
                    waiter = self._request_waiter.pop(stream_id)
                    waiter.set_result(self._request_events.pop(stream_id))
            elif stream_id in self._websockets:
                self._websockets[stream_id].http_event_received(event)
            elif event.push_id in self.pushes:
                self.pushes[event.push_id].append(event)
        elif isinstance(event, PushPromiseReceived):
            self.pushes[event.push_id] = deque()
            self.pushes[event.push_id].append(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

    async def _request(self, request: HttpRequest) -> Deque[H3Event]:
        stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", request.method.encode()),
                (b":scheme", request.url.scheme.encode()),
                (b":authority", request.url.authority.encode()),
                (b":path", request.url.full_path.encode()),
                (b"user-agent", USER_AGENT.encode()),
            ] + [(k.encode(), v.encode()) for k, v in request.headers.items()],
            end_stream=not request.content,
        )
        if request.content:
            self._http.send_data(stream_id=stream_id, data=request.content, end_stream=True)

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()
        return await asyncio.shield(waiter)


# ─────────────────────────────────────────────────────────────────────────────
# File-size discovery
# ─────────────────────────────────────────────────────────────────────────────

async def get_file_size(client: HttpClient, url: str) -> int:
    """
    HEAD request → parse Content-Length.
    Returns 0 if unavailable (caller falls back to 1 stream).
    """
    try:
        events = await client.head(url)
        for event in events:
            if isinstance(event, HeadersReceived):
                for header, value in event.headers:
                    if header.lower() == b"content-length":
                        size = int(value.decode().strip())
                        logger.info("HEAD %s → Content-Length: %d bytes", url, size)
                        return size
        logger.warning("HEAD %s returned no Content-Length — defaulting to 1 stream", url)
        return 0
    except Exception as e:
        logger.warning("HEAD request failed (%s) — defaulting to 1 stream", e)
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Stream count calculation
# ─────────────────────────────────────────────────────────────────────────────

def calculate_num_streams(file_size_bytes: int, available_streams: int) -> int:
    """
    How many concurrent streams to keep open at all times?

      needed = ceil(TARGET_BYTES / file_size)
      result = max(1, min(needed, available_streams))

    Examples (TARGET = 10 MB):
      200 MB → 1 stream    (file already > target)
       10 MB → 1 stream
        1 MB → 10 streams
      100 KB → 100 streams
        1 KB → min(10240, available)
    """
    if file_size_bytes <= 0:
        logger.info("File size unknown — using 1 stream")
        return 1
    needed = math.ceil(TARGET_BYTES / file_size_bytes)
    result = max(1, min(needed, available_streams))
    logger.info(
        "File: %d B | Target: %d B | Needed streams: %d | "
        "Available: %d | Persistent slots: %d",
        file_size_bytes, TARGET_BYTES, needed, available_streams, result,
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Single request  (one GET, returns bytes transferred + elapsed)
# ─────────────────────────────────────────────────────────────────────────────

async def perform_http_request(
    client: HttpClient,
    url: str,
    data: Optional[str],
    include: bool,
    output_dir: Optional[str],
    stream_index: int = 0,
) -> None:
    start = time.time()
    if data is not None:
        data_bytes = data.encode()
        http_events = await client.post(
            url, data=data_bytes,
            headers={
                "content-length": str(len(data_bytes)),
                "content-type": "application/x-www-form-urlencoded",
            },
        )
        method = "POST"
    else:
        http_events = await client.get(url)
        method = "GET"
    elapsed = time.time() - start

    octets = sum(len(e.data) for e in http_events if isinstance(e, DataReceived))
    logger.debug(
        "[slot %d] %s %s → %d B in %.3f s (%.3f Mbps)",
        stream_index, method, urlparse(url).path,
        octets, elapsed,
        octets * 8 / elapsed / 1_000_000 if elapsed > 0 else 0,
    )

    # Only write to disk for non-pipeline (single-shot) usage.
    # In pipeline mode output_dir is passed as None to avoid millions of files.
    if output_dir is not None:
        basename = os.path.basename(urlparse(url).path) or "index.html"
        if stream_index > 0:
            name, ext = os.path.splitext(basename)
            basename = f"{name}_s{stream_index}{ext}"
        with open(os.path.join(output_dir, basename), "wb") as f:
            write_response(http_events=http_events, include=include, output_file=f)


# ─────────────────────────────────────────────────────────────────────────────
# Persistent pipeline worker
# ─────────────────────────────────────────────────────────────────────────────

async def pipeline_worker(
    client: HttpClient,
    url: str,
    data: Optional[str],
    slot_id: int,
    stop_event: asyncio.Event,
) -> None:
    """
    One pipeline slot: runs GET requests back-to-back with zero gap.

    As soon as a request completes, the next one is issued immediately —
    no waiting for other slots, no batch synchronisation.
    This guarantees exactly N streams in flight at all times.

    Exits cleanly when stop_event is set or the task is cancelled (timeout).
    """
    count = 0
    while not stop_event.is_set():
        try:
            await perform_http_request(
                client=client,
                url=url,
                data=data,
                include=False,
                output_dir=None,   # no disk I/O in pipeline mode
                stream_index=slot_id,
            )
            count += 1
        except asyncio.CancelledError:
            # timeout cancelled us — exit gracefully
            raise
        except Exception as e:
            # transient error (e.g. server reset a stream) — log and retry
            logger.warning("[slot %d] request error: %s — retrying", slot_id, e)
            await asyncio.sleep(0.05)   # tiny back-off to avoid tight error spin

    logger.debug("[slot %d] stop signal received after %d requests", slot_id, count)


# ─────────────────────────────────────────────────────────────────────────────
# Persistent pipeline orchestrator
# ─────────────────────────────────────────────────────────────────────────────

async def run_persistent_pipeline(
    client: HttpClient,
    url: str,
    data: Optional[str],
    duration_s: float,
) -> None:
    """
    1. HEAD → file size
    2. Calculate N = min(ceil(TARGET/size), available_streams)
    3. Launch N persistent worker coroutines via asyncio.gather
    4. Each worker loops forever: finish one GET → immediately start next
    5. After duration_s seconds, cancel all workers cleanly

    Why this eliminates throughput gaps
    ────────────────────────────────────
    In a batch gather approach all N streams finish at roughly the same time,
    leaving a dead period while Python spins up the next batch.
    Here, each slot is independent: slot-0 finishing has nothing to do with
    slot-1, so there is never a moment where ALL slots are idle simultaneously.
    """
    # ── Step 1: discover file size (one HEAD, cached for the whole run) ──
    file_size = await get_file_size(client, url)

    # ── Step 2: stream count ──────────────────────────────────────────────
    available = client.get_available_streams()
    n_streams = calculate_num_streams(file_size, available)

    logger.info(
        "Starting persistent pipeline: %d slot(s) × %s for %.0f s",
        n_streams, url, duration_s,
    )

    stop_event = asyncio.Event()

    # ── Step 3 & 4: launch N independent looping workers ─────────────────
    workers = [
        asyncio.ensure_future(
            pipeline_worker(
                client=client,
                url=url,
                data=data,
                slot_id=i,
                stop_event=stop_event,
            )
        )
        for i in range(n_streams)
    ]

    # ── Step 5: run until duration_s, then cancel cleanly ────────────────
    try:
        await asyncio.wait_for(
            asyncio.gather(*workers, return_exceptions=True),
            timeout=duration_s,
        )
    except asyncio.TimeoutError:
        logger.info("Pipeline duration %.0f s elapsed — stopping all slots", duration_s)
        stop_event.set()
        # cancel any still-running workers
        for w in workers:
            if not w.done():
                w.cancel()
        # wait for all cancellations to settle
        await asyncio.gather(*workers, return_exceptions=True)

    logger.info("Pipeline finished for %s", url)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP push / write helpers  (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def process_http_pushes(client: HttpClient, include: bool, output_dir: Optional[str]) -> None:
    for _, http_events in client.pushes.items():
        method = octets = path = ""
        for http_event in http_events:
            if isinstance(http_event, DataReceived):
                octets += len(http_event.data)
            elif isinstance(http_event, PushPromiseReceived):
                for header, value in http_event.headers:
                    if header == b":method":
                        method = value.decode()
                    elif header == b":path":
                        path = value.decode()
        logger.info("Push received for %s %s : %s bytes", method, path, octets)
        if output_dir is not None:
            output_path = os.path.join(output_dir, os.path.basename(path) or "index.html")
            with open(output_path, "wb") as f:
                write_response(http_events=http_events, include=include, output_file=f)


def write_response(http_events: Deque[H3Event], output_file: BinaryIO, include: bool) -> None:
    for http_event in http_events:
        if isinstance(http_event, HeadersReceived) and include:
            headers = b""
            for k, v in http_event.headers:
                headers += k + b": " + v + b"\r\n"
            if headers:
                output_file.write(headers + b"\r\n")
        elif isinstance(http_event, DataReceived):
            output_file.write(http_event.data)


def save_session_ticket(ticket: SessionTicket) -> None:
    logger.info("New session ticket received")
    if args.session_ticket:
        with open(args.session_ticket, "wb") as fp:
            pickle.dump(ticket, fp)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

async def main(
    configuration: QuicConfiguration,
    urls: List[str],
    data: Optional[str],
    include: bool,
    output_dir: Optional[str],
    local_port: int,
    zero_rtt: bool,
    duration_s: float,
) -> None:
    parsed = urlparse(urls[0])
    assert parsed.scheme in ("https", "wss"), "Only https:// or wss:// URLs are supported."
    host = parsed.hostname
    port = parsed.port if parsed.port is not None else 443

    for i in range(1, len(urls)):
        _p = urlparse(urls[i])
        _scheme = _p.scheme or parsed.scheme
        _host   = _p.hostname or host
        _port   = _p.port or port
        assert _scheme == parsed.scheme, "URL scheme doesn't match"
        assert _host == host,            "URL hostname doesn't match"
        assert _port == port,            "URL port doesn't match"
        _p = _p._replace(scheme=_scheme, netloc="{}:{}".format(_host, _port))
        urls[i] = urlparse(_p.geturl()).geturl()

    async with connect(
        host, port,
        configuration=configuration,
        create_protocol=HttpClient,
        session_ticket_handler=save_session_ticket,
        local_port=local_port,
        wait_connected=not zero_rtt,
    ) as client:
        client = cast(HttpClient, client)

        # Each URL gets its own persistent pipeline run sequentially.
        # (If you want multiple URLs pipelined simultaneously, wrap in gather.)
        for url in urls:
            await run_persistent_pipeline(
                client=client,
                url=url,
                data=data,
                duration_s=duration_s,
            )

        client.close(error_code=ErrorCode.H3_NO_ERROR)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    defaults = QuicConfiguration(is_client=True)

    parser = argparse.ArgumentParser(
        description="HTTP/3 client with persistent auto-pipelined streams"
    )
    parser.add_argument("url", type=str, nargs="+", help="URL(s) to request (must be HTTPS)")
    parser.add_argument("--ca-certs", type=str)
    parser.add_argument("--certificate", type=str)
    parser.add_argument("--cipher-suites", type=str)
    parser.add_argument(
        "--congestion-control-algorithm", type=str, default="reno",
        help="CCA to use (default: reno)",
    )
    parser.add_argument("-d", "--data", type=str, help="body for POST requests")
    parser.add_argument("-i", "--include", action="store_true",
                        help="include HTTP response headers in output")
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS certificate verification")
    parser.add_argument("--legacy-http", action="store_true", help="use HTTP/0.9")
    parser.add_argument("--max-data", type=int,
                        help="connection-wide flow control limit (default: %d)" % defaults.max_data)
    parser.add_argument("--max-stream-data", type=int,
                        help="per-stream flow control limit (default: %d)" % defaults.max_stream_data)
    parser.add_argument("--negotiate-v2", action="store_true")
    parser.add_argument("--output-dir", type=str,
                        help="write responses here (single-shot mode only; "
                             "disabled in pipeline mode to avoid disk flood)")
    parser.add_argument("--private-key", type=str)
    parser.add_argument("-q", "--quic-log", type=str,
                        help="write QLOG files to this directory")
    parser.add_argument("-l", "--secrets-log", type=str)
    parser.add_argument("-s", "--session-ticket", type=str)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--local-port", type=int, default=0)
    parser.add_argument("--max-datagram-size", type=int, default=defaults.max_datagram_size)
    parser.add_argument("--zero-rtt", action="store_true")
    parser.add_argument(
        "--target-bytes", type=int, default=TARGET_BYTES,
        help="pipeline fill target in bytes (default: 10485760 = 10 MB). "
             "Number of concurrent streams = ceil(target / file_size).",
    )
    parser.add_argument(
        "--duration", type=float, default=120.0,
        help="how long to run the persistent pipeline in seconds (default: 120)",
    )

    args = parser.parse_args()
    TARGET_BYTES = args.target_bytes   # propagate CLI override to module-level constant

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    if args.output_dir is not None and not os.path.isdir(args.output_dir):
        raise Exception("%s is not a directory" % args.output_dir)

    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H0_ALPN if args.legacy_http else H3_ALPN,
        congestion_control_algorithm=args.congestion_control_algorithm,
        max_datagram_size=args.max_datagram_size,
    )
    if args.ca_certs:
        configuration.load_verify_locations(args.ca_certs)
    if args.cipher_suites:
        configuration.cipher_suites = [
            CipherSuite[s] for s in args.cipher_suites.split(",")
        ]
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.max_data:
        configuration.max_data = args.max_data
    if args.max_stream_data:
        configuration.max_stream_data = args.max_stream_data
    if args.negotiate_v2:
        configuration.original_version = QuicProtocolVersion.VERSION_1
        configuration.supported_versions = [
            QuicProtocolVersion.VERSION_2,
            QuicProtocolVersion.VERSION_1,
        ]
    if args.quic_log:
        configuration.quic_logger = QuicFileLogger(args.quic_log)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")
    if args.session_ticket:
        try:
            with open(args.session_ticket, "rb") as fp:
                configuration.session_ticket = pickle.load(fp)
        except FileNotFoundError:
            pass
    if args.certificate is not None:
        configuration.load_cert_chain(args.certificate, args.private_key)

    if uvloop is not None:
        uvloop.install()

    asyncio.run(
        main(
            configuration=configuration,
            urls=args.url,
            data=args.data,
            include=args.include,
            output_dir=args.output_dir,
            local_port=args.local_port,
            zero_rtt=args.zero_rtt,
            duration_s=args.duration,
        )
    )