import argparse
import asyncio
import logging
import math
import os
import pickle
import random
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
from aioquic.quic.events import HandshakeCompleted, QuicEvent
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

# Pipeline tuning defaults — all overridable via CLI
TARGET_BYTES  = 100 * 1024 * 1024   # 100 MB: base for stream-count formula
MIN_STREAMS   = 20                   # floor: large files never drop below this
MAX_STREAMS   = 50                   # ceiling: small files never exceed this


# ─────────────────────────────────────────────────────────────────────────────
# Response parse result
# ─────────────────────────────────────────────────────────────────────────────

class HttpResponse:
    """Parsed result of a single HTTP/3 response."""
    def __init__(self, events: Deque[H3Event]) -> None:
        self.status: int = 0
        self.headers: Dict[bytes, bytes] = {}
        self.body_bytes: int = 0
        for event in events:
            if isinstance(event, HeadersReceived):
                for k, v in event.headers:
                    self.headers[k.lower()] = v
                    if k == b":status":
                        self.status = int(v)
            elif isinstance(event, DataReceived):
                self.body_bytes += len(event.data)

    @property
    def content_length(self) -> int:
        try:
            return int(self.headers.get(b"content-length", b"0"))
        except ValueError:
            return 0

    def is_ok(self)          -> bool: return 200 <= self.status < 300
    def is_rate_limited(self) -> bool: return self.status == 429
    def is_server_error(self) -> bool: return 500 <= self.status < 600
    def is_client_error(self) -> bool: return 400 <= self.status < 500 and self.status != 429


# ─────────────────────────────────────────────────────────────────────────────
# URL / Request / WebSocket helpers
# ─────────────────────────────────────────────────────────────────────────────

class URL:
    def __init__(self, url: str) -> None:
        parsed = urlparse(url)
        self.authority = parsed.netloc
        self.full_path  = parsed.path or "/"
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
        self.method  = method
        self.url     = url


class WebSocket:
    def __init__(
        self, http: HttpConnection, stream_id: int, transmit: Callable[[], None]
    ) -> None:
        self.http         = http
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.stream_id    = stream_id
        self.subprotocol: Optional[str] = None
        self.transmit     = transmit
        self.websocket    = wsproto.Connection(wsproto.ConnectionType.CLIENT)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        data = self.websocket.send(wsproto.events.CloseConnection(code=code, reason=reason))
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
        self._http: Optional[HttpConnection]   = None
        self._request_events:  Dict[int, Deque[H3Event]]              = {}
        self._request_waiter:  Dict[int, asyncio.Future[Deque[H3Event]]] = {}
        self._websockets:      Dict[int, WebSocket]                    = {}
        # Set when HandshakeCompleted fires. wait_connected() on connect()
        # can resolve before the peer's transport parameters (incl. stream
        # limits) are fully processed — this is the reliable signal instead.
        self._handshake_complete = asyncio.Event()

        if self._quic.configuration.alpn_protocols[0].startswith("hq-"):
            self._http = H0Connection(self._quic)
        else:
            self._http = H3Connection(self._quic)

    async def get(self, url: str, headers: Optional[Dict] = None) -> Deque[H3Event]:
        return await self._request(HttpRequest(method="GET", url=URL(url), headers=headers))

    async def head(self, url: str, headers: Optional[Dict] = None) -> Deque[H3Event]:
        return await self._request(HttpRequest(method="HEAD", url=URL(url), headers=headers))

    async def post(self, url: str, data: bytes, headers: Optional[Dict] = None) -> Deque[H3Event]:
        return await self._request(
            HttpRequest(method="POST", url=URL(url), content=data, headers=headers)
        )

    def get_available_streams(self) -> int:
        try:
            quic       = self._quic
            max_str    = quic._remote_max_streams_bidi
            next_id    = quic.get_next_available_stream_id(is_unidirectional=False)
            used       = next_id // 4
            available  = max(1, max_str - used)
            logger.debug("Stream limits: remote_max=%d used=%d available=%d",
                         max_str, used, available)
            return available
        except Exception as e:
            logger.debug("Could not read stream limits (%s), defaulting to 100", e)
            return 100

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, (HeadersReceived, DataReceived)):
            sid = event.stream_id
            if sid in self._request_events:
                self._request_events[sid].append(event)
                if event.stream_ended:
                    waiter = self._request_waiter.pop(sid)
                    waiter.set_result(self._request_events.pop(sid))
            elif sid in self._websockets:
                self._websockets[sid].http_event_received(event)
            elif event.push_id in self.pushes:
                self.pushes[event.push_id].append(event)
        elif isinstance(event, PushPromiseReceived):
            self.pushes[event.push_id] = deque()
            self.pushes[event.push_id].append(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            self._handshake_complete.set()
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

    async def wait_handshake_complete(self, timeout: float = 10.0) -> None:
        """
        Block until the QUIC handshake is complete, i.e. until the peer's
        transport parameters (including remote stream limits) have been
        processed. Must be awaited before get_available_streams() is called
        anywhere that isn't already guaranteed to run after a request has
        completed (e.g. the --fixed-streams path, which skips the HEAD
        request that used to create that guarantee as a side effect).
        """
        try:
            await asyncio.wait_for(self._handshake_complete.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(
                "Handshake completion wait timed out after %.1f s — "
                "proceeding anyway, stream limits may be inaccurate", timeout,
            )

    async def _request(self, request: HttpRequest) -> Deque[H3Event]:
        stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method",    request.method.encode()),
                (b":scheme",    request.url.scheme.encode()),
                (b":authority", request.url.authority.encode()),
                (b":path",      request.url.full_path.encode()),
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
    Returns 0 if unavailable (caller uses MIN_STREAMS as fallback).
    """
    try:
        resp = HttpResponse(await client.head(url))
        if resp.content_length > 0:
            logger.info("HEAD %s → Content-Length: %d bytes", url, resp.content_length)
            return resp.content_length
        logger.warning("HEAD %s returned no Content-Length", url)
        return 0
    except Exception as e:
        logger.warning("HEAD request failed (%s)", e)
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Stream count calculation
# ─────────────────────────────────────────────────────────────────────────────

def calculate_num_streams(
    file_size_bytes: int,
    available_streams: int,
    min_streams: int = MIN_STREAMS,
    max_streams: int = MAX_STREAMS,
    fixed_streams: Optional[int] = None,
) -> int:
    """
    How many concurrent persistent streams to maintain.

    If fixed_streams is set, bypasses the file-size formula entirely and
    uses that value directly (still capped by what the server will allow).

    Otherwise:
        needed = ceil(TARGET_BYTES / file_size)
        result = clamp(needed, min_streams, min(max_streams, available))

    The clamp is the key fix for equal throughput across file sizes:

        Small files (1KB):  needed=102400 → capped at max_streams (e.g. 50)
        Large files (200MB): needed=1     → floored at min_streams (e.g. 20)

    This keeps all sizes in the same narrow stream-count band so aggregate
    throughput is comparable regardless of individual file size.

    Tune --min-streams and --max-streams to adjust the band.
    """
    if fixed_streams is not None:
        result = min(fixed_streams, available_streams)
        logger.info(
            "Fixed streams explicitly set: %d | available: %d | opening: %d streams",
            fixed_streams, available_streams, result,
        )
        return result

    if file_size_bytes <= 0:
        result = min_streams
    else:
        needed = math.ceil(TARGET_BYTES / file_size_bytes)
        result = max(min_streams, min(needed, max_streams, available_streams))

    logger.info(
        "File: %d B | needed: %d | available: %d | "
        "min: %d | max: %d | opening: %d streams",
        file_size_bytes,
        math.ceil(TARGET_BYTES / file_size_bytes) if file_size_bytes > 0 else -1,
        available_streams, min_streams, max_streams, result,
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Backoff helper
# ─────────────────────────────────────────────────────────────────────────────

def exponential_backoff(attempt: int, base: float = 0.5, cap: float = 30.0) -> float:
    """
    Full-jitter exponential backoff.
    attempt=0 → up to 0.5s
    attempt=5 → up to 16s
    always capped at cap seconds.
    """
    return random.uniform(0, min(cap, base * (2 ** attempt)))


# ─────────────────────────────────────────────────────────────────────────────
# Single request with full internet-safe error handling
# ─────────────────────────────────────────────────────────────────────────────

class RateLimitedError(Exception):
    """Server returned 429 — caller should back off."""

class FatalResponseError(Exception):
    """4xx (not 429) — no point retrying this URL."""

class ServerError(Exception):
    """5xx — transient, retry with backoff."""


async def do_request(
    client: HttpClient,
    url: str,
    data: Optional[str],
    request_timeout: float,
    stream_index: int,
) -> HttpResponse:
    """
    One GET (or POST) with:
      - per-request timeout              → asyncio.TimeoutError
      - status code inspection           → typed exceptions for caller
      - Retry-After header respected     → returned as attribute on RateLimitedError
    """
    start = time.time()
    try:
        if data is not None:
            data_bytes = data.encode()
            raw = await asyncio.wait_for(
                client.post(url, data=data_bytes, headers={
                    "content-length": str(len(data_bytes)),
                    "content-type":   "application/x-www-form-urlencoded",
                }),
                timeout=request_timeout,
            )
            method = "POST"
        else:
            raw    = await asyncio.wait_for(client.get(url), timeout=request_timeout)
            method = "GET"
    except asyncio.TimeoutError:
        logger.warning("[slot %d] request timed out after %.1f s", stream_index, request_timeout)
        raise

    elapsed  = time.time() - start
    resp     = HttpResponse(raw)

    logger.debug(
        "[slot %d] %s %s → HTTP %d | %d B | %.3f s | %.3f Mbps",
        stream_index, method, urlparse(url).path,
        resp.status, resp.body_bytes, elapsed,
        resp.body_bytes * 8 / elapsed / 1_000_000 if elapsed > 0 else 0,
    )

    if resp.is_rate_limited():
        retry_after = float(resp.headers.get(b"retry-after", b"5").decode())
        logger.warning("[slot %d] 429 rate-limited — Retry-After: %.0f s",
                       stream_index, retry_after)
        err = RateLimitedError(str(resp.status))
        err.retry_after = retry_after          # type: ignore[attr-defined]
        raise err

    if resp.is_client_error():
        logger.error("[slot %d] fatal %d for %s — stopping this slot",
                     stream_index, resp.status, url)
        raise FatalResponseError(str(resp.status))

    if resp.is_server_error():
        logger.warning("[slot %d] server error %d — will retry with backoff",
                       stream_index, resp.status)
        raise ServerError(str(resp.status))

    return resp


# ─────────────────────────────────────────────────────────────────────────────
# Persistent pipeline worker  (one independent slot)
# ─────────────────────────────────────────────────────────────────────────────

async def pipeline_worker(
    client:          HttpClient,
    url:             str,
    data:            Optional[str],
    slot_id:         int,
    stop_event:      asyncio.Event,
    request_timeout: float,
    max_retries:     int,
) -> None:
    """
    One pipeline slot: runs requests in a tight back-to-back loop.

    Internet-safe behaviour:
      • 429 Rate Limited  → respects Retry-After, then resumes
      • 4xx Fatal         → stops this slot permanently (URL is broken)
      • 5xx Server Error  → exponential backoff, up to max_retries then stops
      • Timeout           → exponential backoff, unlimited retries
      • CancelledError    → exits cleanly (duration elapsed)
    """
    consecutive_errors = 0
    requests_done      = 0

    while not stop_event.is_set():
        try:
            await do_request(
                client=client, url=url, data=data,
                request_timeout=request_timeout,
                stream_index=slot_id,
            )
            requests_done      += 1
            consecutive_errors  = 0   # reset on success

        except asyncio.CancelledError:
            raise   # propagate — duration elapsed, time to stop

        except RateLimitedError as e:
            wait = getattr(e, "retry_after", 5.0)
            logger.info("[slot %d] backing off %.1f s (rate limited)", slot_id, wait)
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=wait)
                return   # stop_event fired during back-off
            except asyncio.TimeoutError:
                pass     # back-off elapsed, resume

        except FatalResponseError:
            logger.error("[slot %d] fatal error — slot exiting permanently", slot_id)
            return   # don't retry 4xx

        except (ServerError, asyncio.TimeoutError, Exception) as e:
            consecutive_errors += 1
            if isinstance(e, ServerError) and consecutive_errors > max_retries:
                logger.error("[slot %d] too many server errors (%d) — slot exiting",
                             slot_id, consecutive_errors)
                return
            wait = exponential_backoff(consecutive_errors - 1)
            logger.warning("[slot %d] error #%d (%s) — retrying in %.2f s",
                           slot_id, consecutive_errors, type(e).__name__, wait)
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=wait)
                return
            except asyncio.TimeoutError:
                pass

    logger.debug("[slot %d] stop signal — exiting after %d requests", slot_id, requests_done)


# ─────────────────────────────────────────────────────────────────────────────
# Persistent pipeline orchestrator
# ─────────────────────────────────────────────────────────────────────────────

async def run_persistent_pipeline(
    client:          HttpClient,
    url:             str,
    data:            Optional[str],
    duration_s:      float,
    request_timeout: float,
    max_retries:     int,
    min_streams:     int,
    max_streams:     int,
    fixed_streams:   Optional[int] = None,
) -> None:
    """
    1. HEAD  → file size (skipped when --fixed-streams is set, since the
       stream count no longer depends on it)
    2. clamp(needed, min_streams, min(max_streams, available)) → N
       (or just fixed_streams, capped by what the server allows)
    3. Launch N independent looping workers
    4. Each worker: finish one request → immediately start next (zero gap)
    5. After duration_s, cancel all workers cleanly

    Why no throughput gaps:
      Each slot is independent — slot-0 finishing has no effect on slots 1…N-1.
      There is never a moment where ALL slots are idle simultaneously.
    """
    # Must happen before ANY stream-limit check. wait_connected=True on
    # connect() is not sufficient on its own — it can resolve before
    # _remote_max_streams_bidi is populated from the peer's transport
    # parameters, which get_available_streams() reads.
    await client.wait_handshake_complete()

    file_size = 0 if fixed_streams is not None else await get_file_size(client, url)
    available = client.get_available_streams()
    n_streams = calculate_num_streams(
        file_size_bytes=file_size,
        available_streams=available,
        min_streams=min_streams,
        max_streams=max_streams,
        fixed_streams=fixed_streams,
    )

    logger.info("Persistent pipeline: %d slot(s) × %s for %.0f s", n_streams, url, duration_s)
    stop_event = asyncio.Event()

    workers = [
        asyncio.ensure_future(
            pipeline_worker(
                client=client, url=url, data=data,
                slot_id=i, stop_event=stop_event,
                request_timeout=request_timeout,
                max_retries=max_retries,
            )
        )
        for i in range(n_streams)
    ]

    try:
        await asyncio.wait_for(
            asyncio.gather(*workers, return_exceptions=True),
            timeout=duration_s,
        )
    except asyncio.TimeoutError:
        logger.info("Pipeline duration %.0f s elapsed — stopping", duration_s)
        stop_event.set()
        for w in workers:
            if not w.done():
                w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

    logger.info("Pipeline finished for %s", url)


# ─────────────────────────────────────────────────────────────────────────────
# Misc helpers
# ─────────────────────────────────────────────────────────────────────────────

def write_response(http_events: Deque[H3Event], output_file: BinaryIO, include: bool) -> None:
    for event in http_events:
        if isinstance(event, HeadersReceived) and include:
            headers = b""
            for k, v in event.headers:
                headers += k + b": " + v + b"\r\n"
            if headers:
                output_file.write(headers + b"\r\n")
        elif isinstance(event, DataReceived):
            output_file.write(event.data)


def save_session_ticket(ticket: SessionTicket) -> None:
    logger.info("New session ticket received")
    if args.session_ticket:
        with open(args.session_ticket, "wb") as fp:
            pickle.dump(ticket, fp)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

async def main(
    configuration:   QuicConfiguration,
    urls:            List[str],
    data:            Optional[str],
    include:         bool,
    output_dir:      Optional[str],
    local_port:      int,
    zero_rtt:        bool,
    duration_s:      float,
    request_timeout: float,
    max_retries:     int,
    min_streams:     int,
    max_streams:     int,
    fixed_streams:   Optional[int] = None,
) -> None:
    parsed = urlparse(urls[0])
    assert parsed.scheme in ("https", "wss"), "Only https:// or wss:// URLs are supported."
    host = parsed.hostname
    port = parsed.port if parsed.port is not None else 443

    for i in range(1, len(urls)):
        _p      = urlparse(urls[i])
        _scheme = _p.scheme   or parsed.scheme
        _host   = _p.hostname or host
        _port   = _p.port     or port
        assert _scheme == parsed.scheme, "URL scheme doesn't match"
        assert _host   == host,          "URL hostname doesn't match"
        assert _port   == port,          "URL port doesn't match"
        _p    = _p._replace(scheme=_scheme, netloc="{}:{}".format(_host, _port))
        urls[i] = urlparse(_p.geturl()).geturl()

    # ── internet-safe connection setup ────────────────────────────────────────
    # wait_for on the connect itself catches UDP-blocked / firewall scenarios
    try:
        conn_ctx = connect(
            host, port,
            configuration=configuration,
            create_protocol=HttpClient,
            session_ticket_handler=save_session_ticket,
            local_port=local_port,
            wait_connected=not zero_rtt,
        )
        async with conn_ctx as client:
            client = cast(HttpClient, client)
            for url in urls:
                await run_persistent_pipeline(
                    client=client, url=url, data=data,
                    duration_s=duration_s,
                    request_timeout=request_timeout,
                    max_retries=max_retries,
                    min_streams=min_streams,
                    max_streams=max_streams,
                    fixed_streams=fixed_streams,
                )
            client.close(error_code=ErrorCode.H3_NO_ERROR)
    except TimeoutError:
        logger.error(
            "Connection to %s:%d timed out after 15 s — "
            "UDP may be blocked by a firewall or middlebox.", host, port
        )
        raise SystemExit(1)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    defaults = QuicConfiguration(is_client=True)

    parser = argparse.ArgumentParser(
        description="HTTP/3 client — persistent auto-pipelined streams"
    )
    parser.add_argument("url", nargs="+", help="URL(s) to request (must be HTTPS)")
    parser.add_argument("--ca-certs")
    parser.add_argument("--certificate")
    parser.add_argument("--cipher-suites")
    parser.add_argument("--congestion-control-algorithm", default="reno")
    parser.add_argument("-d", "--data")
    parser.add_argument("-i", "--include", action="store_true")
    parser.add_argument("--insecure",    action="store_true")
    parser.add_argument("--legacy-http", action="store_true")
    parser.add_argument("--max-data",        type=int)
    parser.add_argument("--max-stream-data", type=int)
    parser.add_argument("--negotiate-v2",    action="store_true")
    parser.add_argument("--output-dir")
    parser.add_argument("--private-key")
    parser.add_argument("-q", "--quic-log")
    parser.add_argument("-l", "--secrets-log")
    parser.add_argument("-s", "--session-ticket")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--local-port",        type=int,   default=0)
    parser.add_argument("--max-datagram-size", type=int,   default=defaults.max_datagram_size)
    parser.add_argument("--zero-rtt",          action="store_true")

    # ── pipeline tuning ───────────────────────────────────────────────────────
    parser.add_argument(
        "--fixed-streams", type=int, default=None,
        help="explicitly set stream count, bypassing the file-size formula "
             "entirely (still capped by what the server allows). "
             "When set, the HEAD request used for file-size discovery is skipped.",
    )
    parser.add_argument(
        "--target-bytes", type=int, default=TARGET_BYTES,
        help="pipeline fill target in bytes (default: 100 MB). "
             "needed_streams = ceil(target / file_size), then clamped by min/max. "
             "Ignored when --fixed-streams is set.",
    )
    parser.add_argument(
        "--min-streams", type=int, default=MIN_STREAMS,
        help="minimum concurrent streams regardless of file size (default: %(default)s). "
             "Prevents large files from using too few streams and getting low throughput. "
             "Ignored when --fixed-streams is set.",
    )
    parser.add_argument(
        "--max-streams", type=int, default=MAX_STREAMS,
        help="maximum concurrent streams regardless of file size (default: %(default)s). "
             "Prevents small files from opening too many streams and dominating throughput. "
             "Ignored when --fixed-streams is set.",
    )
    parser.add_argument(
        "--duration", type=float, default=120.0,
        help="pipeline run time in seconds (default: 120)",
    )

    # ── internet-safety tuning ────────────────────────────────────────────────
    parser.add_argument(
        "--request-timeout", type=float, default=30.0,
        help="per-request timeout in seconds (default: 30). "
             "Stuck streams are killed and retried rather than blocking a slot forever.",
    )
    parser.add_argument(
        "--max-retries", type=int, default=5,
        help="max consecutive 5xx / server errors before a slot gives up (default: 5). "
             "Timeout errors always retry (with backoff) regardless of this limit.",
    )

    args = parser.parse_args()

    # propagate CLI overrides to module-level constants used by helpers
    TARGET_BYTES = args.target_bytes
    MIN_STREAMS  = args.min_streams
    MAX_STREAMS  = args.max_streams

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    if args.output_dir is not None and not os.path.isdir(args.output_dir):
        raise SystemExit(f"{args.output_dir} is not a directory")

    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H0_ALPN if args.legacy_http else H3_ALPN,
        congestion_control_algorithm=args.congestion_control_algorithm,
        max_datagram_size=args.max_datagram_size,
    )
    if args.ca_certs:         configuration.load_verify_locations(args.ca_certs)
    if args.cipher_suites:
        configuration.cipher_suites = [CipherSuite[s] for s in args.cipher_suites.split(",")]
    if args.insecure:         configuration.verify_mode = ssl.CERT_NONE
    if args.max_data:         configuration.max_data = args.max_data
    if args.max_stream_data:  configuration.max_stream_data = args.max_stream_data
    if args.negotiate_v2:
        configuration.original_version    = QuicProtocolVersion.VERSION_1
        configuration.supported_versions  = [
            QuicProtocolVersion.VERSION_2,
            QuicProtocolVersion.VERSION_1,
        ]
    if args.quic_log:     configuration.quic_logger        = QuicFileLogger(args.quic_log)
    if args.secrets_log:  configuration.secrets_log_file   = open(args.secrets_log, "a")
    if args.session_ticket:
        try:
            with open(args.session_ticket, "rb") as fp:
                configuration.session_ticket = pickle.load(fp)
        except FileNotFoundError:
            pass
    if args.certificate:
        configuration.load_cert_chain(args.certificate, args.private_key)

    if uvloop is not None:
        uvloop.install()

    asyncio.run(
        main(
            configuration   = configuration,
            urls            = args.url,
            data            = args.data,
            include         = args.include,
            output_dir      = args.output_dir,
            local_port      = args.local_port,
            zero_rtt        = args.zero_rtt,
            duration_s      = args.duration,
            request_timeout = args.request_timeout,
            max_retries     = args.max_retries,
            min_streams     = args.min_streams,
            max_streams     = args.max_streams,
            fixed_streams   = args.fixed_streams,
        )
    )