import argparse
import asyncio
import ssl
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.quic.packet import QuicProtocolVersion


class Http3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._responses: Dict[int, Dict[str, object]] = {}

    async def get(self, url: str) -> Tuple[List[Tuple[bytes, bytes]], bytes]:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "https").encode()
        authority = parsed.netloc.encode()
        path = (parsed.path or "/")
        if parsed.query:
            path += "?" + parsed.query

        stream_id = self._quic.get_next_available_stream_id(is_unidirectional=False)
        waiter = asyncio.get_running_loop().create_future()
        self._responses[stream_id] = {
            "headers": [],
            "body": bytearray(),
            "waiter": waiter,
        }

        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", scheme),
                (b":authority", authority),
                (b":path", path.encode()),
                (b"user-agent", b"ocaml-quic-v2-check/1"),
            ],
            end_stream=True,
        )
        self.transmit()
        response = await waiter
        return response["headers"], bytes(response["body"])

    def quic_event_received(self, event: QuicEvent) -> None:
        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                response = self._responses.get(http_event.stream_id)
                if response is not None:
                    response["headers"] = list(http_event.headers)
                    if http_event.stream_ended:
                        waiter = response["waiter"]
                        if not waiter.done():
                            waiter.set_result(response)
            elif isinstance(http_event, DataReceived):
                response = self._responses.get(http_event.stream_id)
                if response is not None:
                    response["body"].extend(http_event.data)
                    if http_event.stream_ended:
                        waiter = response["waiter"]
                        if not waiter.done():
                            waiter.set_result(response)


async def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP/3 request over QUIC v2")
    parser.add_argument(
        "url",
        nargs="?",
        default="https://127.0.0.1:4433/",
        help="Target URL (default: https://127.0.0.1:4433/)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10)",
    )
    args = parser.parse_args()

    parsed = urlparse(args.url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 443

    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    cfg.original_version = QuicProtocolVersion.VERSION_2
    cfg.supported_versions = [QuicProtocolVersion.VERSION_2]

    async with connect(
        host,
        port,
        configuration=cfg,
        create_protocol=Http3ClientProtocol,
        wait_connected=True,
    ) as protocol:
        p = protocol
        headers, body = await asyncio.wait_for(p.get(args.url), timeout=args.timeout)
        version = int(p._quic._version)
        print(f"connected; negotiated_version=0x{version:08x}")

        status = b""
        for k, v in headers:
            if k == b":status":
                status = v
                break
        if status:
            print(f"status: {status.decode()}")

        if body:
            print(body.decode(errors="replace"))


if __name__ == "__main__":
    asyncio.run(main())
