"""In-memory stand-ins for the events emitted by an HTTP/2 implementation."""
from __future__ import annotations

from typing import Optional

from wsproto.typing import Headers as HeaderList


class RequestReceived:
    def __init__(self, headers: HeaderList, stream_ended: bool = False) -> None:
        self.headers = headers
        self.stream_ended = stream_ended


class ResponseReceived:
    def __init__(self, headers: HeaderList, stream_ended: bool = False) -> None:
        self.headers = headers
        self.stream_ended = stream_ended


class DataReceived:
    def __init__(self, data: bytes, stream_ended: bool = False) -> None:
        self.data = data
        self.stream_ended = stream_ended


class StreamEnded:
    pass


CONNECT_HEADERS: HeaderList = [
    (b":method", b"CONNECT"),
    (b":protocol", b"websocket"),
    (b":scheme", b"https"),
    (b":authority", b"localhost"),
    (b":path", b"/"),
]


def success_headers(extra: Optional[HeaderList] = None) -> HeaderList:
    headers: HeaderList = [(b":status", b"200")]
    if extra:
        headers.extend(extra)
    return headers
