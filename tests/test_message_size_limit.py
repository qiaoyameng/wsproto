from __future__ import annotations

import struct
import tracemalloc
import zlib

from wsproto.connection import CLIENT, Connection
from wsproto.events import (
    BytesMessage,
    CloseConnection,
    Ping,
    Pong,
    TextMessage,
)
from wsproto.extensions import PerMessageDeflate
from wsproto.frame_protocol import CloseReason, Opcode


def make_frame(
    opcode: Opcode, payload: bytes, fin: bool = True, rsv1: bool = False,
) -> bytes:
    first_byte = opcode | (0x80 if fin else 0) | (0x40 if rsv1 else 0)
    header = bytes([first_byte])
    length = len(payload)
    if length <= 125:
        header += bytes([length])
    elif length <= 0xFFFF:
        header += bytes([126]) + struct.pack("!H", length)
    else:
        header += bytes([127]) + struct.pack("!Q", length)
    return header + payload


def compress_message(data: bytes) -> bytes:
    compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    payload = compressor.compress(data) + compressor.flush(zlib.Z_SYNC_FLUSH)
    return payload[:-4]


def deflate_connection(max_size: int | None) -> Connection:
    extension = PerMessageDeflate()
    extension._enabled = True
    return Connection(
        CLIENT, extensions=[extension], max_inbound_message_size=max_size,
    )


def receive(conn: Connection, data: bytes) -> list:
    conn.receive_data(data)
    return list(conn.events())


class TestUncompressedMessageSizeLimit:
    def test_message_at_limit_completes(self) -> None:
        conn = Connection(CLIENT, max_inbound_message_size=5)
        events = receive(conn, make_frame(Opcode.BINARY, b"12345"))
        assert len(events) == 1
        assert isinstance(events[0], BytesMessage)
        assert events[0].data == b"12345"
        assert events[0].message_finished

    def test_message_over_limit_by_one_byte(self) -> None:
        conn = Connection(CLIENT, max_inbound_message_size=5)
        events = receive(conn, make_frame(Opcode.BINARY, b"123456"))
        assert len(events) == 1
        assert isinstance(events[0], CloseConnection)
        assert events[0].code == CloseReason.MESSAGE_TOO_BIG

    def test_no_limit_by_default(self) -> None:
        conn = Connection(CLIENT)
        payload = b"x" * (10 * 1024 * 1024)
        events = receive(conn, make_frame(Opcode.BINARY, payload))
        assert len(events) == 1
        assert isinstance(events[0], BytesMessage)
        assert events[0].data == payload

    def test_limit_spans_continuation_frames(self) -> None:
        conn = Connection(CLIENT, max_inbound_message_size=6)

        events = receive(conn, make_frame(Opcode.TEXT, b"abc", fin=False))
        assert len(events) == 1
        assert isinstance(events[0], TextMessage)
        assert events[0].data == "abc"
        assert not events[0].message_finished

        # Interleaved control frames must not reset the running count.
        events = receive(conn, make_frame(Opcode.PING, b"x"))
        assert len(events) == 1
        assert isinstance(events[0], Ping)
        events = receive(conn, make_frame(Opcode.PONG, b"x"))
        assert len(events) == 1
        assert isinstance(events[0], Pong)

        events = receive(conn, make_frame(Opcode.CONTINUATION, b"de", fin=False))
        assert len(events) == 1
        assert isinstance(events[0], TextMessage)
        assert events[0].data == "de"

        # 5 bytes so far; two more push the message one byte over the limit.
        events = receive(conn, make_frame(Opcode.CONTINUATION, b"fg", fin=True))
        assert len(events) == 1
        assert isinstance(events[0], CloseConnection)
        assert events[0].code == CloseReason.MESSAGE_TOO_BIG

    def test_delivery_stops_after_limit_exceeded(self) -> None:
        conn = Connection(CLIENT, max_inbound_message_size=2)

        events = receive(conn, make_frame(Opcode.TEXT, b"ab", fin=False))
        assert len(events) == 1
        assert isinstance(events[0], TextMessage)

        events = receive(conn, make_frame(Opcode.CONTINUATION, b"c", fin=False))
        assert len(events) == 1
        assert isinstance(events[0], CloseConnection)
        assert events[0].code == CloseReason.MESSAGE_TOO_BIG

        # No further content of this message is delivered to the application.
        assert receive(conn, make_frame(Opcode.CONTINUATION, b"de", fin=True)) == []

    def test_text_counted_as_utf8_bytes_across_chunks(self) -> None:
        # "é" is two UTF-8 bytes; feed the frame one byte at a time so the
        # character straddles network chunks. It must be counted exactly
        # once, as two bytes.
        conn = Connection(CLIENT, max_inbound_message_size=2)
        frame = make_frame(Opcode.TEXT, "é".encode("utf-8"))

        events: list = []
        for byte in frame:
            events.extend(receive(conn, bytes([byte])))

        text_events = [event for event in events if isinstance(event, TextMessage)]
        assert text_events
        assert text_events[-1].data == "é"
        assert text_events[-1].message_finished
        assert not any(isinstance(event, CloseConnection) for event in events)

    def test_split_character_over_limit_by_one_byte(self) -> None:
        conn = Connection(CLIENT, max_inbound_message_size=1)
        frame = make_frame(Opcode.TEXT, "é".encode("utf-8"))

        events: list = []
        for byte in frame:
            events.extend(receive(conn, bytes([byte])))

        close_events = [
            event for event in events if isinstance(event, CloseConnection)
        ]
        assert len(close_events) == 1
        assert close_events[0].code == CloseReason.MESSAGE_TOO_BIG


class TestCompressedMessageSizeLimit:
    def test_compressed_message_within_limit(self) -> None:
        conn = deflate_connection(max_size=32)
        payload = compress_message(b"hello hello hello")
        events = receive(conn, make_frame(Opcode.TEXT, payload, rsv1=True))
        assert len(events) == 1
        assert isinstance(events[0], TextMessage)
        assert events[0].data == "hello hello hello"
        assert events[0].message_finished

    def test_compressed_message_at_limit_completes(self) -> None:
        conn = deflate_connection(max_size=17)
        payload = compress_message(b"hello hello hello")
        events = receive(conn, make_frame(Opcode.TEXT, payload, rsv1=True))
        assert len(events) == 1
        assert isinstance(events[0], TextMessage)
        assert events[0].message_finished

    def test_compressed_bomb_rejected_with_1009(self) -> None:
        conn = deflate_connection(max_size=1024)
        # A small frame that would decompress to far more than the limit.
        payload = compress_message(b"\x00" * (16 * 1024 * 1024))
        assert len(payload) < 100 * 1024

        events = receive(conn, make_frame(Opcode.BINARY, payload, rsv1=True))
        assert len(events) == 1
        assert isinstance(events[0], CloseConnection)
        assert events[0].code == CloseReason.MESSAGE_TOO_BIG

    def test_decompression_is_bounded_by_budget(self) -> None:
        # The peak intermediate buffer must track the configured limit, not
        # the theoretical decompressed size of the attack payload.
        decompressed_size = 64 * 1024 * 1024
        payload = compress_message(b"\x00" * decompressed_size)
        frame = make_frame(Opcode.BINARY, payload, rsv1=True)
        del payload

        conn = deflate_connection(max_size=1024)
        tracemalloc.start()
        try:
            events = receive(conn, frame)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        assert len(events) == 1
        assert isinstance(events[0], CloseConnection)
        assert events[0].code == CloseReason.MESSAGE_TOO_BIG
        assert peak < decompressed_size // 8

    def test_compressed_limit_spans_frames_and_control_frames(self) -> None:
        conn = deflate_connection(max_size=8)

        compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
        first = compressor.compress(b"abcdef") + compressor.flush(zlib.Z_SYNC_FLUSH)
        second = compressor.compress(b"ghij") + compressor.flush(zlib.Z_SYNC_FLUSH)
        second = second[:-4]

        events = receive(conn, make_frame(Opcode.BINARY, first, fin=False, rsv1=True))
        assert len(events) == 1
        assert isinstance(events[0], BytesMessage)
        assert events[0].data == b"abcdef"

        events = receive(conn, make_frame(Opcode.PING, b""))
        assert len(events) == 1
        assert isinstance(events[0], Ping)

        # 6 bytes so far; 4 more exceed the limit of 8.
        events = receive(conn, make_frame(Opcode.CONTINUATION, second, fin=True))
        assert len(events) == 1
        assert isinstance(events[0], CloseConnection)
        assert events[0].code == CloseReason.MESSAGE_TOO_BIG
