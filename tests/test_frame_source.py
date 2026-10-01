from __future__ import annotations

import random

from wsproto.connection import CLIENT, SERVER, Connection
from wsproto.events import (
    BytesMessage,
    CloseConnection,
    Message,
    Ping,
    TextMessage,
)
from wsproto.extensions import PerMessageDeflate
from wsproto.frame_protocol import CloseReason, FrameSource


def _collect(events):  # type: ignore[no-untyped-def]
    return [event for event in events if isinstance(event, Message)]


def _feed(conn: Connection, wire: bytes, chunk_sizes: list[int]) -> list[Message]:
    events = []
    pos = 0
    for size in chunk_sizes:
        conn.receive_data(wire[pos : pos + size])
        events.extend(_collect(conn.events()))
        pos += size
    if pos < len(wire):
        conn.receive_data(wire[pos:])
        events.extend(_collect(conn.events()))
    return events


def _whole(wire: bytes) -> list[int]:
    return [len(wire)]


def _bytewise(wire: bytes) -> list[int]:
    return [1] * len(wire)


def _random_chunks(wire: bytes, seed: int = 42) -> list[int]:
    rng = random.Random(seed)
    sizes = []
    remaining = len(wire)
    while remaining:
        size = rng.randint(1, max(1, min(remaining, 17)))
        sizes.append(size)
        remaining -= size
    return sizes


def _payload_labels(events: list[Message]) -> dict[int, tuple[int, int]]:
    labels: dict[int, tuple[int, int]] = {}
    for event in events:
        source = event.frame_source
        assert source is not None
        for offset in range(source.payload_start, source.payload_end):
            assert offset not in labels
            labels[offset] = (source.message_index, source.frame_index)
    return labels


def _frame_headers(events: list[Message]) -> set[tuple[int, ...]]:
    headers = set()
    for event in events:
        source = event.frame_source
        assert source is not None
        headers.add(
            (
                source.message_index,
                source.frame_index,
                source.header_start,
                source.header_end,
                source.mask_start or -1,
                source.mask_end or -1,
            )
        )
    return headers


def test_single_masked_text_message() -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    payload = "hello 🌍"
    wire = client.send(TextMessage(data=payload))
    server.receive_data(wire)
    (event,) = _collect(server.events())

    assert event.data == payload
    source = event.frame_source
    assert source is not None
    # 2 byte header, 4 byte mask, then the masked payload.
    assert source.message_index == 0
    assert source.frame_index == 0
    assert source.header_start == 0
    assert source.header_end == 2
    assert source.mask_start == 2
    assert source.mask_end == 6
    assert source.payload_start == 6
    assert source.payload_end == len(wire)


def test_unmasked_server_to_client_has_no_mask_range() -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    wire = server.send(BytesMessage(data=b"x" * 200))
    client.receive_data(wire)
    (event,) = _collect(client.events())

    source = event.frame_source
    assert source is not None
    # 2 byte header + 2 byte extended payload length, no mask.
    assert source.header_start == 0
    assert source.header_end == 4
    assert source.mask_start is None
    assert source.mask_end is None
    assert source.payload_start == 4
    assert source.payload_end == len(wire)


def test_fragmented_message_with_interleaved_control_frame() -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    wire = b""
    wire += client.send(TextMessage(data="hel", message_finished=False))
    wire += client.send(Ping(payload=b"p"))
    wire += client.send(TextMessage(data="lo", message_finished=True))
    wire += client.send(TextMessage(data="next"))

    server.receive_data(wire)
    events = list(server.events())
    messages = [e for e in events if isinstance(e, Message)]
    pings = [e for e in events if isinstance(e, Ping)]

    assert len(pings) == 1
    assert [m.data for m in messages] == ["hel", "lo", "next"]
    assert [
        (m.frame_source.message_index, m.frame_source.frame_index)  # type: ignore[union-attr]
        for m in messages
    ] == [(0, 0), (0, 1), (1, 0)]
    # The interleaved ping must not disturb the message's byte offsets.
    first, second, third = (m.frame_source for m in messages)
    assert first.header_start == 0  # type: ignore[union-attr]
    assert second.header_start > first.payload_end  # type: ignore[union-attr]
    assert third.header_start == second.payload_end  # type: ignore[union-attr]


def test_source_ranges_do_not_depend_on_chunking() -> None:
    client = Connection(CLIENT)
    wire = b""
    wire += client.send(TextMessage(data="frag", message_finished=False))
    wire += client.send(Ping(payload=b"ctl"))
    wire += client.send(TextMessage(data="mented", message_finished=True))
    wire += client.send(BytesMessage(data=b"b" * 300))
    wire += client.send(TextMessage(data=""))

    all_events = []
    for chunk_sizes in (_whole(wire), _bytewise(wire), _random_chunks(wire)):
        server = Connection(SERVER)
        all_events.append(_feed(server, wire, chunk_sizes))

    def joined(events: list[Message]) -> bytes:
        return b"".join(
            e.data.encode("utf-8") if isinstance(e.data, str) else bytes(e.data)
            for e in events
        )

    for events in all_events[1:]:
        assert joined(events) == joined(all_events[0])
        # Every wire payload byte is labelled with the same
        # (message_index, frame_index) regardless of how the stream was
        # chunked, and the frame header/mask ranges are identical.
        assert _payload_labels(events) == _payload_labels(all_events[0])
        assert _frame_headers(events) == _frame_headers(all_events[0])


def test_source_ranges_match_wire_bytes() -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    wire = b""
    wire += client.send(TextMessage(data="hello ", message_finished=False))
    wire += client.send(TextMessage(data="world", message_finished=True))

    events = _feed(server, wire, _random_chunks(wire, seed=7))

    # Reassemble each frame's payload from the wire bytes using the recorded
    # ranges and compare against the delivered event data.
    frames: dict[int, list[FrameSource]] = {}
    for event in events:
        source = event.frame_source
        assert source is not None
        frames.setdefault(source.frame_index, []).append(source)

    decoded = ""
    for frame_index in sorted(frames):
        sources = frames[frame_index]
        first = sources[0]
        assert first.mask_start is not None and first.mask_end is not None
        mask = wire[first.mask_start : first.mask_end]
        assert len(mask) == 4
        payload_start = min(s.payload_start for s in sources)
        data = bytearray()
        for source in sorted(sources, key=lambda s: s.payload_start):
            for offset in range(source.payload_start, source.payload_end):
                data.append(wire[offset] ^ mask[(offset - payload_start) % 4])
        decoded += data.decode("utf-8")
    assert decoded == "hello world"


def test_compressed_message_has_frame_level_source() -> None:
    client_ext = PerMessageDeflate()
    server_ext = PerMessageDeflate()
    offer = client_ext.offer()
    assert isinstance(offer, str)
    server_ext.accept(offer)
    client_ext.finalize(offer)

    client = Connection(CLIENT, extensions=[client_ext])
    server = Connection(SERVER, extensions=[server_ext])

    payload = "compressible " * 40
    wire = client.send(TextMessage(data=payload))
    # Sanity check: the extension actually compressed the payload.
    assert len(wire) < len(payload)

    server.receive_data(wire)
    (event,) = _collect(server.events())
    assert event.data == payload

    source = event.frame_source
    assert source is not None
    # Only frame-level provenance is promised: the ranges cover the whole
    # wire frame, but the decompressed data does not map 1:1 onto it.
    assert source.header_start == 0
    assert source.payload_end == len(wire)
    assert source.payload_end - source.payload_start != len(payload)


def test_frame_source_defaults_and_equality_compatible() -> None:
    assert TextMessage(data="x").frame_source is None
    assert BytesMessage(data=b"x").frame_source is None

    client = Connection(CLIENT)
    server = Connection(SERVER)
    server.receive_data(client.send(TextMessage(data="x")))
    (event,) = _collect(server.events())
    assert event.frame_source is not None
    # The metadata does not affect comparisons with plain events.
    assert event == TextMessage(data="x")

    # Close events and close behaviour are unchanged.
    server.receive_data(client.send(CloseConnection(code=CloseReason.NORMAL_CLOSURE)))
    (close,) = [e for e in server.events() if isinstance(e, CloseConnection)]
    assert close.code is CloseReason.NORMAL_CLOSURE
    assert not hasattr(close, "frame_source")
