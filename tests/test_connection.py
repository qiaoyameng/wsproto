from __future__ import annotations

import random
from collections import defaultdict
from collections.abc import Callable

import pytest

from wsproto.connection import CLIENT, SERVER, Connection, ConnectionState
from wsproto.events import (
    BytesMessage,
    CloseConnection,
    Ping,
    Pong,
    Request,
    TextMessage,
)
from wsproto.frame_protocol import ByteRange, CloseReason, PayloadSourceLevel
from wsproto.utilities import LocalProtocolError


@pytest.mark.parametrize("client_sends", [True, False])
@pytest.mark.parametrize("final", [True, False])
def test_send_message(client_sends: bool, final: bool) -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    if client_sends:
        local = client
        remote = server
    else:
        local = server
        remote = client

    data = b"x" * 23
    remote.receive_data(local.send(BytesMessage(data=data, message_finished=final)))
    event = next(remote.events())
    assert isinstance(event, BytesMessage)
    assert event.data == data
    assert event.message_finished is final


@pytest.mark.parametrize("client_sends", [True, False])
@pytest.mark.parametrize(
    "code, reason",
    [(CloseReason.NORMAL_CLOSURE, "bye"), (CloseReason.GOING_AWAY, "👋👋")],
)
def test_closure(client_sends: bool, code: CloseReason, reason: str) -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    if client_sends:
        local = client
        remote = server
    else:
        local = server
        remote = client

    remote.receive_data(local.send(CloseConnection(code=code, reason=reason)))
    event = next(remote.events())
    assert isinstance(event, CloseConnection)
    assert event.code is code
    assert event.reason == reason

    assert remote.state is ConnectionState.REMOTE_CLOSING
    assert local.state is ConnectionState.LOCAL_CLOSING

    local.receive_data(remote.send(event.response()))
    event = next(local.events())
    assert isinstance(event, CloseConnection)
    assert event.code is code
    assert event.reason == reason

    assert remote.state is ConnectionState.CLOSED  # type: ignore[comparison-overlap]
    assert local.state is ConnectionState.CLOSED

    with pytest.raises(LocalProtocolError):
        local.receive_data(b"foobar")


def test_abnormal_closure() -> None:
    client = Connection(CLIENT)
    client.receive_data(None)
    event = next(client.events())
    assert isinstance(event, CloseConnection)
    assert event.code is CloseReason.ABNORMAL_CLOSURE
    assert client.state is ConnectionState.CLOSED


def test_close_whilst_closing() -> None:
    client = Connection(CLIENT)
    client.send(CloseConnection(code=CloseReason.NORMAL_CLOSURE))
    with pytest.raises(LocalProtocolError):
        client.send(CloseConnection(code=CloseReason.NORMAL_CLOSURE))


def test_send_after_close() -> None:
    client = Connection(CLIENT)
    client.send(CloseConnection(code=CloseReason.NORMAL_CLOSURE))
    with pytest.raises(LocalProtocolError):
        client.send(TextMessage(data="", message_finished=True))


@pytest.mark.parametrize("client_sends", [True, False])
def test_ping_pong(client_sends: bool) -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    if client_sends:
        local = client
        remote = server
    else:
        local = server
        remote = client

    payload = b"x" * 23
    remote.receive_data(local.send(Ping(payload=payload)))
    event = next(remote.events())
    assert isinstance(event, Ping)
    assert event.payload == payload

    local.receive_data(remote.send(event.response()))
    event = next(local.events())
    assert isinstance(event, Pong)
    assert event.payload == payload


def test_unsolicited_pong() -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    payload = b"x" * 23
    server.receive_data(client.send(Pong(payload=payload)))
    event = next(server.events())
    assert isinstance(event, Pong)
    assert event.payload == payload


@pytest.mark.parametrize("split_message", [True, False])
def test_data(split_message: bool) -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    data = "ƒñö®∂😎"
    server.receive_data(
        client.send(TextMessage(data=data, message_finished=not split_message)),
    )
    event = next(server.events())
    assert isinstance(event, TextMessage)
    assert event.message_finished is not split_message


def test_frame_protocol_gets_fed_garbage() -> None:
    client = Connection(CLIENT)

    payload = b"x" * 23
    frame = b"\x09" + bytearray([len(payload)]) + payload

    client.receive_data(frame)
    event = next(client.events())
    assert isinstance(event, CloseConnection)
    assert event.code == CloseReason.PROTOCOL_ERROR


def test_send_invalid_event() -> None:
    client = Connection(CLIENT)
    with pytest.raises(LocalProtocolError):
        client.send(Request(target="/", host="wsproto"))


def test_receive_data_when_closed() -> None:
    client = Connection(CLIENT)
    client._state = ConnectionState.CLOSED
    with pytest.raises(LocalProtocolError):
        client.receive_data(b"something")


def _frame(opcode: int, payload: bytes, fin: bool = True) -> bytes:
    return bytes([(0x80 if fin else 0) | opcode, len(payload)]) + payload


def _merge_ranges(ranges: list[ByteRange]) -> tuple[ByteRange, ...]:
    merged: list[list[int]] = []
    for start, end in sorted(ranges):
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return tuple(ByteRange(start, end) for start, end in merged)


def _collect_sources(
    stream: bytes,
    chunks: Callable[[bytes], list[bytes]],
) -> dict[int, tuple]:
    connection = Connection(CLIENT, track_frame_sources=True)
    collected: dict[int, dict] = defaultdict(
        lambda: {
            "data": bytearray(),
            "headers": set(),
            "masks": set(),
            "payload": [],
            "levels": set(),
            "message_numbers": set(),
            "fragment_numbers": set(),
            "frame_finished": False,
            "message_finished": False,
            "types": set(),
        },
    )

    for chunk in chunks(stream):
        connection.receive_data(chunk)
        for event in connection.events():
            source = event.frame_source
            assert source is not None
            entry = collected[source.frame_number]
            entry["types"].add(type(event).__name__)
            entry["headers"].add(source.header)
            if source.mask is not None:
                entry["masks"].add(source.mask)
            entry["payload"].append(source.payload)
            entry["levels"].add(source.payload_source_level)
            entry["message_numbers"].add(source.message_number)
            entry["fragment_numbers"].add(source.fragment_number)
            entry["frame_finished"] = entry["frame_finished"] or getattr(
                event,
                "frame_finished",
                True,
            )
            entry["message_finished"] = entry["message_finished"] or getattr(
                event,
                "message_finished",
                True,
            )
            if isinstance(event, BytesMessage):
                entry["data"] += event.data
            elif isinstance(event, Ping):
                entry["data"] += event.payload
            elif isinstance(event, CloseConnection):
                entry["data"] += int(event.code).to_bytes(2, "big")
                if event.reason:
                    entry["data"] += event.reason.encode()

    return {
        frame_number: (
            tuple(sorted(entry["types"])),
            tuple(entry["message_numbers"]),
            tuple(entry["fragment_numbers"]),
            tuple(sorted(entry["headers"])),
            tuple(sorted(entry["masks"])),
            _merge_ranges(entry["payload"]),
            tuple(sorted(entry["levels"], key=lambda level: level.value)),
            bytes(entry["data"]),
            entry["frame_finished"],
            entry["message_finished"],
        )
        for frame_number, entry in collected.items()
    }


def _single_chunk(data: bytes) -> list[bytes]:
    return [data]


def _byte_chunks(data: bytes) -> list[bytes]:
    return [data[index : index + 1] for index in range(len(data))]


def _random_chunks(data: bytes) -> list[bytes]:
    cuts = sorted(random.Random(1234).sample(range(1, len(data)), 8))
    bounds = [0, *cuts, len(data)]
    return [data[start:end] for start, end in zip(bounds, bounds[1:])]


def test_frame_sources_are_stable_across_chunking() -> None:
    stream = b"".join(
        [
            _frame(0x2, b"ab", fin=False),
            _frame(0x9, b"p"),
            _frame(0x0, b"cd", fin=True),
            _frame(0x2, b"ef"),
            _frame(0x8, (1000).to_bytes(2, "big")),
        ],
    )

    results = [
        _collect_sources(stream, _single_chunk),
        _collect_sources(stream, _byte_chunks),
        _collect_sources(stream, _random_chunks),
    ]

    assert results[0] == results[1] == results[2]
    assert results[0] == {
        0: (
            ("BytesMessage",),
            (0,),
            (0,),
            (ByteRange(0, 2),),
            (),
            (ByteRange(2, 4),),
            (PayloadSourceLevel.BYTE,),
            b"ab",
            True,
            False,
        ),
        1: (
            ("Ping",),
            (None,),
            (None,),
            (ByteRange(4, 6),),
            (),
            (ByteRange(6, 7),),
            (PayloadSourceLevel.BYTE,),
            b"p",
            True,
            True,
        ),
        2: (
            ("BytesMessage",),
            (0,),
            (1,),
            (ByteRange(7, 9),),
            (),
            (ByteRange(9, 11),),
            (PayloadSourceLevel.BYTE,),
            b"cd",
            True,
            True,
        ),
        3: (
            ("BytesMessage",),
            (1,),
            (0,),
            (ByteRange(11, 13),),
            (),
            (ByteRange(13, 15),),
            (PayloadSourceLevel.BYTE,),
            b"ef",
            True,
            True,
        ),
        4: (
            ("CloseConnection",),
            (None,),
            (None,),
            (ByteRange(15, 17),),
            (),
            (ByteRange(17, 19),),
            (PayloadSourceLevel.BYTE,),
            (1000).to_bytes(2, "big"),
            True,
            True,
        ),
    }


def test_frame_sources_include_mask_ranges() -> None:
    masking_key = b"abcd"
    payload = b"xy"
    frame = b"\x81\x82" + masking_key + bytes(
        value ^ masking_key[index % 4]
        for index, value in enumerate(payload)
    )

    connection = Connection(SERVER, track_frame_sources=True)
    connection.receive_data(frame)
    event = next(connection.events())

    assert event.frame_source is not None
    assert event.frame_source.header == ByteRange(0, 2)
    assert event.frame_source.mask == ByteRange(2, 6)
    assert event.frame_source.payload == ByteRange(6, 8)


def test_frame_sources_default_to_none() -> None:
    connection = Connection(CLIENT)
    connection.receive_data(_frame(0x2, b"xy"))
    event = next(connection.events())

    assert event == BytesMessage(data=b"xy")
    assert event.frame_source is None
