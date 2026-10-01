from __future__ import annotations

import struct

import pytest

from wsproto import WSConnection
from wsproto import frame_protocol as fp
from wsproto.connection import CLIENT, SERVER, Connection, ConnectionState
from wsproto.events import (
    BytesMessage,
    CloseConnection,
    Ping,
    Pong,
    Request,
    TextMessage,
)
from wsproto.extensions import PerMessageDeflate
from wsproto.frame_protocol import CloseReason, Opcode
from wsproto.utilities import LocalProtocolError


def _parse_frames(data: bytes) -> list[dict[str, object]]:
    frames = []
    offset = 0
    while offset < len(data):
        start = offset
        fin = bool(data[offset] & 0x80)
        rsv1 = bool(data[offset] & 0x40)
        opcode = Opcode(data[offset] & 0x0F)
        offset += 1

        masked = bool(data[offset] & 0x80)
        payload_len = data[offset] & 0x7F
        offset += 1
        if payload_len == 126:
            payload_len = struct.unpack_from("!H", data, offset)[0]
            offset += 2
        elif payload_len == 127:
            payload_len = struct.unpack_from("!Q", data, offset)[0]
            offset += 8

        masking_key = None
        if masked:
            masking_key = data[offset : offset + 4]
            offset += 4

        payload = data[offset : offset + payload_len]
        if masking_key is not None:
            payload = bytes(
                byte ^ masking_key[index % 4]
                for index, byte in enumerate(payload)
            )
        offset += payload_len

        frames.append(
            {
                "raw": data[start:offset],
                "fin": fin,
                "rsv1": rsv1,
                "opcode": opcode,
                "masked": masked,
                "masking_key": masking_key,
                "payload": payload,
            }
        )
    return frames


def _enabled_extension() -> PerMessageDeflate:
    extension = PerMessageDeflate()
    extension.finalize("permessage-deflate")
    return extension


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
@pytest.mark.parametrize("compressed", [False, True])
def test_send_message_respects_frame_payload_limit(
    monkeypatch: pytest.MonkeyPatch, client_sends: bool, compressed: bool,
) -> None:
    extensions = [_enabled_extension()] if compressed else []
    local = Connection(
        CLIENT if client_sends else SERVER,
        extensions=extensions,
        max_frame_payload=16,
    )
    remote = Connection(
        SERVER if client_sends else CLIENT,
        extensions=[_enabled_extension()] if compressed else [],
    )
    payload = bytes((index * index + 17) % 251 for index in range(200))
    masking_keys: list[bytes] = []
    if client_sends:

        def fake_urandom(length: int) -> bytes:
            key = bytes([len(masking_keys)]) * length
            masking_keys.append(key)
            return key

        monkeypatch.setattr(fp.os, "urandom", fake_urandom)

    wire = local.send(BytesMessage(data=payload))
    frames = _parse_frames(wire)

    assert len(frames) > 1
    assert frames[0]["opcode"] is Opcode.BINARY
    assert all(len(frame["payload"]) <= 16 for frame in frames)
    assert all(frame["masked"] is client_sends for frame in frames)
    assert all(frame["fin"] is False for frame in frames[:-1])
    assert frames[-1]["fin"] is True
    assert all(frame["opcode"] is Opcode.CONTINUATION for frame in frames[1:])
    if compressed:
        assert frames[0]["rsv1"] is True
        assert all(frame["rsv1"] is False for frame in frames[1:])

        keys = [
            frame["masking_key"]
            for frame in frames
            if frame["masking_key"] is not None
        ]
        assert keys == masking_keys
    else:
        assert all(frame["rsv1"] is False for frame in frames)

    remote.receive_data(wire)
    event_payload = b"".join(event.data for event in remote.events())
    assert event_payload == payload


@pytest.mark.parametrize("client_sends", [True, False])
def test_send_multibyte_text_respects_frame_payload_limit(
    client_sends: bool,
) -> None:
    local = Connection(
        CLIENT if client_sends else SERVER, max_frame_payload=5,
    )
    remote = Connection(SERVER if client_sends else CLIENT)
    payload = "".join(chr(0x4E00 + index * 37) for index in range(40))

    wire = local.send(TextMessage(data=payload))
    frames = _parse_frames(wire)

    assert frames[0]["opcode"] is Opcode.TEXT
    assert all(len(frame["payload"]) <= 5 for frame in frames)
    remote.receive_data(wire)
    received = "".join(event.data for event in remote.events())
    assert received == payload


@pytest.mark.parametrize("final", [False, True])
def test_application_fragments_do_not_finish_early(final: bool) -> None:
    local = Connection(CLIENT, max_frame_payload=4)
    wire = b""

    wire += local.send(BytesMessage(data=b"abcdef", message_finished=False))
    wire += local.send(BytesMessage(data=b"ghij", message_finished=final))
    frames = _parse_frames(wire)

    assert [frame["opcode"] for frame in frames] == [
        Opcode.BINARY,
        Opcode.CONTINUATION,
        Opcode.CONTINUATION,
    ]
    assert [frame["fin"] for frame in frames] == [
        False,
        False,
        final,
    ]


def test_compressed_application_fragments_do_not_finish_early() -> None:
    local = Connection(
        CLIENT,
        extensions=[_enabled_extension()],
        max_frame_payload=4,
    )
    remote = Connection(SERVER, extensions=[_enabled_extension()])

    wire = local.send(
        BytesMessage(data=b"abcdef", message_finished=False),
    ) + local.send(BytesMessage(data=b"ghij", message_finished=True))
    frames = _parse_frames(wire)

    assert frames[0]["opcode"] is Opcode.BINARY
    assert frames[0]["rsv1"] is True
    assert all(frame["opcode"] is Opcode.CONTINUATION for frame in frames[1:])
    assert all(frame["rsv1"] is False for frame in frames[1:])
    assert all(frame["fin"] is False for frame in frames[:-1])
    assert frames[-1]["fin"] is True

    remote.receive_data(wire)
    events = list(remote.events())
    assert all(not event.message_finished for event in events[:-1])
    assert events[-1].message_finished is True
    assert b"".join(event.data for event in events) == b"abcdefghij"


@pytest.mark.parametrize("final", [False, True])
@pytest.mark.parametrize("compressed", [False, True])
def test_empty_message_has_explicit_frame(final: bool, compressed: bool) -> None:
    extensions = [_enabled_extension()] if compressed else []
    local = Connection(CLIENT, extensions=extensions, max_frame_payload=16)
    remote = Connection(
        SERVER,
        extensions=[_enabled_extension()] if compressed else [],
    )

    wire = local.send(TextMessage(data="", message_finished=final))
    frames = _parse_frames(wire)

    assert len(frames) == 1
    assert frames[0]["opcode"] is Opcode.TEXT
    assert frames[0]["fin"] is final
    assert frames[0]["masked"] is True

    remote.receive_data(wire)
    event = next(remote.events())
    assert isinstance(event, TextMessage)
    assert event.data == ""
    assert event.message_finished is final


def test_control_frame_is_not_fragmented() -> None:
    local = Connection(CLIENT, max_frame_payload=8)
    payload = b"x" * 9

    with pytest.raises(ValueError, match="payload too long for control frame"):
        local.send(Ping(payload=payload))


@pytest.mark.parametrize("limit", [0, 2**64])
def test_invalid_frame_payload_limit(limit: int) -> None:
    with pytest.raises(ValueError, match="max_frame_payload"):
        Connection(CLIENT, max_frame_payload=limit)


def test_wsconnection_accepts_frame_payload_limit() -> None:
    connection = WSConnection(CLIENT, max_frame_payload=16)
    assert connection.handshake.max_frame_payload == 16


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
