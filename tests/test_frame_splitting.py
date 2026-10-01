from __future__ import annotations

import os
import struct
from dataclasses import dataclass

import pytest

from wsproto import ConnectionType, WSConnection
from wsproto.connection import CLIENT, SERVER, Connection
from wsproto.events import (
    AcceptConnection,
    BytesMessage,
    Ping,
    Request,
    TextMessage,
)
from wsproto.extensions import PerMessageDeflate
from wsproto.frame_protocol import Opcode


@dataclass
class WireFrame:
    fin: bool
    rsv1: bool
    rsv2: bool
    rsv3: bool
    opcode: int
    masked: bool
    mask: bytes | None
    payload: bytes


def parse_wire_frames(data: bytes) -> list[WireFrame]:
    frames = []
    index = 0
    while index < len(data):
        first, second = data[index], data[index + 1]
        index += 2
        length = second & 0x7F
        if length == 126:
            (length,) = struct.unpack("!H", data[index : index + 2])
            index += 2
        elif length == 127:
            (length,) = struct.unpack("!Q", data[index : index + 8])
            index += 8
        masked = bool(second & 0x80)
        mask = None
        if masked:
            mask = data[index : index + 4]
            index += 4
        payload = data[index : index + length]
        index += length
        if mask is not None:
            payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        frames.append(
            WireFrame(
                fin=bool(first & 0x80),
                rsv1=bool(first & 0x40),
                rsv2=bool(first & 0x20),
                rsv3=bool(first & 0x10),
                opcode=first & 0x0F,
                masked=masked,
                mask=mask,
                payload=payload,
            )
        )
    assert index == len(data)
    return frames


def make_pair(
    limit: int | None, compress: bool = False,
) -> tuple[Connection, Connection]:
    client_extensions = [PerMessageDeflate()] if compress else []
    server_extensions = [PerMessageDeflate()] if compress else []
    for extension in client_extensions + server_extensions:
        extension._enabled = True
    client = Connection(
        CLIENT, extensions=client_extensions, max_frame_payload_size=limit,
    )
    server = Connection(
        SERVER, extensions=server_extensions, max_frame_payload_size=limit,
    )
    return client, server


def receive_all(connection: Connection, data: bytes) -> list:
    connection.receive_data(data)
    return list(connection.events())


@pytest.mark.parametrize("client_sends", [True, False])
@pytest.mark.parametrize("limit", [1, 5, 125, 126, 65536])
def test_binary_message_split_into_continuation_frames(
    client_sends: bool, limit: int,
) -> None:
    client, server = make_pair(limit)
    local, remote = (client, server) if client_sends else (server, client)

    payload = bytes(range(256)) * 40  # 10240 bytes
    wire = local.send(BytesMessage(data=payload))

    frames = parse_wire_frames(wire)
    assert len(frames) == -(-len(payload) // limit)  # ceil division
    for frame in frames:
        assert len(frame.payload) <= limit
        assert not frame.rsv1 and not frame.rsv2 and not frame.rsv3
    assert frames[0].opcode == Opcode.BINARY
    assert all(frame.opcode == Opcode.CONTINUATION for frame in frames[1:])
    assert all(not frame.fin for frame in frames[:-1])
    assert frames[-1].fin
    if client_sends:
        assert all(frame.masked for frame in frames)
        # Each frame is masked with its own freshly generated key.
        if len(frames) > 1:
            assert len({frame.mask for frame in frames}) > 1
    else:
        assert all(not frame.masked for frame in frames)

    events = receive_all(remote, wire)
    chunks = [event for event in events if isinstance(event, BytesMessage)]
    assert b"".join(bytes(event.data) for event in chunks) == payload
    assert chunks[-1].message_finished


@pytest.mark.parametrize("client_sends", [True, False])
def test_multibyte_text_message_split(client_sends: bool) -> None:
    client, server = make_pair(7)
    local, remote = (client, server) if client_sends else (server, client)

    text = "héllo, 世界! 👋 " * 50
    wire = local.send(TextMessage(data=text))

    frames = parse_wire_frames(wire)
    assert len(frames) > 1
    assert all(len(frame.payload) <= 7 for frame in frames)
    assert frames[0].opcode == Opcode.TEXT
    assert all(frame.opcode == Opcode.CONTINUATION for frame in frames[1:])
    assert frames[-1].fin

    events = receive_all(remote, wire)
    chunks = [event for event in events if isinstance(event, TextMessage)]
    assert "".join(event.data for event in chunks) == text
    assert chunks[-1].message_finished


@pytest.mark.parametrize("client_sends", [True, False])
def test_split_cooperates_with_application_fragmentation(
    client_sends: bool,
) -> None:
    client, server = make_pair(10)
    local, remote = (client, server) if client_sends else (server, client)

    first = b"a" * 25
    second = b"b" * 25
    wire = local.send(BytesMessage(data=first, message_finished=False))
    frames = parse_wire_frames(wire)
    # No frame may finish the message early.
    assert all(not frame.fin for frame in frames)
    assert frames[0].opcode == Opcode.BINARY
    assert all(frame.opcode == Opcode.CONTINUATION for frame in frames[1:])

    wire += local.send(BytesMessage(data=second, message_finished=True))
    frames = parse_wire_frames(wire)
    assert frames[-1].fin
    assert frames[-1].opcode == Opcode.CONTINUATION
    assert all(not frame.fin for frame in frames[:-1])
    assert all(len(frame.payload) <= 10 for frame in frames)

    events = receive_all(remote, wire)
    chunks = [event for event in events if isinstance(event, BytesMessage)]
    assert b"".join(bytes(event.data) for event in chunks) == first + second
    assert not chunks[0].message_finished
    assert chunks[-1].message_finished


@pytest.mark.parametrize("client_sends", [True, False])
def test_empty_message_has_single_final_frame(client_sends: bool) -> None:
    client, server = make_pair(10)
    local, remote = (client, server) if client_sends else (server, client)

    wire = local.send(BytesMessage(data=b""))
    frames = parse_wire_frames(wire)
    assert len(frames) == 1
    assert frames[0].fin
    assert frames[0].opcode == Opcode.BINARY
    assert frames[0].payload == b""

    events = receive_all(remote, wire)
    assert len(events) == 1
    assert events[0].data == b""
    assert events[0].message_finished


@pytest.mark.parametrize("client_sends", [True, False])
def test_control_frames_are_not_split(client_sends: bool) -> None:
    client, server = make_pair(10)
    local, remote = (client, server) if client_sends else (server, client)

    ping_payload = b"p" * 125
    wire = local.send(Ping(payload=ping_payload))
    frames = parse_wire_frames(wire)
    assert len(frames) == 1
    assert frames[0].opcode == Opcode.PING
    assert frames[0].fin
    assert frames[0].payload == ping_payload

    events = receive_all(remote, wire)
    assert len(events) == 1
    assert isinstance(events[0], Ping)
    assert events[0].payload == ping_payload


@pytest.mark.parametrize("client_sends", [True, False])
def test_split_with_permessage_deflate(client_sends: bool) -> None:
    client, server = make_pair(64, compress=True)
    local, remote = (client, server) if client_sends else (server, client)

    # Incompressible data so the compressed payload exceeds the limit.
    payload = os.urandom(1024)
    wire = local.send(BytesMessage(data=payload))

    frames = parse_wire_frames(wire)
    assert len(frames) > 1
    # The limit applies to the compressed payload on the wire.
    assert all(len(frame.payload) <= 64 for frame in frames)
    # RSV1 is set on the first frame only, as required by RFC 7692.
    assert frames[0].rsv1
    assert all(not frame.rsv1 for frame in frames[1:])
    assert frames[0].opcode == Opcode.BINARY
    assert all(frame.opcode == Opcode.CONTINUATION for frame in frames[1:])
    assert frames[-1].fin

    events = receive_all(remote, wire)
    chunks = [event for event in events if isinstance(event, BytesMessage)]
    assert b"".join(bytes(event.data) for event in chunks) == payload
    assert chunks[-1].message_finished


@pytest.mark.parametrize("client_sends", [True, False])
def test_split_with_permessage_deflate_multiple_messages(
    client_sends: bool,
) -> None:
    client, server = make_pair(64, compress=True)
    local, remote = (client, server) if client_sends else (server, client)

    # Compressible messages exercise the shared compression context across
    # messages (context takeover) as well as the final flush bytes.
    messages = [b"the quick brown fox " * 30, b"jumps over the lazy dog " * 30]
    for payload in messages:
        wire = local.send(BytesMessage(data=payload))
        frames = parse_wire_frames(wire)
        assert all(len(frame.payload) <= 64 for frame in frames)
        assert frames[0].rsv1
        assert frames[-1].fin
        events = receive_all(remote, wire)
        chunks = [event for event in events if isinstance(event, BytesMessage)]
        assert b"".join(bytes(event.data) for event in chunks) == payload
        assert chunks[-1].message_finished


def test_no_limit_by_default() -> None:
    client, server = make_pair(None)
    payload = b"x" * 100000
    wire = client.send(BytesMessage(data=payload))
    frames = parse_wire_frames(wire)
    assert len(frames) == 1
    assert frames[0].fin
    events = receive_all(server, wire)
    assert events[0].data == payload


def test_invalid_limit_rejected() -> None:
    with pytest.raises(ValueError, match="max_frame_payload_size"):
        Connection(CLIENT, max_frame_payload_size=0)


def test_wsconnection_passes_limit_through() -> None:
    client = WSConnection(ConnectionType.CLIENT)
    server = WSConnection(ConnectionType.SERVER, max_frame_payload_size=16)

    server.receive_data(client.send(Request(host="localhost", target="/")))
    request = next(server.events())
    assert isinstance(request, Request)
    client.receive_data(server.send(AcceptConnection()))
    assert isinstance(next(client.events()), AcceptConnection)

    payload = b"y" * 100
    wire = server.send(BytesMessage(data=payload))
    frames = parse_wire_frames(wire)
    assert len(frames) == -(-len(payload) // 16)
    assert all(len(frame.payload) <= 16 for frame in frames)
    assert frames[-1].fin

    client.receive_data(wire)
    chunks = [
        event for event in client.events() if isinstance(event, BytesMessage)
    ]
    assert b"".join(bytes(event.data) for event in chunks) == payload
