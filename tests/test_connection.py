from __future__ import annotations

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
from wsproto.frame_protocol import CloseReason
from wsproto.utilities import LocalProtocolError


def data_frame(
    opcode: int,
    payload: bytes,
    *,
    fin: bool = True,
    compressed: bool = False,
) -> bytes:
    first_byte = (0x80 if fin else 0x00) | (0x40 if compressed else 0x00) | opcode
    return bytes([first_byte, len(payload)]) + payload


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


def test_invalid_max_message_size() -> None:
    with pytest.raises(ValueError, match="non-negative integer"):
        Connection(CLIENT, max_message_size=-1)


def test_max_message_size_continuation_and_control_frames() -> None:
    client = Connection(CLIENT, max_message_size=4)
    frames = (
        data_frame(2, b"ab", fin=False)
        + data_frame(9, b"p")
        + data_frame(0, b"c", fin=False)
        + data_frame(10, b"q")
        + data_frame(0, b"de")
    )

    client.receive_data(frames)
    events = list(client.events())

    assert [type(event) for event in events] == [
        BytesMessage,
        Ping,
        BytesMessage,
        Pong,
        CloseConnection,
    ]
    assert events[0].data == b"ab"
    assert events[2].data == b"c"
    assert events[4].code is CloseReason.MESSAGE_TOO_BIG


def test_max_message_size_accepts_exact_continuation_size() -> None:
    client = Connection(CLIENT, max_message_size=5)
    frames = (
        data_frame(2, b"abc", fin=False)
        + data_frame(9, b"p")
        + data_frame(0, b"de")
    )

    client.receive_data(frames)
    events = list(client.events())

    assert [type(event) for event in events] == [BytesMessage, Ping, BytesMessage]
    assert events[0].data == b"abc"
    assert events[2].data == b"de"


def test_max_message_size_counts_text_bytes_across_network_chunks() -> None:
    payload = "∂".encode("utf-8")

    accepted = Connection(CLIENT, max_message_size=3)
    for chunk in (bytes([byte]) for byte in b"\x81\x03" + payload):
        accepted.receive_data(chunk)
    events = list(accepted.events())
    assert events == [TextMessage(data="∂")]

    fragmented = Connection(CLIENT, max_message_size=3)
    fragmented.receive_data(data_frame(1, payload[:1], fin=False))
    fragmented.receive_data(data_frame(0, payload[1:]))
    assert list(fragmented.events()) == [
        TextMessage(data="", message_finished=False),
        TextMessage(data="∂"),
    ]

    rejected = Connection(CLIENT, max_message_size=2)
    rejected.receive_data(data_frame(1, payload[:1], fin=False))
    assert list(rejected.events()) == [TextMessage(data="", message_finished=False)]
    assert rejected._proto._frame_decoder.message_size == 1
    rejected.receive_data(data_frame(0, payload[1:]))
    events = list(rejected.events())

    assert [type(event) for event in events] == [CloseConnection]
    assert events[0].code is CloseReason.MESSAGE_TOO_BIG
