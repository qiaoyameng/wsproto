"""
Tests for the RFC 8441 (bootstrapping WebSockets with HTTP/2) handshake.

The handshake is driven entirely by in-memory header blocks and DATA
payloads: wsproto neither establishes the HTTP/2 connection nor
implements HTTP/2 flow control.
"""
from __future__ import annotations

import pytest

from wsproto import WSConnection
from wsproto.connection import CLIENT, SERVER, ConnectionState
from wsproto.events import (
    AcceptConnection,
    BytesMessage,
    CloseConnection,
    Ping,
    RejectConnection,
    RejectData,
    Request,
    TextMessage,
)
from wsproto.extensions import PerMessageDeflate
from wsproto.handshake import H2Handshake
from wsproto.typing import Headers
from wsproto.utilities import LocalProtocolError, RemoteProtocolError

from .h2_test_helpers import (
    CONNECT_HEADERS,
    DataReceived,
    RequestReceived,
    ResponseReceived,
    StreamEnded,
    success_headers,
)
from .helpers import FakeExtension


# ---------------------------------------------------------------------------
# Successful handshake
# ---------------------------------------------------------------------------


def _handshake_pair(
    request: Request | None = None,
    accept: AcceptConnection | None = None,
) -> tuple[WSConnection, WSConnection, Headers, Headers]:
    client = WSConnection(H2Handshake(CLIENT))
    server = WSConnection(H2Handshake(SERVER))
    request_headers = client.send(request or Request(host="localhost", target="/"))
    server.receive_data(RequestReceived(request_headers))
    received_request = next(server.events())
    assert isinstance(received_request, Request)
    response_headers = server.send(accept or AcceptConnection())
    client.receive_data(ResponseReceived(response_headers))
    received_accept = next(client.events())
    assert isinstance(received_accept, AcceptConnection)
    assert client.state is ConnectionState.OPEN
    assert server.state is ConnectionState.OPEN
    return client, server, request_headers, response_headers


def test_successful_handshake() -> None:
    client, server, request_headers, response_headers = _handshake_pair()

    # RFC 8441 extended CONNECT request shape.
    assert request_headers[:5] == [
        (b":method", b"CONNECT"),
        (b":protocol", b"websocket"),
        (b":scheme", b"https"),
        (b":authority", b"localhost"),
        (b":path", b"/"),
    ]

    # HTTP/2 response semantics: 200 with the :status pseudo-header, and
    # never the HTTP/1.1 Upgrade/Connection/101 machinery.
    assert response_headers == [(b":status", b"200")]
    names = {name.lower() for name, _ in response_headers}
    assert b"upgrade" not in names
    assert b"connection" not in names

    assert repr(client.handshake) == (
        "H2Handshake(client=True, state=ConnectionState.OPEN)"
    )
    assert repr(server.handshake) == (
        "H2Handshake(client=False, state=ConnectionState.OPEN)"
    )


def test_handshake_plain_header_list_events() -> None:
    # The h2 event objects are optional; raw header blocks work too.
    client = H2Handshake(CLIENT)
    server = H2Handshake(SERVER)

    server.receive_data(client.send(Request(host="localhost", target="/ws")))
    request = next(server.events())
    assert isinstance(request, Request)
    assert request.target == "/ws"

    client.receive_data(server.send(AcceptConnection()))
    assert isinstance(next(client.events()), AcceptConnection)
    assert client.state is ConnectionState.OPEN
    assert server.state is ConnectionState.OPEN


def test_handshake_tuple_data_events_after_acceptance() -> None:
    client = WSConnection(H2Handshake(CLIENT))
    server = WSConnection(H2Handshake(SERVER))

    server.receive_data(client.send(Request(host="localhost", target="/")))
    next(server.events())
    client.receive_data(server.send(AcceptConnection()))
    next(client.events())

    wire = client.send(TextMessage("tuple", message_finished=False))
    server.receive_data((b"DATA", wire))
    event = next(server.events())
    assert isinstance(event, TextMessage)
    assert event.data == "tuple"
    assert event.message_finished is False


def test_request_target_authority_and_headers() -> None:
    client = WSConnection(H2Handshake(CLIENT))
    server = WSConnection(H2Handshake(SERVER))

    request_headers = client.send(
        Request(
            host="api.example.com",
            target="/chat?room=1",
            subprotocols=["chat", "superchat"],
            extra_headers=[(b"origin", b"https://example.com")],
        ),
    )
    server.receive_data(RequestReceived(request_headers))
    request = next(server.events())
    assert isinstance(request, Request)
    assert request.host == "api.example.com"
    assert request.target == "/chat?room=1"
    assert request.subprotocols == ["chat", "superchat"]
    assert request.extra_headers == [(b"origin", b"https://example.com")]


def test_authority_with_port_and_ipv6() -> None:
    def with_authority(authority: bytes) -> Headers:
        return [
            (name, authority if name == b":authority" else value)
            for name, value in CONNECT_HEADERS
        ]

    server = H2Handshake(SERVER)
    server.receive_data(
        RequestReceived(with_authority(b"localhost:8443")),
    )
    assert next(server.events()).host == "localhost"

    server = H2Handshake(SERVER)
    server.receive_data(
        RequestReceived(with_authority(b"[2001:db8::1]:443")),
    )
    assert next(server.events()).host == "2001:db8::1"


def test_handshake_extra_response_headers() -> None:
    _, _, _, response_headers = _handshake_pair(
        accept=AcceptConnection(extra_headers=[(b"x-foo", b"bar")]),
    )
    assert (b"x-foo", b"bar") in response_headers


# ---------------------------------------------------------------------------
# Pseudo-header and regular header boundary validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("removed", "message"),
    [
        (b":method", "Missing pseudo-header :method"),
        (b":protocol", "Missing pseudo-header :protocol"),
        (b":scheme", "Missing pseudo-header :scheme"),
        (b":authority", "Missing pseudo-header :authority"),
        (b":path", "Missing pseudo-header :path"),
    ],
)
def test_server_requires_pseudo_headers(removed: bytes, message: str) -> None:
    server = H2Handshake(SERVER)
    headers = [
        (name, value) for name, value in CONNECT_HEADERS if name != removed
    ]
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.receive_data(RequestReceived(headers))
    assert str(excinfo.value) == message
    assert isinstance(excinfo.value.event_hint, RejectConnection)


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        (b":method", b"GET", "Pseudo-header ':method' must be CONNECT"),
        (b":protocol", b"webnotsocket", "Pseudo-header ':protocol' must be websocket"),
    ],
)
def test_server_rejects_pseudo_header_values(
    name: bytes, value: bytes, message: str,
) -> None:
    server = H2Handshake(SERVER)
    headers = [
        (header_name, value if header_name == name else header_value)
        for header_name, header_value in CONNECT_HEADERS
    ]
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.receive_data(RequestReceived(headers))
    assert str(excinfo.value) == message


def test_server_rejects_pseudo_header_after_regular_header() -> None:
    server = H2Handshake(SERVER)
    headers = [
        (b":method", b"CONNECT"),
        (b"x-foo", b"bar"),
        (b":protocol", b"websocket"),
        (b":scheme", b"https"),
        (b":authority", b"localhost"),
        (b":path", b"/"),
    ]
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.receive_data(RequestReceived(headers))
    assert str(excinfo.value) == (
        "Pseudo-headers must precede regular header fields"
    )


def test_server_rejects_duplicate_pseudo_header() -> None:
    server = H2Handshake(SERVER)
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.receive_data(
            RequestReceived(CONNECT_HEADERS + [(b":scheme", b"http")]),
        )
    assert str(excinfo.value) == "Duplicate pseudo-header :scheme"


def test_server_rejects_unknown_pseudo_header() -> None:
    server = H2Handshake(SERVER)
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.receive_data(
            RequestReceived(CONNECT_HEADERS + [(b":status", b"200")]),
        )
    assert str(excinfo.value) == "Unexpected pseudo-header :status"


@pytest.mark.parametrize(
    "forbidden",
    [
        (b"connection", b"keep-alive"),
        (b"keep-alive", b"timeout=5"),
        (b"proxy-connection", b"keep-alive"),
        (b"transfer-encoding", b"chunked"),
        (b"upgrade", b"websocket"),
    ],
)
def test_server_rejects_connection_specific_headers(
    forbidden: tuple[bytes, bytes],
) -> None:
    server = H2Handshake(SERVER)
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.receive_data(
            RequestReceived(CONNECT_HEADERS + [forbidden]),
        )
    assert forbidden[0].decode() in str(excinfo.value)


def test_server_rejects_te_header_other_than_trailers() -> None:
    server = H2Handshake(SERVER)
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.receive_data(
            RequestReceived(CONNECT_HEADERS + [(b"te", b"gzip")]),
        )
    assert str(excinfo.value) == "The TE header field may only contain 'trailers'"


def test_server_accepts_te_trailers() -> None:
    server = H2Handshake(SERVER)
    server.receive_data(
        RequestReceived(CONNECT_HEADERS + [(b"te", b"trailers")]),
    )
    request = next(server.events())
    assert (b"te", b"trailers") in request.extra_headers


def test_server_data_before_headers() -> None:
    server = H2Handshake(SERVER)
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.receive_data(DataReceived(b"not websocket yet"))
    assert str(excinfo.value) == (
        "DATA frame received before the WebSocket handshake completed"
    )


def test_server_stream_end_before_headers() -> None:
    server = H2Handshake(SERVER)
    with pytest.raises(RemoteProtocolError):
        server.receive_data(StreamEnded())


def test_server_accept_rejects_unknown_subprotocol() -> None:
    server = H2Handshake(SERVER)
    server.receive_data(RequestReceived(CONNECT_HEADERS))
    next(server.events())
    with pytest.raises(LocalProtocolError):
        server.send(AcceptConnection(subprotocol="not-offered"))


# ---------------------------------------------------------------------------
# Client-side response validation
# ---------------------------------------------------------------------------


def _client_with_request(
    request: Request | None = None,
) -> WSConnection:
    client = WSConnection(H2Handshake(CLIENT))
    client.send(request or Request(host="localhost", target="/"))
    return client


def test_client_requires_status_pseudo_header() -> None:
    client = _client_with_request()
    with pytest.raises(RemoteProtocolError) as excinfo:
        client.receive_data(ResponseReceived([(b"x-foo", b"bar")]))
    assert str(excinfo.value) == "Missing pseudo-header :status"


def test_client_requires_valid_status_pseudo_header() -> None:
    client = _client_with_request()
    with pytest.raises(RemoteProtocolError) as excinfo:
        client.receive_data(ResponseReceived([(b":status", b"OK")]))
    assert str(excinfo.value) == "Invalid pseudo-header ':status'"


def test_client_rejects_unknown_response_pseudo_header() -> None:
    client = _client_with_request()
    with pytest.raises(RemoteProtocolError) as excinfo:
        client.receive_data(
            ResponseReceived(
                [(b":status", b"200"), (b":path", b"/")],
            ),
        )
    assert str(excinfo.value) == "Unexpected pseudo-header :path"


def test_client_rejects_end_stream_on_success() -> None:
    client = _client_with_request()
    with pytest.raises(RemoteProtocolError) as excinfo:
        client.receive_data(
            ResponseReceived(success_headers(), stream_ended=True),
        )
    assert str(excinfo.value) == (
        "Successful WebSocket response must not end the HTTP/2 stream"
    )


def test_client_rejects_duplicate_status_pseudo_header() -> None:
    client = _client_with_request()
    with pytest.raises(RemoteProtocolError) as excinfo:
        client.receive_data(
            ResponseReceived([(b":status", b"200"), (b":status", b"200")]),
        )
    assert str(excinfo.value) == "Duplicate pseudo-header :status"


def test_client_rejects_non_2xx_status() -> None:
    # 101 Switching Protocols is an HTTP/1.1 concept and must never be used
    # to bootstrap a WebSocket over HTTP/2.
    client = _client_with_request()
    client.receive_data(
        ResponseReceived(
            [
                (b":status", b"101"),
                (b"upgrade", b"websocket"),
                (b"connection", b"upgrade"),
            ],
            stream_ended=True,
        ),
    )
    events = list(client.events())
    assert events == [
        RejectConnection(
            headers=[(b"upgrade", b"websocket"), (b"connection", b"upgrade")],
            status_code=101,
            has_body=False,
        ),
    ]
    assert client.state is ConnectionState.CLOSED


def test_client_rejects_unnegotiated_subprotocol() -> None:
    client = _client_with_request(
        Request(host="localhost", target="/", subprotocols=["chat"]),
    )
    with pytest.raises(RemoteProtocolError) as excinfo:
        client.receive_data(
            ResponseReceived(
                success_headers([(b"sec-websocket-protocol", b"superchat")]),
            ),
        )
    assert str(excinfo.value) == "unrecognized subprotocol superchat"


# ---------------------------------------------------------------------------
# Subprotocol negotiation reuses the existing rules
# ---------------------------------------------------------------------------


def test_subprotocol_negotiation() -> None:
    _, _, request_headers, response_headers = _handshake_pair(
        request=Request(
            host="localhost", target="/", subprotocols=["chat", "superchat"],
        ),
        accept=AcceptConnection(subprotocol="chat"),
    )
    assert (b"sec-websocket-protocol", b"chat, superchat") in request_headers
    assert (b"sec-websocket-protocol", b"chat") in response_headers


def test_extension_offer_and_accept_headers() -> None:
    offered = FakeExtension(offer_response="parameter=value")
    accepted = FakeExtension(accept_response=True)

    client = WSConnection(H2Handshake(CLIENT))
    server = WSConnection(H2Handshake(SERVER))
    request_headers = client.send(
        Request(host="localhost", target="/", extensions=[offered]),
    )
    assert (
        b"sec-websocket-extensions",
        b"fake; parameter=value",
    ) in request_headers

    server.receive_data(RequestReceived(request_headers))
    next(server.events())
    response_headers = server.send(AcceptConnection(extensions=[accepted]))
    assert (b"sec-websocket-extensions", b"fake") in response_headers

    client.receive_data(ResponseReceived(response_headers))
    accept = next(client.events())
    assert isinstance(accept, AcceptConnection)
    assert accept.extensions == [offered]


def test_client_rejects_unoffered_extension() -> None:
    client = _client_with_request()
    with pytest.raises(RemoteProtocolError) as excinfo:
        client.receive_data(
            ResponseReceived(
                success_headers([(b"sec-websocket-extensions", b"nope")]),
            ),
        )
    assert str(excinfo.value) == "unrecognized extension nope"


def test_permessage_deflate_roundtrip() -> None:
    client_extension = PerMessageDeflate()
    server_extension = PerMessageDeflate()

    client = WSConnection(H2Handshake(CLIENT))
    server = WSConnection(H2Handshake(SERVER))

    request_headers = client.send(
        Request(host="localhost", target="/", extensions=[client_extension]),
    )
    assert any(
        name == b"sec-websocket-extensions" and b"permessage-deflate" in value
        for name, value in request_headers
    )
    server.receive_data(RequestReceived(request_headers))
    next(server.events())
    response_headers = server.send(
        AcceptConnection(extensions=[server_extension]),
    )
    client.receive_data(ResponseReceived(response_headers))
    assert isinstance(next(client.events()), AcceptConnection)
    assert client_extension.enabled()
    assert server_extension.enabled()

    payload = "compressed " * 100
    wire = client.send(TextMessage(payload))
    assert len(wire) < len(payload)
    server.receive_data(DataReceived(wire))
    message = next(server.events())
    assert isinstance(message, TextMessage)
    assert message.data == payload


# ---------------------------------------------------------------------------
# Rejection
# ---------------------------------------------------------------------------


def test_server_rejection_without_body() -> None:
    server = H2Handshake(SERVER)
    server.receive_data(RequestReceived(CONNECT_HEADERS))
    next(server.events())
    headers = server.send(RejectConnection(status_code=403))
    assert headers == [(b":status", b"403")]
    assert server.state is ConnectionState.CLOSED


def test_server_rejection_with_body() -> None:
    server = H2Handshake(SERVER)
    server.receive_data(RequestReceived(CONNECT_HEADERS))
    next(server.events())
    headers = server.send(
        RejectConnection(
            status_code=403,
            has_body=True,
            headers=[(b"content-type", b"text/plain")],
        ),
    )
    assert headers == [
        (b":status", b"403"),
        (b"content-type", b"text/plain"),
    ]
    assert server.state is ConnectionState.REJECTING
    assert server.send(RejectData(data=b"nope", body_finished=True)) == b"nope"
    assert server.state is ConnectionState.CLOSED


def test_client_rejection_without_body() -> None:
    client = _client_with_request()
    client.receive_data(
        ResponseReceived(
            [(b":status", b"403"), (b"content-length", b"0")],
            stream_ended=True,
        ),
    )
    assert list(client.events()) == [
        RejectConnection(
            headers=[(b"content-length", b"0")],
            status_code=403,
            has_body=False,
        ),
    ]
    assert client.state is ConnectionState.CLOSED


def test_client_rejection_with_body() -> None:
    client = _client_with_request()
    client.receive_data(
        ResponseReceived(
            [(b":status", b"404"), (b"content-length", b"5")],
        ),
    )
    assert list(client.events()) == [
        RejectConnection(
            headers=[(b"content-length", b"5")],
            status_code=404,
            has_body=True,
        ),
    ]
    assert client.state is ConnectionState.REJECTING

    client.receive_data(DataReceived(b"Hello"))
    client.receive_data(StreamEnded())
    assert list(client.events()) == [
        RejectData(data=b"Hello", body_finished=False),
        RejectData(data=b"", body_finished=True),
    ]
    assert client.state is ConnectionState.CLOSED


def test_client_rejection_body_end_stream_on_data() -> None:
    client = _client_with_request()
    client.receive_data(ResponseReceived([(b":status", b"404")]))
    list(client.events())
    client.receive_data(DataReceived(b"Hello", stream_ended=True))
    assert list(client.events()) == [
        RejectData(data=b"Hello", body_finished=True),
        RejectData(data=b"", body_finished=True),
    ]
    assert client.state is ConnectionState.CLOSED


# ---------------------------------------------------------------------------
# Post-handshake framing and trailing data
# ---------------------------------------------------------------------------


def _established_pair() -> tuple[WSConnection, WSConnection]:
    client, server, _, _ = _handshake_pair()
    return client, server


def test_fragmented_text_messages() -> None:
    client, server = _established_pair()

    first = client.send(TextMessage("hello, ", message_finished=False))
    second = client.send(TextMessage("world!"))
    server.receive_data(DataReceived(first))
    server.receive_data(DataReceived(second))

    messages = list(server.events())
    assert messages == [
        TextMessage(data="hello, ", frame_finished=True, message_finished=False),
        TextMessage(data="world!", frame_finished=True, message_finished=True),
    ]


def test_fragmented_binary_messages_and_coalesced_data() -> None:
    client, server = _established_pair()

    first = server.send(BytesMessage(b"\x00\x01", message_finished=False))
    second = server.send(BytesMessage(b"\x02\x03"))
    # Several DATA frames may arrive concatenated together.
    client.receive_data(DataReceived(first + second))

    messages = list(client.events())
    assert messages == [
        BytesMessage(
            data=bytearray(b"\x00\x01"),
            frame_finished=True,
            message_finished=False,
        ),
        BytesMessage(
            data=bytearray(b"\x02\x03"),
            frame_finished=True,
            message_finished=True,
        ),
    ]


def test_trailing_data_on_the_headers_event() -> None:
    # The HTTP/2 implementation is allowed to surface DATA received in the
    # same packet via a subsequent event carrying stream_ended.
    client, server = _established_pair()
    wire = server.send(TextMessage("late arrival"))
    client.receive_data(DataReceived(wire, stream_ended=True))
    messages = list(client.events())
    assert messages == [TextMessage(data="late arrival")]
    # A stream end after the data is not itself a WebSocket close.
    client.receive_data(StreamEnded())
    assert client.state is ConnectionState.OPEN


def test_raw_bytes_after_handshake() -> None:
    client, server = _established_pair()
    wire = client.send(Ping(payload=b"abc"))
    server.receive_data(wire)
    assert list(server.events()) == [Ping(payload=b"abc")]


def test_closing_handshake() -> None:
    client, server = _established_pair()

    # Server initiates the closing handshake.
    client.receive_data(DataReceived(server.send(CloseConnection(code=1001))))
    close = next(client.events())
    assert isinstance(close, CloseConnection)
    assert close.code == 1001
    assert client.state is ConnectionState.REMOTE_CLOSING

    # Client echoes the close; both sides are now closed.
    response = client.send(close.response())
    server.receive_data(DataReceived(response))
    server_close = next(server.events())
    assert isinstance(server_close, CloseConnection)
    assert server.state is ConnectionState.CLOSED
    assert client.state is ConnectionState.CLOSED
    assert client.connection is not None
    assert server.connection is not None


# ---------------------------------------------------------------------------
# Local errors and HTTP/1.1-only helpers
# ---------------------------------------------------------------------------


def test_initiate_upgrade_connection_unsupported() -> None:
    with pytest.raises(LocalProtocolError):
        H2Handshake(SERVER).initiate_upgrade_connection([], "/")


def test_send_invalid_event_during_handshake() -> None:
    with pytest.raises(LocalProtocolError):
        H2Handshake(CLIENT).send(Ping())


def test_rejection_data_requires_rejecting_state() -> None:
    client = H2Handshake(CLIENT)
    with pytest.raises(LocalProtocolError):
        client.send(RejectData(data=b"x"))


def test_cannot_reject_after_acceptance() -> None:
    _, server = _established_pair()
    with pytest.raises(LocalProtocolError):
        server.send(RejectConnection())
