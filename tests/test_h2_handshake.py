from __future__ import annotations

import pytest

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
from wsproto.frame_protocol import CloseReason
from wsproto.handshake import H2Handshake
from wsproto.typing import Headers
from wsproto.utilities import (
    LocalProtocolError,
    RemoteProtocolError,
    normed_header_dict,
)

from .helpers import FakeExtension


def _request_headers() -> Headers:
    return list(
        {
            b":method": b"CONNECT",
            b":protocol": b"websocket",
            b":scheme": b"https",
            b":authority": b"localhost",
            b":path": b"/",
        }.items(),
    )


def _with_headers(overrides: dict[bytes, bytes]) -> Headers:
    headers = dict(_request_headers())
    headers.update(overrides)
    return list(headers.items())


def _complete_handshake(
    client: H2Handshake,
    server: H2Handshake,
) -> None:
    server.initiate_upgrade_connection(client.send(Request(host="localhost", target="/")))
    assert isinstance(next(server.events()), Request)
    client.receive_headers(server.send(AcceptConnection()))
    assert isinstance(next(client.events()), AcceptConnection)


def test_successful_handshake() -> None:
    client = H2Handshake(CLIENT)
    server = H2Handshake(SERVER)

    request_headers = client.send(Request(host="localhost", target="/"))
    assert request_headers[:5] == [
        (b":method", b"CONNECT"),
        (b":protocol", b"websocket"),
        (b":scheme", b"https"),
        (b":authority", b"localhost"),
        (b":path", b"/"),
    ]
    header_names = [name for name, _ in request_headers]
    assert b"upgrade" not in header_names
    assert b"connection" not in header_names
    assert b"sec-websocket-key" not in header_names
    assert b"sec-websocket-version" not in header_names

    server.initiate_upgrade_connection(request_headers)
    request = next(server.events())
    assert isinstance(request, Request)
    assert request.host == "localhost"
    assert request.target == "/"

    response_headers = server.send(AcceptConnection())
    assert response_headers == [(b":status", b"200")]

    client.receive_headers(response_headers)
    accept = next(client.events())
    assert isinstance(accept, AcceptConnection)

    assert client.state is ConnectionState.OPEN
    assert server.state is ConnectionState.OPEN
    assert client.connection is not None
    assert server.connection is not None

    assert repr(client) == "H2Handshake(client=True, state=ConnectionState.OPEN)"
    assert repr(server) == "H2Handshake(client=False, state=ConnectionState.OPEN)"


def test_host_encoding() -> None:
    client = H2Handshake(CLIENT)
    server = H2Handshake(SERVER)
    headers = client.send(Request(host="芝士汉堡", target="/"))
    assert (b":authority", "芝士汉堡".encode("idna")) in headers
    server.initiate_upgrade_connection(headers)
    request = next(server.events())
    assert isinstance(request, Request)
    assert request.host == "芝士汉堡"


def test_request_event_fields() -> None:
    server = H2Handshake(SERVER)
    server.initiate_upgrade_connection(
        [
            *_request_headers(),
            (b"sec-websocket-protocol", b"chat, super"),
            (b"sec-websocket-extensions", b"fake; parameter, other"),
            (b"x-foo", b"bar"),
        ],
    )
    request = next(server.events())
    assert isinstance(request, Request)
    assert request.host == "localhost"
    assert request.target == "/"
    assert request.subprotocols == ["chat", "super"]
    assert request.extensions == ["fake; parameter", "other"]
    headers = normed_header_dict(request.extra_headers)
    assert headers == {b"x-foo": b"bar"}


@pytest.mark.parametrize(
    "headers",
    [
        # Wrong method
        _with_headers({b":method": b"GET"}),
        # Missing :protocol
        [(name, value) for name, value in _request_headers() if name != b":protocol"],
        # Wrong :protocol
        _with_headers({b":protocol": b"h2c"}),
        # Missing :scheme
        [(name, value) for name, value in _request_headers() if name != b":scheme"],
        # Missing :authority
        [(name, value) for name, value in _request_headers() if name != b":authority"],
        # Missing :path
        [(name, value) for name, value in _request_headers() if name != b":path"],
        # Pseudo-header after a regular header
        [*_request_headers(), (b"x-foo", b"bar"), (b":method", b"CONNECT")],
        # Duplicate pseudo-header
        [*_request_headers(), (b":path", b"/other")],
        # Unknown pseudo-header
        [*_request_headers(), (b":status", b"200")],
        # Connection-specific headers are forbidden in HTTP/2
        [*_request_headers(), (b"connection", b"upgrade")],
        [*_request_headers(), (b"upgrade", b"websocket")],
        [*_request_headers(), (b"keep-alive", b"timeout=5")],
        [*_request_headers(), (b"transfer-encoding", b"chunked")],
        # TE is only allowed with the value "trailers"
        [*_request_headers(), (b"te", b"gzip")],
    ],
)
def test_invalid_request_headers(headers: Headers) -> None:
    server = H2Handshake(SERVER)
    with pytest.raises(RemoteProtocolError) as excinfo:
        server.initiate_upgrade_connection(headers)
    assert isinstance(excinfo.value.event_hint, RejectConnection)


def test_request_te_trailers_allowed() -> None:
    server = H2Handshake(SERVER)
    server.initiate_upgrade_connection([*_request_headers(), (b"te", b"trailers")])
    request = next(server.events())
    assert isinstance(request, Request)
    assert (b"te", b"trailers") in request.extra_headers


def test_subprotocol_negotiation() -> None:
    client = H2Handshake(CLIENT)
    server = H2Handshake(SERVER)

    request_headers = client.send(
        Request(host="localhost", target="/", subprotocols=["chat", "super"]),
    )
    assert (b"sec-websocket-protocol", b"chat, super") in request_headers

    server.initiate_upgrade_connection(request_headers)
    request = next(server.events())
    assert isinstance(request, Request)
    assert request.subprotocols == ["chat", "super"]

    response_headers = server.send(AcceptConnection(subprotocol="chat"))
    assert (b"sec-websocket-protocol", b"chat") in response_headers

    client.receive_headers(response_headers)
    accept = next(client.events())
    assert isinstance(accept, AcceptConnection)
    assert accept.subprotocol == "chat"


def test_server_accept_unexpected_subprotocol() -> None:
    server = H2Handshake(SERVER)
    server.initiate_upgrade_connection(_request_headers())
    assert isinstance(next(server.events()), Request)
    with pytest.raises(LocalProtocolError):
        server.send(AcceptConnection(subprotocol="chat"))


def test_client_receive_unexpected_subprotocol() -> None:
    client = H2Handshake(CLIENT)
    client.send(Request(host="localhost", target="/", subprotocols=["chat"]))
    with pytest.raises(RemoteProtocolError):
        client.receive_headers(
            [(b":status", b"200"), (b"sec-websocket-protocol", b"super")],
        )


def test_extension_negotiation() -> None:
    client = H2Handshake(CLIENT)
    server = H2Handshake(SERVER)

    client_extension = FakeExtension(offer_response="parameter=value")
    request_headers = client.send(
        Request(host="localhost", target="/", extensions=[client_extension]),
    )
    assert (b"sec-websocket-extensions", b"fake; parameter=value") in request_headers

    server.initiate_upgrade_connection(request_headers)
    request = next(server.events())
    assert isinstance(request, Request)
    assert request.extensions == ["fake; parameter=value"]

    server_extension = FakeExtension(accept_response="parameter=value")
    response_headers = server.send(AcceptConnection(extensions=[server_extension]))
    assert (b"sec-websocket-extensions", b"fake; parameter=value") in response_headers
    assert server_extension.offered == "fake; parameter=value"

    client.receive_headers(response_headers)
    accept = next(client.events())
    assert isinstance(accept, AcceptConnection)
    assert accept.extensions == [client_extension]
    assert client_extension.accepted_offer == "fake; parameter=value"


def test_permessage_deflate_negotiation() -> None:
    client = H2Handshake(CLIENT)
    server = H2Handshake(SERVER)

    server.initiate_upgrade_connection(
        client.send(
            Request(host="localhost", target="/", extensions=[PerMessageDeflate()]),
        ),
    )
    request = next(server.events())
    assert isinstance(request, Request)

    response_headers = server.send(AcceptConnection(extensions=[PerMessageDeflate()]))
    headers = normed_header_dict(response_headers)
    assert headers[b"sec-websocket-extensions"].startswith(b"permessage-deflate")

    client.receive_headers(response_headers)
    accept = next(client.events())
    assert isinstance(accept, AcceptConnection)
    assert len(accept.extensions) == 1
    assert accept.extensions[0].enabled()

    # The negotiated extension is used by the frame protocol.
    assert client.connection is not None
    assert server.connection is not None
    server.connection.receive_data(client.connection.send(TextMessage(data="compressible")))
    message = next(server.connection.events())
    assert isinstance(message, TextMessage)
    assert message.data == "compressible"


def test_client_receive_unknown_extension() -> None:
    client = H2Handshake(CLIENT)
    client.send(Request(host="localhost", target="/"))
    with pytest.raises(RemoteProtocolError):
        client.receive_headers(
            [(b":status", b"200"), (b"sec-websocket-extensions", b"unknown")],
        )


def test_rejected_handshake() -> None:
    client = H2Handshake(CLIENT)
    server = H2Handshake(SERVER)

    server.initiate_upgrade_connection(client.send(Request(host="localhost", target="/")))
    assert isinstance(next(server.events()), Request)

    response_headers = server.send(
        RejectConnection(status_code=403, headers=[(b"x-reason", b"nope")]),
    )
    assert response_headers == [(b":status", b"403"), (b"x-reason", b"nope")]
    assert server.state is ConnectionState.CLOSED

    client.receive_headers(response_headers)
    reject = next(client.events())
    assert isinstance(reject, RejectConnection)
    assert reject.status_code == 403
    assert reject.has_body
    assert (b"x-reason", b"nope") in reject.headers
    assert client.state is ConnectionState.REJECTING

    client.receive_data(b"body")
    reject_data = next(client.events())
    assert isinstance(reject_data, RejectData)
    assert reject_data.data == b"body"
    assert not reject_data.body_finished

    client.receive_data(None)
    reject_data = next(client.events())
    assert isinstance(reject_data, RejectData)
    assert reject_data.body_finished
    assert client.state is ConnectionState.CLOSED


def test_rejected_handshake_with_body() -> None:
    server = H2Handshake(SERVER)
    server.initiate_upgrade_connection(_request_headers())
    assert isinstance(next(server.events()), Request)

    headers = server.send(RejectConnection(status_code=400, has_body=True))
    assert headers == [(b":status", b"400")]
    assert server.state is ConnectionState.REJECTING

    assert server.send(RejectData(data=b"some", body_finished=False)) == b"some"
    assert server.state is ConnectionState.REJECTING
    assert server.send(RejectData(data=b"body", body_finished=True)) == b"body"
    assert server.state is ConnectionState.CLOSED


def test_reject_twice() -> None:
    server = H2Handshake(SERVER)
    server.initiate_upgrade_connection(_request_headers())
    assert isinstance(next(server.events()), Request)
    server.send(RejectConnection())
    with pytest.raises(LocalProtocolError):
        server.send(RejectConnection())


def test_send_reject_data_in_wrong_state() -> None:
    server = H2Handshake(SERVER)
    with pytest.raises(LocalProtocolError):
        server.send(RejectData(data=b"body"))


@pytest.mark.parametrize(
    "headers",
    [
        # Missing :status
        [(b"x-foo", b"bar")],
        # Invalid :status
        [(b":status", b"OK")],
        # Duplicate :status
        [(b":status", b"200"), (b":status", b"200")],
        # Unexpected pseudo-header
        [(b":status", b"200"), (b":path", b"/")],
        # Pseudo-header after a regular header
        [(b"x-foo", b"bar"), (b":status", b"200")],
    ],
)
def test_invalid_response_headers(headers: Headers) -> None:
    client = H2Handshake(CLIENT)
    client.send(Request(host="localhost", target="/"))
    with pytest.raises(RemoteProtocolError):
        client.receive_headers(headers)


def test_non_2xx_response_is_a_rejection() -> None:
    client = H2Handshake(CLIENT)
    client.send(Request(host="localhost", target="/"))
    client.receive_headers([(b":status", b"301"), (b"location", b"https://elsewhere/")])
    reject = next(client.events())
    assert isinstance(reject, RejectConnection)
    assert reject.status_code == 301
    assert client.state is ConnectionState.REJECTING


def test_initiate_upgrade_as_client() -> None:
    client = H2Handshake(CLIENT)
    with pytest.raises(LocalProtocolError):
        client.initiate_upgrade_connection(_request_headers())


def test_receive_headers_as_server() -> None:
    server = H2Handshake(SERVER)
    with pytest.raises(LocalProtocolError):
        server.receive_headers([(b":status", b"200")])


def test_send_request_as_server() -> None:
    server = H2Handshake(SERVER)
    with pytest.raises(LocalProtocolError):
        server.send(Request(host="localhost", target="/"))


def test_send_invalid_event() -> None:
    client = H2Handshake(CLIENT)
    with pytest.raises(LocalProtocolError):
        client.send(Ping())


def test_receive_data_before_headers() -> None:
    client = H2Handshake(CLIENT)
    with pytest.raises(LocalProtocolError):
        client.receive_data(b"data")


def test_trailing_data_after_handshake() -> None:
    client = H2Handshake(CLIENT)
    server = H2Handshake(SERVER)
    _complete_handshake(client, server)

    assert server.connection is not None
    trailing = server.connection.send(TextMessage(data="hello"))

    # Data received with (or after) the response headers is WebSocket
    # frame data for the established connection.
    client.receive_data(trailing)
    events = list(client.events())
    assert len(events) == 1
    assert isinstance(events[0], TextMessage)
    assert events[0].data == "hello"


def test_fragmented_messages_and_close() -> None:
    client = H2Handshake(CLIENT)
    server = H2Handshake(SERVER)
    _complete_handshake(client, server)

    assert client.connection is not None
    assert server.connection is not None

    # Fragmented text message, client to server.
    data = client.connection.send(TextMessage(data="Hel", message_finished=False))
    data += client.connection.send(TextMessage(data="lo", message_finished=True))
    server.connection.receive_data(data)
    events = list(server.connection.events())
    assert events == [
        TextMessage(data="Hel", frame_finished=True, message_finished=False),
        TextMessage(data="lo", frame_finished=True, message_finished=True),
    ]

    # Binary message, server to client.
    data = server.connection.send(BytesMessage(data=b"\x00\x01"))
    client.connection.receive_data(data)
    events = list(client.connection.events())
    assert events == [BytesMessage(data=b"\x00\x01")]

    # Closing handshake.
    data = client.connection.send(CloseConnection(code=CloseReason.NORMAL_CLOSURE))
    server.connection.receive_data(data)
    close = next(server.connection.events())
    assert isinstance(close, CloseConnection)
    assert close.code == CloseReason.NORMAL_CLOSURE
    assert server.connection.state is ConnectionState.REMOTE_CLOSING

    data = server.connection.send(close.response())
    client.connection.receive_data(data)
    close = next(client.connection.events())
    assert isinstance(close, CloseConnection)
    assert client.connection.state is ConnectionState.CLOSED
    assert server.connection.state is ConnectionState.CLOSED
