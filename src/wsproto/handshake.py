"""
wsproto/handshake
~~~~~~~~~~~~~~~~~~

An implementation of WebSocket handshakes.
"""
from __future__ import annotations

from collections import deque
from typing import (
    TYPE_CHECKING,
    cast,
)

import h11

from .connection import Connection, ConnectionState, ConnectionType
from .events import AcceptConnection, Event, RejectConnection, RejectData, Request
from .extensions import Extension
from .utilities import (
    LocalProtocolError,
    RemoteProtocolError,
    generate_accept_token,
    generate_nonce,
    normed_header_dict,
    split_comma_header,
)

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable, Sequence

    from .typing import Headers

# RFC6455, Section 4.2.1/6 - Reading the Client's Opening Handshake
WEBSOCKET_VERSION = b"13"

# RFC6455, Section 4.2.1/3 - Value of the Upgrade header
WEBSOCKET_UPGRADE = b"websocket"

# RFC 8441 - The :protocol pseudo-header value for WebSockets over HTTP/2
H2_WEBSOCKET_PROTOCOL = WEBSOCKET_UPGRADE

# RFC 7540, Section 8.1.2.2 - Connection-Specific Header Fields that must
# not appear in an HTTP/2 message.
H2_FORBIDDEN_HEADERS = frozenset(
    {
        b"connection",
        b"keep-alive",
        b"proxy-connection",
        b"transfer-encoding",
        b"upgrade",
    },
)

# RFC 7540, Section 8.1.2.3 - Pseudo-headers valid in an HTTP/2 request,
# extended with :protocol as per RFC 8441.
H2_REQUEST_PSEUDO_HEADERS = frozenset(
    {
        b":method",
        b":scheme",
        b":authority",
        b":path",
        b":protocol",
    },
)


class H11Handshake:
    """A Handshake implementation for HTTP/1.1 connections."""

    def __init__(self, connection_type: ConnectionType) -> None:
        self.client = connection_type is ConnectionType.CLIENT
        self._state = ConnectionState.CONNECTING

        if self.client:
            self._h11_connection = h11.Connection(h11.CLIENT)
        else:
            self._h11_connection = h11.Connection(h11.SERVER)

        self._connection: Connection | None = None
        self._events: deque[Event] = deque()
        self._initiating_request: Request | None = None
        self._nonce: bytes | None = None

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def connection(self) -> Connection | None:
        """
        Return the established connection.

        This will either return the connection or raise a
        LocalProtocolError if the connection has not yet been
        established.

        :rtype: h11.Connection
        """
        return self._connection

    def initiate_upgrade_connection(
        self, headers: Headers, path: bytes | str,
    ) -> None:
        """
        Initiate an upgrade connection.

        This should be used if the request has already be received and
        parsed.

        :param list headers: HTTP headers represented as a list of 2-tuples.
        :param str path: A URL path.
        """
        if self.client:
            msg = "Cannot initiate an upgrade connection when acting as the client"
            raise LocalProtocolError(
                msg,
            )
        upgrade_request = h11.Request(method=b"GET", target=path, headers=headers)
        h11_client = h11.Connection(h11.CLIENT)
        self.receive_data(h11_client.send(upgrade_request))

    def send(self, event: Event) -> bytes:
        """
        Send an event to the remote.

        This will return the bytes to send based on the event or raise
        a LocalProtocolError if the event is not valid given the
        state.

        :returns: Data to send to the WebSocket peer.
        :rtype: bytes
        """
        data = b""
        if isinstance(event, Request):
            data += self._initiate_connection(event)
        elif isinstance(event, AcceptConnection):
            data += self._accept(event)
        elif isinstance(event, RejectConnection):
            data += self._reject(event)
        elif isinstance(event, RejectData):
            data += self._send_reject_data(event)
        else:
            msg = f"Event {event} cannot be sent during the handshake"
            raise LocalProtocolError(
                msg,
            )
        return data

    def receive_data(self, data: bytes | None) -> None:
        """
        Receive data from the remote.

        A list of events that the remote peer triggered by sending
        this data can be retrieved with :meth:`events`.

        :param bytes data: Data received from the WebSocket peer.
        """
        self._h11_connection.receive_data(data or b"")
        while True:
            try:
                event = self._h11_connection.next_event()
            except h11.RemoteProtocolError:
                msg = "Bad HTTP message"
                raise RemoteProtocolError(
                    msg, event_hint=RejectConnection(),
                )
            if (
                isinstance(event, h11.ConnectionClosed)
                or event is h11.NEED_DATA
                or event is h11.PAUSED
            ):
                break

            if self.client:
                if isinstance(event, h11.InformationalResponse):
                    if event.status_code == 101:
                        self._events.append(self._establish_client_connection(event))
                    else:
                        self._events.append(
                            RejectConnection(
                                headers=list(event.headers),
                                status_code=event.status_code,
                                has_body=False,
                            ),
                        )
                        self._state = ConnectionState.CLOSED
                elif isinstance(event, h11.Response):
                    self._state = ConnectionState.REJECTING
                    self._events.append(
                        RejectConnection(
                            headers=list(event.headers),
                            status_code=event.status_code,
                            has_body=True,
                        ),
                    )
                elif isinstance(event, h11.Data):
                    self._events.append(
                        RejectData(data=event.data, body_finished=False),
                    )
                elif isinstance(event, h11.EndOfMessage):
                    self._events.append(RejectData(data=b"", body_finished=True))
                    self._state = ConnectionState.CLOSED
            elif isinstance(event, h11.Request):
                self._events.append(self._process_connection_request(event))

    def events(self) -> Generator[Event, None, None]:
        """
        Return a generator that provides any events that have been generated
        by protocol activity.

        :returns: a generator that yields H11 events.
        """
        while self._events:
            yield self._events.popleft()

    # Server mode methods

    def _process_connection_request(
        self, event: h11.Request,
    ) -> Request:
        if event.method != b"GET":
            msg = "Request method must be GET"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        connection_tokens = None
        extensions: list[str] = []
        host = None
        key = None
        subprotocols: list[str] = []
        upgrade = b""
        version = None
        headers: Headers = []
        for name, value in event.headers:
            name = name.lower()
            if name == b"connection":
                connection_tokens = split_comma_header(value)
            elif name == b"host":
                host = value.decode("idna")
                continue  # Skip appending to headers
            elif name == b"sec-websocket-extensions":
                extensions.extend(split_comma_header(value))
                continue  # Skip appending to headers
            elif name == b"sec-websocket-key":
                key = value
            elif name == b"sec-websocket-protocol":
                subprotocols.extend(split_comma_header(value))
                continue  # Skip appending to headers
            elif name == b"sec-websocket-version":
                version = value
            elif name == b"upgrade":
                upgrade = value
            headers.append((name, value))
        if connection_tokens is None or not any(
            token.lower() == "upgrade" for token in connection_tokens
        ):
            msg = "Missing header, 'Connection: Upgrade'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        if version != WEBSOCKET_VERSION:
            msg = "Missing header, 'Sec-WebSocket-Version'"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(
                    headers=[(b"Sec-WebSocket-Version", WEBSOCKET_VERSION)],
                    status_code=426 if version else 400,
                ),
            )
        if key is None:
            msg = "Missing header, 'Sec-WebSocket-Key'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        if upgrade.lower() != WEBSOCKET_UPGRADE:
            msg = f"Missing header, 'Upgrade: {WEBSOCKET_UPGRADE.decode()}'"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(),
            )
        if host is None:
            msg = "Missing header, 'Host'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )

        self._initiating_request = Request(
            extensions=extensions,
            extra_headers=headers,
            host=host,
            subprotocols=subprotocols,
            target=event.target.decode("ascii"),
        )
        return self._initiating_request

    def _accept(self, event: AcceptConnection) -> bytes:
        # _accept is always called after _process_connection_request.
        assert self._initiating_request is not None
        request_headers = normed_header_dict(self._initiating_request.extra_headers)

        nonce = request_headers[b"sec-websocket-key"]
        accept_token = generate_accept_token(nonce)

        headers = [
            (b"Upgrade", WEBSOCKET_UPGRADE),
            (b"Connection", b"Upgrade"),
            (b"Sec-WebSocket-Accept", accept_token),
        ]

        if event.subprotocol is not None:
            if event.subprotocol not in self._initiating_request.subprotocols:
                msg = f"unexpected subprotocol {event.subprotocol}"
                raise LocalProtocolError(msg)
            headers.append(
                (b"Sec-WebSocket-Protocol", event.subprotocol.encode("ascii")),
            )

        if event.extensions:
            accepts = server_extensions_handshake(
                cast("Sequence[str]", self._initiating_request.extensions),
                event.extensions,
            )
            if accepts:
                headers.append((b"Sec-WebSocket-Extensions", accepts))

        response = h11.InformationalResponse(
            status_code=101,
            headers=headers + event.extra_headers,
            reason=b"Switching Protocols",
        )
        self._connection = Connection(
            ConnectionType.CLIENT if self.client else ConnectionType.SERVER,
            event.extensions,
        )
        self._state = ConnectionState.OPEN
        return self._h11_connection.send(response) or b""

    def _reject(self, event: RejectConnection) -> bytes:
        if self.state != ConnectionState.CONNECTING:
            msg = f"Connection cannot be rejected in state {self.state}"
            raise LocalProtocolError(
                msg,
            )

        headers = list(event.headers)
        if not event.has_body:
            headers.append((b"content-length", b"0"))
        response = h11.Response(status_code=event.status_code, headers=headers)
        data = self._h11_connection.send(response) or b""
        self._state = ConnectionState.REJECTING
        if not event.has_body:
            data += self._h11_connection.send(h11.EndOfMessage()) or b""
            self._state = ConnectionState.CLOSED
        return data

    def _send_reject_data(self, event: RejectData) -> bytes:
        if self.state != ConnectionState.REJECTING:
            msg = f"Cannot send rejection data in state {self.state}"
            raise LocalProtocolError(
                msg,
            )

        data = self._h11_connection.send(h11.Data(data=event.data)) or b""
        if event.body_finished:
            data += self._h11_connection.send(h11.EndOfMessage()) or b""
            self._state = ConnectionState.CLOSED
        return data

    # Client mode methods

    def _initiate_connection(self, request: Request) -> bytes:
        self._initiating_request = request
        self._nonce = generate_nonce()

        headers = [
            (b"Host", request.host.encode("idna")),
            (b"Upgrade", WEBSOCKET_UPGRADE),
            (b"Connection", b"Upgrade"),
            (b"Sec-WebSocket-Key", self._nonce),
            (b"Sec-WebSocket-Version", WEBSOCKET_VERSION),
        ]

        if request.subprotocols:
            headers.append(
                (
                    b"Sec-WebSocket-Protocol",
                    (", ".join(request.subprotocols)).encode("ascii"),
                ),
            )

        offers = client_extension_offers(
            cast("Sequence[Extension]", request.extensions),
        )
        if offers:
            headers.append((b"Sec-WebSocket-Extensions", b", ".join(offers)))

        upgrade = h11.Request(
            method=b"GET",
            target=request.target.encode("ascii"),
            headers=headers + request.extra_headers,
        )
        return self._h11_connection.send(upgrade) or b""

    def _establish_client_connection(
        self, event: h11.InformationalResponse,
    ) -> AcceptConnection:
        # _establish_client_connection is always called after _initiate_connection.
        assert self._initiating_request is not None
        assert self._nonce is not None

        accept = None
        connection_tokens = None
        accepts: list[str] = []
        subprotocol = None
        upgrade = b""
        headers: Headers = []
        for name, value in event.headers:
            name = name.lower()
            if name == b"connection":
                connection_tokens = split_comma_header(value)
                continue  # Skip appending to headers
            if name == b"sec-websocket-extensions":
                accepts = split_comma_header(value)
                continue  # Skip appending to headers
            if name == b"sec-websocket-accept":
                accept = value
                continue  # Skip appending to headers
            if name == b"sec-websocket-protocol":
                subprotocol = value.decode("ascii")
                continue  # Skip appending to headers
            if name == b"upgrade":
                upgrade = value
                continue  # Skip appending to headers
            headers.append((name, value))

        if connection_tokens is None or not any(
            token.lower() == "upgrade" for token in connection_tokens
        ):
            msg = "Missing header, 'Connection: Upgrade'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        if upgrade.lower() != WEBSOCKET_UPGRADE:
            msg = f"Missing header, 'Upgrade: {WEBSOCKET_UPGRADE.decode()}'"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(),
            )
        accept_token = generate_accept_token(self._nonce)
        if accept != accept_token:
            msg = "Bad accept token"
            raise RemoteProtocolError(msg, event_hint=RejectConnection())
        if subprotocol is not None and subprotocol not in self._initiating_request.subprotocols:
            msg = f"unrecognized subprotocol {subprotocol}"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(),
            )
        extensions = client_extensions_handshake(
            accepts, cast("Sequence[Extension]", self._initiating_request.extensions),
        )

        self._connection = Connection(
            ConnectionType.CLIENT if self.client else ConnectionType.SERVER,
            extensions,
            self._h11_connection.trailing_data[0],
        )
        self._state = ConnectionState.OPEN
        return AcceptConnection(
            extensions=extensions, extra_headers=headers, subprotocol=subprotocol,
        )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(client={self.client}, state={self.state})"


class H2Handshake:
    """
    A Handshake implementation for HTTP/2 connections.

    This implements the WebSocket handshake over HTTP/2 as defined in
    RFC 8441 (Bootstrapping WebSockets with HTTP/2). It does not manage
    a network connection, HTTP/2 framing, or flow control. Instead the
    caller is expected to translate between HTTP/2 frames and the
    header lists and data bytes used by this class: request and
    response headers are exchanged as lists of 2-tuples (including the
    HTTP/2 pseudo-headers), whilst data after the handshake is raw
    WebSocket frame data carried in DATA frames.
    """

    def __init__(self, connection_type: ConnectionType) -> None:
        self.client = connection_type is ConnectionType.CLIENT
        self._state = ConnectionState.CONNECTING

        self._connection: Connection | None = None
        self._events: deque[Event] = deque()
        self._initiating_request: Request | None = None

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def connection(self) -> Connection | None:
        """
        Return the established connection.

        This will either return the connection or None if the
        connection has not yet been established.
        """
        return self._connection

    def initiate_upgrade_connection(self, headers: Headers) -> None:
        """
        Initiate an upgrade connection.

        This should be used if the request headers have already been
        received and parsed, for example from a HTTP/2 HEADERS frame.

        :param list headers: HTTP headers represented as a list of 2-tuples,
            including the ``:method``, ``:protocol``, ``:scheme``,
            ``:authority`` and ``:path`` pseudo-headers.
        """
        if self.client:
            msg = "Cannot initiate an upgrade connection when acting as the client"
            raise LocalProtocolError(
                msg,
            )
        self._events.append(self._process_connection_request(headers))

    def send(self, event: Event) -> Headers | bytes:
        """
        Generate the data to send for the specified event.

        For :class:`~wsproto.events.Request`,
        :class:`~wsproto.events.AcceptConnection` and
        :class:`~wsproto.events.RejectConnection` events this returns
        the HTTP/2 headers (including pseudo-headers) to send in a
        HEADERS frame. For :class:`~wsproto.events.RejectData` events
        this returns the response body bytes to send in DATA frames.

        :returns: Headers or data to send to the WebSocket peer.
        """
        if isinstance(event, Request):
            return self._initiate_connection(event)
        if isinstance(event, AcceptConnection):
            return self._accept(event)
        if isinstance(event, RejectConnection):
            return self._reject(event)
        if isinstance(event, RejectData):
            return self._send_reject_data(event)
        msg = f"Event {event} cannot be sent during the handshake"
        raise LocalProtocolError(
            msg,
        )

    def receive_headers(self, headers: Headers) -> None:
        """
        Process response headers received from the remote peer.

        This should be called with the headers of a HTTP/2 HEADERS
        frame received in response to the connection request. Any
        resulting events can be retrieved with :meth:`events`.

        :param list headers: HTTP headers represented as a list of 2-tuples,
            including the ``:status`` pseudo-header.
        """
        if not self.client:
            msg = "Cannot receive response headers when acting as the server"
            raise LocalProtocolError(
                msg,
            )
        if self._state is not ConnectionState.CONNECTING:
            msg = f"Cannot receive response headers in state {self._state}"
            raise LocalProtocolError(
                msg,
            )
        self._process_response_headers(headers)

    def receive_data(self, data: bytes | None) -> None:
        """
        Receive DATA frame payload from the remote peer.

        Once the connection is established the data is WebSocket frame
        data and is passed on to the connection. Whilst the connection
        is being rejected the data is response body data. Passing None
        indicates that the stream has ended.

        :param bytes data: Data received from the WebSocket peer.
        """
        if self._connection is not None:
            self._connection.receive_data(data)
        elif self._state is ConnectionState.REJECTING:
            if data is None:
                self._events.append(RejectData(data=b"", body_finished=True))
                self._state = ConnectionState.CLOSED
            else:
                self._events.append(RejectData(data=data, body_finished=False))
        elif data is None:
            self._state = ConnectionState.CLOSED
        else:
            msg = f"Cannot receive data in state {self._state}"
            raise LocalProtocolError(
                msg,
            )

    def events(self) -> Generator[Event, None, None]:
        """
        Return a generator that provides any events that have been generated
        by protocol activity.

        :returns: a generator that yields events.
        """
        while self._events:
            yield self._events.popleft()
        if self._connection is not None:
            yield from self._connection.events()

    # Server mode methods

    def _process_connection_request(self, headers: Headers) -> Request:
        pseudo_headers: dict[bytes, bytes] = {}
        extensions: list[str] = []
        subprotocols: list[str] = []
        extra_headers: Headers = []
        seen_regular_header = False
        for name, value in headers:
            if name.startswith(b":"):
                if seen_regular_header:
                    msg = f"Pseudo-header {name!r} sent after a regular header"
                    raise RemoteProtocolError(
                        msg, event_hint=RejectConnection(),
                    )
                if name in pseudo_headers:
                    msg = f"Duplicate pseudo-header {name!r}"
                    raise RemoteProtocolError(
                        msg, event_hint=RejectConnection(),
                    )
                if name not in H2_REQUEST_PSEUDO_HEADERS:
                    msg = f"Unexpected pseudo-header {name!r}"
                    raise RemoteProtocolError(
                        msg, event_hint=RejectConnection(),
                    )
                pseudo_headers[name] = value
                continue
            seen_regular_header = True
            name = name.lower()
            if name in H2_FORBIDDEN_HEADERS:
                msg = f"Connection-specific header {name!r} is not allowed"
                raise RemoteProtocolError(
                    msg, event_hint=RejectConnection(),
                )
            if name == b"te" and value.strip() != b"trailers":
                msg = "Only the 'TE: trailers' header is allowed"
                raise RemoteProtocolError(
                    msg, event_hint=RejectConnection(),
                )
            if name == b"sec-websocket-protocol":
                subprotocols.extend(split_comma_header(value))
                continue  # Skip appending to headers
            if name == b"sec-websocket-extensions":
                extensions.extend(split_comma_header(value))
                continue  # Skip appending to headers
            extra_headers.append((name, value))

        if pseudo_headers.get(b":method") != b"CONNECT":
            msg = "Request method must be CONNECT"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        if pseudo_headers.get(b":protocol") != H2_WEBSOCKET_PROTOCOL:
            msg = f"Missing pseudo-header, ':protocol: {H2_WEBSOCKET_PROTOCOL.decode()}'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        scheme = pseudo_headers.get(b":scheme")
        if not scheme:
            msg = "Missing pseudo-header, ':scheme'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        authority = pseudo_headers.get(b":authority")
        if not authority:
            msg = "Missing pseudo-header, ':authority'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        path = pseudo_headers.get(b":path")
        if not path:
            msg = "Missing pseudo-header, ':path'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )

        self._initiating_request = Request(
            extensions=extensions,
            extra_headers=extra_headers,
            host=authority.decode("idna"),
            subprotocols=subprotocols,
            target=path.decode("ascii"),
        )
        return self._initiating_request

    def _accept(self, event: AcceptConnection) -> Headers:
        # _accept is always called after _process_connection_request.
        assert self._initiating_request is not None

        headers: Headers = [(b":status", b"200")]

        if event.subprotocol is not None:
            if event.subprotocol not in self._initiating_request.subprotocols:
                msg = f"unexpected subprotocol {event.subprotocol}"
                raise LocalProtocolError(msg)
            headers.append(
                (b"sec-websocket-protocol", event.subprotocol.encode("ascii")),
            )

        if event.extensions:
            accepts = server_extensions_handshake(
                cast("Sequence[str]", self._initiating_request.extensions),
                event.extensions,
            )
            if accepts:
                headers.append((b"sec-websocket-extensions", accepts))

        self._connection = Connection(
            ConnectionType.CLIENT if self.client else ConnectionType.SERVER,
            event.extensions,
        )
        self._state = ConnectionState.OPEN
        return headers + event.extra_headers

    def _reject(self, event: RejectConnection) -> Headers:
        if self.state != ConnectionState.CONNECTING:
            msg = f"Connection cannot be rejected in state {self.state}"
            raise LocalProtocolError(
                msg,
            )

        headers: Headers = [(b":status", str(event.status_code).encode("ascii"))]
        headers += event.headers
        self._state = ConnectionState.REJECTING
        if not event.has_body:
            self._state = ConnectionState.CLOSED
        return headers

    def _send_reject_data(self, event: RejectData) -> bytes:
        if self.state != ConnectionState.REJECTING:
            msg = f"Cannot send rejection data in state {self.state}"
            raise LocalProtocolError(
                msg,
            )
        if event.body_finished:
            self._state = ConnectionState.CLOSED
        return event.data

    # Client mode methods

    def _initiate_connection(self, request: Request) -> Headers:
        if not self.client:
            msg = "Cannot initiate a connection request when acting as the server"
            raise LocalProtocolError(
                msg,
            )
        self._initiating_request = request

        headers: Headers = [
            (b":method", b"CONNECT"),
            (b":protocol", H2_WEBSOCKET_PROTOCOL),
            (b":scheme", b"https"),
            (b":authority", request.host.encode("idna")),
            (b":path", request.target.encode("ascii")),
        ]

        if request.subprotocols:
            headers.append(
                (
                    b"sec-websocket-protocol",
                    (", ".join(request.subprotocols)).encode("ascii"),
                ),
            )

        offers = client_extension_offers(
            cast("Sequence[Extension]", request.extensions),
        )
        if offers:
            headers.append((b"sec-websocket-extensions", b", ".join(offers)))

        return headers + request.extra_headers

    def _process_response_headers(self, headers: Headers) -> None:
        # _process_response_headers is always called after _initiate_connection.
        assert self._initiating_request is not None

        status_code: int | None = None
        accepts: list[str] = []
        subprotocol = None
        extra_headers: Headers = []
        seen_regular_header = False
        for name, value in headers:
            if name.startswith(b":"):
                if seen_regular_header:
                    msg = f"Pseudo-header {name!r} sent after a regular header"
                    raise RemoteProtocolError(
                        msg, event_hint=RejectConnection(),
                    )
                if name != b":status" or status_code is not None:
                    msg = f"Unexpected pseudo-header {name!r}"
                    raise RemoteProtocolError(
                        msg, event_hint=RejectConnection(),
                    )
                if not value.isdigit():
                    msg = f"Invalid ':status' pseudo-header value {value!r}"
                    raise RemoteProtocolError(
                        msg, event_hint=RejectConnection(),
                    )
                status_code = int(value)
                continue
            seen_regular_header = True
            name = name.lower()
            if name == b"sec-websocket-protocol":
                subprotocol = value.decode("ascii")
                continue  # Skip appending to headers
            if name == b"sec-websocket-extensions":
                accepts.extend(split_comma_header(value))
                continue  # Skip appending to headers
            extra_headers.append((name, value))

        if status_code is None:
            msg = "Missing pseudo-header, ':status'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )

        # RFC 8441 - A 2xx response indicates a successful handshake.
        if not 200 <= status_code < 300:
            self._state = ConnectionState.REJECTING
            self._events.append(
                RejectConnection(
                    headers=extra_headers,
                    status_code=status_code,
                    has_body=True,
                ),
            )
            return

        if subprotocol is not None and subprotocol not in self._initiating_request.subprotocols:
            msg = f"unrecognized subprotocol {subprotocol}"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(),
            )
        extensions = client_extensions_handshake(
            accepts, cast("Sequence[Extension]", self._initiating_request.extensions),
        )

        self._connection = Connection(
            ConnectionType.CLIENT if self.client else ConnectionType.SERVER,
            extensions,
        )
        self._state = ConnectionState.OPEN
        self._events.append(
            AcceptConnection(
                extensions=extensions,
                extra_headers=extra_headers,
                subprotocol=subprotocol,
            ),
        )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(client={self.client}, state={self.state})"


def client_extension_offers(extensions: Sequence[Extension]) -> list[bytes]:
    """
    Build the Sec-WebSocket-Extensions offer header values.

    This returns a list of header value components, one per offered
    extension, or an empty list if no extension makes an offer.
    """
    offers: dict[str, str | bool] = {}
    for extension in extensions:
        assert isinstance(extension, Extension)
        offers[extension.name] = extension.offer()
    values = []
    for name, params in offers.items():
        name_bytes = name.encode("ascii")
        if isinstance(params, bool):
            if params:
                values.append(name_bytes)
        else:
            values.append(b"%s; %s" % (name_bytes, params.encode("ascii")))
    return values


def server_extensions_handshake(
    requested: Iterable[str], supported: list[Extension],
) -> bytes | None:
    """
    Agree on the extensions to use returning an appropriate header value.

    This returns None if there are no agreed extensions
    """
    accepts: dict[str, bool | bytes] = {}
    for offer in requested:
        name = offer.split(";", 1)[0].strip()
        for extension in supported:
            if extension.name == name:
                accept = extension.accept(offer)
                if isinstance(accept, bool):
                    if accept:
                        accepts[extension.name] = True
                elif accept is not None:
                    accepts[extension.name] = accept.encode("ascii")

    if accepts:
        extensions: list[bytes] = []
        for name, params in accepts.items():
            name_bytes = name.encode("ascii")
            if isinstance(params, bool):
                assert params
                extensions.append(name_bytes)
            elif params == b"":
                extensions.append(b"%s" % (name_bytes))
            else:
                extensions.append(b"%s; %s" % (name_bytes, params))
        return b", ".join(extensions)

    return None


def client_extensions_handshake(
    accepted: Iterable[str], supported: Sequence[Extension],
) -> list[Extension]:
    # This raises RemoteProtocolError is the accepted extension is not
    # supported.
    extensions = []
    for accept in accepted:
        name = accept.split(";", 1)[0].strip()
        for extension in supported:
            if extension.name == name:
                extension.finalize(accept)
                extensions.append(extension)
                break
        else:
            msg = f"unrecognized extension {name}"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
    return extensions
