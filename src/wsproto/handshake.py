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
    from typing import Union

    from .typing import Headers

    # h2 event objects, the plain tuple/list equivalents documented on
    # H2Handshake, or raw WebSocket bytes.
    EventData = Union[object, bytes, tuple, list]

    Handshake = Union[H11Handshake, H2Handshake]

# RFC6455, Section 4.2.1/6 - Reading the Client's Opening Handshake
WEBSOCKET_VERSION = b"13"

# RFC6455, Section 4.2.1/3 - Value of the Upgrade header
WEBSOCKET_UPGRADE = b"websocket"

# RFC8441, Section 5 - The value of the :protocol pseudo-header
WEBSOCKET_PROTOCOL = b"websocket"

# RFC8441, Section 5 - HTTP/2 header fields that are not allowed on the
# extended CONNECT request for WebSocket bootstrapping.
H2_FORBIDDEN_HEADERS = frozenset(
    {
        b"connection",
        b"keep-alive",
        b"proxy-connection",
        b"transfer-encoding",
        b"upgrade",
    },
)

# The HTTP/2 pseudo-headers that are valid on an RFC8441 CONNECT request.
H2_REQUEST_PSEUDO_HEADERS = frozenset(
    {b":authority", b":method", b":path", b":protocol", b":scheme"},
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

        if request.extensions:
            offers: dict[str, str | bool] = {}
            for e in request.extensions:
                assert isinstance(e, Extension)
                offers[e.name] = e.offer()
            extensions = []
            for name, params in offers.items():
                bname = name.encode("ascii")
                if isinstance(params, bool):
                    if params:
                        extensions.append(bname)
                else:
                    extensions.append(b"%s; %s" % (bname, params.encode("ascii")))
            if extensions:
                headers.append((b"Sec-WebSocket-Extensions", b", ".join(extensions)))

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
    A Handshake implementation for RFC 8441 WebSockets over HTTP/2.

    Unlike :class:`H11Handshake`, this does not establish a network
    connection, parse the HTTP/2 wire protocol or implement HTTP/2 flow
    control. Instead, the caller uses an HTTP/2 implementation (such as
    hyper-h2) and feeds the inbound header blocks, DATA payloads and
    stream-end notifications into :meth:`receive_data`. The headers to put
    on the outbound HEADERS frame are returned by :meth:`send`.

    Inbound events may be supplied either as h2 event objects (``RequestReceived``,
    ``ResponseReceived``, ``DataReceived`` and ``StreamEnded``) or as plain
    tuples/lists: ``[(b":method", b"CONNECT"), ...]`` for a header block,
    ``(b"DATA", payload)`` for a DATA payload and ``(b"END",)`` for a stream
    end.

    Once the handshake has completed, :attr:`connection` holds the same
    :class:`~wsproto.connection.Connection` used for HTTP/1.1 and the WebSocket
    frame handling is identical.
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

        This is ``None`` until the extended CONNECT handshake has completed.
        """
        return self._connection

    def initiate_upgrade_connection(
        self, headers: Headers, path: bytes | str,
    ) -> None:
        """
        The extended CONNECT handshake is bootstrapped from the HTTP/2
        header block; there is no HTTP/1.1 style Upgrade request to replay.
        """
        msg = "Cannot initiate an upgrade connection over HTTP/2"
        raise LocalProtocolError(
            msg,
        )

    def send(self, event: Event) -> Headers | bytes:
        """
        Send an event to the remote.

        :class:`Request`, :class:`AcceptConnection` and
        :class:`RejectConnection` events return the header block (a list of
        ``(name, value)`` byte tuples) to place on the outbound HTTP/2
        HEADERS frame. :class:`RejectData` and post-handshake events return
        the raw bytes to place on outbound DATA frames.

        :returns: Data to send to the WebSocket peer.
        """
        if self._connection is not None:
            return self._connection.send(event)

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

    def receive_data(
        self, event: EventData | None,
    ) -> None:
        """
        Receive an HTTP/2 event or raw WebSocket data from the remote.

        A list of events that the remote peer triggered can be retrieved with
        :meth:`events`.
        """
        kind, value, stream_ended = self._coerce_event(event)

        if event is None:
            if self._connection is not None:
                self._connection.receive_data(None)
            else:
                msg = "Stream ended before the WebSocket handshake completed"
                raise RemoteProtocolError(
                    msg, event_hint=RejectConnection(),
                )
            return

        if self._connection is not None:
            # The handshake is over; only DATA frames carrying WebSocket
            # frames are meaningful. Any trailing headers or stream-end
            # notifications are ignored (or reported via receive_data(None)
            # if the transport itself is lost).
            if kind == "DATA":
                self._connection.receive_data(value)
            return

        if kind == "HEADERS":
            if self.client:
                self._process_response(value, stream_ended)
            else:
                self._events.append(self._process_connection_request(value))
        elif kind == "DATA":
            if self._state is ConnectionState.REJECTING:
                self._events.append(
                    RejectData(data=value, body_finished=stream_ended),
                )
                if stream_ended:
                    self._events.append(RejectData(data=b"", body_finished=True))
                    self._state = ConnectionState.CLOSED
            else:
                msg = "DATA frame received before the WebSocket handshake completed"
                raise RemoteProtocolError(
                    msg, event_hint=RejectConnection(),
                )
        elif kind == "END":
            if self._state is ConnectionState.REJECTING:
                self._events.append(RejectData(data=b"", body_finished=True))
                self._state = ConnectionState.CLOSED
            elif self._state is ConnectionState.CONNECTING:
                msg = "Stream ended before the WebSocket handshake completed"
                raise RemoteProtocolError(
                    msg, event_hint=RejectConnection(),
                )

    def events(self) -> Generator[Event, None, None]:
        """
        Return a generator that provides any events that have been generated
        by protocol activity.
        """
        while self._events:
            yield self._events.popleft()

    # Server mode methods

    def _process_connection_request(self, raw_headers: Headers) -> Request:
        pseudo_headers, headers = self._split_request_pseudo_headers(raw_headers)

        if pseudo_headers[b":method"] != b"CONNECT":
            msg = "Pseudo-header ':method' must be CONNECT"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        if pseudo_headers[b":protocol"] != WEBSOCKET_PROTOCOL:
            msg = "Pseudo-header ':protocol' must be websocket"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        authority = pseudo_headers[b":authority"]
        path = pseudo_headers[b":path"]

        extensions: list[str] = []
        subprotocols: list[str] = []
        extra_headers: Headers = []
        for name, value in headers:
            if name == b"sec-websocket-extensions":
                extensions.extend(split_comma_header(value))
            elif name == b"sec-websocket-protocol":
                subprotocols.extend(split_comma_header(value))
            else:
                extra_headers.append((name, value))

        self._initiating_request = Request(
            extensions=extensions,
            extra_headers=extra_headers,
            host=self._authority_to_host(authority),
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

        headers.extend(event.extra_headers)

        self._connection = Connection(
            ConnectionType.CLIENT if self.client else ConnectionType.SERVER,
            event.extensions,
        )
        self._state = ConnectionState.OPEN
        return headers

    def _reject(self, event: RejectConnection) -> Headers:
        if self.state != ConnectionState.CONNECTING:
            msg = f"Connection cannot be rejected in state {self.state}"
            raise LocalProtocolError(
                msg,
            )

        headers: Headers = [(b":status", str(event.status_code).encode("ascii"))]
        headers.extend(event.headers)
        if not event.has_body:
            self._state = ConnectionState.CLOSED
        else:
            self._state = ConnectionState.REJECTING
        return headers

    def _send_reject_data(self, event: RejectData) -> bytes:
        if self.state != ConnectionState.REJECTING:
            msg = f"Cannot send rejection data in state {self.state}"
            raise LocalProtocolError(
                msg,
            )
        if event.body_finished:
            self._state = ConnectionState.CLOSED
        return bytes(event.data)

    # Client mode methods

    def _initiate_connection(self, request: Request) -> Headers:
        self._initiating_request = request

        headers: Headers = [
            (b":method", b"CONNECT"),
            (b":protocol", WEBSOCKET_PROTOCOL),
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

        if request.extensions:
            offers: dict[str, str | bool] = {}
            for e in request.extensions:
                assert isinstance(e, Extension)
                offers[e.name] = e.offer()
            extension_headers = []
            for name, params in offers.items():
                bname = name.encode("ascii")
                if isinstance(params, bool):
                    if params:
                        extension_headers.append(bname)
                else:
                    extension_headers.append(b"%s; %s" % (bname, params.encode("ascii")))
            if extension_headers:
                headers.append(
                    (b"sec-websocket-extensions", b", ".join(extension_headers)),
                )

        headers.extend(request.extra_headers)
        return headers

    def _process_response(
        self, raw_headers: Headers, stream_ended: bool,
    ) -> None:
        pseudo_headers, headers = self._split_response_pseudo_headers(raw_headers)

        try:
            status_code = int(pseudo_headers[b":status"])
        except ValueError:
            msg = "Invalid pseudo-header ':status'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )

        if not 200 <= status_code < 300:
            # RFC8441 requires a 2xx status code (typically 200); 101 and the
            # HTTP/1.1 Upgrade semantics are never used over HTTP/2.
            self._events.append(
                RejectConnection(
                    headers=headers,
                    status_code=status_code,
                    has_body=not stream_ended,
                ),
            )
            if stream_ended:
                self._state = ConnectionState.CLOSED
            else:
                self._state = ConnectionState.REJECTING
            return

        if stream_ended:
            # RFC8441 section 5: the 2xx response MUST NOT include the
            # END_STREAM flag, since the stream is reused for the frames.
            msg = "Successful WebSocket response must not end the HTTP/2 stream"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )

        accepts: list[str] = []
        subprotocol = None
        extra_headers: Headers = []
        for name, value in headers:
            if name == b"sec-websocket-extensions":
                accepts = split_comma_header(value)
            elif name == b"sec-websocket-protocol":
                subprotocol = value.decode("ascii")
            else:
                extra_headers.append((name, value))

        assert self._initiating_request is not None
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

    # Helpers

    def _split_request_pseudo_headers(
        self, raw_headers: Headers,
    ) -> tuple[dict[bytes, bytes], Headers]:
        pseudo_headers, headers = self._split_pseudo_headers(raw_headers)
        for required_name in (
            b":method",
            b":protocol",
            b":scheme",
            b":authority",
            b":path",
        ):
            if required_name not in pseudo_headers:
                msg = (
                    "Missing pseudo-header "
                    f"{required_name.decode('ascii', 'replace')}"
                )
                raise RemoteProtocolError(
                    msg, event_hint=RejectConnection(),
                )
        return pseudo_headers, headers

    def _split_response_pseudo_headers(
        self, raw_headers: Headers,
    ) -> tuple[dict[bytes, bytes], Headers]:
        pseudo_headers, headers = self._split_pseudo_headers(
            raw_headers,
            allowed_pseudo_headers={b":status"},
            reject_forbidden_headers=False,
        )
        if b":status" not in pseudo_headers:
            msg = "Missing pseudo-header :status"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        return pseudo_headers, headers

    def _split_pseudo_headers(
        self,
        raw_headers: Headers,
        allowed_pseudo_headers: frozenset[bytes] = H2_REQUEST_PSEUDO_HEADERS,
        reject_forbidden_headers: bool = True,
    ) -> tuple[dict[bytes, bytes], Headers]:
        pseudo_headers: dict[bytes, bytes] = {}
        headers: Headers = []
        seen_regular = False

        for raw_name, raw_value in raw_headers:
            try:
                name = bytes(raw_name).lower()
                value = bytes(raw_value)
            except (TypeError, ValueError) as exc:
                msg = "Invalid HTTP/2 header block"
                raise RemoteProtocolError(
                    msg, event_hint=RejectConnection(),
                ) from exc

            if name.startswith(b":"):
                if seen_regular:
                    msg = "Pseudo-headers must precede regular header fields"
                    raise RemoteProtocolError(
                        msg, event_hint=RejectConnection(),
                    )
                if name not in allowed_pseudo_headers:
                    msg = f"Unexpected pseudo-header {name.decode('ascii', 'replace')}"
                    raise RemoteProtocolError(
                        msg, event_hint=RejectConnection(),
                    )
                if name in pseudo_headers:
                    msg = f"Duplicate pseudo-header {name.decode('ascii', 'replace')}"
                    raise RemoteProtocolError(
                        msg, event_hint=RejectConnection(),
                    )
                pseudo_headers[name] = value
            else:
                seen_regular = True
                if reject_forbidden_headers and name in H2_FORBIDDEN_HEADERS:
                    msg = (
                        f"HTTP/2 header field {name.decode('ascii', 'replace')} "
                        "is not allowed on a WebSocket CONNECT request"
                    )
                    raise RemoteProtocolError(
                        msg, event_hint=RejectConnection(),
                    )
                if (
                    reject_forbidden_headers
                    and name == b"te"
                    and value.lower().strip() != b"trailers"
                ):
                    msg = "The TE header field may only contain 'trailers'"
                    raise RemoteProtocolError(
                        msg, event_hint=RejectConnection(),
                    )
                headers.append((name, value))
        return pseudo_headers, headers

    @staticmethod
    def _authority_to_host(authority: bytes) -> str:
        # Strip the port (and IPv6 brackets) before IDNA decoding, since the
        # idna codec rejects the ':' separator.
        host = authority
        if host.startswith(b"["):
            host = host[1:].split(b"]", 1)[0]
        else:
            host = host.rsplit(b":", 1)[0]
        try:
            return host.decode("idna")
        except UnicodeError:
            return host.decode("ascii")

    def _coerce_event(
        self, event: EventData,
    ) -> tuple[str, Headers | bytes, bool]:
        if event is None:
            return ("END", b"", True)

        if isinstance(event, (bytes, bytearray)):
            return ("DATA", bytes(event), False)

        headers = getattr(event, "headers", None)
        if headers is not None:
            stream_ended = getattr(event, "stream_ended", False)
            return ("HEADERS", list(headers), bool(stream_ended))

        data = getattr(event, "data", None)
        if data is not None:
            stream_ended = getattr(event, "stream_ended", False)
            return ("DATA", bytes(data), bool(stream_ended))

        # An object with neither headers nor data is treated as a stream-end
        # notification (e.g. h2.events.StreamEnded).
        if not isinstance(event, (tuple, list)):
            return ("END", b"", True)

        if isinstance(event, tuple):
            if not event:
                msg = "Unsupported HTTP/2 event ()"
                raise LocalProtocolError(msg)
            tag = event[0]
            if tag == "DATA" or (isinstance(tag, bytes) and tag == b"DATA"):
                return ("DATA", bytes(event[1]), bool(event[2]) if len(event) > 2 else False)
            if tag == "END" or (isinstance(tag, bytes) and tag == b"END"):
                return ("END", b"", True)
            # Assume it is a header block of (name, value) tuples.
            return ("HEADERS", list(event), False)

        if isinstance(event, list):
            return ("HEADERS", list(event), False)

        msg = f"Unsupported HTTP/2 event {event}"
        raise LocalProtocolError(msg)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(client={self.client}, state={self.state})"


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
