"""
wsproto
~~~~~~~

A WebSocket implementation.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .connection import Connection, ConnectionState, ConnectionType
from .handshake import H11Handshake, H2Handshake

if TYPE_CHECKING:
    from collections.abc import Generator

    from .events import Event
    from .handshake import Handshake
    from .typing import Headers

__version__ = "1.3.2"


class WSConnection:
    """
    Represents the local end of a WebSocket connection to a remote peer.
    """

    def __init__(
        self,
        connection_type: ConnectionType | Handshake,
    ) -> None:
        """
        Constructor

        :param wsproto.connection.ConnectionType connection_type: Controls
            whether the library behaves as a client or as a server.
            An existing handshake instance may also be passed, which is how
            an RFC 8441 WebSocket-over-HTTP/2 connection is created, e.g.
            ``WSConnection(H2Handshake(ConnectionType.CLIENT))``.
        """
        if isinstance(connection_type, (H11Handshake, H2Handshake)):
            self.client = connection_type.client
            self.handshake = connection_type
        else:
            self.client = connection_type is ConnectionType.CLIENT
            self.handshake = H11Handshake(connection_type)
        self.connection: Connection | None = None

    @property
    def state(self) -> ConnectionState:
        """
        :returns: Connection state
        :rtype: wsproto.connection.ConnectionState
        """
        if self.connection is None:
            return self.handshake.state
        return self.connection.state

    def initiate_upgrade_connection(
        self, headers: Headers, path: bytes | str,
    ) -> None:
        self.handshake.initiate_upgrade_connection(headers, path)

    def send(self, event: Event) -> Any:
        """
        Generate network data for the specified event.

        When you want to communicate with a WebSocket peer, you should construct
        an event and pass it to this method. This method will return the bytes
        that you should send to the peer. During an RFC 8441 HTTP/2 handshake
        this is instead the header block (a list of ``(name, value)`` tuples)
        to place on the outbound HEADERS frame.

        :param wsproto.events.Event event: The event to generate data for
        :returns bytes: The data to send to the peer
        """
        data: Any
        if self.connection is None:
            data = self.handshake.send(event)
            self.connection = self.handshake.connection
        else:
            data = self.connection.send(event)
        return data

    def receive_data(self, data: Any) -> None:
        """
        Feed network data into the connection instance.

        After calling this method, you should call :meth:`events` to see if the
        received data triggered any new events.

        :param data: Data received from the remote peer. For an HTTP/1.1
            handshake this is raw bytes; for an RFC 8441 HTTP/2 handshake
            this is an h2 event (``RequestReceived``, ``ResponseReceived``,
            ``DataReceived`` or ``StreamEnded``) or the plain tuple/list
            equivalents accepted by :class:`~wsproto.handshake.H2Handshake`.
        """
        if self.connection is None:
            self.handshake.receive_data(data)
            self.connection = self.handshake.connection
        elif isinstance(self.handshake, H2Handshake):
            # With HTTP/2 the established WebSocket connection receives
            # DATA payloads wrapped as h2 events; the handshake forwards them
            # to the frame protocol.
            self.handshake.receive_data(data)
        else:
            self.connection.receive_data(data)

    def events(self) -> Generator[Event, None, None]:
        """
        A generator that yields pending events.

        Each event is an instance of a subclass of
        :class:`wsproto.events.Event`.
        """
        yield from self.handshake.events()
        if self.connection is not None:
            yield from self.connection.events()


__all__ = ("ConnectionType", "H2Handshake", "WSConnection")
