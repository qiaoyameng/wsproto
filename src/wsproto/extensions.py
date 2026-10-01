"""
wsproto/extensions
~~~~~~~~~~~~~~~~~~

WebSocket extensions.
"""
from __future__ import annotations

import zlib
from abc import ABC, abstractmethod
from typing import NamedTuple, Optional

from .frame_protocol import CloseReason, FrameDecoder, FrameProtocol, Opcode, RsvBits


class _PerMessageDeflateParameters(NamedTuple):
    client_no_context_takeover: bool
    server_no_context_takeover: bool
    client_max_window_bits: int | None
    server_max_window_bits: int | None
    client_max_window_bits_without_value: bool


class Extension(ABC):
    name: str
    strict_negotiation = False

    def enabled(self) -> bool:
        return False

    @abstractmethod
    def offer(self) -> bool | str:
        pass

    def accept(self, offer: str) -> bool | str | None:
        pass

    def finalize(self, offer: str) -> None:
        pass

    def frame_inbound_header(
        self,
        proto: FrameDecoder | FrameProtocol,
        opcode: Opcode,
        rsv: RsvBits,
        payload_length: int,
    ) -> CloseReason | RsvBits:
        return RsvBits(False, False, False)

    def frame_inbound_payload_data(
        self, proto: FrameDecoder | FrameProtocol, data: bytes,
    ) -> bytes | CloseReason:
        return data

    def frame_inbound_complete(
        self, proto: FrameDecoder | FrameProtocol, fin: bool,
    ) -> bytes | CloseReason | None:
        pass

    def frame_outbound(
        self,
        proto: FrameDecoder | FrameProtocol,
        opcode: Opcode,
        rsv: RsvBits,
        data: bytes,
        fin: bool,
    ) -> tuple[RsvBits, bytes]:
        return (rsv, data)


class PerMessageDeflate(Extension):
    name = "permessage-deflate"

    DEFAULT_CLIENT_MAX_WINDOW_BITS = 15
    DEFAULT_SERVER_MAX_WINDOW_BITS = 15

    def __init__(
        self,
        client_no_context_takeover: bool = False,
        client_max_window_bits: int | None = None,
        server_no_context_takeover: bool = False,
        server_max_window_bits: int | None = None,
        strict_negotiation: bool = False,
        strict: bool | None = None,
    ) -> None:
        if strict is not None:
            strict_negotiation = strict
        self.client_no_context_takeover = client_no_context_takeover
        self.server_no_context_takeover = server_no_context_takeover
        self.strict_negotiation = strict_negotiation
        self._client_max_window_bits = self.DEFAULT_CLIENT_MAX_WINDOW_BITS
        self._server_max_window_bits = self.DEFAULT_SERVER_MAX_WINDOW_BITS
        if client_max_window_bits is not None:
            self.client_max_window_bits = client_max_window_bits
        if server_max_window_bits is not None:
            self.server_max_window_bits = server_max_window_bits

        self._compressor: Optional[zlib._Compress] = None  # noqa
        self._decompressor: Optional[zlib._Decompress] = None  # noqa
        # This refers to the current frame
        self._inbound_is_compressible: bool | None = None
        # This refers to the ongoing message (which might span multiple
        # frames). Only the first frame in a fragmented message is flagged for
        # compression, so this carries that bit forward.
        self._inbound_compressed: bool | None = None

        self._enabled = False

    @property
    def client_max_window_bits(self) -> int:
        return self._client_max_window_bits

    @client_max_window_bits.setter
    def client_max_window_bits(self, value: int) -> None:
        if value < 9 or value > 15:
            msg = "Window size must be between 9 and 15 inclusive"
            raise ValueError(msg)
        self._client_max_window_bits = value

    @property
    def server_max_window_bits(self) -> int:
        return self._server_max_window_bits

    @server_max_window_bits.setter
    def server_max_window_bits(self, value: int) -> None:
        if value < 9 or value > 15:
            msg = "Window size must be between 9 and 15 inclusive"
            raise ValueError(msg)
        self._server_max_window_bits = value

    def _compressible_opcode(self, opcode: Opcode) -> bool:
        return opcode in (Opcode.TEXT, Opcode.BINARY, Opcode.CONTINUATION)

    def enabled(self) -> bool:
        return self._enabled

    def offer(self) -> bool | str:
        parameters = [
            f"client_max_window_bits={self.client_max_window_bits}",
            f"server_max_window_bits={self.server_max_window_bits}",
        ]

        if self.client_no_context_takeover:
            parameters.append("client_no_context_takeover")
        if self.server_no_context_takeover:
            parameters.append("server_no_context_takeover")

        return "; ".join(parameters)

    def _parse_params(
        self,
        params: str,
        *,
        allow_client_max_window_bits_without_value: bool = False,
    ) -> _PerMessageDeflateParameters:
        bits = [b.strip() for b in params.split(";")]

        if bits[0] != self.name:
            msg = (
                f"invalid {self.name} extension name: expected {self.name}, "
                f"got {bits[0]!r}"
            )
            raise ValueError(msg)

        client_no_context_takeover = False
        server_no_context_takeover = False
        client_max_window_bits: int | None = None
        server_max_window_bits: int | None = None
        client_max_window_bits_without_value = False

        seen: set[str] = set()
        for bit in bits[1:]:
            if not bit:
                msg = f"empty parameter in {self.name} extension offer"
                raise ValueError(msg)

            name, has_value, value = bit.partition("=")
            if name in seen:
                msg = f"duplicate {self.name} parameter {name!r}"
                raise ValueError(msg)

            if name in (
                "client_no_context_takeover",
                "server_no_context_takeover",
                "client_max_window_bits",
                "server_max_window_bits",
            ):
                seen.add(name)
            else:
                msg = f"unknown {self.name} parameter {name!r}"
                raise ValueError(msg)

            if name in ("client_no_context_takeover", "server_no_context_takeover"):
                if has_value:
                    msg = f"{self.name} parameter {name!r} must not have a value"
                    raise ValueError(msg)
                if name == "client_no_context_takeover":
                    client_no_context_takeover = True
                else:
                    server_no_context_takeover = True
                continue

            if not has_value:
                if (
                    name == "client_max_window_bits"
                    and allow_client_max_window_bits_without_value
                ):
                    client_max_window_bits_without_value = True
                else:
                    msg = f"{self.name} parameter {name!r} must have a value"
                    raise ValueError(msg)
                continue

            if not value or not value.isdigit():
                msg = (
                    f"{self.name} parameter {name!r} must be an integer between "
                    f"9 and 15, got {value!r}"
                )
                raise ValueError(msg)

            window_bits = int(value)
            if window_bits < 9 or window_bits > 15:
                msg = (
                    f"{self.name} parameter {name!r} must be between 9 and 15 "
                    f"inclusive, got {window_bits}"
                )
                raise ValueError(msg)

            if name == "client_max_window_bits":
                client_max_window_bits = window_bits
            else:
                server_max_window_bits = window_bits

        return _PerMessageDeflateParameters(
            client_no_context_takeover=client_no_context_takeover,
            server_no_context_takeover=server_no_context_takeover,
            client_max_window_bits=client_max_window_bits,
            server_max_window_bits=server_max_window_bits,
            client_max_window_bits_without_value=(
                client_max_window_bits_without_value
            ),
        )

    def _parse_legacy_params(self, params: str) -> tuple[int | None, int | None]:
        client_max_window_bits = None
        server_max_window_bits = None

        bits = [b.strip() for b in params.split(";")]
        for bit in bits[1:]:
            if bit.startswith("client_no_context_takeover"):
                self.client_no_context_takeover = True
            elif bit.startswith("server_no_context_takeover"):
                self.server_no_context_takeover = True
            elif bit.startswith("client_max_window_bits"):
                if "=" in bit:
                    client_max_window_bits = int(bit.split("=", 1)[1].strip())
                else:
                    client_max_window_bits = self.client_max_window_bits
            elif bit.startswith("server_max_window_bits"):
                if "=" in bit:
                    server_max_window_bits = int(bit.split("=", 1)[1].strip())
                else:
                    server_max_window_bits = self.server_max_window_bits

        return client_max_window_bits, server_max_window_bits

    def finalize(self, offer: str) -> None:
        if self.strict_negotiation:
            parsed = self._parse_params(offer)
            offered = self._parse_params(
                f"{self.name}; {self.offer()}",
                allow_client_max_window_bits_without_value=True,
            )

            if (
                parsed.client_no_context_takeover
                and not offered.client_no_context_takeover
            ):
                msg = (
                    f"server accepted {self.name} parameter "
                    "'client_no_context_takeover' that was not offered"
                )
                raise ValueError(msg)
            if (
                parsed.client_max_window_bits is not None
                and offered.client_max_window_bits is None
            ):
                msg = (
                    f"server accepted {self.name} parameter "
                    "'client_max_window_bits' that was not offered"
                )
                raise ValueError(msg)
            if (
                parsed.server_max_window_bits is not None
                and offered.server_max_window_bits is None
            ):
                msg = (
                    f"server accepted {self.name} parameter "
                    "'server_max_window_bits' that was not offered"
                )
                raise ValueError(msg)
            if (
                parsed.client_max_window_bits is not None
                and offered.client_max_window_bits is not None
                and parsed.client_max_window_bits > offered.client_max_window_bits
            ):
                msg = (
                    f"server accepted {self.name} client_max_window_bits="
                    f"{parsed.client_max_window_bits}, exceeding offered "
                    f"client_max_window_bits={offered.client_max_window_bits}"
                )
                raise ValueError(msg)
            if (
                parsed.server_max_window_bits is not None
                and offered.server_max_window_bits is not None
                and parsed.server_max_window_bits > offered.server_max_window_bits
            ):
                msg = (
                    f"server accepted {self.name} server_max_window_bits="
                    f"{parsed.server_max_window_bits}, exceeding offered "
                    f"server_max_window_bits={offered.server_max_window_bits}"
                )
                raise ValueError(msg)

            self.client_no_context_takeover = parsed.client_no_context_takeover
            self.server_no_context_takeover = parsed.server_no_context_takeover
            if parsed.client_max_window_bits is not None:
                self.client_max_window_bits = parsed.client_max_window_bits
            if parsed.server_max_window_bits is not None:
                self.server_max_window_bits = parsed.server_max_window_bits
            self._enabled = True
            return

        client_max_window_bits, server_max_window_bits = self._parse_legacy_params(
            offer,
        )
        if client_max_window_bits is not None:
            self.client_max_window_bits = client_max_window_bits
        if server_max_window_bits is not None:
            self.server_max_window_bits = server_max_window_bits
        self._enabled = True

    def accept(self, offer: str) -> bool | None | str:
        if not self.strict_negotiation:
            client_max_window_bits, server_max_window_bits = self._parse_legacy_params(
                offer,
            )

            parameters = []

            if self.client_no_context_takeover:
                parameters.append("client_no_context_takeover")
            if self.server_no_context_takeover:
                parameters.append("server_no_context_takeover")
            try:
                if client_max_window_bits is not None:
                    parameters.append(f"client_max_window_bits={client_max_window_bits}")
                    self.client_max_window_bits = client_max_window_bits
                if server_max_window_bits is not None:
                    parameters.append(f"server_max_window_bits={server_max_window_bits}")
                    self.server_max_window_bits = server_max_window_bits
            except ValueError:
                return None

            self._enabled = True
            return "; ".join(parameters)

        parsed = self._parse_params(
            offer,
            allow_client_max_window_bits_without_value=True,
        )

        client_max_window_bits: int | None = None
        server_max_window_bits: int | None = None

        offered_client_max_window_bits = (
            self.client_max_window_bits
            if parsed.client_max_window_bits_without_value
            else parsed.client_max_window_bits
        )
        offered_server_max_window_bits = parsed.server_max_window_bits

        if offered_client_max_window_bits is not None:
            client_max_window_bits = offered_client_max_window_bits
            client_max_window_bits = min(
                self.client_max_window_bits, client_max_window_bits,
            )
        if offered_server_max_window_bits is not None:
            server_max_window_bits = offered_server_max_window_bits
            server_max_window_bits = min(
                self.server_max_window_bits, server_max_window_bits,
            )

        parameters = []

        if parsed.client_no_context_takeover:
            parameters.append("client_no_context_takeover")
        if self.server_no_context_takeover or parsed.server_no_context_takeover:
            parameters.append("server_no_context_takeover")
        if client_max_window_bits is not None:
            parameters.append(
                f"client_max_window_bits={client_max_window_bits}",
            )
        if server_max_window_bits is not None:
            parameters.append(
                f"server_max_window_bits={server_max_window_bits}",
            )

        self.client_no_context_takeover = parsed.client_no_context_takeover
        self.server_no_context_takeover = parsed.server_no_context_takeover
        if client_max_window_bits is not None:
            self.client_max_window_bits = client_max_window_bits
        if server_max_window_bits is not None:
            self.server_max_window_bits = server_max_window_bits
        self._enabled = True

        return "; ".join(parameters)

    def frame_inbound_header(
        self,
        proto: FrameDecoder | FrameProtocol,
        opcode: Opcode,
        rsv: RsvBits,
        payload_length: int,
    ) -> CloseReason | RsvBits:
        if rsv.rsv1 and opcode.iscontrol():
            return CloseReason.PROTOCOL_ERROR
        if rsv.rsv1 and opcode is Opcode.CONTINUATION:
            return CloseReason.PROTOCOL_ERROR

        self._inbound_is_compressible = self._compressible_opcode(opcode)

        if self._inbound_compressed is None:
            self._inbound_compressed = rsv.rsv1
            if self._inbound_compressed:
                assert self._inbound_is_compressible
                if proto.client:
                    bits = self.server_max_window_bits
                else:
                    bits = self.client_max_window_bits
                if self._decompressor is None:
                    self._decompressor = zlib.decompressobj(-int(bits))

        return RsvBits(True, False, False)

    def frame_inbound_payload_data(
        self, proto: FrameDecoder | FrameProtocol, data: bytes,
    ) -> bytes | CloseReason:
        if not self._inbound_compressed or not self._inbound_is_compressible:
            return data
        assert self._decompressor is not None

        try:
            return self._decompressor.decompress(bytes(data))
        except zlib.error:
            return CloseReason.INVALID_FRAME_PAYLOAD_DATA

    def frame_inbound_complete(
        self, proto: FrameDecoder | FrameProtocol, fin: bool,
    ) -> bytes | CloseReason | None:
        if not fin:
            return None
        if not self._inbound_is_compressible:
            self._inbound_compressed = None
            return None
        if not self._inbound_compressed:
            self._inbound_compressed = None
            return None
        assert self._decompressor is not None

        try:
            data = self._decompressor.decompress(b"\x00\x00\xff\xff")
            data += self._decompressor.flush()
        except zlib.error:
            return CloseReason.INVALID_FRAME_PAYLOAD_DATA

        if proto.client:
            no_context_takeover = self.server_no_context_takeover
        else:
            no_context_takeover = self.client_no_context_takeover

        if no_context_takeover:
            self._decompressor = None

        self._inbound_compressed = None

        return data

    def frame_outbound(
        self,
        proto: FrameDecoder | FrameProtocol,
        opcode: Opcode,
        rsv: RsvBits,
        data: bytes,
        fin: bool,
    ) -> tuple[RsvBits, bytes]:
        if not self._compressible_opcode(opcode):
            return (rsv, data)

        if opcode is not Opcode.CONTINUATION:
            rsv = RsvBits(True, rsv[1], rsv[2])

        if self._compressor is None:
            assert opcode is not Opcode.CONTINUATION
            if proto.client:
                bits = self.client_max_window_bits
            else:
                bits = self.server_max_window_bits
            self._compressor = zlib.compressobj(
                zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -int(bits),
            )

        data = self._compressor.compress(bytes(data))

        if fin:
            data += self._compressor.flush(zlib.Z_SYNC_FLUSH)
            data = data[:-4]

            if proto.client:
                no_context_takeover = self.client_no_context_takeover
            else:
                no_context_takeover = self.server_no_context_takeover

            if no_context_takeover:
                self._compressor = None

        return (rsv, data)

    def __repr__(self) -> str:
        descr = [f"client_max_window_bits={self.client_max_window_bits}"]
        if self.client_no_context_takeover:
            descr.append("client_no_context_takeover")
        descr.append(f"server_max_window_bits={self.server_max_window_bits}")
        if self.server_no_context_takeover:
            descr.append("server_no_context_takeover")

        return "<{} {}>".format(self.__class__.__name__, "; ".join(descr))


#: SUPPORTED_EXTENSIONS maps all supported extension names to their class.
#: This can be used to iterate all supported extensions of wsproto, instantiate
#: new extensions based on their name, or check if a given extension is
#: supported or not.
SUPPORTED_EXTENSIONS = {PerMessageDeflate.name: PerMessageDeflate}
