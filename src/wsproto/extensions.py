"""
wsproto/extensions
~~~~~~~~~~~~~~~~~~

WebSocket extensions.
"""
from __future__ import annotations

import zlib
from abc import ABC, abstractmethod
from typing import Optional

from .frame_protocol import CloseReason, FrameDecoder, FrameProtocol, Opcode, RsvBits


class Extension(ABC):
    name: str

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

    _PARAMETER_NAMES = (
        "client_no_context_takeover",
        "server_no_context_takeover",
        "client_max_window_bits",
        "server_max_window_bits",
    )

    def __init__(
        self,
        client_no_context_takeover: bool = False,
        client_max_window_bits: int | None = None,
        server_no_context_takeover: bool = False,
        server_max_window_bits: int | None = None,
        strict: bool = False,
    ) -> None:
        self.client_no_context_takeover = client_no_context_takeover
        self.server_no_context_takeover = server_no_context_takeover
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

        #: Strictly validate extension parameters during negotiation. In
        #: strict mode invalid offers are rejected without mutating this
        #: instance and :attr:`rejection_reason` explains which negotiation
        #: constraint was not met. The default (``False``) keeps the
        #: historical lenient behaviour.
        self.strict = strict
        #: Why the last strict negotiation attempt failed, if it did.
        self.rejection_reason: str | None = None

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

    def finalize(self, offer: str) -> None:
        if self.strict:
            try:
                parsed = self._strict_parse(offer, response=True)
                if (
                    parsed["client_no_context_takeover"]
                    and not self.client_no_context_takeover
                ):
                    msg = (
                        "server selected client_no_context_takeover, "
                        "which was not offered"
                    )
                    raise ValueError(msg)
            except ValueError as exc:
                self.rejection_reason = str(exc)
                raise
            self.client_no_context_takeover = bool(
                self.client_no_context_takeover or parsed["client_no_context_takeover"]
            )
            self.server_no_context_takeover = bool(
                self.server_no_context_takeover or parsed["server_no_context_takeover"]
            )
            if parsed["client_max_window_bits"] is not None:
                self.client_max_window_bits = parsed["client_max_window_bits"]
            if parsed["server_max_window_bits"] is not None:
                self.server_max_window_bits = parsed["server_max_window_bits"]
            self._enabled = True
            return

        bits = [b.strip() for b in offer.split(";")]
        for bit in bits[1:]:
            if bit.startswith("client_no_context_takeover"):
                self.client_no_context_takeover = True
            elif bit.startswith("server_no_context_takeover"):
                self.server_no_context_takeover = True
            elif bit.startswith("client_max_window_bits"):
                self.client_max_window_bits = int(bit.split("=", 1)[1].strip())
            elif bit.startswith("server_max_window_bits"):
                self.server_max_window_bits = int(bit.split("=", 1)[1].strip())

        self._enabled = True

    def _compat_parse(self, params: str) -> dict[str, bool | int | None]:
        # Lenient parsing, kept for backwards compatibility. Unknown
        # parameters are ignored and values are matched by prefix. This
        # does not mutate the instance; it may still raise ValueError for
        # non-integer window bits values, as the historical code did.
        parsed: dict[str, bool | int | None] = {
            "client_no_context_takeover": False,
            "server_no_context_takeover": False,
            "client_max_window_bits": None,
            "server_max_window_bits": None,
        }
        bits = [b.strip() for b in params.split(";")]
        for bit in bits[1:]:
            if bit.startswith("client_no_context_takeover"):
                parsed["client_no_context_takeover"] = True
            elif bit.startswith("server_no_context_takeover"):
                parsed["server_no_context_takeover"] = True
            elif bit.startswith("client_max_window_bits"):
                if "=" in bit:
                    parsed["client_max_window_bits"] = int(bit.split("=", 1)[1].strip())
                else:
                    parsed["client_max_window_bits"] = self.client_max_window_bits
            elif bit.startswith("server_max_window_bits"):
                if "=" in bit:
                    parsed["server_max_window_bits"] = int(bit.split("=", 1)[1].strip())
                else:
                    parsed["server_max_window_bits"] = self.server_max_window_bits

        return parsed

    def _strict_parse(
        self, params: str, response: bool,
    ) -> dict[str, bool | int | None]:
        # Validate a single offer/response, raising ValueError describing
        # the unmet negotiation constraint. This never mutates the
        # instance, so a failed negotiation attempt leaves no trace.
        parsed: dict[str, bool | int | None] = {
            "client_no_context_takeover": False,
            "server_no_context_takeover": False,
            "client_max_window_bits": None,
            "server_max_window_bits": None,
        }
        seen: set[str] = set()
        bits = params.split(";")
        for bit in bits[1:]:
            bit = bit.strip()
            if not bit:
                msg = "empty extension parameter"
                raise ValueError(msg)
            name, has_value, value = bit.partition("=")
            name = name.strip()
            value = value.strip()
            if name not in self._PARAMETER_NAMES:
                msg = f"unknown extension parameter {name!r}"
                raise ValueError(msg)
            if name in seen:
                msg = f"duplicate extension parameter {name!r}"
                raise ValueError(msg)
            seen.add(name)
            if name.endswith("no_context_takeover"):
                if has_value:
                    msg = f"extension parameter {name!r} must not have a value"
                    raise ValueError(msg)
                parsed[name] = True
            elif not has_value:
                # A valueless client_max_window_bits is only valid in an
                # offer, where it indicates support without a preference.
                if name == "client_max_window_bits" and not response:
                    parsed[name] = self.client_max_window_bits
                else:
                    msg = f"extension parameter {name!r} requires a value"
                    raise ValueError(msg)
            elif not value:
                msg = f"extension parameter {name!r} has an empty value"
                raise ValueError(msg)
            else:
                try:
                    window_bits = int(value)
                except ValueError:
                    msg = f"extension parameter {name!r} value {value!r} is not an integer"
                    raise ValueError(msg) from None
                if not 9 <= window_bits <= 15:
                    msg = (
                        f"extension parameter {name!r} value {window_bits} "
                        "is out of range (9-15)"
                    )
                    raise ValueError(msg)
                parsed[name] = window_bits

        return parsed

    def accept(self, offer: str) -> bool | None | str:
        self.rejection_reason = None
        if self.strict:
            try:
                parsed = self._strict_parse(offer, response=False)
            except ValueError as exc:
                self.rejection_reason = str(exc)
                return None
        else:
            parsed = self._compat_parse(offer)

        client_no_context_takeover = bool(
            self.client_no_context_takeover or parsed["client_no_context_takeover"]
        )
        server_no_context_takeover = bool(
            self.server_no_context_takeover or parsed["server_no_context_takeover"]
        )
        client_max_window_bits = parsed["client_max_window_bits"]
        server_max_window_bits = parsed["server_max_window_bits"]

        parameters = []

        if client_no_context_takeover:
            parameters.append("client_no_context_takeover")
        if server_no_context_takeover:
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
        else:
            self.client_no_context_takeover = client_no_context_takeover
            self.server_no_context_takeover = server_no_context_takeover
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
