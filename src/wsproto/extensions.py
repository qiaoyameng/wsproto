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

    def frame_inbound_pending(self, _proto: FrameDecoder | FrameProtocol) -> bool:
        return False

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
        self._inbound_unconsumed = b""
        self._inbound_finalizing = False
        self._inbound_terminator_sent = False

        self._enabled = False

    def _new_decompressor(self, bits: int) -> zlib._Decompress:
        return zlib.decompressobj(-int(bits))

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

    def _parse_params(self, params: str) -> tuple[int | None, int | None]:
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

    def accept(self, offer: str) -> bool | None | str:
        client_max_window_bits, server_max_window_bits = self._parse_params(offer)

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
        else:
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
                    self._decompressor = self._new_decompressor(bits)
                    self._inbound_unconsumed = b""
                    self._inbound_finalizing = False
                    self._inbound_terminator_sent = False

        return RsvBits(True, False, False)

    def frame_inbound_payload_data(
        self, proto: FrameDecoder | FrameProtocol, data: bytes,
    ) -> bytes | CloseReason:
        if not self._inbound_compressed or not self._inbound_is_compressible:
            return data
        assert self._decompressor is not None

        try:
            data = self._inbound_unconsumed + bytes(data)
            self._inbound_unconsumed = b""
            budget = proto.message_size_remaining()
            if budget is None:
                return self._decompressor.decompress(data)

            output = self._decompressor.decompress(data, budget + 1)
            self._inbound_unconsumed = bytes(
                getattr(self._decompressor, "unconsumed_tail", b""),
            )
            return output
        except zlib.error:
            return CloseReason.INVALID_FRAME_PAYLOAD_DATA

    def frame_inbound_pending(self, _proto: FrameDecoder | FrameProtocol) -> bool:
        return bool(self._inbound_unconsumed) or self._inbound_finalizing

    def frame_inbound_complete(
        self, proto: FrameDecoder | FrameProtocol, fin: bool,
    ) -> bytes | CloseReason | None:
        if not fin:
            return None
        if not self._inbound_is_compressible:
            if not self._inbound_compressed:
                self._inbound_compressed = None
            return None
        if not self._inbound_compressed:
            self._inbound_compressed = None
            return None
        assert self._decompressor is not None
        if proto.client:
            no_context_takeover = self.server_no_context_takeover
        else:
            no_context_takeover = self.client_no_context_takeover

        self._inbound_finalizing = True

        try:
            budget = proto.message_size_remaining()
            if self._inbound_unconsumed:
                return b""

            if not self._inbound_terminator_sent:
                self._inbound_terminator_sent = True
                if budget is None:
                    data = self._decompressor.decompress(b"\x00\x00\xff\xff")
                else:
                    data = self._decompressor.decompress(b"\x00\x00\xff\xff", budget + 1)
                self._inbound_unconsumed = bytes(
                    getattr(self._decompressor, "unconsumed_tail", b""),
                )
                if not self._inbound_unconsumed and not data:
                    self._inbound_terminator_sent = False
                    if budget is None:
                        data = self._decompressor.flush()
                    else:
                        data = self._decompressor.flush(budget + 1)
                    if budget is None or len(data) <= budget:
                        self._inbound_compressed = None
                        self._inbound_unconsumed = b""
                        self._inbound_terminator_sent = False
                        self._inbound_finalizing = False
                        if no_context_takeover:
                            self._decompressor = None
                        return data
                return data

            if self._inbound_terminator_sent:
                if budget is None:
                    data = self._decompressor.decompress(b"")
                else:
                    data = self._decompressor.decompress(b"", budget + 1)
                self._inbound_unconsumed = bytes(
                    getattr(self._decompressor, "unconsumed_tail", b""),
                )
                if not self._inbound_unconsumed:
                    self._inbound_terminator_sent = False
                if data or self._inbound_unconsumed:
                    return data

            if budget is None:
                data = self._decompressor.flush()
            else:
                data = self._decompressor.flush(budget + 1)
            if budget is not None and len(data) > budget:
                return data
        except zlib.error:
            self._inbound_finalizing = False
            return CloseReason.INVALID_FRAME_PAYLOAD_DATA

        self._inbound_compressed = None
        self._inbound_unconsumed = b""
        self._inbound_terminator_sent = False
        self._inbound_finalizing = False

        if no_context_takeover:
            self._decompressor = None

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
