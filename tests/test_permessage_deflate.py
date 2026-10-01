from __future__ import annotations

import struct
import zlib
from collections.abc import Sequence
from typing import TYPE_CHECKING, Optional, cast

import pytest

from wsproto import extensions as wpext
from wsproto import frame_protocol as fp

if TYPE_CHECKING:
    from typing import TypedDict

    class Params(TypedDict, total=False):
        client_no_context_takeover: bool
        client_max_window_bits: Optional[int]
        server_no_context_takeover: bool
        server_max_window_bits: Optional[int]

else:
    Params = dict


def frame_bytes(
    opcode: int,
    payload: bytes,
    *,
    fin: bool = True,
    compressed: bool = False,
    mask: bool = False,
) -> bytes:
    first_byte = (0x80 if fin else 0x00) | (0x40 if compressed else 0x00) | opcode
    if mask:
        masking_key = b"mask"
        masked_payload = bytes(
            byte ^ masking_key[index % len(masking_key)]
            for index, byte in enumerate(payload)
        )
        mask_bit = 0x80
    else:
        masking_key = b""
        masked_payload = payload
        mask_bit = 0x00
    if len(payload) <= 125:
        header = bytes([first_byte, mask_bit | len(payload)])
        return header + masking_key + masked_payload
    length = struct.pack("!H", len(payload))
    return bytes([first_byte, mask_bit | 0x7E]) + length + masking_key + masked_payload


def compressed_message(parts: list[bytes]) -> list[bytes]:
    compressor = zlib.compressobj(
        zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15,
    )
    result = []
    for index, part in enumerate(parts):
        data = compressor.compress(part)
        if index == len(parts) - 1:
            data += compressor.flush(zlib.Z_SYNC_FLUSH)[:-4]
        result.append(data)
    return result


class TrackedDecompressor:
    def __init__(self, decompressor: zlib._Decompress) -> None:
        self._decompressor = decompressor
        self.peak_output = 0

    def decompress(self, data: bytes, max_length: int | None = None) -> bytes:
        if max_length is None:
            output = self._decompressor.decompress(data)
        else:
            output = self._decompressor.decompress(data, max_length)
        self.peak_output = max(self.peak_output, len(output))
        return output

    def flush(self, max_length: int | None = None) -> bytes:
        if max_length is None:
            output = self._decompressor.flush()
        else:
            output = self._decompressor.flush(max_length)
        self.peak_output = max(self.peak_output, len(output))
        return output

    @property
    def unconsumed_tail(self) -> bytes:
        return self._decompressor.unconsumed_tail

    @property
    def unused_data(self) -> bytes:
        return self._decompressor.unused_data


class TrackedPerMessageDeflate(wpext.PerMessageDeflate):
    def __init__(self) -> None:
        super().__init__()
        self.tracked_decompressor: TrackedDecompressor | None = None

    def _new_decompressor(self, bits: int) -> zlib._Decompress:
        self.tracked_decompressor = TrackedDecompressor(super()._new_decompressor(bits))
        return cast("zlib._Decompress", self.tracked_decompressor)


class TestPerMessageDeflate:
    parameter_sets: Sequence[Params] = [
        {
            "client_no_context_takeover": False,
            "client_max_window_bits": 15,
            "server_no_context_takeover": False,
            "server_max_window_bits": 15,
        },
        {
            "client_no_context_takeover": True,
            "client_max_window_bits": 9,
            "server_no_context_takeover": False,
            "server_max_window_bits": 15,
        },
        {
            "client_no_context_takeover": False,
            "client_max_window_bits": 15,
            "server_no_context_takeover": True,
            "server_max_window_bits": 9,
        },
        {
            "client_no_context_takeover": True,
            "client_max_window_bits": 9,
            "server_no_context_takeover": True,
            "server_max_window_bits": 9,
        },
        {"client_no_context_takeover": True, "server_max_window_bits": 9},
        {"server_no_context_takeover": True, "client_max_window_bits": 9},
        {"client_max_window_bits": None, "server_max_window_bits": None},
        {},
    ]

    def make_offer_string(self, params: Params) -> str:
        offer = ["permessage-deflate"]

        if "client_max_window_bits" in params:
            if params["client_max_window_bits"] is None:
                offer.append("client_max_window_bits")
            else:
                offer.append(
                    "client_max_window_bits=%d" % params["client_max_window_bits"],
                )
        if "server_max_window_bits" in params:
            if params["server_max_window_bits"] is None:
                offer.append("server_max_window_bits")
            else:
                offer.append(
                    "server_max_window_bits=%d" % params["server_max_window_bits"],
                )
        if params.get("client_no_context_takeover", False):
            offer.append("client_no_context_takeover")
        if params.get("server_no_context_takeover", False):
            offer.append("server_no_context_takeover")

        return "; ".join(offer)

    def compare_params_to_string(
        self, params: Params, ext: wpext.PerMessageDeflate, param_string: str,
    ) -> None:
        if "client_max_window_bits" in params:
            if params["client_max_window_bits"] is None:
                bits = ext.client_max_window_bits
            else:
                bits = params["client_max_window_bits"]
            assert "client_max_window_bits=%d" % bits in param_string
        if "server_max_window_bits" in params:
            if params["server_max_window_bits"] is None:
                bits = ext.server_max_window_bits
            else:
                bits = params["server_max_window_bits"]
            assert "server_max_window_bits=%d" % bits in param_string
        if params.get("client_no_context_takeover", False):
            assert "client_no_context_takeover" in param_string
        if params.get("server_no_context_takeover", False):
            assert "server_no_context_takeover" in param_string

    @pytest.mark.parametrize("params", parameter_sets)
    def test_offer(self, params: Params) -> None:
        ext = wpext.PerMessageDeflate(**params)
        offer = ext.offer()
        offer = cast("str", offer)

        self.compare_params_to_string(params, ext, offer)

    @pytest.mark.parametrize("params", parameter_sets)
    def test_finalize(self, params: Params) -> None:
        ext = wpext.PerMessageDeflate()
        assert not ext.enabled()

        if "client_max_window_bits" in params:
            if params["client_max_window_bits"] is None:
                del params["client_max_window_bits"]
        if "server_max_window_bits" in params:
            if params["server_max_window_bits"] is None:
                del params["server_max_window_bits"]
        offer = self.make_offer_string(params)
        ext.finalize(offer)

        if params.get("client_max_window_bits", None):
            assert ext.client_max_window_bits == params["client_max_window_bits"]
        if params.get("server_max_window_bits", None):
            assert ext.server_max_window_bits == params["server_max_window_bits"]
        assert ext.client_no_context_takeover is params.get(
            "client_no_context_takeover", False,
        )
        assert ext.server_no_context_takeover is params.get(
            "server_no_context_takeover", False,
        )

        assert ext.enabled()

    def test_finalize_ignores_rubbish(self) -> None:
        ext = wpext.PerMessageDeflate()
        assert not ext.enabled()

        ext.finalize("i am the lizard queen; worship me")

        assert ext.enabled()

    @pytest.mark.parametrize("params", parameter_sets)
    def test_accept(self, params: Params) -> None:
        ext = wpext.PerMessageDeflate()
        assert not ext.enabled()

        offer = self.make_offer_string(params)
        response = ext.accept(offer)
        response = cast("str", response)

        if ext.client_no_context_takeover:
            assert "client_no_context_takeover" in response
        if ext.server_no_context_takeover:
            assert "server_no_context_takeover" in response
        if "client_max_window_bits" in params:
            if params["client_max_window_bits"] is None:
                bits = ext.client_max_window_bits
            else:
                bits = params["client_max_window_bits"]
            assert ext.client_max_window_bits == bits
            assert "client_max_window_bits=%d" % bits in response
        if "server_max_window_bits" in params:
            if params["server_max_window_bits"] is None:
                bits = ext.server_max_window_bits
            else:
                bits = params["server_max_window_bits"]
            assert ext.server_max_window_bits == bits
            assert "server_max_window_bits=%d" % bits in response

    def test_accept_ignores_rubbish(self) -> None:
        ext = wpext.PerMessageDeflate()
        assert not ext.enabled()

        ext.accept("i am the lizard queen; worship me")

        assert ext.enabled()

    def test_inbound_uncompressed_control_frame(self) -> None:
        payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.PING, fp.RsvBits(False, False, False), len(payload),
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1

        data = ext.frame_inbound_payload_data(proto, payload)
        assert data == payload

        assert ext.frame_inbound_complete(proto, True) is None

    def test_inbound_compressed_control_frame(self) -> None:
        payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.PING, fp.RsvBits(True, False, False), len(payload),
        )
        assert result == fp.CloseReason.PROTOCOL_ERROR

    def test_inbound_compressed_continuation_frame(self) -> None:
        payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.CONTINUATION, fp.RsvBits(True, False, False), len(payload),
        )
        assert result == fp.CloseReason.PROTOCOL_ERROR

    def test_inbound_uncompressed_data_frame(self) -> None:
        payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.BINARY, fp.RsvBits(False, False, False), len(payload),
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1

        data = ext.frame_inbound_payload_data(proto, payload)
        assert data == payload

        assert ext.frame_inbound_complete(proto, True) is None

    @pytest.mark.parametrize("client", [True, False])
    def test_client_inbound_compressed_single_data_frame(self, client: bool) -> None:
        payload = b"x" * 23
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        result = ext.frame_inbound_header(
            proto,
            fp.Opcode.BINARY,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1

        data = ext.frame_inbound_payload_data(proto, compressed_payload)
        assert isinstance(data, bytes)
        data2 = ext.frame_inbound_complete(proto, True)
        assert isinstance(data2, bytes)
        assert data + data2 == payload

    @pytest.mark.parametrize("client", [True, False])
    @pytest.mark.parametrize(
        "max_message_size,expected_error",
        [(22, True), (23, False), (24, False)],
    )
    def test_message_size_limit_uses_decompressed_size(
        self, client: bool, max_message_size: int, expected_error: bool,
    ) -> None:
        payload = b"x" * 23
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"
        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext], max_message_size=max_message_size)

        proto.receive_bytes(
            frame_bytes(
                fp.Opcode.BINARY,
                compressed_payload,
                compressed=True,
                mask=not client,
            ),
        )

        if expected_error:
            with pytest.raises(fp.ParseFailed) as excinfo:
                list(proto.received_frames())
            assert excinfo.value.code is fp.CloseReason.MESSAGE_TOO_BIG
        else:
            frames = list(proto.received_frames())
            assert len(frames) == 1
            assert frames[0].payload == payload

    @pytest.mark.parametrize("client", [True, False])
    @pytest.mark.parametrize("max_message_size", [None, 5, 6, 100])
    def test_message_size_limit_spans_fragments_and_control_frame(
        self, client: bool, max_message_size: int | None,
    ) -> None:
        first_payload, final_payload = compressed_message([b"abc", b"def"])
        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(
            client=client,
            extensions=[ext],
            max_message_size=max_message_size,
        )
        frames = (
            frame_bytes(
                fp.Opcode.TEXT, first_payload, fin=False, compressed=True,
                mask=not client,
            )
            + frame_bytes(
                fp.Opcode.PING, b"p", mask=not client,
            )
            + frame_bytes(
                fp.Opcode.CONTINUATION,
                final_payload,
                mask=not client,
            )
        )

        proto.receive_bytes(frames)

        if max_message_size == 5:
            with pytest.raises(fp.ParseFailed) as excinfo:
                list(proto.received_frames())
            assert excinfo.value.code is fp.CloseReason.MESSAGE_TOO_BIG
        else:
            frames = list(proto.received_frames())
            assert [(frame.opcode, frame.payload) for frame in frames] == [
                (fp.Opcode.TEXT, ""),
                (fp.Opcode.PING, b"p"),
                (fp.Opcode.TEXT, "abcdef"),
            ]

    @pytest.mark.parametrize("uncompressed_size", [4096, 16 * 1024 * 1024])
    def test_message_size_limit_bounds_decompression(
        self, uncompressed_size: int,
    ) -> None:
        compressed_payload = compressed_message([b"\0" * uncompressed_size])[0]
        ext = TrackedPerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(
            client=True, extensions=[ext], max_message_size=1024,
        )

        proto.receive_bytes(
            frame_bytes(
                fp.Opcode.BINARY, compressed_payload, compressed=True,
            ),
        )

        with pytest.raises(fp.ParseFailed) as excinfo:
            list(proto.received_frames())
        assert excinfo.value.code is fp.CloseReason.MESSAGE_TOO_BIG
        assert ext.tracked_decompressor is not None
        assert ext.tracked_decompressor.peak_output <= 1025

    @pytest.mark.parametrize("client", [True, False])
    def test_client_inbound_compressed_multiple_data_frames(self, client: bool) -> None:
        payload = b"x" * 23
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"
        split = 3
        data = b""

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.BINARY, fp.RsvBits(True, False, False), split,
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1
        result2 = ext.frame_inbound_payload_data(proto, compressed_payload[:split])
        assert not isinstance(result2, fp.CloseReason)
        data += result2
        assert ext.frame_inbound_complete(proto, False) is None

        result3 = ext.frame_inbound_header(
            proto,
            fp.Opcode.CONTINUATION,
            fp.RsvBits(False, False, False),
            len(compressed_payload) - split,
        )
        assert isinstance(result3, fp.RsvBits)
        assert result3.rsv1
        result4 = ext.frame_inbound_payload_data(proto, compressed_payload[split:])
        assert not isinstance(result4, fp.CloseReason)
        data += result4

        result5 = ext.frame_inbound_complete(proto, True)
        assert isinstance(result5, bytes)
        data += result5

        assert data == payload

    @pytest.mark.parametrize("client", [True, False])
    def test_client_decompress_after_uncompressible_frame(self, client: bool) -> None:
        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        # A PING frame
        ext.frame_inbound_header(
            proto, fp.Opcode.PING, fp.RsvBits(False, False, False), 0,
        )
        result2 = ext.frame_inbound_payload_data(proto, b"")
        assert not isinstance(result2, fp.CloseReason)
        assert ext.frame_inbound_complete(proto, True) is None

        # A compressed TEXT frame
        payload = b"x" * 23
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"

        result3 = ext.frame_inbound_header(
            proto,
            fp.Opcode.TEXT,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        assert isinstance(result3, fp.RsvBits)
        assert result3.rsv1
        result4 = ext.frame_inbound_payload_data(proto, compressed_payload)
        assert result4 == payload

        result5 = ext.frame_inbound_complete(proto, True)
        assert not isinstance(result5, fp.CloseReason)

    def test_inbound_bad_zlib_payload(self) -> None:
        compressed_payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto,
            fp.Opcode.BINARY,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1
        result2 = ext.frame_inbound_payload_data(proto, compressed_payload)
        assert result2 is fp.CloseReason.INVALID_FRAME_PAYLOAD_DATA

    def test_inbound_bad_zlib_decoder_end_state(self) -> None:
        compressed_payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto,
            fp.Opcode.BINARY,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1

        class FailDecompressor:
            def decompress(self, data: bytes) -> bytes:
                return b""

            def flush(self) -> None:
                raise zlib.error()

        ext._decompressor = cast("zlib._Decompress", FailDecompressor())
        result2 = ext.frame_inbound_complete(proto, True)

        assert result2 is fp.CloseReason.INVALID_FRAME_PAYLOAD_DATA

    @pytest.mark.parametrize(
        "client,no_context_takeover",
        [(True, True), (True, False), (False, True), (False, False)],
    )
    def test_decompressor_reset(self, client: bool, no_context_takeover: bool) -> None:
        if client:
            args = {"server_no_context_takeover": no_context_takeover}
        else:
            args = {"client_no_context_takeover": no_context_takeover}
        ext = wpext.PerMessageDeflate(**args)
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.BINARY, fp.RsvBits(True, False, False), 0,
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1

        assert ext._decompressor is not None

        result2 = ext.frame_inbound_complete(proto, True)
        assert not isinstance(result2, fp.CloseReason)

        if no_context_takeover:
            assert ext._decompressor is None
        else:
            assert ext._decompressor is not None

        result3 = ext.frame_inbound_header(
            proto, fp.Opcode.BINARY, fp.RsvBits(True, False, False), 0,
        )
        assert isinstance(result3, fp.RsvBits)
        assert result3.rsv1

        assert ext._decompressor is not None

    def test_outbound_uncompressible_opcode(self) -> None:
        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        rsv = fp.RsvBits(False, False, False)
        payload = b"x" * 23

        rsv, data = ext.frame_outbound(proto, fp.Opcode.PING, rsv, payload, True)

        assert rsv.rsv1 is False
        assert data == payload

    @pytest.mark.parametrize("client", [True, False])
    def test_outbound_compress_single_frame(self, client: bool) -> None:
        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        rsv = fp.RsvBits(False, False, False)
        payload = b"x" * 23
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"

        rsv, data = ext.frame_outbound(proto, fp.Opcode.BINARY, rsv, payload, True)

        assert rsv.rsv1 is True
        assert data == compressed_payload

    @pytest.mark.parametrize("client", [True, False])
    def test_outbound_compress_multiple_frames(self, client: bool) -> None:
        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        rsv = fp.RsvBits(False, False, False)
        payload = b"x" * 23
        split = 12
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"

        rsv, data = ext.frame_outbound(
            proto, fp.Opcode.BINARY, rsv, payload[:split], False,
        )
        assert rsv.rsv1 is True

        rsv = fp.RsvBits(False, False, False)
        rsv, more_data = ext.frame_outbound(
            proto, fp.Opcode.CONTINUATION, rsv, payload[split:], True,
        )
        assert rsv.rsv1 is False
        assert data + more_data == compressed_payload

    @pytest.mark.parametrize(
        "client,no_context_takeover",
        [(True, True), (True, False), (False, True), (False, False)],
    )
    def test_compressor_reset(self, client: bool, no_context_takeover: bool) -> None:
        if client:
            args = {"client_no_context_takeover": no_context_takeover}
        else:
            args = {"server_no_context_takeover": no_context_takeover}
        ext = wpext.PerMessageDeflate(**args)
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])
        rsv = fp.RsvBits(False, False, False)

        rsv, data = ext.frame_outbound(proto, fp.Opcode.BINARY, rsv, b"", False)
        assert rsv.rsv1 is True
        assert ext._compressor is not None

        rsv = fp.RsvBits(False, False, False)
        rsv, data = ext.frame_outbound(proto, fp.Opcode.CONTINUATION, rsv, b"", True)
        assert rsv.rsv1 is False
        if no_context_takeover:
            assert ext._compressor is None
        else:
            assert ext._compressor is not None

        rsv = fp.RsvBits(False, False, False)
        rsv, data = ext.frame_outbound(proto, fp.Opcode.BINARY, rsv, b"", False)
        assert rsv.rsv1 is True
        assert ext._compressor is not None

    @pytest.mark.parametrize("params", parameter_sets)
    def test_repr(self, params: Params) -> None:
        ext = wpext.PerMessageDeflate(**params)
        self.compare_params_to_string(params, ext, repr(ext))
