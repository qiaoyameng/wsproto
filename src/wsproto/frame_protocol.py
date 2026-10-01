"""
wsproto/frame_protocol
~~~~~~~~~~~~~~~~~~~~~~

WebSocket frame protocol implementation.
"""
from __future__ import annotations

import contextlib
import os
import struct
from codecs import IncrementalDecoder, getincrementaldecoder
from dataclasses import dataclass, replace
from enum import Enum, IntEnum
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Generator

    from .extensions import Extension  # pragma: no cover


_XOR_TABLE = [bytes(a ^ b for a in range(256)) for b in range(256)]


class XorMaskerSimple:
    def __init__(self, masking_key: bytearray | bytes) -> None:
        self._masking_key = masking_key

    def process(self, data: bytearray) -> bytearray:
        data = bytearray(data)
        if data:
            data_array = data
            a, b, c, d = (_XOR_TABLE[n] for n in self._masking_key)
            data_array[::4] = data_array[::4].translate(a)
            data_array[1::4] = data_array[1::4].translate(b)
            data_array[2::4] = data_array[2::4].translate(c)
            data_array[3::4] = data_array[3::4].translate(d)

            # Rotate the masking key so that the next usage continues
            # with the next key element, rather than restarting.
            key_rotation = len(data) % 4
            self._masking_key = (
                self._masking_key[key_rotation:] + self._masking_key[:key_rotation]
            )

            return data_array
        return data


class XorMaskerNull:
    def process(self, data: bytearray) -> bytearray:
        return data


# RFC6455, Section 5.2 - Base Framing Protocol

# Payload length constants
PAYLOAD_LENGTH_TWO_BYTE = 126
PAYLOAD_LENGTH_EIGHT_BYTE = 127
MAX_PAYLOAD_NORMAL = 125
MAX_PAYLOAD_TWO_BYTE = 2**16 - 1
MAX_PAYLOAD_EIGHT_BYTE = 2**64 - 1
MAX_FRAME_PAYLOAD = MAX_PAYLOAD_EIGHT_BYTE

# MASK and PAYLOAD LEN are packed into a byte
MASK_MASK = 0x80
PAYLOAD_LEN_MASK = 0x7F

# FIN, RSV[123] and OPCODE are packed into a single byte
FIN_MASK = 0x80
RSV1_MASK = 0x40
RSV2_MASK = 0x20
RSV3_MASK = 0x10
OPCODE_MASK = 0x0F


class Opcode(IntEnum):
    """
    RFC 6455, Section 5.2 - Base Framing Protocol
    """

    #: Continuation frame
    CONTINUATION = 0x0

    #: Text message
    TEXT = 0x1

    #: Binary message
    BINARY = 0x2

    #: Close frame
    CLOSE = 0x8

    #: Ping frame
    PING = 0x9

    #: Pong frame
    PONG = 0xA

    def iscontrol(self) -> bool:
        return bool(self & 0x08)


class CloseReason(IntEnum):
    """
    RFC 6455, Section 7.4.1 - Defined Status Codes
    """

    #: indicates a normal closure, meaning that the purpose for
    #: which the connection was established has been fulfilled.
    NORMAL_CLOSURE = 1000

    #: indicates that an endpoint is "going away", such as a server
    #: going down or a browser having navigated away from a page.
    GOING_AWAY = 1001

    #: indicates that an endpoint is terminating the connection due
    #: to a protocol error.
    PROTOCOL_ERROR = 1002

    #: indicates that an endpoint is terminating the connection
    #: because it has received a type of data it cannot accept (e.g., an
    #: endpoint that understands only text data MAY send this if it
    #: receives a binary message).
    UNSUPPORTED_DATA = 1003

    #: Reserved.  The specific meaning might be defined in the future.
    # DON'T DEFINE THIS: RESERVED_1004 = 1004

    #: is a reserved value and MUST NOT be set as a status code in a
    #: Close control frame by an endpoint.  It is designated for use in
    #: applications expecting a status code to indicate that no status
    #: code was actually present.
    NO_STATUS_RCVD = 1005

    #: is a reserved value and MUST NOT be set as a status code in a
    #: Close control frame by an endpoint.  It is designated for use in
    #: applications expecting a status code to indicate that the
    #: connection was closed abnormally, e.g., without sending or
    #: receiving a Close control frame.
    ABNORMAL_CLOSURE = 1006

    #: indicates that an endpoint is terminating the connection
    #: because it has received data within a message that was not
    #: consistent with the type of the message (e.g., non-UTF-8 [RFC3629]
    #: data within a text message).
    INVALID_FRAME_PAYLOAD_DATA = 1007

    #: indicates that an endpoint is terminating the connection
    #: because it has received a message that violates its policy.  This
    #: is a generic status code that can be returned when there is no
    #: other more suitable status code (e.g., 1003 or 1009) or if there
    #: is a need to hide specific details about the policy.
    POLICY_VIOLATION = 1008

    #: indicates that an endpoint is terminating the connection
    #: because it has received a message that is too big for it to
    #: process.
    MESSAGE_TOO_BIG = 1009

    #: indicates that an endpoint (client) is terminating the
    #: connection because it has expected the server to negotiate one or
    #: more extension, but the server didn't return them in the response
    #: message of the WebSocket handshake.  The list of extensions that
    #: are needed SHOULD appear in the /reason/ part of the Close frame.
    #: Note that this status code is not used by the server, because it
    #: can fail the WebSocket handshake instead.
    MANDATORY_EXT = 1010

    #: indicates that a server is terminating the connection because
    #: it encountered an unexpected condition that prevented it from
    #: fulfilling the request.
    INTERNAL_ERROR = 1011

    #: Server/service is restarting
    #: (not part of RFC6455)
    SERVICE_RESTART = 1012

    #: Temporary server condition forced blocking client's request
    #: (not part of RFC6455)
    TRY_AGAIN_LATER = 1013

    #: is a reserved value and MUST NOT be set as a status code in a
    #: Close control frame by an endpoint.  It is designated for use in
    #: applications expecting a status code to indicate that the
    #: connection was closed due to a failure to perform a TLS handshake
    #: (e.g., the server certificate can't be verified).
    TLS_HANDSHAKE_FAILED = 1015


# RFC 6455, Section 7.4.1 - Defined Status Codes
LOCAL_ONLY_CLOSE_REASONS = (
    CloseReason.NO_STATUS_RCVD,
    CloseReason.ABNORMAL_CLOSURE,
    CloseReason.TLS_HANDSHAKE_FAILED,
)


# RFC 6455, Section 7.4.2 - Status Code Ranges
MIN_CLOSE_REASON = 1000
MIN_PROTOCOL_CLOSE_REASON = 1000
MAX_PROTOCOL_CLOSE_REASON = 2999
MIN_LIBRARY_CLOSE_REASON = 3000
MAX_LIBRARY_CLOSE_REASON = 3999
MIN_PRIVATE_CLOSE_REASON = 4000
MAX_PRIVATE_CLOSE_REASON = 4999
MAX_CLOSE_REASON = 4999


NULL_MASK = struct.pack("!I", 0)


class ParseFailed(Exception):
    def __init__(
        self, msg: str, code: CloseReason = CloseReason.PROTOCOL_ERROR,
    ) -> None:
        super().__init__(msg)
        self.code = code


class RsvBits(NamedTuple):
    rsv1: bool
    rsv2: bool
    rsv3: bool


class ByteRange(NamedTuple):
    """A half-open byte range in a connection's WebSocket frame stream."""

    start: int
    end: int


class PayloadSourceLevel(Enum):
    """The relationship between event payload bytes and wire payload bytes."""

    BYTE = "byte"
    FRAME = "frame"


@dataclass(frozen=True)
class FrameSource:
    """
    Location of a received event in the WebSocket frame stream.

    Byte offsets are zero-based and counted from the first byte after the
    opening handshake. Ranges are half-open. Control frames have frame
    metadata but no message or fragment number.

    ``BYTE`` payload sources map directly to wire payload bytes. ``FRAME``
    payload sources identify the complete frame only, which is used when an
    extension such as permessage-deflate changes the payload length.
    """

    frame_number: int
    header: ByteRange
    payload: ByteRange
    message_number: int | None = None
    fragment_number: int | None = None
    mask: ByteRange | None = None
    payload_source_level: PayloadSourceLevel = PayloadSourceLevel.BYTE


class Header(NamedTuple):
    fin: bool
    rsv: RsvBits
    opcode: Opcode
    payload_len: int
    masking_key: bytes | None


class Frame(NamedTuple):
    opcode: Opcode
    payload: bytes | str | tuple[int, str]
    frame_finished: bool
    message_finished: bool
    source: FrameSource | None = None


def _truncate_utf8(data: bytes, nbytes: int) -> bytes:
    if len(data) <= nbytes:
        return data

    # Truncate
    data = data[:nbytes]
    # But we might have cut a codepoint in half, in which case we want to
    # discard the partial character so the data is at least
    # well-formed. This is a little inefficient since it processes the
    # whole message twice when in theory we could just peek at the last
    # few characters, but since this is only used for close messages (max
    # length = 125 bytes) it really doesn't matter.
    return data.decode("utf-8", errors="ignore").encode("utf-8")


class Buffer:
    def __init__(self, initial_bytes: bytes | None = None) -> None:
        self.buffer = bytearray()
        self.bytes_used = 0
        self.stream_position = 0
        if initial_bytes:
            self.feed(initial_bytes)

    def feed(self, new_bytes: bytes) -> None:
        self.buffer += new_bytes

    def consume_at_most(self, nbytes: int) -> bytearray:
        if not nbytes:
            return bytearray()

        data = self.buffer[self.bytes_used : self.bytes_used + nbytes]
        self.bytes_used += len(data)
        return data

    def consume_exactly(self, nbytes: int) -> bytearray | None:
        if len(self.buffer) - self.bytes_used < nbytes:
            return None

        return self.consume_at_most(nbytes)

    def commit(self) -> None:
        # In CPython 3.4+, del[:n] is amortized O(n), *not* quadratic
        self.stream_position += self.bytes_used
        del self.buffer[: self.bytes_used]
        self.bytes_used = 0

    def rollback(self) -> None:
        self.bytes_used = 0

    def __len__(self) -> int:
        return len(self.buffer)


class MessageDecoder:
    def __init__(self) -> None:
        self.opcode: Opcode | None = None
        self.decoder: IncrementalDecoder | None = None

    def process_frame(self, frame: Frame) -> Frame:
        assert not frame.opcode.iscontrol()

        if self.opcode is None:
            if frame.opcode is Opcode.CONTINUATION:
                msg = "unexpected CONTINUATION"
                raise ParseFailed(msg)
            self.opcode = frame.opcode
        elif frame.opcode is not Opcode.CONTINUATION:
            msg = f"expected CONTINUATION, got {frame.opcode!r}"
            raise ParseFailed(msg)

        if frame.opcode is Opcode.TEXT:
            self.decoder = getincrementaldecoder("utf-8")()

        finished = frame.frame_finished and frame.message_finished

        if self.decoder is None:
            data = frame.payload
        else:
            assert isinstance(frame.payload, (bytes, bytearray))
            try:
                data = self.decoder.decode(frame.payload, finished)
            except UnicodeDecodeError as exc:
                raise ParseFailed(str(exc), CloseReason.INVALID_FRAME_PAYLOAD_DATA)

        frame = Frame(
            self.opcode,
            data,
            frame.frame_finished,
            finished,
            frame.source,
        )

        if finished:
            self.opcode = None
            self.decoder = None

        return frame


class FrameDecoder:
    def __init__(
        self,
        client: bool,
        extensions: list[Extension] | None = None,
        track_frame_sources: bool = False,
    ) -> None:
        self.client = client
        self.extensions = extensions or []
        self.track_frame_sources = track_frame_sources

        self.buffer = Buffer()

        self.header: Header | None = None
        self.effective_opcode: Opcode | None = None
        self.masker: None | XorMaskerNull | XorMaskerSimple = None
        self.payload_required = 0
        self.payload_consumed = 0
        self.frames_received = 0
        self.frame_number = 0
        self.frame_start = 0
        self.header_end = 0
        self.mask_start: int | None = None
        self.payload_start = 0
        self.payload_source_level = PayloadSourceLevel.BYTE

    def receive_bytes(self, data: bytes) -> None:
        self.buffer.feed(data)

    def process_buffer(self) -> Frame | None:
        if not self.header and not self.parse_header():
            return None
        # parse_header() sets these.
        assert self.header is not None
        assert self.masker is not None
        assert self.effective_opcode is not None

        if len(self.buffer) < self.payload_required:
            return None

        payload_remaining = self.header.payload_len - self.payload_consumed
        wire_payload_start = self.buffer.stream_position + self.buffer.bytes_used
        payload = self.buffer.consume_at_most(payload_remaining)
        if not payload and self.header.payload_len > 0:
            return None
        wire_payload_end = self.buffer.stream_position + self.buffer.bytes_used
        self.buffer.commit()

        self.payload_consumed += len(payload)
        finished = self.payload_consumed == self.header.payload_len

        payload = self.masker.process(payload)

        for extension in self.extensions:
            payload_ = extension.frame_inbound_payload_data(self, bytes(payload))
            if isinstance(payload_, CloseReason):
                msg = "error in extension"
                raise ParseFailed(msg, payload_)
            payload = bytearray(payload_)

        if finished:
            final = bytearray()
            for extension in self.extensions:
                result = extension.frame_inbound_complete(self, self.header.fin)
                if isinstance(result, CloseReason):
                    msg = "error in extension"
                    raise ParseFailed(msg, result)
                if result is not None:
                    final += result
            payload += final

        source = None
        if self.track_frame_sources:
            if self.payload_source_level is PayloadSourceLevel.FRAME:
                source_payload = ByteRange(
                    self.payload_start,
                    self.payload_start + self.header.payload_len,
                )
            else:
                source_payload = ByteRange(wire_payload_start, wire_payload_end)
            source = FrameSource(
                frame_number=self.frame_number,
                header=ByteRange(self.frame_start, self.header_end),
                payload=source_payload,
                mask=(
                    None
                    if self.mask_start is None
                    else ByteRange(self.mask_start, self.payload_start)
                ),
                payload_source_level=self.payload_source_level,
            )

        frame = Frame(
            self.effective_opcode,
            bytes(payload),
            finished,
            self.header.fin,
            source,
        )

        if finished:
            self.header = None
            self.effective_opcode = None
            self.masker = None
        else:
            self.effective_opcode = Opcode.CONTINUATION

        return frame

    def parse_header(self) -> bool:
        frame_start = self.buffer.stream_position + self.buffer.bytes_used
        data = self.buffer.consume_exactly(2)
        if data is None:
            self.buffer.rollback()
            return False

        fin = bool(data[0] & FIN_MASK)
        rsv = RsvBits(
            bool(data[0] & RSV1_MASK),
            bool(data[0] & RSV2_MASK),
            bool(data[0] & RSV3_MASK),
        )
        opcode = data[0] & OPCODE_MASK
        try:
            opcode = Opcode(opcode)
        except ValueError:
            msg = f"Invalid opcode {opcode:#x}"
            raise ParseFailed(msg)

        if opcode.iscontrol() and not fin:
            msg = "Invalid attempt to fragment control frame"
            raise ParseFailed(msg)

        has_mask = bool(data[1] & MASK_MASK)
        payload_len_short = data[1] & PAYLOAD_LEN_MASK
        payload_len = self.parse_extended_payload_length(opcode, payload_len_short)
        if payload_len is None:
            self.buffer.rollback()
            return False

        header_end = self.buffer.stream_position + self.buffer.bytes_used
        self.extension_processing(opcode, rsv, payload_len)

        if has_mask and self.client:
            msg = "client received unexpected masked frame"
            raise ParseFailed(msg)
        if not has_mask and not self.client:
            msg = "server received unexpected unmasked frame"
            raise ParseFailed(msg)
        if has_mask:
            masking_key = self.buffer.consume_exactly(4)
            if masking_key is None:
                self.buffer.rollback()
                return False
            mask_start = header_end
            self.masker = XorMaskerSimple(masking_key)
        else:
            mask_start = None
            self.masker = XorMaskerNull()

        self.buffer.commit()
        payload_start = self.buffer.stream_position
        if self.track_frame_sources:
            self.frame_number = self.frames_received
            self.frame_start = frame_start
            self.header_end = header_end
            self.mask_start = mask_start
            self.payload_start = payload_start
            self.payload_source_level = self._payload_source_level()
        self.frames_received += 1
        self.header = Header(fin, rsv, opcode, payload_len, None)
        self.effective_opcode = self.header.opcode
        if self.header.opcode.iscontrol():
            self.payload_required = payload_len
        else:
            self.payload_required = 0
        self.payload_consumed = 0
        return True

    def _payload_source_level(self) -> PayloadSourceLevel:
        for extension in self.extensions:
            if (
                extension.frame_inbound_payload_source_level()
                is PayloadSourceLevel.FRAME
            ):
                return PayloadSourceLevel.FRAME
        return PayloadSourceLevel.BYTE

    def parse_extended_payload_length(
        self, opcode: Opcode, payload_len: int,
    ) -> int | None:
        if opcode.iscontrol() and payload_len > MAX_PAYLOAD_NORMAL:
            msg = "Control frame with payload len > 125"
            raise ParseFailed(msg)
        if payload_len == PAYLOAD_LENGTH_TWO_BYTE:
            data = self.buffer.consume_exactly(2)
            if data is None:
                return None
            (payload_len,) = struct.unpack("!H", data)
            if payload_len <= MAX_PAYLOAD_NORMAL:
                msg = "Payload length used 2 bytes when 1 would have sufficed"
                raise ParseFailed(
                    msg,
                )
        elif payload_len == PAYLOAD_LENGTH_EIGHT_BYTE:
            data = self.buffer.consume_exactly(8)
            if data is None:
                return None
            (payload_len,) = struct.unpack("!Q", data)
            if payload_len <= MAX_PAYLOAD_TWO_BYTE:
                msg = "Payload length used 8 bytes when 2 would have sufficed"
                raise ParseFailed(
                    msg,
                )
            if payload_len >> 63:
                # I'm not sure why this is illegal, but that's what the RFC
                # says, so...
                msg = "8-byte payload length with non-zero MSB"
                raise ParseFailed(msg)

        return payload_len

    def extension_processing(
        self, opcode: Opcode, rsv: RsvBits, payload_len: int,
    ) -> None:
        rsv_used = [False, False, False]
        for extension in self.extensions:
            result = extension.frame_inbound_header(self, opcode, rsv, payload_len)
            if isinstance(result, CloseReason):
                msg = "error in extension"
                raise ParseFailed(msg, result)
            for bit, used in enumerate(result):
                if used:
                    rsv_used[bit] = True
        for expected, found in zip(rsv_used, rsv):
            if found and not expected:
                msg = "Reserved bit set unexpectedly"
                raise ParseFailed(msg)


class FrameProtocol:
    def __init__(
        self,
        client: bool,
        extensions: list[Extension],
        track_frame_sources: bool = False,
    ) -> None:
        self.client = client
        self.extensions = [ext for ext in extensions if ext.enabled()]

        # Global state
        self._frame_decoder = FrameDecoder(
            self.client,
            self.extensions,
            track_frame_sources,
        )
        self._message_decoder = MessageDecoder()
        self._parse_more = self._parse_more_gen()

        self._outbound_opcode: Opcode | None = None
        self._message_number = 0
        self._fragment_number = 0
        self._message_in_progress = False
        self._last_data_frame_number: int | None = None

    def _process_close(self, frame: Frame) -> Frame:
        data = frame.payload
        assert isinstance(data, (bytes, bytearray))

        if not data:
            # "If this Close control frame contains no status code, _The
            # WebSocket Connection Close Code_ is considered to be 1005"
            data = (CloseReason.NO_STATUS_RCVD, "")
        elif len(data) == 1:
            msg = "CLOSE with 1 byte payload"
            raise ParseFailed(msg)
        else:
            (code,) = struct.unpack("!H", data[:2])
            if code < MIN_CLOSE_REASON or code > MAX_CLOSE_REASON:
                msg = "CLOSE with invalid code"
                raise ParseFailed(msg)
            with contextlib.suppress(ValueError):
                code = CloseReason(code)
            if code in LOCAL_ONLY_CLOSE_REASONS:
                msg = "remote CLOSE with local-only reason"
                raise ParseFailed(msg)
            if not isinstance(code, CloseReason) and code <= MAX_PROTOCOL_CLOSE_REASON:
                msg = "CLOSE with unknown reserved code"
                raise ParseFailed(msg)
            try:
                reason = data[2:].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ParseFailed(
                    "Error decoding CLOSE reason: " + str(exc),
                    CloseReason.INVALID_FRAME_PAYLOAD_DATA,
                )
            data = (code, reason)

        return Frame(
            frame.opcode,
            data,
            frame.frame_finished,
            frame.message_finished,
            frame.source,
        )

    def _annotate_frame(self, frame: Frame) -> Frame:
        source = frame.source
        if source is None or frame.opcode.iscontrol():
            return frame

        if source.frame_number != self._last_data_frame_number:
            if not self._message_in_progress:
                self._fragment_number = 0
                self._message_in_progress = True
            else:
                self._fragment_number += 1
            self._last_data_frame_number = source.frame_number

        source = replace(
            source,
            message_number=self._message_number,
            fragment_number=self._fragment_number,
        )
        return Frame(
            frame.opcode,
            frame.payload,
            frame.frame_finished,
            frame.message_finished,
            source,
        )

    def _message_finished(self, frame: Frame) -> None:
        if (
            frame.frame_finished
            and frame.message_finished
            and not frame.opcode.iscontrol()
        ):
            self._message_number += 1
            self._fragment_number = 0
            self._message_in_progress = False

    def _parse_more_gen(self) -> Generator[Frame | None, None, None]:
        # Consume as much as we can from self._buffer, yielding events, and
        # then yield None when we need more data. Or raise ParseFailed.

        # XX FIXME this should probably be refactored so that we never see
        # disabled extensions in the first place...
        self.extensions = [ext for ext in self.extensions if ext.enabled()]
        closed = False

        while not closed:
            frame = self._frame_decoder.process_buffer()

            if frame is not None:
                if not frame.opcode.iscontrol():
                    frame = self._annotate_frame(frame)
                    frame = self._message_decoder.process_frame(frame)
                    self._message_finished(frame)
                elif frame.opcode == Opcode.CLOSE:
                    frame = self._process_close(frame)
                    closed = True

            yield frame

    def receive_bytes(self, data: bytes) -> None:
        self._frame_decoder.receive_bytes(data)

    def received_frames(self) -> Generator[Frame, None, None]:
        for event in self._parse_more:
            if event is None:
                break
            else:
                yield event

    def close(self, code: int | None = None, reason: str | None = None) -> bytearray:
        payload = bytearray()
        if code is CloseReason.NO_STATUS_RCVD:
            code = None
        if code is None and reason:
            msg = "cannot specify a reason without a code"
            raise TypeError(msg)
        if code in LOCAL_ONLY_CLOSE_REASONS:
            code = CloseReason.NORMAL_CLOSURE
        if code is not None:
            payload += bytearray(struct.pack("!H", code))
            if reason is not None:
                payload += _truncate_utf8(
                    reason.encode("utf-8"), MAX_PAYLOAD_NORMAL - 2,
                )

        return self._serialize_frame(Opcode.CLOSE, payload)

    def ping(self, payload: bytes = b"") -> bytearray:
        return self._serialize_frame(Opcode.PING, payload)

    def pong(self, payload: bytes = b"") -> bytearray:
        return self._serialize_frame(Opcode.PONG, payload)

    def send_data(
        self, payload: bytes | bytearray | str = b"", fin: bool = True,
    ) -> bytearray:
        if isinstance(payload, (bytes, bytearray, memoryview)):
            opcode = Opcode.BINARY
        elif isinstance(payload, str):
            opcode = Opcode.TEXT
            payload = payload.encode("utf-8")
        else:
            msg = "Must provide bytes or text"
            raise TypeError(msg)

        if self._outbound_opcode is None:
            self._outbound_opcode = opcode
        elif self._outbound_opcode is not opcode:
            msg = "Data type mismatch inside message"
            raise TypeError(msg)
        else:
            opcode = Opcode.CONTINUATION

        if fin:
            self._outbound_opcode = None

        return self._serialize_frame(opcode, payload, fin)

    def _make_fin_rsv_opcode(self, fin: bool, rsv: RsvBits, opcode: Opcode) -> int:
        fin_bits = int(fin) << 7
        rsv_bits = (int(rsv.rsv1) << 6) + (int(rsv.rsv2) << 5) + (int(rsv.rsv3) << 4)
        opcode_bits = int(opcode)

        return fin_bits | rsv_bits | opcode_bits

    def _serialize_frame(
        self, opcode: Opcode, payload: bytes | bytearray = b"", fin: bool = True,
    ) -> bytearray:
        payload = bytearray(payload)

        rsv = RsvBits(False, False, False)
        for extension in reversed(self.extensions):
            rsv, payload = extension.frame_outbound(self, opcode, rsv, bytes(payload), fin)

        fin_rsv_opcode = self._make_fin_rsv_opcode(fin, rsv, opcode)

        payload_length = len(payload)
        quad_payload = False
        if payload_length <= MAX_PAYLOAD_NORMAL:
            first_payload = payload_length
            second_payload = None
        elif payload_length <= MAX_PAYLOAD_TWO_BYTE:
            first_payload = PAYLOAD_LENGTH_TWO_BYTE
            second_payload = payload_length
        else:
            first_payload = PAYLOAD_LENGTH_EIGHT_BYTE
            second_payload = payload_length
            quad_payload = True

        if self.client:
            first_payload |= 1 << 7

        header = bytearray([fin_rsv_opcode, first_payload])
        if second_payload is not None:
            if opcode.iscontrol():
                msg = "payload too long for control frame"
                raise ValueError(msg)
            if quad_payload:
                header += bytearray(struct.pack("!Q", second_payload))
            else:
                header += bytearray(struct.pack("!H", second_payload))

        if self.client:
            # "The masking key is a 32-bit value chosen at random by the
            # client.  When preparing a masked frame, the client MUST pick a
            # fresh masking key from the set of allowed 32-bit values.  The
            # masking key needs to be unpredictable; thus, the masking key
            # MUST be derived from a strong source of entropy, and the masking
            # key for a given frame MUST NOT make it simple for a server/proxy
            # to predict the masking key for a subsequent frame.  The
            # unpredictability of the masking key is essential to prevent
            # authors of malicious applications from selecting the bytes that
            # appear on the wire."
            #   -- https://tools.ietf.org/html/rfc6455#section-5.3
            masking_key = bytearray(os.urandom(4))
            masker = XorMaskerSimple(masking_key)
            return bytearray(header + masking_key + masker.process(bytearray(payload)))

        return bytearray(header + payload)
