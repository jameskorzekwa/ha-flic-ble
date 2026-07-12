"""Flic 2 GATT protocol implementation.

This module implements the public Flic 2 protocol specification. The Chaskey
implementation is a Python translation of Shortcut Labs AB's permissively
licensed Android reference implementation; see NOTICE and FLIC_LICENSE.txt.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum, auto
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

FLIC_ED25519_PUBLIC_KEY: Final = bytes.fromhex(
    "d33f2440dd54b31b2e1dcf40132efa41d8f8a7474168df4008f5a95fb3b0d022"
)

OP_FULL_VERIFY_REQUEST_1 = 0
OP_FULL_VERIFY_RESPONSE_1 = 0
OP_FULL_VERIFY_RESPONSE_2 = 1
OP_NO_LOGICAL_CONNECTION_SLOTS = 2
OP_FULL_VERIFY_REQUEST_2 = 2
OP_FULL_VERIFY_FAIL_RESPONSE = 3
OP_QUICK_VERIFY_REQUEST = 5
OP_QUICK_VERIFY_NEGATIVE_RESPONSE = 6
OP_QUICK_VERIFY_RESPONSE = 8
OP_DISCONNECT_VERIFIED_LINK = 9
OP_INIT_BUTTON_EVENTS_RESPONSE_WITH_BOOT_ID = 10
OP_INIT_BUTTON_EVENTS_RESPONSE_WITHOUT_BOOT_ID = 11
OP_BUTTON_EVENT_NOTIFICATION = 12
OP_PING_RESPONSE = 14
OP_PING_REQUEST = 15
OP_ACK_BUTTON_EVENTS = 16
OP_GET_BATTERY_LEVEL_RESPONSE = 20
OP_INIT_BUTTON_EVENTS_LIGHT = 23
OP_INIT_BUTTON_EVENTS_DUO_RESPONSE_WITH_BOOT_ID = 30
OP_INIT_BUTTON_EVENTS_DUO_RESPONSE_WITHOUT_BOOT_ID = 31
OP_BUTTON_EVENT_DUO_NOTIFICATION = 32
OP_INIT_BUTTON_EVENTS_DUO_LIGHT = 35
OP_ACK_BUTTON_EVENTS_DUO = 36

_MASK32 = 0xFFFFFFFF


class Flic2ProtocolError(Exception):
    """Base protocol error."""


class PairingError(Flic2ProtocolError):
    """Pairing failed."""


class AuthenticationError(Flic2ProtocolError):
    """Packet authentication failed."""


class SessionState(Enum):
    """Flic protocol session states."""

    IDLE = auto()
    WAIT_FULL_VERIFY_1 = auto()
    WAIT_FULL_VERIFY_2 = auto()
    WAIT_QUICK_VERIFY = auto()
    ESTABLISHED = auto()
    FAILED = auto()


class PairingModeError(PairingError):
    """The button is not in public pairing mode."""


class NoPairingSlotsError(PairingError):
    """The button has no free logical pairing slots."""


class PairingRejectedError(PairingError):
    """The button explicitly rejected pairing."""


class PairingTimeoutError(PairingError):
    """Pairing stopped progressing in a known protocol state."""

    def __init__(self, state: SessionState) -> None:
        self.state = state
        super().__init__(f"Timed out in protocol state {state.name}")


@dataclass(slots=True)
class PairingData:
    """Persisted application-layer pairing credentials."""

    identifier: int
    key: bytes


@dataclass(slots=True)
class ButtonInfo:
    """Information returned after full verification."""

    uuid: str
    serial_number: str
    name: str
    firmware_version: int
    battery_voltage: float
    is_duo: bool = False


@dataclass(slots=True)
class ButtonEvent:
    """A decoded user-facing Flic event."""

    event_type: str
    event_count: int
    queued: bool
    timestamp_ms: int
    button: str = "big"
    gesture: str | None = None
    accelerometer: tuple[int, int, int] | None = None


@dataclass(slots=True)
class SessionResult:
    """Persistable state produced by a session."""

    pairing: PairingData | None = None
    info: ButtonInfo | None = None
    event_count: int = 0
    event_count_small: int = 0
    boot_id: int = 0
    battery_voltage: float | None = None
    is_duo: bool = False


@dataclass(slots=True)
class DuoDecodeResult:
    """State and user events decoded from one Duo notification."""

    events: list[ButtonEvent]
    event_counts: tuple[int, int]
    last_timestamp: int
    end_of_queue: bool
    needs_ack: bool
    hold_states: tuple[int, int]


_HOLD_NONE = 0
_HOLD_ACTIVE = 1
_HOLD_RELEASED = 2


class _BitReader:
    """Read the Duo's little-endian packed bitstream."""

    def __init__(self, data: bytes) -> None:
        self._value = int.from_bytes(data, "little")
        self._size = len(data) * 8
        self._position = 0

    @property
    def remaining(self) -> int:
        return self._size - self._position

    @property
    def unread_bytes(self) -> int:
        """Return whole unread bytes after the byte currently being consumed."""
        return self._size // 8 - (self._position + 7) // 8

    def read(self, width: int) -> int:
        if width < 0 or self._position + width > self._size:
            raise Flic2ProtocolError("Truncated Flic Duo event bitstream")
        value = (self._value >> self._position) & ((1 << width) - 1)
        self._position += width
        return value


def _signed_byte(value: int) -> int:
    return value - 256 if value >= 128 else value


def _duo_event_type(button_number: int, event_type: str) -> str:
    return f"small_{event_type}" if button_number else event_type


def decode_duo_button_events(
    payload: bytes,
    event_counts: tuple[int, int],
    last_timestamp: int,
    end_of_queue: bool,
    hold_states: tuple[int, int] = (_HOLD_NONE, _HOLD_NONE),
) -> DuoDecodeResult:
    """Decode Flic Duo button and swipe updates."""
    reader = _BitReader(payload)
    counts = [event_counts[0], event_counts[1]]
    got_event_count = [False, False]
    holds = [hold_states[0], hold_states[1]]
    events: list[ButtonEvent] = []
    needs_ack = False

    # Flic's reference decoder continues only while more than one untouched
    # byte remains. Bits at the end of the current byte plus the final byte are
    # padding and cannot begin another update.
    while reader.unread_bytes > 1:
        button_number = reader.read(1)
        if not got_event_count[button_number]:
            event_count_delta = reader.read(1)
            if event_count_delta == 1 and reader.read(1):
                width = (2, 4, 8, 32)[reader.read(2)]
                event_count_delta = reader.read(width)
            counts[button_number] += event_count_delta + 1
            got_event_count[button_number] = True
        else:
            counts[button_number] += 1

        timestamp_width = (8, 10, 13, 16, 24, 32, 40, 48)[reader.read(3)]
        last_timestamp += reader.read(timestamp_width)

        queued = False
        if not end_of_queue:
            if reader.read(1) == 0:
                queued = True
            else:
                end_of_queue = True
                queued = reader.read(1) == 0

        event_code = reader.read(3)
        double_click_was_hold = False
        next_up_will_be_double = False
        if event_code == 4:
            double_click_was_hold = bool(reader.read(1))
        elif event_code == 7:
            next_up_will_be_double = bool(reader.read(1))

        gesture: str | None = None
        if event_code <= 4 or event_code == 6:
            if reader.read(1):
                if reader.read(1):
                    gesture = ("left", "right", "up", "down")[reader.read(2)]
                else:
                    gesture = "unrecognized"

        acceleration = tuple(_signed_byte(reader.read(8)) for _ in range(3))

        if event_code <= 5 and counts[button_number] % 2 == 0:
            counts[button_number] += 1

        event_count = counts[button_number]
        button = "small" if button_number else "big"
        event_type: str | None = None
        suppress_click_after_hold = False
        if event_code == 5:
            # A new physical press always starts a new gesture sequence.
            holds[button_number] = _HOLD_NONE
        elif event_code == 7 and not next_up_will_be_double:
            holds[button_number] = _HOLD_ACTIVE
        elif event_code <= 4 and holds[button_number] != _HOLD_NONE:
            # The release belongs to the hold already emitted to HA. Keep a
            # marker for a possible single-click-timeout update that can
            # arrive in a later notification.
            suppress_click_after_hold = True
            holds[button_number] = _HOLD_RELEASED
        elif event_code == 6 and holds[button_number] != _HOLD_NONE:
            suppress_click_after_hold = True
            if holds[button_number] == _HOLD_RELEASED:
                holds[button_number] = _HOLD_NONE

        if event_code <= 4:
            was_hold = event_code == 2 or (event_code == 4 and double_click_was_hold)
            single_click = event_code in (1, 2)
            double_click = event_code in (3, 4)
            if single_click:
                event_type = "single"
            elif double_click:
                event_type = "double"
            if single_click or double_click:
                needs_ack = True
            if was_hold and not double_click:
                event_type = None
        elif event_code == 6:
            event_type = "single"
            needs_ack = True
        elif event_code == 7 and not next_up_will_be_double:
            event_type = "hold"

        if suppress_click_after_hold:
            event_type = None

        recognized_gesture = gesture in ("left", "right", "up", "down")
        if recognized_gesture:
            # Treat a swipe as the user's action, not as a swipe plus the
            # physical click that was required to activate gesture detection.
            event_type = None

        if event_type:
            events.append(
                ButtonEvent(
                    _duo_event_type(button_number, event_type),
                    event_count,
                    queued,
                    last_timestamp,
                    button,
                    gesture,
                    acceleration,
                )
            )
        # The single-click timeout repeats the gesture attached to the earlier
        # release. Emit the swipe only from that release to avoid duplicates.
        if event_code <= 4 and recognized_gesture:
            events.append(
                ButtonEvent(
                    _duo_event_type(button_number, f"swipe_{gesture}"),
                    event_count,
                    queued,
                    last_timestamp,
                    button,
                    gesture,
                    acceleration,
                )
            )

    return DuoDecodeResult(
        events,
        (counts[0], counts[1]),
        last_timestamp,
        end_of_queue,
        needs_ack,
        (holds[0], holds[1]),
    )


def _rol32(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (32 - bits))) & _MASK32


def _u32(value: int) -> int:
    return value & _MASK32


def chaskey_subkeys(key: bytes) -> tuple[int, ...]:
    """Generate Chaskey K, K1 and K2 words."""
    if len(key) != 16:
        raise ValueError("Chaskey keys must be 16 bytes")
    words = list(struct.unpack("<4I", key))
    result = words.copy()
    for _ in range(2):
        v0, v1, v2, v3 = words
        carry = 0x87 if v3 >> 31 else 0
        words = [
            _u32((v0 << 1) ^ carry),
            _u32((v1 << 1) | (v0 >> 31)),
            _u32((v2 << 1) | (v1 >> 31)),
            _u32((v3 << 1) | (v2 >> 31)),
        ]
        result.extend(words)
    return tuple(result)


def _chaskey_permute(v0: int, v1: int, v2: int, v3: int) -> tuple[int, ...]:
    v2 = _rol32(v2, 16)
    for _ in range(16):
        v0 = _u32(v0 + v1)
        v1 = v0 ^ _rol32(v1, 5)
        v2 = _u32(v3 + _rol32(v2, 16))
        v3 = v2 ^ _rol32(v3, 8)
        v2 = _u32(v2 + v1)
        v0 = _u32(v3 + _rol32(v0, 16))
        v1 = v2 ^ _rol32(v1, 7)
        v3 = v0 ^ _rol32(v3, 13)
    v2 = _rol32(v2, 16)
    return _u32(v0), _u32(v1), _u32(v2), _u32(v3)


def chaskey_16(key: bytes, message: bytes) -> bytes:
    """Calculate the 16-byte Chaskey-LTS result for a 16-byte message."""
    if len(message) != 16:
        raise ValueError("This Flic Chaskey operation requires exactly 16 bytes")
    keys = chaskey_subkeys(key)
    msg = struct.unpack("<4I", message)
    v = tuple(keys[i] ^ keys[i + 4] ^ msg[i] for i in range(4))
    v = _chaskey_permute(*v)
    return struct.pack("<4I", *(v[i] ^ keys[i + 4] for i in range(4)))


def chaskey_signature(key: bytes, direction: int, counter: int, packet: bytes) -> bytes:
    """Calculate Flic's five-byte signed-packet authenticator."""
    if not packet:
        raise ValueError("Cannot sign an empty packet")
    keys = chaskey_subkeys(key)
    v0 = keys[0] ^ (counter & _MASK32)
    v1 = keys[1] ^ ((counter >> 32) & _MASK32)
    v2 = keys[2] ^ direction
    v3 = keys[3]
    offset = 0
    remaining = len(packet)
    first = True
    while True:
        key_offset = 0
        if not first:
            if remaining >= 16:
                block = struct.unpack_from("<4I", packet, offset)
                v0 ^= block[0]
                v1 ^= block[1]
                v2 ^= block[2]
                v3 ^= block[3]
                offset += 16
                remaining -= 16
                if remaining == 0:
                    key_offset = 4
            else:
                tail = packet[offset:] + b"\x01" + bytes(15 - remaining)
                block = struct.unpack("<4I", tail)
                v0 ^= block[0]
                v1 ^= block[1]
                v2 ^= block[2]
                v3 ^= block[3]
                key_offset = 8
            if key_offset:
                v0 ^= keys[key_offset]
                v1 ^= keys[key_offset + 1]
                v2 ^= keys[key_offset + 2]
                v3 ^= keys[key_offset + 3]
        else:
            first = False
        v0, v1, v2, v3 = _chaskey_permute(v0, v1, v2, v3)
        if key_offset:
            v0 ^= keys[key_offset]
            v1 ^= keys[key_offset + 1]
            return struct.pack("<IB", _u32(v0), v1 & 0xFF)


def decode_button_events(payload: bytes, final_event_count: int) -> list[ButtonEvent]:
    """Decode Flic 2 event items into single/double/hold events."""
    events: list[ButtonEvent] = []
    for offset in range(0, len(payload) - 6, 7):
        raw = int.from_bytes(payload[offset : offset + 7], "little")
        timestamp_ms = (raw & ((1 << 48) - 1)) * 1000 // 32768
        event_encoded = (raw >> 48) & 0xF
        queued = bool((raw >> 52) & 1)
        base_type = event_encoded & 3
        was_hold = single = double = next_up_double = False
        if event_encoded & 8:
            base_type = 0
            was_hold = bool(event_encoded & 4)
            single = bool(event_encoded & 2) and not bool(event_encoded & 1)
            double = bool(event_encoded & 2) and bool(event_encoded & 1)
        elif event_encoded == 7:
            next_up_double = True

        event_type: str | None = None
        if base_type == 0:
            if single:
                event_type = "single"
            elif double:
                event_type = "double"
            elif not was_hold:
                # A plain up is a click for click/hold mode, but Flic normally
                # follows it with a single-click timeout. Wait for that packet.
                event_type = None
        elif base_type == 2:
            event_type = "single"
        elif base_type == 3 and not next_up_double:
            event_type = "hold"
        if event_type:
            events.append(
                ButtonEvent(event_type, final_event_count, queued, timestamp_ms)
            )
    return events


def button_events_need_ack(payload: bytes) -> bool:
    """Return whether a button-event notification requires acknowledgement."""
    for offset in range(0, len(payload) - 6, 7):
        raw = int.from_bytes(payload[offset : offset + 7], "little")
        encoded = (raw >> 48) & 0xF
        base_type = encoded & 3
        single_or_double_up = bool(encoded & 8) and bool(encoded & 2)
        if base_type == 2 or single_or_double_up:
            return True
    return False


class Flic2Session:
    """State machine for one Flic 2 GATT connection."""

    def __init__(
        self,
        address: str,
        send_gatt: Callable[[bytes], Awaitable[None]],
        *,
        pairing: PairingData | None = None,
        event_count: int = 0,
        event_count_small: int = 0,
        boot_id: int = 0,
        event_callback: Callable[[ButtonEvent], None] | None = None,
        state_callback: Callable[[SessionResult], None] | None = None,
        mtu: int = 23,
        auto_disconnect_time: int = 60,
    ) -> None:
        self.address = address.upper()
        self._send_gatt = send_gatt
        self._event_callback = event_callback
        self._state_callback = state_callback
        self._mtu = max(23, mtu)
        self._auto_disconnect_time = min(max(auto_disconnect_time, 40), 511)
        self.result = SessionResult(
            pairing=pairing,
            event_count=event_count,
            event_count_small=event_count_small,
            boot_id=boot_id,
        )
        self.state = SessionState.IDLE
        self.ready = asyncio.Event()
        self.pairing_complete = asyncio.Event()
        self.failure: Exception | None = None
        self._tmp_id = 0
        self._conn_id = 0
        self._session_key: bytes | None = None
        self._rx_counter = 0
        self._tx_counter = 0
        self._qv_random = b""
        self._full_verify_hmac_key: bytes | None = None
        self._pending_fragment = bytearray()
        self._private_key: X25519PrivateKey | None = None
        self._client_random = b""
        self._supports_duo_flag = 0x80
        self._is_duo = False
        self._duo_last_timestamp = 0
        self._duo_end_of_queue = False
        self._duo_hold_states = (_HOLD_NONE, _HOLD_NONE)

    async def start(self) -> None:
        """Start full pairing or quick verification."""
        self._tmp_id = struct.unpack("<I", os.urandom(4))[0]
        if self.result.pairing is None:
            self.state = SessionState.WAIT_FULL_VERIFY_1
            await self._send_unsigned(
                bytes([OP_FULL_VERIFY_REQUEST_1]) + struct.pack("<I", self._tmp_id)
            )
            return
        self.state = SessionState.WAIT_QUICK_VERIFY
        self._qv_random = os.urandom(7)
        flags = 0x40  # Duo support; signature/encryption variant 0
        packet = (
            bytes([OP_QUICK_VERIFY_REQUEST])
            + self._qv_random
            + bytes([flags])
            + struct.pack("<II", self._tmp_id, self.result.pairing.identifier)
        )
        await self._send_unsigned(packet)

    async def feed_gatt(self, value: bytes) -> None:
        """Process a notification from the Flic RX characteristic."""
        try:
            for header, packet in self._defragment(value):
                await self._handle_packet(header, packet)
        except Exception as err:  # surfaced to the config flow/runtime
            self.failure = err
            self.state = SessionState.FAILED
            self.ready.set()
            self.pairing_complete.set()
            raise

    def _defragment(self, value: bytes) -> list[tuple[int, bytes]]:
        if len(value) < 2:
            return []
        header = value[0]
        fragment = bool(header & 0x80)
        if fragment or self._pending_fragment:
            self._pending_fragment.extend(value[1:])
            if fragment:
                return []
            packet = bytes(self._pending_fragment)
            self._pending_fragment.clear()
            return [(header, packet)]
        if header & 0x40:
            packets: list[tuple[int, bytes]] = []
            # The first byte is both the notification header and the first
            # packet header. Each packet is ``header, length, payload``.
            pos = 0
            while pos + 2 <= len(value):
                item_header = value[pos]
                size = value[pos + 1]
                pos += 2
                if pos + size > len(value):
                    break
                packets.append((item_header, value[pos : pos + size]))
                pos += size
            return packets
        return [(header, value[1:])]

    async def _send_unsigned(self, packet: bytes) -> None:
        await self._send_packet(packet)

    async def _send_signed(self, packet: bytes) -> None:
        if self._session_key is None:
            raise Flic2ProtocolError("Session key is not established")
        signature = chaskey_signature(self._session_key, 1, self._tx_counter, packet)
        self._tx_counter += 1
        await self._send_packet(packet + signature)

    async def _send_packet(self, packet: bytes) -> None:
        max_fragment = max(1, self._mtu - 4)
        if len(packet) <= self._mtu - 4:
            await self._send_gatt(bytes([self._conn_id]) + packet)
            return
        for offset in range(0, len(packet), max_fragment):
            last = offset + max_fragment >= len(packet)
            header = self._conn_id | (0 if last else 0x80)
            await self._send_gatt(
                bytes([header]) + packet[offset : offset + max_fragment]
            )

    def _verify_signed(self, packet: bytes) -> bytes:
        if self._session_key is None or len(packet) < 6:
            raise AuthenticationError("Missing session key or packet signature")
        unsigned, signature = packet[:-5], packet[-5:]
        expected = chaskey_signature(self._session_key, 0, self._rx_counter, unsigned)
        self._rx_counter += 1
        if not hmac.compare_digest(signature, expected):
            raise AuthenticationError("Invalid Flic packet signature")
        return unsigned

    async def _handle_packet(self, header: int, packet: bytes) -> None:
        if not packet:
            return
        conn_id = header & 0x1F
        newly_assigned = bool(header & 0x20)
        opcode = packet[0]

        if opcode == OP_NO_LOGICAL_CONNECTION_SLOTS:
            ids = [x[0] for x in struct.iter_unpack("<I", packet[1:])]
            if self._tmp_id in ids:
                raise NoPairingSlotsError(
                    "The button has no free logical connection slots"
                )
            return

        if (
            self.state is SessionState.WAIT_FULL_VERIFY_1
            and opcode == OP_FULL_VERIFY_RESPONSE_1
        ):
            await self._handle_full_verify_1(conn_id, newly_assigned, packet[1:])
            return
        if (
            self.state is SessionState.WAIT_FULL_VERIFY_2
            and opcode == OP_FULL_VERIFY_RESPONSE_2
        ):
            await self._handle_full_verify_2(conn_id, packet)
            return
        if (
            self.state is SessionState.WAIT_FULL_VERIFY_2
            and opcode == OP_FULL_VERIFY_FAIL_RESPONSE
        ):
            reason = packet[1] if len(packet) > 1 else 255
            raise PairingRejectedError(f"Flic rejected pairing (reason {reason})")
        if self.state is SessionState.WAIT_QUICK_VERIFY:
            if opcode == OP_QUICK_VERIFY_NEGATIVE_RESPONSE:
                raise PairingError("The stored Flic pairing is no longer valid")
            if opcode == OP_QUICK_VERIFY_RESPONSE:
                await self._handle_quick_verify(conn_id, newly_assigned, packet)
            return
        if self.state is not SessionState.ESTABLISHED or conn_id != self._conn_id:
            return
        unsigned = self._verify_signed(packet)
        await self._handle_established(unsigned)

    async def _handle_full_verify_1(
        self, conn_id: int, newly_assigned: bool, data: bytes
    ) -> None:
        if not newly_assigned or len(data) < 116:
            raise PairingError("Malformed first verification response")
        tmp_id = struct.unpack_from("<I", data, 0)[0]
        if tmp_id != self._tmp_id:
            return
        signature = data[4:68]
        address_bytes = data[68:74]
        address_type = data[74]
        button_public = data[75:107]
        button_random = data[107:115]
        flags = data[115]
        returned_address = ":".join(f"{byte:02X}" for byte in reversed(address_bytes))
        if returned_address != self.address:
            raise PairingError(
                "Button address mismatch: "
                f"expected {self.address}, got {returned_address}"
            )
        if not flags & 0x02:
            raise PairingModeError("The button left public pairing mode")

        message = address_bytes + bytes([address_type]) + button_public
        sig_bits = self._verify_button_certificate(signature, message)
        self._conn_id = conn_id
        self._private_key = X25519PrivateKey.generate()
        client_public = self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        shared = self._private_key.exchange(
            X25519PublicKey.from_public_bytes(button_public)
        )
        self._client_random = os.urandom(8)
        request_flags = self._supports_duo_flag
        self._full_verify_hmac_key = hashlib.sha256(
            shared
            + bytes([sig_bits])
            + button_random
            + self._client_random
            + bytes([request_flags])
        ).digest()
        verifier = hmac.new(self._full_verify_hmac_key, b"AT", hashlib.sha256).digest()[
            :16
        ]
        self._session_key = hmac.new(
            self._full_verify_hmac_key, b"SK", hashlib.sha256
        ).digest()[:16]
        request = (
            bytes([OP_FULL_VERIFY_REQUEST_2])
            + client_public
            + self._client_random
            + bytes([request_flags])
            + verifier
        )
        self.state = SessionState.WAIT_FULL_VERIFY_2
        await self._send_unsigned(request)

    @staticmethod
    def _verify_button_certificate(signature: bytes, message: bytes) -> int:
        public_key = Ed25519PublicKey.from_public_bytes(FLIC_ED25519_PUBLIC_KEY)
        matches: list[int] = []
        for sig_bits in range(4):
            candidate = bytearray(signature)
            candidate[32] = (candidate[32] & 0xFC) | sig_bits
            try:
                public_key.verify(bytes(candidate), message)
            except InvalidSignature:
                continue
            matches.append(sig_bits)
        if len(matches) != 1:
            raise AuthenticationError("The Flic authenticity certificate is invalid")
        return matches[0]

    async def _handle_full_verify_2(self, conn_id: int, packet: bytes) -> None:
        if conn_id != self._conn_id:
            return
        unsigned = self._verify_signed(packet)
        data = unsigned[1:]
        if len(data) < 58 or self._full_verify_hmac_key is None:
            raise PairingError("Malformed second verification response")
        flags = data[0]
        if not flags & 0x01:
            raise AuthenticationError("Flic application credentials did not match")
        button_uuid = data[1:17].hex()
        name_len = min(data[17], 23)
        name = data[18 : 18 + name_len].decode("utf-8", "replace")
        firmware_offset = 18 + 23
        firmware = struct.unpack_from("<I", data, firmware_offset)[0]
        battery = struct.unpack_from("<H", data, firmware_offset + 4)[0]
        serial = data[firmware_offset + 6 : firmware_offset + 17].decode(
            "ascii", "replace"
        )
        pk = hmac.new(self._full_verify_hmac_key, b"PK", hashlib.sha256).digest()
        self.result.pairing = PairingData(struct.unpack_from("<I", pk)[0], pk[4:20])
        self.result.info = ButtonInfo(
            button_uuid,
            serial,
            name,
            firmware,
            battery * 3.6 / 1024.0,
            bool(flags & 0x04),
        )
        self._is_duo = self.result.info.is_duo
        self.result.is_duo = self._is_duo
        self.result.battery_voltage = self.result.info.battery_voltage
        self.state = SessionState.ESTABLISHED
        self.pairing_complete.set()
        await self._send_init(full_pairing=True)

    async def _handle_quick_verify(
        self, conn_id: int, newly_assigned: bool, packet: bytes
    ) -> None:
        if not newly_assigned or len(packet) < 19 or self.result.pairing is None:
            raise AuthenticationError("Malformed quick verification response")
        data = packet[1:]
        button_random = data[:8]
        tmp_id = struct.unpack_from("<I", data, 8)[0]
        if tmp_id != self._tmp_id:
            return
        flags = 0x40
        quick_message = self._qv_random + bytes([flags]) + button_random
        self._session_key = chaskey_16(self.result.pairing.key, quick_message)
        self._conn_id = conn_id
        self._verify_signed(packet)
        self._is_duo = bool(data[12] & 0x04)
        self.result.is_duo = self._is_duo
        self.state = SessionState.ESTABLISHED
        await self._send_init(full_pairing=False)

    async def _send_init(self, *, full_pairing: bool) -> None:
        options = (
            (self._auto_disconnect_time & 0x1FF)
            | ((0 if full_pairing else 31) << 9)
            | (0xFFFFF << 14)
        )
        if self._is_duo:
            packet = (
                bytes([OP_INIT_BUTTON_EVENTS_DUO_LIGHT])
                + struct.pack(
                    "<III",
                    self.result.event_count,
                    self.result.event_count_small,
                    self.result.boot_id,
                )
                + options.to_bytes(5, "little")
            )
        else:
            packet = (
                bytes([OP_INIT_BUTTON_EVENTS_LIGHT])
                + struct.pack("<II", self.result.event_count, self.result.boot_id)
                + options.to_bytes(5, "little")
            )
        await self._send_signed(packet)

    async def _handle_established(self, packet: bytes) -> None:
        opcode = packet[0]
        data = packet[1:]
        if opcode in (
            OP_INIT_BUTTON_EVENTS_RESPONSE_WITH_BOOT_ID,
            OP_INIT_BUTTON_EVENTS_RESPONSE_WITHOUT_BOOT_ID,
        ):
            if len(data) < 10:
                raise Flic2ProtocolError("Malformed init response")
            packed_time = int.from_bytes(data[:6], "little")
            has_queued = bool(packed_time & 1)
            self.result.event_count = struct.unpack_from("<I", data, 6)[0]
            if opcode == OP_INIT_BUTTON_EVENTS_RESPONSE_WITH_BOOT_ID:
                if len(data) < 14:
                    raise Flic2ProtocolError("Init response omitted its boot id")
                self.result.boot_id = struct.unpack_from("<I", data, 10)[0]
            self.ready.set()
            self._notify_state()
            if not has_queued:
                return
        elif opcode in (
            OP_INIT_BUTTON_EVENTS_DUO_RESPONSE_WITH_BOOT_ID,
            OP_INIT_BUTTON_EVENTS_DUO_RESPONSE_WITHOUT_BOOT_ID,
        ):
            if len(data) < 14:
                raise Flic2ProtocolError("Malformed Flic Duo init response")
            packed_time = int.from_bytes(data[:6], "little")
            has_queued = bool(packed_time & 1)
            self.result.event_count, self.result.event_count_small = struct.unpack_from(
                "<II", data, 6
            )
            if opcode == OP_INIT_BUTTON_EVENTS_DUO_RESPONSE_WITH_BOOT_ID:
                if len(data) < 18:
                    raise Flic2ProtocolError("Duo init response omitted its boot id")
                self.result.boot_id = struct.unpack_from("<I", data, 14)[0]
            self._duo_last_timestamp = 0
            self._duo_end_of_queue = not has_queued
            self._duo_hold_states = (_HOLD_NONE, _HOLD_NONE)
            self.ready.set()
            self._notify_state()
        elif opcode == OP_BUTTON_EVENT_NOTIFICATION:
            if len(data) < 11:
                return
            event_count = struct.unpack_from("<I", data, 0)[0]
            events = decode_button_events(data[4:], event_count)
            self.result.event_count = event_count
            self._notify_state()
            for event in events:
                if self._event_callback:
                    self._event_callback(event)
            if button_events_need_ack(data[4:]):
                await self._send_signed(
                    bytes([OP_ACK_BUTTON_EVENTS]) + struct.pack("<I", event_count)
                )
        elif opcode == OP_BUTTON_EVENT_DUO_NOTIFICATION:
            decoded = decode_duo_button_events(
                data,
                (self.result.event_count, self.result.event_count_small),
                self._duo_last_timestamp,
                self._duo_end_of_queue,
                self._duo_hold_states,
            )
            self.result.event_count, self.result.event_count_small = (
                decoded.event_counts
            )
            self._duo_last_timestamp = decoded.last_timestamp
            self._duo_end_of_queue = decoded.end_of_queue
            self._duo_hold_states = decoded.hold_states
            self._notify_state()
            for event in decoded.events:
                if self._event_callback:
                    self._event_callback(event)
            if decoded.needs_ack:
                await self._send_signed(
                    bytes([OP_ACK_BUTTON_EVENTS_DUO])
                    + struct.pack("<II", *decoded.event_counts)
                )
        elif opcode == OP_PING_REQUEST:
            await self._send_signed(bytes([OP_PING_RESPONSE]))
        elif opcode == OP_GET_BATTERY_LEVEL_RESPONSE and len(data) >= 2:
            self.result.battery_voltage = (
                struct.unpack_from("<H", data)[0] * 3.6 / 1024.0
            )
            self._notify_state()
        elif opcode == OP_DISCONNECT_VERIFIED_LINK:
            raise Flic2ProtocolError("Flic terminated the verified session")

    def _notify_state(self) -> None:
        if self._state_callback:
            self._state_callback(self.result)
