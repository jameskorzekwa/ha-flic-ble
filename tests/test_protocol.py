"""Tests for the standalone Flic protocol implementation."""

from __future__ import annotations

import struct

import pytest

from custom_components.flic_ble.protocol import (
    ADV_INTERVAL_FAST,
    ADV_INTERVAL_SLOW,
    ADV_TIMEOUT_SECONDS,
    OP_FORCE_BT_DISCONNECT,
    OP_GET_FIRMWARE_VERSION_REQUEST,
    OP_GET_FIRMWARE_VERSION_RESPONSE,
    OP_INIT_BUTTON_EVENTS_DUO_RESPONSE_WITHOUT_BOOT_ID,
    OP_INIT_BUTTON_EVENTS_RESPONSE_WITH_BOOT_ID,
    OP_SET_ADV_PARAMETERS_REQUEST,
    OP_SET_ADV_PARAMETERS_RESPONSE,
    FlicProtocolError,
    FlicSession,
    NoPairingSlotsError,
    PairingData,
    PairingTimeoutError,
    SessionState,
    button_events_need_ack,
    chaskey_16,
    chaskey_signature,
    chaskey_subkeys,
    decode_button_events,
    decode_duo_button_events,
)


def _event_item(encoded: int, *, queued: bool = False, timestamp: int = 32768) -> bytes:
    raw = timestamp | (encoded << 48) | (int(queued) << 52)
    return raw.to_bytes(7, "little")


_RAW_TYPES = {"up", "down", "small_up", "small_down"}


def _user(events):
    """Events other than the raw press and release ones."""
    return [event for event in events if event.event_type not in _RAW_TYPES]


def _types(events) -> list[str]:
    return [event.event_type for event in events]


def _packed_bits(*fields: tuple[int, int]) -> bytes:
    value = 0
    position = 0
    for item, width in fields:
        value |= item << position
        position += width
    return value.to_bytes((position + 7) // 8, "little")


def test_chaskey_subkeys_are_deterministic() -> None:
    keys = chaskey_subkeys(bytes(range(16)))
    assert len(keys) == 12
    assert keys[:4] == (0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C)
    assert chaskey_subkeys(bytes(range(16))) == keys


def test_chaskey_operations_have_expected_lengths_and_avalanche() -> None:
    key = bytes(range(16))
    block = bytes(range(16, 32))
    first = chaskey_16(key, block)
    second = chaskey_16(key, block[:-1] + bytes([block[-1] ^ 1]))
    assert len(first) == 16
    assert first != second
    signature = chaskey_signature(key, 1, 0x1122334455667788, bytes(range(37)))
    assert len(signature) == 5
    assert signature != chaskey_signature(key, 0, 0x1122334455667788, bytes(range(37)))


def test_decode_single_double_and_hold() -> None:
    payload = b"".join(
        [
            _event_item(0b1010),  # up + single
            _event_item(0b1011),  # up + double
            _event_item(0b0011),  # hold
        ]
    )
    events = decode_button_events(payload, 12)
    assert _types(_user(events)) == ["single", "double", "hold"]
    # Every release is reported, including the one ending a double click.
    assert _types(events) == ["up", "single", "up", "double", "hold"]
    assert all(event.timestamp_ms == 1000 for event in events)
    assert button_events_need_ack(payload)


def test_plain_up_down_only_create_raw_events() -> None:
    events = decode_button_events(_event_item(0) + _event_item(1), 2)
    assert _types(events) == ["up", "down"]
    assert _user(events) == []
    assert not button_events_need_ack(_event_item(0) + _event_item(1))


def test_base_flic_hold_release_does_not_emit_single() -> None:
    # Captured from a round Flic v2 button: down, hold, then up+single+was_hold.
    down = bytes.fromhex("a2267246ca0031")
    hold = bytes.fromhex("a2a67246ca0003")
    release = bytes.fromhex("37d27246ca000e")

    assert _types(decode_button_events(down, 153)) == ["down"]
    assert _types(decode_button_events(hold, 154)) == ["hold"]
    assert _types(decode_button_events(release, 155)) == ["up"]
    assert button_events_need_ack(release)


@pytest.mark.asyncio
async def test_quick_verify_request_is_fragmented_for_default_mtu() -> None:
    writes: list[bytes] = []

    async def send(value: bytes) -> None:
        writes.append(value)

    session = FlicSession(
        "01:02:03:04:05:06",
        send,
        pairing=PairingData(0x01020304, bytes(range(16))),
        mtu=23,
    )
    await session.start()
    assert session.state is SessionState.WAIT_QUICK_VERIFY
    assert len(writes) == 1
    assert writes[0][1] == 5
    assert writes[0][9] == 0x40
    assert struct.unpack_from("<I", writes[0], 14)[0] == 0x01020304


def test_decode_duo_big_single_and_swipe_left() -> None:
    payload = _packed_bits(
        (0, 1),  # big button
        (0, 1),  # first event counter is previous + 1
        (0, 3),
        (5, 8),  # timestamp delta
        (1, 3),  # single click
        (1, 1),
        (1, 1),
        (0, 2),  # recognized left swipe
        (1, 8),
        (254, 8),
        (3, 8),
    )

    decoded = decode_duo_button_events(payload, (0, 0), 0, True)

    assert _types(_user(decoded.events)) == ["swipe_left"]
    assert all(event.button == "big" for event in _user(decoded.events))
    assert all(event.gesture == "left" for event in _user(decoded.events))
    assert all(event.accelerometer == (1, -2, 3) for event in _user(decoded.events))
    assert decoded.event_counts == (1, 0)
    assert decoded.last_timestamp == 5
    assert decoded.needs_ack


def test_duo_double_click_with_gesture_stays_double_click() -> None:
    payload = _packed_bits(
        (0, 1),  # big button
        (1, 1),
        (1, 1),
        (1, 2),  # four-bit event counter delta
        (7, 4),  # eight raw events for a physical double click
        (0, 3),
        (5, 8),  # timestamp delta
        (3, 3),  # double click
        (1, 1),  # motion detected
        (1, 1),  # recognized gesture
        (3, 2),  # down
        (247, 8),
        (3, 8),
        (89, 8),
    )

    decoded = decode_duo_button_events(payload, (100, 0), 0, True)

    assert _types(_user(decoded.events)) == ["double"]
    assert _user(decoded.events)[0].gesture == "down"
    assert _user(decoded.events)[0].accelerometer == (-9, 3, 89)
    assert decoded.event_counts == (109, 0)
    assert decoded.needs_ack


def test_duo_decoder_ignores_final_padding_byte() -> None:
    payload = (
        _packed_bits(
            (0, 1),
            (0, 1),
            (0, 3),
            (5, 8),
            (1, 3),
            (0, 1),
            (0, 8),
            (0, 8),
            (64, 8),
        )
        + b"\x00"
    )

    decoded = decode_duo_button_events(payload, (0, 0), 0, True)

    assert _types(_user(decoded.events)) == ["single"]


def test_duo_click_timeout_does_not_repeat_swipe() -> None:
    payload = _packed_bits(
        (0, 1),
        (0, 1),
        (0, 3),
        (5, 8),
        (6, 3),
        (1, 1),
        (1, 1),
        (3, 2),
        (0, 8),
        (0, 8),
        (64, 8),
    )

    decoded = decode_duo_button_events(payload, (0, 0), 0, True)

    assert _user(decoded.events) == []


def test_duo_unrecognized_gesture_preserves_click() -> None:
    payload = _packed_bits(
        (0, 1),
        (0, 1),
        (0, 3),
        (5, 8),
        (1, 3),
        (1, 1),  # motion detected
        (0, 1),  # gesture not recognized
        (0, 8),
        (0, 8),
        (64, 8),
    )

    decoded = decode_duo_button_events(payload, (0, 0), 0, True)

    assert _types(_user(decoded.events)) == ["single"]
    assert _user(decoded.events)[0].gesture == "unrecognized"


def test_decode_duo_small_button_hold() -> None:
    payload = _packed_bits(
        (1, 1),  # small button
        (0, 1),
        (0, 3),
        (9, 8),
        (7, 3),  # hold
        (0, 1),  # next release is not a double click
        (0, 8),
        (64, 8),
        (192, 8),
    )

    decoded = decode_duo_button_events(payload, (12, 20), 100, True)

    assert _types(_user(decoded.events)) == ["small_hold"]
    assert _user(decoded.events)[0].button == "small"
    assert _user(decoded.events)[0].accelerometer == (0, 64, -64)
    assert decoded.event_counts == (12, 21)
    assert decoded.last_timestamp == 109
    assert not decoded.needs_ack


def test_decode_multiple_duo_updates_from_one_packet() -> None:
    payload = _packed_bits(
        (0, 1),
        (0, 1),
        (0, 3),
        (2, 8),
        (5, 3),  # big button down
        (0, 8),
        (0, 8),
        (64, 8),
        (0, 1),
        (0, 3),
        (6, 8),
        (6, 3),  # single-click timeout for the same button
        (0, 1),  # no gesture
        (0, 8),
        (0, 8),
        (64, 8),
    )

    decoded = decode_duo_button_events(payload, (0, 0), 0, True)

    assert _types(_user(decoded.events)) == ["single"]
    assert decoded.event_counts == (2, 0)
    assert decoded.last_timestamp == 8
    assert decoded.needs_ack


@pytest.mark.asyncio
async def test_duo_init_contains_both_event_counters() -> None:
    writes: list[bytes] = []

    async def send(value: bytes) -> None:
        writes.append(value)

    session = FlicSession(
        "01:02:03:04:05:06",
        send,
        pairing=PairingData(1, bytes(range(16))),
        event_count=12,
        event_count_small=34,
        boot_id=56,
        mtu=100,
    )
    session._is_duo = True
    session._session_key = bytes(range(16))

    await session._send_init(full_pairing=False)

    assert writes[0][1] == 35
    assert struct.unpack_from("<III", writes[0], 2) == (12, 34, 56)


@pytest.mark.asyncio
async def test_no_pairing_slots_has_specific_error() -> None:
    writes: list[bytes] = []

    async def send(value: bytes) -> None:
        writes.append(value)

    session = FlicSession("01:02:03:04:05:06", send)
    await session.start()
    temporary_id = struct.unpack_from("<I", writes[0], 2)[0]

    with pytest.raises(NoPairingSlotsError):
        await session.feed_gatt(bytes([0, 2]) + struct.pack("<I", temporary_id))


def test_pairing_timeout_preserves_protocol_state() -> None:
    error = PairingTimeoutError(SessionState.ESTABLISHED)

    assert error.state is SessionState.ESTABLISHED
    assert str(error) == "Timed out in protocol state ESTABLISHED"


def test_multiple_packet_notification() -> None:
    """The outer header is also the first packet header."""

    async def send(_: bytes) -> None:
        return None

    session = FlicSession("AA:BB:CC:DD:EE:FF", send)
    value = bytes([0x40, 2, 0x10, 0x11, 0x01, 3, 0x20, 0x21, 0x22])

    assert session._defragment(value) == [
        (0x40, bytes([0x10, 0x11])),
        (0x01, bytes([0x20, 0x21, 0x22])),
    ]


_SESSION_KEY = bytes(range(16, 32))
_CONN_ID = 3


def _established_session(
    writes: list[bytes], *, firmware_version: int | None, readvertise: bool = True
) -> FlicSession:
    """Return a session in the established state with a known session key."""

    async def send(value: bytes) -> None:
        writes.append(value)

    session = FlicSession(
        "01:02:03:04:05:06",
        send,
        pairing=PairingData(1, bytes(range(16))),
        firmware_version=firmware_version,
        mtu=100,
        readvertise_after_loss=readvertise,
    )
    session.state = SessionState.ESTABLISHED
    session._conn_id = _CONN_ID
    session._session_key = _SESSION_KEY
    return session


def _from_button(session: FlicSession, packet: bytes) -> bytes:
    """Sign a packet the way the button would for the next rx counter."""
    signature = chaskey_signature(_SESSION_KEY, 0, session._rx_counter, packet)
    return bytes([_CONN_ID]) + packet + signature


def _init_response(*, duo: bool = False) -> bytes:
    if duo:
        return bytes([OP_INIT_BUTTON_EVENTS_DUO_RESPONSE_WITHOUT_BOOT_ID]) + bytes(14)
    return bytes([OP_INIT_BUTTON_EVENTS_RESPONSE_WITH_BOOT_ID]) + bytes(14)


def _opcodes(writes: list[bytes]) -> list[int]:
    return [value[1] for value in writes]


def _expected_adv_parameters() -> bytes:
    return bytes([OP_SET_ADV_PARAMETERS_REQUEST]) + struct.pack(
        "<????HHI",
        True,
        False,
        True,
        True,
        ADV_INTERVAL_FAST,
        ADV_INTERVAL_SLOW,
        ADV_TIMEOUT_SECONDS,
    )


@pytest.mark.asyncio
async def test_init_response_requests_advertising_after_connection_loss() -> None:
    writes: list[bytes] = []
    session = _established_session(writes, firmware_version=11)

    await session.feed_gatt(_from_button(session, _init_response()))

    assert session.ready.is_set()
    assert _opcodes(writes) == [OP_SET_ADV_PARAMETERS_REQUEST]
    # conn id, signed payload, five signature bytes
    assert writes[0][1:-5] == _expected_adv_parameters()
    assert writes[0][-5:] == chaskey_signature(
        _SESSION_KEY, 1, 0, _expected_adv_parameters()
    )


@pytest.mark.asyncio
async def test_duo_init_response_requests_advertising_after_connection_loss() -> None:
    writes: list[bytes] = []
    session = _established_session(writes, firmware_version=17)
    session._is_duo = True

    await session.feed_gatt(_from_button(session, _init_response(duo=True)))

    assert session.ready.is_set()
    assert _opcodes(writes) == [OP_SET_ADV_PARAMETERS_REQUEST]


@pytest.mark.asyncio
async def test_unknown_firmware_is_queried_before_advertising_parameters() -> None:
    writes: list[bytes] = []
    session = _established_session(writes, firmware_version=None)

    await session.feed_gatt(_from_button(session, _init_response()))
    assert _opcodes(writes) == [OP_GET_FIRMWARE_VERSION_REQUEST]

    await session.feed_gatt(
        _from_button(
            session,
            bytes([OP_GET_FIRMWARE_VERSION_RESPONSE]) + struct.pack("<I", 11),
        )
    )

    assert session.result.firmware_version == 11
    assert _opcodes(writes) == [
        OP_GET_FIRMWARE_VERSION_REQUEST,
        OP_SET_ADV_PARAMETERS_REQUEST,
    ]


@pytest.mark.asyncio
async def test_old_firmware_does_not_get_advertising_parameters() -> None:
    writes: list[bytes] = []
    session = _established_session(writes, firmware_version=None)

    await session.feed_gatt(_from_button(session, _init_response()))
    await session.feed_gatt(
        _from_button(
            session,
            bytes([OP_GET_FIRMWARE_VERSION_RESPONSE]) + struct.pack("<I", 6),
        )
    )

    assert session.result.firmware_version == 6
    assert _opcodes(writes) == [OP_GET_FIRMWARE_VERSION_REQUEST]


@pytest.mark.asyncio
async def test_pairing_sessions_do_not_change_advertising() -> None:
    writes: list[bytes] = []
    session = _established_session(writes, firmware_version=11, readvertise=False)

    await session.feed_gatt(_from_button(session, _init_response()))

    assert session.ready.is_set()
    assert writes == []


@pytest.mark.asyncio
async def test_advertising_parameters_response_is_recorded() -> None:
    writes: list[bytes] = []
    session = _established_session(writes, firmware_version=11)
    results = []
    session._state_callback = results.append

    await session.feed_gatt(_from_button(session, _init_response()))
    assert not session.result.adv_parameters_set

    await session.feed_gatt(
        _from_button(session, bytes([OP_SET_ADV_PARAMETERS_RESPONSE]))
    )

    assert session.result.adv_parameters_set
    assert results[-1].adv_parameters_set


def test_advertising_parameters_response_opcode_matches_firmware() -> None:
    """A firmware 17 Flic Duo answers SetAdvParametersRequest with opcode 25."""
    assert OP_SET_ADV_PARAMETERS_RESPONSE == 25


@pytest.mark.asyncio
async def test_request_disconnect_asks_button_to_restart_advertising() -> None:
    writes: list[bytes] = []
    session = _established_session(writes, firmware_version=11)

    await session.request_disconnect(restart_advertising=True)

    assert writes[0][1:-5] == bytes([OP_FORCE_BT_DISCONNECT, 1])
    assert writes[0][-5:] == chaskey_signature(
        _SESSION_KEY, 1, 0, bytes([OP_FORCE_BT_DISCONNECT, 1])
    )


@pytest.mark.asyncio
async def test_request_disconnect_needs_an_established_session() -> None:
    async def send(_: bytes) -> None:
        return None

    session = FlicSession("01:02:03:04:05:06", send)

    with pytest.raises(FlicProtocolError):
        await session.request_disconnect(restart_advertising=True)


def _duo_update(button: int, event_code: int, *, gesture: bool = False) -> list:
    """One Duo update: first event for the button, 8-bit timestamp of 1."""
    fields = [(button, 1), (0, 1), (0, 3), (1, 8), (event_code, 3)]
    if event_code in (4, 7):
        fields.append((0, 1))
    if event_code <= 4 or event_code == 6:
        fields.append((int(gesture), 1))
    fields += [(0, 8), (0, 8), (0, 8)]
    return fields


def test_duo_reports_raw_press_and_release_per_button() -> None:
    payload = _packed_bits(*_duo_update(1, 5), *_duo_update(0, 0)) + b"\x00"

    decoded = decode_duo_button_events(payload, (0, 0), 0, True)

    assert _types(decoded.events) == ["small_down", "up"]
    assert [event.button for event in decoded.events] == ["small", "big"]
    assert _user(decoded.events) == []
    assert not decoded.needs_ack


def test_duo_click_release_reports_up_then_single() -> None:
    payload = _packed_bits(*_duo_update(0, 1)) + b"\x00"

    decoded = decode_duo_button_events(payload, (0, 0), 0, True)

    assert _types(decoded.events) == ["up", "single"]
    assert decoded.needs_ack
