"""Tests for the standalone Flic 2 protocol implementation."""

from __future__ import annotations

import struct

import pytest

from custom_components.flic2.protocol import (
    Flic2Session,
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
    assert [event.event_type for event in events] == ["single", "double", "hold"]
    assert all(event.timestamp_ms == 1000 for event in events)
    assert button_events_need_ack(payload)


def test_plain_up_down_do_not_create_user_event() -> None:
    assert decode_button_events(_event_item(0) + _event_item(1), 2) == []
    assert not button_events_need_ack(_event_item(0) + _event_item(1))


@pytest.mark.asyncio
async def test_quick_verify_request_is_fragmented_for_default_mtu() -> None:
    writes: list[bytes] = []

    async def send(value: bytes) -> None:
        writes.append(value)

    session = Flic2Session(
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

    assert [event.event_type for event in decoded.events] == ["swipe_left"]
    assert all(event.button == "big" for event in decoded.events)
    assert all(event.gesture == "left" for event in decoded.events)
    assert all(event.accelerometer == (1, -2, 3) for event in decoded.events)
    assert decoded.event_counts == (1, 0)
    assert decoded.last_timestamp == 5
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

    assert [event.event_type for event in decoded.events] == ["single"]


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

    assert decoded.events == []


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

    assert [event.event_type for event in decoded.events] == ["single"]
    assert decoded.events[0].gesture == "unrecognized"


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

    assert [event.event_type for event in decoded.events] == ["small_hold"]
    assert decoded.events[0].button == "small"
    assert decoded.events[0].accelerometer == (0, 64, -64)
    assert decoded.event_counts == (12, 21)
    assert decoded.last_timestamp == 109
    assert not decoded.needs_ack


def test_duo_hold_suppresses_release_and_click_timeout_across_packets() -> None:
    hold_payload = _packed_bits(
        (0, 1),  # big button
        (0, 1),
        (0, 3),
        (5, 8),
        (7, 3),  # hold
        (0, 1),
        (0, 8),
        (0, 8),
        (64, 8),
    )
    hold = decode_duo_button_events(hold_payload, (0, 0), 0, True)
    assert [event.event_type for event in hold.events] == ["hold"]

    release_payload = _packed_bits(
        (0, 1),
        (0, 1),
        (2, 3),
        (1100, 13),
        (2, 3),  # release after at least one second
        (0, 1),  # no gesture
        (0, 8),
        (0, 8),
        (64, 8),
    )
    release = decode_duo_button_events(
        release_payload,
        hold.event_counts,
        hold.last_timestamp,
        hold.end_of_queue,
        hold.hold_states,
    )
    assert release.events == []

    timeout_payload = _packed_bits(
        (0, 1),
        (0, 1),
        (0, 3),
        (5, 8),
        (6, 3),  # stale single-click timeout for the held press
        (0, 1),
        (0, 8),
        (0, 8),
        (64, 8),
    )
    timeout = decode_duo_button_events(
        timeout_payload,
        release.event_counts,
        release.last_timestamp,
        release.end_of_queue,
        release.hold_states,
    )
    assert timeout.events == []


def test_duo_click_after_hold_starts_a_new_sequence() -> None:
    down_payload = _packed_bits(
        (0, 1),
        (0, 1),
        (0, 3),
        (5, 8),
        (5, 3),  # new button down clears stale hold suppression
        (0, 8),
        (0, 8),
        (64, 8),
    )
    down = decode_duo_button_events(down_payload, (2, 0), 100, True, (2, 0))

    single_payload = _packed_bits(
        (0, 1),
        (0, 1),
        (0, 3),
        (100, 8),
        (1, 3),
        (0, 1),
        (0, 8),
        (0, 8),
        (64, 8),
    )
    single = decode_duo_button_events(
        single_payload,
        down.event_counts,
        down.last_timestamp,
        down.end_of_queue,
        down.hold_states,
    )
    assert [event.event_type for event in single.events] == ["single"]


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

    assert [event.event_type for event in decoded.events] == ["single"]
    assert decoded.event_counts == (2, 0)
    assert decoded.last_timestamp == 8
    assert decoded.needs_ack


@pytest.mark.asyncio
async def test_duo_init_contains_both_event_counters() -> None:
    writes: list[bytes] = []

    async def send(value: bytes) -> None:
        writes.append(value)

    session = Flic2Session(
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

    session = Flic2Session("01:02:03:04:05:06", send)
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

    session = Flic2Session("AA:BB:CC:DD:EE:FF", send)
    value = bytes([0x40, 2, 0x10, 0x11, 0x01, 3, 0x20, 0x21, 0x22])

    assert session._defragment(value) == [
        (0x40, bytes([0x10, 0x11])),
        (0x01, bytes([0x20, 0x21, 0x22])),
    ]
