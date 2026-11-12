"""Tests for raw press events, Flic Duo rotation and Flic Twist support."""

from __future__ import annotations

import asyncio
import struct
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.flic_ble import config_flow, const, runtime, twist
from custom_components.flic_ble.protocol import (
    OP_ENABLE_PUSH_TWIST,
    OP_INIT_BUTTON_EVENTS_DUO_RESPONSE_WITHOUT_BOOT_ID,
    OP_INIT_BUTTON_EVENTS_RESPONSE_WITH_BOOT_ID,
    OP_PUSH_TWIST_DATA_NOTIFICATION,
    FlicSession,
    PairingData,
    SessionState,
    chaskey_signature,
)
from custom_components.flic_ble.rotation import (
    ROTATION_GATE_SECONDS,
    SWIPE_SUPPRESS_SECONDS,
    DuoRotation,
    PushTwistData,
)

DETENT = 4096  # pyflic-ble units per detent; 65536 is a full turn


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def _push(buttons: int, angle: int, *, first: bool = False) -> PushTwistData:
    return PushTwistData(buttons, 1 if first else 0, 0, angle)


# --- push-twist parsing and rotation gating ---------------------------------


def test_push_twist_payload_is_parsed() -> None:
    payload = bytes([0b01_0110]) + struct.pack("<i", -1234)

    report = PushTwistData.from_payload(payload)

    assert report.buttons_pressed == 2
    assert report.is_first_event == 1
    assert report.pressed_half_second == 1
    assert report.angle_diff == -1234


def test_truncated_push_twist_payload_is_rejected() -> None:
    with pytest.raises(ValueError):
        PushTwistData.from_payload(b"\x01\x00")


def test_rotation_reports_direction_button_and_dial_data() -> None:
    rotation = DuoRotation(_Clock())

    big = rotation.push_twist(_push(1, 2 * DETENT))
    small = rotation.push_twist(_push(2, -2 * DETENT))

    assert [event.event_type for event in big] == ["rotate_clockwise"]
    assert big[0].button == "big"
    assert big[0].data["angle_degrees"] > 0
    assert 0 < big[0].data["dial_percentage"] <= 100
    assert [event.event_type for event in small] == ["small_rotate_counter_clockwise"]
    assert small[0].button == "small"


def test_zero_rotation_and_no_button_are_ignored() -> None:
    rotation = DuoRotation(_Clock())

    assert rotation.push_twist(_push(1, 0)) == []
    assert rotation.push_twist(_push(0, DETENT)) == []


def test_rotation_right_after_press_is_held_until_gate_opens() -> None:
    clock = _Clock()
    rotation = DuoRotation(clock)
    rotation.button_down(0)

    assert rotation.push_twist(_push(1, 2 * DETENT)) == []
    clock.now += ROTATION_GATE_SECONDS + 0.01
    events = rotation.push_twist(_push(1, 2 * DETENT))

    # The buffered report is flushed together with the current one.
    assert [event.event_type for event in events] == ["rotate_clockwise"] * 2


def test_swipe_discards_buffered_rotation_and_mutes_the_dial() -> None:
    clock = _Clock()
    rotation = DuoRotation(clock)
    rotation.button_down(0)
    rotation.push_twist(_push(1, 2 * DETENT))
    rotation.button_up(0, swiped=True)

    clock.now += SWIPE_SUPPRESS_SECONDS / 2
    assert rotation.push_twist(_push(1, 2 * DETENT)) == []
    clock.now += SWIPE_SUPPRESS_SECONDS
    assert [e.event_type for e in rotation.push_twist(_push(1, 2 * DETENT))] == [
        "rotate_clockwise"
    ]


# --- Flic Duo session enables and routes push-twist -------------------------

_KEY = bytes(range(16, 32))


def _session(writes: list[bytes], **kwargs) -> FlicSession:
    async def send(value: bytes) -> None:
        writes.append(value)

    session = FlicSession(
        "01:02:03:04:05:06",
        send,
        pairing=PairingData(1, bytes(range(16))),
        firmware_version=17,
        mtu=100,
        **kwargs,
    )
    session.state = SessionState.ESTABLISHED
    session._conn_id = 3
    session._session_key = _KEY
    return session


def _signed(session: FlicSession, packet: bytes) -> bytes:
    return bytes([3]) + packet + chaskey_signature(_KEY, 0, session._rx_counter, packet)


@pytest.mark.asyncio
async def test_duo_session_enables_push_twist_and_routes_reports() -> None:
    writes: list[bytes] = []
    reports: list[bytes] = []
    session = _session(writes, push_twist_callback=reports.append)
    session._is_duo = True

    await session.feed_gatt(
        _signed(
            session,
            bytes([OP_INIT_BUTTON_EVENTS_DUO_RESPONSE_WITHOUT_BOOT_ID]) + bytes(14),
        )
    )
    # Slow the link first, as pyflic-ble does, then enable push-twist.
    assert writes[0][1] == 12
    assert struct.unpack_from("<4H", writes[0], 2) == (80, 90, 17, 800)
    assert writes[1][1:3] == bytes([OP_ENABLE_PUSH_TWIST, 0b11])

    payload = bytes([1]) + struct.pack("<i", DETENT)
    await session.feed_gatt(
        _signed(session, bytes([OP_PUSH_TWIST_DATA_NOTIFICATION]) + payload)
    )
    assert reports == [payload]


@pytest.mark.asyncio
async def test_round_flic_and_pairing_sessions_do_not_enable_push_twist() -> None:
    round_writes: list[bytes] = []
    round_flic = _session(round_writes, push_twist_callback=lambda _: None)
    await round_flic.feed_gatt(
        _signed(
            round_flic,
            bytes([OP_INIT_BUTTON_EVENTS_RESPONSE_WITH_BOOT_ID]) + bytes(14),
        )
    )

    duo_writes: list[bytes] = []
    pairing = _session(duo_writes)  # no callback, as during pairing
    pairing._is_duo = True
    await pairing.feed_gatt(
        _signed(
            pairing,
            bytes([OP_INIT_BUTTON_EVENTS_DUO_RESPONSE_WITHOUT_BOOT_ID]) + bytes(14),
        )
    )

    sent = [value[1] for value in round_writes + duo_writes]
    assert OP_ENABLE_PUSH_TWIST not in sent
    assert 12 not in sent  # round Flics keep their connection parameters


# --- runtime wiring -----------------------------------------------------------


class _FakeHass:
    def async_create_task(self, coro, name=None, eager_start=True):
        return asyncio.create_task(coro)


def _device() -> runtime.FlicDevice:
    entry = SimpleNamespace(
        data={"address": "01:02:03:04:05:06", "is_duo": True}, title="Duo"
    )
    return runtime.FlicDevice(_FakeHass(), entry)


def test_runtime_turns_push_twist_into_rotation_events() -> None:
    device = _device()
    seen = []
    device.async_add_event_listener(seen.append)

    device._handle_push_twist(bytes([2]) + struct.pack("<i", 2 * DETENT))

    assert [event.event_type for event in seen] == ["small_rotate_clockwise"]
    assert seen[0].button == "small"
    assert "dial_percentage" in seen[0].data


def test_runtime_gates_rotation_on_press_and_swipe(monkeypatch) -> None:
    device = _device()
    calls = []
    monkeypatch.setattr(device._rotation, "button_down", calls.append)
    monkeypatch.setattr(
        device._rotation,
        "button_up",
        lambda index, *, swiped: calls.append((index, swiped)),
    )

    device._handle_event(runtime.ButtonEvent("small_down", 1, False, 0, "small"))
    device._handle_event(runtime.ButtonEvent("up", 2, False, 0, "big", gesture="left"))

    assert calls == [1, (0, True)]


# --- Flic Twist ---------------------------------------------------------------


def test_twist_click_events_use_the_integration_vocabulary() -> None:
    click = twist.twist_event("click", {"timestamp_ms": 5, "was_queued": True})
    double = twist.twist_event("double_click", {})
    turn = twist.twist_event(
        "twist_increment", {"twist_mode_index": 0, "mode_percentage": 42.0}
    )

    assert (click.event_type, click.queued, click.timestamp_ms) == ("single", True, 5)
    assert double.event_type == "double"
    assert turn.event_type == "twist_increment"
    assert turn.data == {"twist_mode_index": 0, "mode_percentage": 42.0}


def _twist_device(monkeypatch) -> twist.FlicTwistDevice:
    entry = SimpleNamespace(
        data={
            "address": "aa:bb:cc:dd:ee:ff",
            "pairing_identifier": 7,
            "pairing_key": bytes(range(16)).hex(),
            "serial_number": "T1-0001",
            "device_type": "twist",
        },
        options={},
        title="Twist",
    )
    return twist.FlicTwistDevice(_FakeHass(), entry)


def test_twist_advertisements_wake_the_client(monkeypatch) -> None:
    device = _twist_device(monkeypatch)
    fresh = object()
    monkeypatch.setattr(
        twist.bluetooth, "async_ble_device_from_address", lambda *a, **k: fresh
    )
    device.client = MagicMock(is_connected=False)

    device._handle_advertisement(SimpleNamespace(device=object()))

    device.client.set_ble_device.assert_called_once_with(fresh)


def test_twist_advertisement_ignored_while_connected(monkeypatch) -> None:
    device = _twist_device(monkeypatch)
    device.client = MagicMock(is_connected=True)

    device._handle_advertisement(SimpleNamespace(device=object()))

    device.client.set_ble_device.assert_not_called()


@pytest.mark.asyncio
async def test_twist_stop_lets_the_twist_close_the_link(monkeypatch) -> None:
    device = _twist_device(monkeypatch)
    client = MagicMock(is_connected=True, state=SimpleNamespace(connected=True))
    client.stop = AsyncMock()

    async def _force_disconnect(*, restart_adv: bool) -> None:
        assert restart_adv
        device._handle_state(
            SimpleNamespace(
                connected=False, battery_voltage=None, firmware_version=None
            )
        )

    client.handler.send_force_disconnect = AsyncMock(side_effect=_force_disconnect)
    device.client = client
    device.hass.config_entries = SimpleNamespace(async_update_entry=MagicMock())

    await device.async_stop()

    client.handler.send_force_disconnect.assert_awaited_once_with(restart_adv=True)
    client.stop.assert_awaited_once()
    assert not device.available


@pytest.mark.asyncio
async def test_twist_stop_falls_back_when_link_stays_up(monkeypatch) -> None:
    monkeypatch.setattr(twist, "_RELEASE_TIMEOUT_SECONDS", 0.05)
    device = _twist_device(monkeypatch)
    client = MagicMock(is_connected=True, state=SimpleNamespace(connected=True))
    client.stop = AsyncMock()
    client.handler.send_force_disconnect = AsyncMock()
    device.client = client

    await device.async_stop()

    client.stop.assert_awaited_once()


def test_twist_is_detected_from_its_service_uuid() -> None:
    info = SimpleNamespace(
        connectable=True, name="Twist", service_uuids=[const.TWIST_SERVICE_UUID.upper()]
    )
    assert config_flow._is_twist(info)
    assert config_flow._is_supported_flic(info)


@pytest.mark.asyncio
async def test_twist_pairing_returns_entry_data(monkeypatch) -> None:
    created = {}

    class _Client:
        def __init__(self, **kwargs) -> None:
            created.update(kwargs)
            self.disconnect = AsyncMock()

        async def connect(self) -> None:
            return None

        async def full_verify_pairing(self):
            return (9, bytes(range(16)), "T1-0002", 900, 2, bytes(16), 3)

    monkeypatch.setattr(config_flow, "FlicClient", _Client)
    info = SimpleNamespace(address="aa:bb:cc:dd:ee:ff", device=object())

    data = await config_flow._async_pair_twist(info)

    assert created["device_type"] is config_flow.DeviceType.TWIST
    assert data["device_type"] == "twist"
    assert data["pairing_identifier"] == 9
    assert data["pairing_key"] == bytes(range(16)).hex()
    assert data["serial_number"] == "T1-0002"
    assert data["sig_bits"] == 2
    assert data["firmware_version"] == 3


# --- per-model event types ----------------------------------------------------


def test_event_types_per_model_keep_existing_names() -> None:
    flic = const.event_types_for(const.MODEL_FLIC)
    duo = const.event_types_for(const.MODEL_DUO)

    assert {"single", "double", "hold", "down", "up"} == set(flic)
    for existing in ("single", "small_double", "small_hold", "swipe_left"):
        assert existing in duo
    assert {"rotate_clockwise", "small_rotate_counter_clockwise", "small_up"} <= set(
        duo
    )
    assert "twist_increment" in const.event_types_for(const.MODEL_TWIST)
    assert "selector_changed" in const.event_types_for(
        const.MODEL_TWIST, const.PUSH_TWIST_SELECTOR
    )
    assert const.model_for({"device_type": "twist"}) == const.MODEL_TWIST
    assert const.model_for({"is_duo": True}) == const.MODEL_DUO
    assert set(const.EVENT_TYPES) >= set(duo) | set(
        const.event_types_for(const.MODEL_TWIST)
    )


@pytest.mark.asyncio
async def test_entry_data_updates_do_not_reload_but_mode_changes_do(
    monkeypatch,
) -> None:
    """A press updates entry data; that must not reload (and release) the button."""
    import custom_components.flic_ble as integration

    listeners = []
    reloads = []
    entry = SimpleNamespace(
        data={"address": "01:02:03:04:05:06"},
        options={},
        entry_id="abc",
        async_on_unload=lambda _: None,
        add_update_listener=lambda listener: listeners.append(listener) or None,
    )
    hass = SimpleNamespace(
        config_entries=SimpleNamespace(
            async_forward_entry_setups=AsyncMock(),
            async_reload=AsyncMock(side_effect=reloads.append),
        )
    )
    device = SimpleNamespace(async_start=AsyncMock())
    monkeypatch.setattr(runtime, "FlicDevice", lambda hass, entry: device)

    await integration.async_setup_entry(hass, entry)
    entry.data = {**entry.data, "event_count": 5}
    await listeners[0](hass, entry)
    assert reloads == []

    entry.options = {"push_twist_mode": "selector"}
    await listeners[0](hass, entry)
    assert reloads == ["abc"]
