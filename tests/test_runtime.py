"""Tests for Flic Bluetooth connection lifecycle handling."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from custom_components.flic_ble import runtime
from custom_components.flic_ble.protocol import PairingError, SessionState


class _FakeHass:
    def async_create_task(self, coro, name=None, eager_start=True):
        return asyncio.create_task(coro)


def _device() -> runtime.FlicDevice:
    entry = SimpleNamespace(data={"address": "01:02:03:04:05:06"}, title="Test Flic")
    return runtime.FlicDevice(_FakeHass(), entry)


@pytest.mark.asyncio
async def test_connected_client_is_kept_without_wake_advertisement(monkeypatch) -> None:
    device = _device()
    client = SimpleNamespace(is_connected=True, disconnect=AsyncMock())
    device._client = client
    lookup = AsyncMock()
    monkeypatch.setattr(runtime.bluetooth, "async_ble_device_from_address", lookup)

    await device.async_connect()

    client.disconnect.assert_not_awaited()
    lookup.assert_not_called()


@pytest.mark.asyncio
async def test_wake_advertisement_replaces_stale_connected_client(
    monkeypatch,
) -> None:
    device = _device()
    stale_client = SimpleNamespace(is_connected=True, disconnect=AsyncMock())
    device._client = stale_client
    device.available = True
    ble_device = object()
    monkeypatch.setattr(
        runtime.bluetooth,
        "async_ble_device_from_address",
        lambda *args, **kwargs: ble_device,
    )
    establish_session = AsyncMock()
    monkeypatch.setattr(device, "_async_establish_session", establish_session)

    await device.async_connect(force_reconnect=True)

    stale_client.disconnect.assert_awaited_once_with()
    establish_session.assert_awaited_once()
    assert device._client is None
    assert not device.available


@pytest.mark.asyncio
async def test_advertisement_during_attempt_schedules_follow_up() -> None:
    device = _device()
    first_attempt_can_finish = asyncio.Event()
    attempts: list[bool] = []

    async def _connect(*, force_reconnect: bool = False) -> None:
        attempts.append(force_reconnect)
        if len(attempts) == 1:
            await first_attempt_can_finish.wait()

    device.async_connect = _connect
    device._schedule_connect()
    await asyncio.sleep(0)

    device._schedule_connect(force_reconnect=True)
    first_attempt_can_finish.set()
    for _ in range(5):
        await asyncio.sleep(0)
        if len(attempts) == 2:
            break

    assert attempts == [False, True]
    if device._connect_task:
        await device._connect_task


@pytest.mark.asyncio
async def test_disconnect_callback_ignores_replaced_client(monkeypatch) -> None:
    device = _device()
    ble_device = object()
    monkeypatch.setattr(
        runtime.bluetooth,
        "async_ble_device_from_address",
        lambda *args, **kwargs: ble_device,
    )
    disconnected_callback = None

    async def _establish_session(*args) -> None:
        nonlocal disconnected_callback
        disconnected_callback = args[2]

    monkeypatch.setattr(device, "_async_establish_session", _establish_session)

    await device.async_connect()
    replacement = SimpleNamespace(is_connected=True)
    device._client = replacement
    device.available = True
    disconnected_callback(object())

    assert device._client is replacement
    assert device.available


class _Services:
    def __init__(self, uuids: set[str]) -> None:
        self._uuids = uuids

    def get_characteristic(self, uuid: str):
        return object() if uuid in self._uuids else None


def _client(uuids: set[str]) -> SimpleNamespace:
    return SimpleNamespace(
        services=_Services(uuids),
        clear_cache=AsyncMock(return_value=True),
        disconnect=AsyncMock(),
    )


_BLE_DEVICE = SimpleNamespace(address="01:02:03:04:05:06")


@pytest.mark.asyncio
async def test_open_client_keeps_complete_gatt_table(monkeypatch) -> None:
    good = _client({runtime.TX_UUID, runtime.RX_UUID})
    establish = AsyncMock(return_value=good)
    monkeypatch.setattr(runtime, "establish_connection", establish)

    client = await runtime._async_open_flic_client(
        _BLE_DEVICE, "Test Flic", lambda: _BLE_DEVICE
    )

    assert client is good
    establish.assert_awaited_once()
    assert establish.await_args.kwargs["use_services_cache"] is True
    good.clear_cache.assert_not_awaited()


@pytest.mark.asyncio
async def test_open_client_clears_cache_when_characteristic_missing(
    monkeypatch,
) -> None:
    stale = _client({runtime.TX_UUID})
    good = _client({runtime.TX_UUID, runtime.RX_UUID})
    establish = AsyncMock(side_effect=[stale, good])
    monkeypatch.setattr(runtime, "establish_connection", establish)
    disconnected = object()

    client = await runtime._async_open_flic_client(
        _BLE_DEVICE, "Test Flic", lambda: _BLE_DEVICE, disconnected
    )

    assert client is good
    stale.clear_cache.assert_awaited_once_with()
    stale.disconnect.assert_awaited_once_with()
    assert establish.await_count == 2
    second = establish.await_args_list[1].kwargs
    assert second["use_services_cache"] is False
    assert second["disconnected_callback"] is disconnected


@pytest.mark.asyncio
async def test_open_client_raises_when_fresh_discovery_still_missing(
    monkeypatch,
) -> None:
    first = _client(set())
    second = _client(set())
    monkeypatch.setattr(
        runtime, "establish_connection", AsyncMock(side_effect=[first, second])
    )

    with pytest.raises(runtime.BleakCharacteristicNotFoundError):
        await runtime._async_open_flic_client(
            _BLE_DEVICE, "Test Flic", lambda: _BLE_DEVICE
        )

    first.clear_cache.assert_awaited_once_with()
    second.disconnect.assert_awaited_once_with()


def test_unresolved_services_count_as_missing() -> None:
    class _Unresolved:
        @property
        def services(self):
            raise RuntimeError("Service Discovery has not been performed yet")

    assert not runtime._has_flic_characteristics(_Unresolved())


@pytest.mark.asyncio
async def test_session_failure_delays_the_next_session(monkeypatch) -> None:
    """A failed session waits out the spec's five second pause before retrying."""
    device = _device()
    monkeypatch.setattr(
        runtime.bluetooth,
        "async_ble_device_from_address",
        lambda *args, **kwargs: object(),
    )
    establish_session = AsyncMock()
    monkeypatch.setattr(device, "_async_establish_session", establish_session)
    loop = asyncio.get_running_loop()
    device._retry_not_before = loop.time() + 0.05

    started = loop.time()
    await device.async_connect()

    establish_session.assert_awaited_once()
    assert loop.time() - started >= 0.05


@pytest.mark.asyncio
async def test_session_failure_sets_backoff_and_disconnects(monkeypatch) -> None:
    device = _device()
    client = SimpleNamespace(
        is_connected=True,
        mtu_size=100,
        start_notify=AsyncMock(),
        write_gatt_char=AsyncMock(),
        disconnect=AsyncMock(),
    )

    async def _open_client(*args, **kwargs):
        return client

    monkeypatch.setattr(runtime, "_async_open_flic_client", _open_client)
    device.entry.data.update(
        {"pairing_identifier": 1, "pairing_key": bytes(range(16)).hex()}
    )
    loop = asyncio.get_running_loop()
    session_task = asyncio.create_task(
        device._async_establish_session(object(), lambda: object(), lambda _: None)
    )
    await asyncio.sleep(0)
    notification = client.start_notify.await_args.args[1]

    # The button rejecting the stored pairing fails the session.
    notification(None, bytearray([0x20, 6]))
    for _ in range(5):
        await asyncio.sleep(0)
    with pytest.raises(PairingError):
        await session_task

    client.disconnect.assert_awaited()
    assert device._retry_not_before > loop.time()


def test_firmware_version_is_persisted_from_session_state() -> None:
    device = _device()
    updates: list[dict] = []
    device.hass.config_entries = SimpleNamespace(
        async_update_entry=lambda entry, data: updates.append(data)
    )
    result = runtime.SessionResult(firmware_version=11, adv_parameters_set=True)

    device._handle_state(result)

    assert updates[-1]["firmware_version"] == 11
    assert device.readvertise_configured


def _established(device: runtime.FlicDevice, *, closes_link: bool):
    client = SimpleNamespace(is_connected=True, disconnect=AsyncMock())
    device._client = client
    device.available = True

    async def _request_disconnect(*, restart_advertising: bool) -> None:
        assert restart_advertising
        if closes_link:
            # The button drops the link; the disconnected callback fires.
            device._client = None
            device._session = None
            device.available = False
            device._link_closed.set()

    session = SimpleNamespace(
        state=SessionState.ESTABLISHED,
        request_disconnect=AsyncMock(side_effect=_request_disconnect),
    )
    device._session = session
    return client, session


@pytest.mark.asyncio
async def test_stop_lets_the_button_close_the_link() -> None:
    device = _device()
    client, session = _established(device, closes_link=True)

    await device.async_stop()

    session.request_disconnect.assert_awaited_once_with(restart_advertising=True)
    client.disconnect.assert_not_awaited()
    assert device._client is None
    assert device._session is None


@pytest.mark.asyncio
async def test_stop_falls_back_to_host_disconnect(monkeypatch) -> None:
    monkeypatch.setattr(runtime, "_RELEASE_TIMEOUT_SECONDS", 0.05)
    device = _device()
    client, session = _established(device, closes_link=False)

    await device.async_stop()

    session.request_disconnect.assert_awaited_once()
    client.disconnect.assert_awaited_once_with()
    assert device._client is None


@pytest.mark.asyncio
async def test_stop_without_session_only_disconnects() -> None:
    device = _device()
    client = SimpleNamespace(is_connected=True, disconnect=AsyncMock())
    device._client = client

    await device.async_stop()

    client.disconnect.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_start_releases_button_when_home_assistant_stops(monkeypatch) -> None:
    device = _device()
    listeners: dict[str, object] = {}
    unloads: list[object] = []
    device.hass.bus = SimpleNamespace(
        async_listen_once=lambda event, action: (
            listeners.__setitem__(event, action) or (lambda: None)
        )
    )
    device.entry.async_on_unload = unloads.append
    monkeypatch.setattr(
        runtime.bluetooth, "async_register_callback", lambda *a, **k: lambda: None
    )
    monkeypatch.setattr(
        runtime.bluetooth, "async_ble_device_from_address", lambda *a, **k: None
    )
    stop = AsyncMock()
    monkeypatch.setattr(device, "async_stop", stop)

    await device.async_start()
    await listeners[runtime.EVENT_HOMEASSISTANT_STOP](object())

    stop.assert_awaited_once()
    assert len(unloads) == 2


def _advert(*, public: bool) -> SimpleNamespace:
    if public:
        return SimpleNamespace(name="F211abcd", service_uuids=[runtime.SERVICE_UUID])
    return SimpleNamespace(name="01:02:03:04:05:06", service_uuids=[])


@pytest.mark.asyncio
async def test_private_mode_advertisement_marks_connection_stale(monkeypatch) -> None:
    device = _device()
    device._client = SimpleNamespace(is_connected=True)
    device.available = True
    device._available_since = asyncio.get_running_loop().time() - 10
    scheduled: list[bool] = []
    monkeypatch.setattr(
        device,
        "_schedule_connect",
        lambda *, force_reconnect=False: scheduled.append(force_reconnect),
    )

    device._handle_advertisement(_advert(public=False))
    device._handle_advertisement(_advert(public=True))
    device._available_since = asyncio.get_running_loop().time()
    device._handle_advertisement(_advert(public=False))

    # private advert, public advert, private advert just after connecting
    assert scheduled == [True, False, False]


@pytest.mark.asyncio
async def test_start_registers_every_advertisement_callback(monkeypatch) -> None:
    device = _device()
    device.hass.bus = SimpleNamespace(async_listen_once=lambda *a: lambda: None)
    device.entry.async_on_unload = lambda _: None
    registered: dict[str, object] = {}
    monkeypatch.setattr(
        runtime.bluetooth,
        "async_register_callback",
        lambda hass, cb, matcher, mode: (
            registered.__setitem__("mode", mode) or (lambda: None)
        ),
    )
    monkeypatch.setattr(
        runtime.bluetooth,
        "async_register_advertisement_callback",
        lambda hass, cb, address: (
            registered.__setitem__("every", (cb, address)) or (lambda: None)
        ),
        raising=False,
    )
    monkeypatch.setattr(
        runtime.bluetooth, "async_ble_device_from_address", lambda *a, **k: None
    )

    await device.async_start()

    assert registered["mode"] is runtime.bluetooth.BluetoothScanningMode.PASSIVE
    assert registered["every"] == (device._handle_advertisement, device.address)


@pytest.mark.asyncio
async def test_failed_connection_sets_retry_backoff(monkeypatch) -> None:
    device = _device()
    monkeypatch.setattr(
        runtime.bluetooth,
        "async_ble_device_from_address",
        lambda *args, **kwargs: object(),
    )
    monkeypatch.setattr(
        device, "_async_establish_session", AsyncMock(side_effect=OSError("no"))
    )
    loop = asyncio.get_running_loop()

    await device.async_connect()

    assert device._retry_not_before > loop.time()
    assert not device.available
