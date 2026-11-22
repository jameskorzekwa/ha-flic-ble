"""Tests for Flic Bluetooth connection lifecycle handling."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from custom_components.flic_ble import runtime


class _FakeHass:
    def async_create_task(self, coro):
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
