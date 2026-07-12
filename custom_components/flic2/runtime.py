"""Bluetooth runtime for Flic 2 buttons."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from bleak_retry_connector import BleakClientWithServiceCache, establish_connection
from homeassistant.components import bluetooth
from homeassistant.components.bluetooth.match import ADDRESS, BluetoothCallbackMatcher
from homeassistant.core import HomeAssistant, callback

from .const import (
    CONF_BOOT_ID,
    CONF_EVENT_COUNT,
    CONF_EVENT_COUNT_SMALL,
    CONF_IS_DUO,
    CONF_PAIRING_IDENTIFIER,
    CONF_PAIRING_KEY,
    RX_UUID,
    TX_UUID,
)
from .protocol import (
    ButtonEvent,
    Flic2Session,
    PairingData,
    PairingTimeoutError,
    SessionResult,
)

if TYPE_CHECKING:
    from bleak.backends.device import BLEDevice
    from homeassistant.config_entries import ConfigEntry

_LOGGER = logging.getLogger(__name__)


class Flic2Device:
    """Manage reconnection and events for one paired Flic 2 button."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self.address: str = entry.data["address"].upper()
        self.name = entry.title
        self.available = False
        self.battery_voltage: float | None = entry.data.get("battery_voltage")
        self._client: BleakClientWithServiceCache | None = None
        self._connect_lock = asyncio.Lock()
        self._event_listeners: set[Callable[[ButtonEvent], None]] = set()
        self._state_listeners: set[Callable[[], None]] = set()
        self._stopping = False

    async def async_start(self) -> None:
        """Start listening for advertisements and connect when reachable."""

        @callback
        def _advertisement(
            service_info: bluetooth.BluetoothServiceInfoBleak,
            change: bluetooth.BluetoothChange,
        ) -> None:
            if not self._stopping:
                self.hass.async_create_task(self.async_connect())

        self.entry.async_on_unload(
            bluetooth.async_register_callback(
                self.hass,
                _advertisement,
                BluetoothCallbackMatcher({ADDRESS: self.address}),
                bluetooth.BluetoothScanningMode.ACTIVE,
            )
        )
        if bluetooth.async_ble_device_from_address(
            self.hass, self.address, connectable=True
        ):
            self.hass.async_create_task(self.async_connect())

    async def async_connect(self) -> None:
        """Connect through the best available local adapter or proxy."""
        async with self._connect_lock:
            if self._stopping or (self._client and self._client.is_connected):
                return
            ble_device = bluetooth.async_ble_device_from_address(
                self.hass, self.address, connectable=True
            )
            if not ble_device:
                return

            def _latest_device() -> BLEDevice:
                return (
                    bluetooth.async_ble_device_from_address(
                        self.hass, self.address, connectable=True
                    )
                    or ble_device
                )

            @callback
            def _disconnected(_: Any) -> None:
                self._client = None

            try:
                client = await establish_connection(
                    BleakClientWithServiceCache,
                    ble_device,
                    self.name,
                    disconnected_callback=_disconnected,
                    max_attempts=3,
                    ble_device_callback=_latest_device,
                    use_services_cache=True,
                )
                self._client = client

                async def _send(payload: bytes) -> None:
                    await client.write_gatt_char(TX_UUID, payload, response=False)

                pairing = PairingData(
                    self.entry.data[CONF_PAIRING_IDENTIFIER],
                    bytes.fromhex(self.entry.data[CONF_PAIRING_KEY]),
                )
                session = Flic2Session(
                    self.address,
                    _send,
                    pairing=pairing,
                    event_count=self.entry.data.get(CONF_EVENT_COUNT, 0),
                    event_count_small=self.entry.data.get(CONF_EVENT_COUNT_SMALL, 0),
                    boot_id=self.entry.data.get(CONF_BOOT_ID, 0),
                    event_callback=self._handle_event,
                    state_callback=self._handle_state,
                    mtu=getattr(client, "mtu_size", 23),
                    auto_disconnect_time=60,
                )

                def _notification(_: Any, data: bytearray) -> None:
                    self.hass.async_create_task(session.feed_gatt(bytes(data)))

                await client.start_notify(RX_UUID, _notification)
                await session.start()
                async with asyncio.timeout(20):
                    await session.ready.wait()
                if session.failure:
                    raise session.failure
                self.available = True
                self._notify_state_listeners()
            except Exception:
                _LOGGER.exception("Unable to connect to Flic 2 %s", self.address)
                if self._client:
                    with contextlib.suppress(Exception):
                        await self._client.disconnect()
                self._client = None

    @callback
    def _handle_event(self, event: ButtonEvent) -> None:
        for listener in tuple(self._event_listeners):
            listener(event)

    @callback
    def _handle_state(self, result: SessionResult) -> None:
        self.battery_voltage = result.battery_voltage or self.battery_voltage
        data = {
            **self.entry.data,
            CONF_EVENT_COUNT: result.event_count,
            CONF_EVENT_COUNT_SMALL: result.event_count_small,
            CONF_BOOT_ID: result.boot_id,
            CONF_IS_DUO: result.is_duo,
        }
        if self.battery_voltage is not None:
            data["battery_voltage"] = self.battery_voltage
        if data != self.entry.data:
            self.hass.config_entries.async_update_entry(self.entry, data=data)
        self._notify_state_listeners()

    @callback
    def _notify_state_listeners(self) -> None:
        for listener in tuple(self._state_listeners):
            listener()

    @callback
    def async_add_event_listener(
        self, listener: Callable[[ButtonEvent], None]
    ) -> Callable[[], None]:
        self._event_listeners.add(listener)
        return lambda: self._event_listeners.discard(listener)

    @callback
    def async_add_state_listener(
        self, listener: Callable[[], None]
    ) -> Callable[[], None]:
        self._state_listeners.add(listener)
        return lambda: self._state_listeners.discard(listener)

    async def async_stop(self) -> None:
        """Stop callbacks and disconnect."""
        self._stopping = True
        if self._client:
            with contextlib.suppress(Exception):
                await self._client.disconnect()
        self._client = None


async def async_pair_device(
    hass: HomeAssistant, service_info: bluetooth.BluetoothServiceInfoBleak
) -> SessionResult:
    """Pair one public-mode Flic through HA's best Bluetooth path."""
    address = service_info.address.upper()

    def _latest_device() -> BLEDevice:
        return (
            bluetooth.async_ble_device_from_address(hass, address, connectable=True)
            or service_info.device
        )

    client = await establish_connection(
        BleakClientWithServiceCache,
        service_info.device,
        service_info.name,
        max_attempts=3,
        ble_device_callback=_latest_device,
        use_services_cache=True,
    )
    try:
        async def _send(payload: bytes) -> None:
            await client.write_gatt_char(TX_UUID, payload, response=False)

        session = Flic2Session(
            address,
            _send,
            mtu=getattr(client, "mtu_size", 23),
            auto_disconnect_time=60,
        )

        def _notification(_: Any, data: bytearray) -> None:
            hass.async_create_task(session.feed_gatt(bytes(data)))

        await client.start_notify(RX_UUID, _notification)
        await session.start()
        try:
            async with asyncio.timeout(25):
                await session.pairing_complete.wait()
                await session.ready.wait()
        except TimeoutError as err:
            raise PairingTimeoutError(session.state) from err
        if session.failure:
            raise session.failure
        return session.result
    finally:
        with contextlib.suppress(Exception):
            await client.disconnect()
