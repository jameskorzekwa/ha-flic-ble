"""Flic Twist support built on the vendored pyflic-ble client.

The Flic Twist uses a different GATT service and packet format from Flic 2 and
Flic Duo, and Shortcut Labs has not published a specification for it, so its
session handling comes from Shortcut Labs' own pyflic-ble library (vendored in
``pyflic_ble``). This module wraps that client with the reconnection behaviour
the rest of the integration relies on:

* every advertisement wakes the client's reconnect loop, so the advertising
  window after a press is used for retries instead of one attempt;
* on unload and when Home Assistant stops, the Twist is asked to drop the link
  itself with ``restart_adv`` set, so it keeps advertising and reconnects on its
  own instead of going silent until the next press.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth.match import ADDRESS, BluetoothCallbackMatcher
from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.core import Event, HomeAssistant, callback

from .const import (
    CONF_FIRMWARE_VERSION,
    CONF_PAIRING_IDENTIFIER,
    CONF_PAIRING_KEY,
    CONF_PUSH_TWIST_MODE,
    CONF_SERIAL_NUMBER,
    CONF_SIG_BITS,
    PUSH_TWIST_DEFAULT,
)
from .protocol import ButtonEvent
from .pyflic_ble import DeviceType, FlicClient, PushTwistMode

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry

    from .pyflic_ble.client import FlicState

_LOGGER = logging.getLogger(__name__)
_RELEASE_TIMEOUT_SECONDS = 3.0

# pyflic-ble names the click events differently from the rest of this
# integration; keep one vocabulary for automations.
_RENAMED = {"click": "single", "double_click": "double"}


def twist_event(event_type: str, data: dict[str, Any]) -> ButtonEvent:
    """Convert a pyflic-ble button or rotate callback into a ButtonEvent."""
    extra = {
        key: value
        for key, value in data.items()
        if key not in ("button_index", "was_queued", "timestamp_ms")
        and isinstance(value, int | float | str | bool)
    }
    return ButtonEvent(
        _RENAMED.get(event_type, event_type),
        0,
        bool(data.get("was_queued", False)),
        int(data.get("timestamp_ms", 0) or 0),
        data=extra or None,
    )


class FlicTwistDevice:
    """Manage one paired Flic Twist through pyflic-ble's client."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self.address: str = entry.data["address"].upper()
        self.name = entry.title
        self.available = False
        self.readvertise_configured = False
        self.battery_voltage: float | None = entry.data.get("battery_voltage")
        self.client = FlicClient(
            address=self.address,
            pairing_id=entry.data[CONF_PAIRING_IDENTIFIER],
            pairing_key=bytes.fromhex(entry.data[CONF_PAIRING_KEY]),
            serial_number=entry.data.get(CONF_SERIAL_NUMBER),
            device_type=DeviceType.TWIST,
            sig_bits=entry.data.get(CONF_SIG_BITS, 0),
            push_twist_mode=PushTwistMode(
                entry.options.get(CONF_PUSH_TWIST_MODE, PUSH_TWIST_DEFAULT)
            ),
        )
        self._event_listeners: set[Callable[[ButtonEvent], None]] = set()
        self._state_listeners: set[Callable[[], None]] = set()
        self._unsubscribers: list[Callable[[], None]] = []
        self._stopping = False
        self._link_closed: asyncio.Event | None = None

    async def async_start(self) -> None:
        """Subscribe to the client and to advertisements, then connect."""
        self._unsubscribers += [
            self.client.register_button_event_callback(self._handle_client_event),
            self.client.register_rotate_event_callback(self._handle_client_event),
            self.client.register_state_callback(self._handle_state),
        ]

        @callback
        def _advertisement(
            service_info: bluetooth.BluetoothServiceInfoBleak,
            change: bluetooth.BluetoothChange,
        ) -> None:
            self._handle_advertisement(service_info)

        self.entry.async_on_unload(
            bluetooth.async_register_callback(
                self.hass,
                _advertisement,
                BluetoothCallbackMatcher({ADDRESS: self.address}),
                bluetooth.BluetoothScanningMode.PASSIVE,
            )
        )
        if register_every := getattr(
            bluetooth, "async_register_advertisement_callback", None
        ):
            self.entry.async_on_unload(
                register_every(self.hass, self._handle_advertisement, self.address)
            )
        self.entry.async_on_unload(
            self.hass.bus.async_listen_once(
                EVENT_HOMEASSISTANT_STOP, self._async_on_hass_stop
            )
        )
        if ble_device := bluetooth.async_ble_device_from_address(
            self.hass, self.address, connectable=True
        ):
            self.client.set_ble_device(ble_device)

    @callback
    def _handle_advertisement(
        self, service_info: bluetooth.BluetoothServiceInfoBleak
    ) -> None:
        """Hand the freshest path to the client; this also wakes its retries."""
        if self._stopping or self.client.is_connected:
            return
        device = (
            bluetooth.async_ble_device_from_address(
                self.hass, self.address, connectable=True
            )
            or service_info.device
        )
        self.client.set_ble_device(device)

    @callback
    def _handle_client_event(self, event_type: str, data: dict[str, Any]) -> None:
        event = twist_event(event_type, data)
        for listener in tuple(self._event_listeners):
            listener(event)

    @callback
    def _handle_state(self, state: FlicState) -> None:
        self.available = state.connected
        if not state.connected and self._link_closed is not None:
            self._link_closed.set()
        if state.battery_voltage is not None:
            self.battery_voltage = state.battery_voltage
        data = dict(self.entry.data)
        if self.battery_voltage is not None:
            data["battery_voltage"] = self.battery_voltage
        if state.firmware_version is not None:
            data[CONF_FIRMWARE_VERSION] = state.firmware_version
        if data != self.entry.data:
            self.hass.config_entries.async_update_entry(self.entry, data=data)
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

    async def _async_on_hass_stop(self, _: Event) -> None:
        await self.async_stop()

    async def async_stop(self) -> None:
        """Release the Twist so it keeps advertising, then stop the client."""
        if self._stopping:
            return
        self._stopping = True
        if self.client.is_connected and self.client.state.connected:
            closed = self._link_closed = asyncio.Event()
            try:
                async with asyncio.timeout(_RELEASE_TIMEOUT_SECONDS):
                    await self.client.handler.send_force_disconnect(restart_adv=True)
                    await closed.wait()
            except Exception as err:  # fall back to a host-side disconnect
                _LOGGER.debug(
                    "Flic Twist %s did not close the link on request (%s)",
                    self.address,
                    err,
                )
            finally:
                self._link_closed = None
        with contextlib.suppress(Exception):
            await self.client.stop()
        for unsubscribe in self._unsubscribers:
            unsubscribe()
        self._unsubscribers.clear()
        self.available = False
