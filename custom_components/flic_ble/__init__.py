"""The Flic Bluetooth integration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .const import CONF_DEVICE_TYPE, CONF_PUSH_TWIST_MODE, DEVICE_TYPE_TWIST, PLATFORMS

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up a paired Flic button."""
    if entry.data.get(CONF_DEVICE_TYPE) == DEVICE_TYPE_TWIST:
        from .twist import FlicTwistDevice

        device = FlicTwistDevice(hass, entry)
    else:
        from .runtime import FlicDevice

        device = FlicDevice(hass, entry)
    entry.runtime_data = device
    await device.async_start()
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    mode = entry.options.get(CONF_PUSH_TWIST_MODE)

    async def _async_entry_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Reload only when the Twist push-twist mode option changes.

        Update listeners also run for every data update, and the runtime stores
        event counters and the boot id on each press and reconnect. Reloading
        then would release the button on every press.
        """
        if entry.options.get(CONF_PUSH_TWIST_MODE) != mode:
            await hass.config_entries.async_reload(entry.entry_id)

    entry.async_on_unload(entry.add_update_listener(_async_entry_updated))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a Flic button."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        await entry.runtime_data.async_stop()
    return unload_ok
