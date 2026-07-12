"""Shared Flic 2 entity helpers."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity

from .const import CONF_FIRMWARE_VERSION, CONF_IS_DUO, CONF_SERIAL_NUMBER, DOMAIN


class Flic2Entity(Entity):
    """Base entity for a paired Flic 2."""

    _attr_has_entity_name = True

    def __init__(self, entry: ConfigEntry) -> None:
        self.entry = entry
        self.device = entry.runtime_data
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.unique_id or self.device.address)},
            manufacturer="Flic",
            model="Flic Duo" if entry.data.get(CONF_IS_DUO) else "Flic 2",
            name=entry.title,
            serial_number=entry.data.get(CONF_SERIAL_NUMBER),
            sw_version=str(entry.data.get(CONF_FIRMWARE_VERSION, "")),
        )

    @property
    def available(self) -> bool:
        """Return whether communication has succeeded at least once."""
        return self.device.available
