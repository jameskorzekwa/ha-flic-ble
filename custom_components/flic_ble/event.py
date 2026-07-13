"""Flic event entity."""

from __future__ import annotations

from homeassistant.components.event import EventEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_DEVICE_ID, CONF_TYPE
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import EVENT_FLIC_EVENT, EVENT_TYPES
from .entity import FlicEntity
from .protocol import ButtonEvent


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Flic event entity."""
    async_add_entities([FlicEventEntity(entry)])


class FlicEventEntity(FlicEntity, EventEntity):
    """Represent click events from one Flic."""

    _attr_name = "Button"
    _attr_event_types = EVENT_TYPES

    def __init__(self, entry: ConfigEntry) -> None:
        super().__init__(entry)
        self._attr_unique_id = f"{entry.unique_id}_button"

    async def async_added_to_hass(self) -> None:
        """Subscribe to protocol events."""
        self.async_on_remove(self.device.async_add_event_listener(self._handle_event))
        self.async_on_remove(
            self.device.async_add_state_listener(self.async_write_ha_state)
        )

    @callback
    def _handle_event(self, event: ButtonEvent) -> None:
        event_data = {
            "button": event.button,
            "gesture": event.gesture,
            "queued": event.queued,
            "event_count": event.event_count,
            "button_timestamp_ms": event.timestamp_ms,
        }
        if event.accelerometer is not None:
            x, y, z = event.accelerometer
            event_data.update(
                {
                    "acceleration_x_g": round(x / 64.036875, 3),
                    "acceleration_y_g": round(y / 64.036875, 3),
                    "acceleration_z_g": round(z / 64.036875, 3),
                }
            )
        self._trigger_event(
            event.event_type,
            event_data,
        )
        self.async_write_ha_state()
        # Also fire an HA bus event so automations can use event/device triggers
        # rather than a state trigger on this entity. Bus events have no state and
        # cannot be "unavailable", so a press queued while the button slept and
        # delivered on reconnect fires reliably instead of being filtered out.
        device_id = self.registry_entry.device_id if self.registry_entry else None
        if device_id is not None:
            self.hass.bus.async_fire(
                EVENT_FLIC_EVENT,
                {
                    CONF_DEVICE_ID: device_id,
                    CONF_TYPE: event.event_type,
                    **event_data,
                },
            )
