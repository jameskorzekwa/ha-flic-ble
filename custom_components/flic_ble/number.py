"""Flic Twist position numbers.

Adapted from Home Assistant core's ``flic_button`` number platform (Apache-2.0).
The Twist takes the position of each of its modes from the host, so these
entities both mirror the dial and let automations move it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from bleak.exc import BleakError
from homeassistant.components.number import (
    DOMAIN as NUMBER_DOMAIN,
)
from homeassistant.components.number import (
    NumberEntityDescription,
    NumberMode,
    RestoreNumber,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    CONF_PUSH_TWIST_MODE,
    DOMAIN,
    MODEL_TWIST,
    PUSH_TWIST_DEFAULT,
    PUSH_TWIST_SELECTOR,
    model_for,
)
from .entity import FlicEntity
from .pyflic_ble import FlicProtocolError
from .pyflic_ble.const import TWIST_MODE_SLOT_CHANGING

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, kw_only=True)
class FlicTwistNumberEntityDescription(NumberEntityDescription):
    """Describes one Flic Twist mode position."""

    mode_index: int


SLOT_DESCRIPTIONS = tuple(
    FlicTwistNumberEntityDescription(
        key=f"slot_{index + 1}",
        name=f"Slot {index + 1}",
        mode_index=index,
    )
    for index in range(TWIST_MODE_SLOT_CHANGING)
)
POSITION_DESCRIPTIONS = (
    FlicTwistNumberEntityDescription(
        key="twist_position", name="Twist position", mode_index=0
    ),
    FlicTwistNumberEntityDescription(
        key="push_twist_position",
        name="Push twist position",
        mode_index=TWIST_MODE_SLOT_CHANGING,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the position numbers for a Flic Twist."""
    if model_for(entry.data) != MODEL_TWIST:
        return
    mode = entry.options.get(CONF_PUSH_TWIST_MODE, PUSH_TWIST_DEFAULT)
    if mode == PUSH_TWIST_SELECTOR:
        descriptions: tuple[FlicTwistNumberEntityDescription, ...] = SLOT_DESCRIPTIONS
    elif mode == PUSH_TWIST_DEFAULT:
        descriptions = POSITION_DESCRIPTIONS
    else:
        # The continuous LED shows raw rotation, which a position write cannot move.
        descriptions = ()

    registry = er.async_get(hass)
    for description in (*SLOT_DESCRIPTIONS, *POSITION_DESCRIPTIONS):
        if description not in descriptions and (
            entity_id := registry.async_get_entity_id(
                NUMBER_DOMAIN, DOMAIN, f"{entry.unique_id}_{description.key}"
            )
        ):
            registry.async_remove(entity_id)
    async_add_entities(
        FlicTwistNumberEntity(entry, description) for description in descriptions
    )


class FlicTwistNumberEntity(FlicEntity, RestoreNumber):
    """The position of one Flic Twist mode, 0-100 %."""

    entity_description: FlicTwistNumberEntityDescription
    _attr_native_min_value = 0
    _attr_native_max_value = 100
    _attr_native_step = 1
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_mode = NumberMode.SLIDER
    _attr_native_value: float | None = None

    def __init__(
        self, entry: ConfigEntry, description: FlicTwistNumberEntityDescription
    ) -> None:
        super().__init__(entry)
        self.entity_description = description
        self._attr_unique_id = f"{entry.unique_id}_{description.key}"
        self._pending_restore: float | None = None

    async def async_added_to_hass(self) -> None:
        """Restore the last position and follow the dial."""
        client = self.device.client
        # The Twist takes its position from the host; hand it back after a
        # restart once the session is up.
        if (
            last := await self.async_get_last_number_data()
        ) is not None and last.native_value is not None:
            self._attr_native_value = last.native_value
            self._pending_restore = last.native_value
            if client.state.connected:
                await self._async_restore_position()
        self.async_on_remove(
            client.register_rotate_event_callback(self._handle_rotate_event)
        )
        self.async_on_remove(self.device.async_add_state_listener(self._handle_state))

    @callback
    def _handle_state(self) -> None:
        if self.device.available and self._pending_restore is not None:
            self.hass.async_create_task(
                self._async_restore_position(), eager_start=False
            )
        self.async_write_ha_state()

    async def _async_restore_position(self) -> None:
        value, self._pending_restore = self._pending_restore, None
        if value is None:
            return
        try:
            await self._async_send_position(value)
        except HomeAssistantError as err:
            _LOGGER.debug("Could not restore %s: %s", self.entity_id, err)

    @callback
    def _handle_rotate_event(self, event_type: str, data: dict[str, Any]) -> None:
        if data.get("twist_mode_index") != self.entity_description.mode_index:
            return
        if (percentage := data.get("mode_percentage")) is None:
            return
        self._attr_native_value = round(percentage)
        self.async_write_ha_state()

    async def async_set_native_value(self, value: float) -> None:
        """Move this mode's position on the Twist."""
        await self._async_send_position(value)
        self._attr_native_value = value
        self.async_write_ha_state()

    async def _async_send_position(self, value: float) -> None:
        try:
            await self.device.client.async_send_update_twist_position(
                self.entity_description.mode_index, value
            )
        except (TimeoutError, BleakError, FlicProtocolError) as err:
            raise HomeAssistantError(
                f"Could not set the position on Flic Twist {self.device.address}"
            ) from err
