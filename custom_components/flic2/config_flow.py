"""Config flow for Flic 2 Bluetooth."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from bleak.exc import BleakError
from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
)
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_ADDRESS

from .const import (
    CONF_BOOT_ID,
    CONF_BUTTON_UUID,
    CONF_EVENT_COUNT,
    CONF_EVENT_COUNT_SMALL,
    CONF_FIRMWARE_VERSION,
    CONF_IS_DUO,
    CONF_PAIRING_IDENTIFIER,
    CONF_PAIRING_KEY,
    CONF_SERIAL_NUMBER,
    DOMAIN,
    SERVICE_UUID,
)
from .protocol import (
    AuthenticationError,
    Flic2ProtocolError,
    NoPairingSlotsError,
    PairingModeError,
    PairingRejectedError,
    PairingTimeoutError,
    SessionState,
)
from .runtime import async_pair_device

_LOGGER = logging.getLogger(__name__)


def _is_flic2(info: BluetoothServiceInfoBleak) -> bool:
    return bool(
        info.connectable
        and (
            info.name.startswith("F2")
            or SERVICE_UUID in {uuid.lower() for uuid in info.service_uuids}
        )
    )


class Flic2ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Pair Flic 2 buttons discovered by HA Bluetooth."""

    VERSION = 1

    def __init__(self) -> None:
        self._discovery_info: BluetoothServiceInfoBleak | None = None
        self._devices: dict[str, BluetoothServiceInfoBleak] = {}

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        """Handle automatic discovery while a Flic is in public mode."""
        if not _is_flic2(discovery_info):
            return self.async_abort(reason="not_supported")
        await self.async_set_unique_id(discovery_info.address.upper())
        self._abort_if_unique_id_configured()
        self._discovery_info = discovery_info
        self.context["title_placeholders"] = {"name": discovery_info.name}
        return await self.async_step_confirm()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Let the user choose a public-mode button."""
        if user_input is not None:
            self._discovery_info = self._devices[user_input[CONF_ADDRESS]]
            await self.async_set_unique_id(
                self._discovery_info.address.upper(), raise_on_progress=False
            )
            self._abort_if_unique_id_configured()
            return await self.async_step_confirm()

        configured = self._async_current_ids(include_ignore=False)
        for info in async_discovered_service_info(self.hass):
            address = info.address.upper()
            if address not in configured and _is_flic2(info):
                self._devices[address] = info
        if not self._devices:
            return self.async_abort(reason="no_devices_found")
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_ADDRESS): vol.In(
                        {
                            address: f"{info.name} ({address})"
                            for address, info in self._devices.items()
                        }
                    )
                }
            ),
        )

    async def async_step_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm and perform application-layer pairing."""
        if self._discovery_info is None:
            return self.async_abort(reason="no_devices_found")
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                result = await async_pair_device(self.hass, self._discovery_info)
            except (BleakError, TimeoutError) as err:
                _LOGGER.warning("Unable to connect to Flic 2: %s", err)
                errors["base"] = "connection_failed"
            except NoPairingSlotsError as err:
                _LOGGER.warning("Unable to pair Flic 2: %s", err)
                errors["base"] = "no_pairing_slots"
            except PairingModeError as err:
                _LOGGER.warning("Unable to pair Flic 2: %s", err)
                errors["base"] = "public_mode_required"
            except PairingRejectedError as err:
                _LOGGER.warning("Unable to pair Flic 2: %s", err)
                errors["base"] = "pairing_rejected"
            except AuthenticationError as err:
                _LOGGER.warning("Unable to authenticate Flic 2: %s", err)
                errors["base"] = "authentication_failed"
            except PairingTimeoutError as err:
                _LOGGER.warning("Flic 2 pairing timed out: %s", err)
                if err.state is SessionState.WAIT_FULL_VERIFY_1:
                    errors["base"] = "public_mode_required"
                elif err.state is SessionState.ESTABLISHED:
                    errors["base"] = "initialization_timeout"
                else:
                    errors["base"] = "pairing_interrupted"
            except Flic2ProtocolError as err:
                _LOGGER.warning("Unable to pair Flic 2: %s", err)
                errors["base"] = "pairing_failed"
            except Exception:
                _LOGGER.exception("Unexpected Flic 2 pairing failure")
                errors["base"] = "unknown"
            else:
                if not result.pairing or not result.info:
                    errors["base"] = "pairing_failed"
                else:
                    info = result.info
                    title = info.name or info.serial_number or self._discovery_info.name
                    return self.async_create_entry(
                        title=title,
                        data={
                            CONF_ADDRESS: self._discovery_info.address.upper(),
                            CONF_PAIRING_IDENTIFIER: result.pairing.identifier,
                            CONF_PAIRING_KEY: result.pairing.key.hex(),
                            CONF_BUTTON_UUID: info.uuid,
                            CONF_SERIAL_NUMBER: info.serial_number,
                            CONF_FIRMWARE_VERSION: info.firmware_version,
                            CONF_EVENT_COUNT: result.event_count,
                            CONF_EVENT_COUNT_SMALL: result.event_count_small,
                            CONF_BOOT_ID: result.boot_id,
                            CONF_IS_DUO: info.is_duo,
                            "battery_voltage": result.battery_voltage,
                        },
                    )
        return self.async_show_form(
            step_id="confirm",
            data_schema=vol.Schema({}),
            errors=errors,
            description_placeholders={
                "name": self._discovery_info.name,
                "address": self._discovery_info.address.upper(),
            },
        )
