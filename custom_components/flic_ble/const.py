"""Constants for the Flic Bluetooth integration."""

from homeassistant.const import Platform

DOMAIN = "flic_ble"
PLATFORMS = [Platform.EVENT, Platform.SENSOR]

# Home Assistant bus event fired for every button press. Automations and device
# triggers listen for this instead of watching the event entity's state, so a
# press queued while the button slept and delivered on reconnect is never lost
# to an entity "unavailable" transition.
EVENT_FLIC_EVENT = f"{DOMAIN}_event"
ATTR_TYPE = "type"
ATTR_BUTTON = "button"
ATTR_GESTURE = "gesture"

SERVICE_UUID = "00420000-8f59-4420-870d-84f3b617e493"
TX_UUID = "00420001-8f59-4420-870d-84f3b617e493"
RX_UUID = "00420002-8f59-4420-870d-84f3b617e493"

CONF_PAIRING_IDENTIFIER = "pairing_identifier"
CONF_PAIRING_KEY = "pairing_key"
CONF_BUTTON_UUID = "button_uuid"
CONF_SERIAL_NUMBER = "serial_number"
CONF_FIRMWARE_VERSION = "firmware_version"
CONF_EVENT_COUNT = "event_count"
CONF_EVENT_COUNT_SMALL = "event_count_small"
CONF_BOOT_ID = "boot_id"
CONF_IS_DUO = "is_duo"

EVENT_TYPES = [
    "single",
    "double",
    "hold",
    "swipe_left",
    "swipe_right",
    "swipe_up",
    "swipe_down",
    "small_single",
    "small_double",
    "small_hold",
    "small_swipe_left",
    "small_swipe_right",
    "small_swipe_up",
    "small_swipe_down",
]
