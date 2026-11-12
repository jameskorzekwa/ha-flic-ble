"""Constants for the Flic Bluetooth integration."""

from homeassistant.const import Platform

DOMAIN = "flic_ble"
PLATFORMS = [Platform.EVENT, Platform.NUMBER, Platform.SENSOR]

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

# Device models as shown in the device registry.
MODEL_FLIC = "Flic Button"
MODEL_DUO = "Flic Duo"
MODEL_TWIST = "Flic Twist"

TWIST_SERVICE_UUID = "00c90000-2cbd-4f2a-a725-5ccd960ffb7d"
CONF_DEVICE_TYPE = "device_type"
DEVICE_TYPE_TWIST = "twist"
CONF_SIG_BITS = "sig_bits"

# Flic Twist push-twist mode (options flow), matching pyflic-ble's values.
CONF_PUSH_TWIST_MODE = "push_twist_mode"
PUSH_TWIST_DEFAULT = "default"
PUSH_TWIST_CONTINUOUS = "continuous"
PUSH_TWIST_SELECTOR = "selector"
PUSH_TWIST_MODES = [PUSH_TWIST_DEFAULT, PUSH_TWIST_CONTINUOUS, PUSH_TWIST_SELECTOR]

_CLICKS = ["single", "double", "hold", "down", "up"]
_SWIPES = ["swipe_left", "swipe_right", "swipe_up", "swipe_down"]
_ROTATIONS = ["rotate_clockwise", "rotate_counter_clockwise"]

FLIC_EVENT_TYPES = list(_CLICKS)
_DUO_BUTTON = [*_CLICKS, *_SWIPES, *_ROTATIONS]
DUO_EVENT_TYPES = [*_DUO_BUTTON, *(f"small_{kind}" for kind in _DUO_BUTTON)]
TWIST_TURN_EVENT_TYPES = [
    "twist_increment",
    "twist_decrement",
    "push_twist_increment",
    "push_twist_decrement",
]
TWIST_SELECTOR_EVENT_TYPES = [*_ROTATIONS, "selector_changed"]
TWIST_EVENT_TYPES = [*_CLICKS, *TWIST_TURN_EVENT_TYPES, *TWIST_SELECTOR_EVENT_TYPES]

# Every event type the integration can fire, for validating device triggers.
EVENT_TYPES = list(dict.fromkeys([*DUO_EVENT_TYPES, *TWIST_EVENT_TYPES]))


def event_types_for(model: str | None, push_twist_mode: str | None = None) -> list[str]:
    """Return the event types a device model can fire."""
    if model == MODEL_DUO:
        return DUO_EVENT_TYPES
    if model == MODEL_TWIST:
        if push_twist_mode == PUSH_TWIST_SELECTOR:
            return [*_CLICKS, *TWIST_SELECTOR_EVENT_TYPES]
        return [*_CLICKS, *TWIST_TURN_EVENT_TYPES]
    return FLIC_EVENT_TYPES


def model_for(data: dict) -> str:
    """Return the device model for a config entry's data."""
    if data.get(CONF_DEVICE_TYPE) == DEVICE_TYPE_TWIST:
        return MODEL_TWIST
    return MODEL_DUO if data.get(CONF_IS_DUO) else MODEL_FLIC
