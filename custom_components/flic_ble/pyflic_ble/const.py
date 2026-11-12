"""Constants for the pyflic-ble library."""

from __future__ import annotations

from enum import StrEnum
from typing import Final


class DeviceType(StrEnum):
    """Flic device types."""

    FLIC2 = "flic2"
    DUO = "duo"
    TWIST = "twist"

    @classmethod
    def from_serial_number(cls, serial: str) -> DeviceType:
        """Detect device type from serial number prefix."""
        if serial.startswith("T"):
            return cls.TWIST
        if serial.startswith("D"):
            return cls.DUO
        return cls.FLIC2


class PushTwistMode(StrEnum):
    """Push twist mode options."""

    DEFAULT = "default"
    CONTINUOUS = "continuous"
    SELECTOR = "selector"


# Flic 2/Duo BLE Service and Characteristics
FLIC_SERVICE_UUID: Final = "00420000-8f59-4420-870d-84f3b617e493"
FLIC_WRITE_CHAR_UUID: Final = "00420001-8f59-4420-870d-84f3b617e493"
FLIC_NOTIFY_CHAR_UUID: Final = "00420002-8f59-4420-870d-84f3b617e493"

# Flic Twist BLE Service and Characteristics
TWIST_SERVICE_UUID: Final = "00c90000-2cbd-4f2a-a725-5ccd960ffb7d"
TWIST_TX_CHAR_UUID: Final = "00c90001-2cbd-4f2a-a725-5ccd960ffb7d"
TWIST_RX_CHAR_UUID: Final = "00c90002-2cbd-4f2a-a725-5ccd960ffb7d"

# Ed25519 public keys for signature verification
FLIC2_ED25519_PUBLIC_KEY: Final = bytes.fromhex(
    "d33f2440dd54b31b2e1dcf40132efa41d8f8a7474168df4008f5a95fb3b0d022"
)
TWIST_ED25519_PUBLIC_KEY: Final = bytes.fromhex(
    "a8b7df10434f565069e4131f5b13f1d9056faf2b61cf929b05d02d630bdaf48b"
)

# Protocol constants
FLIC_MTU: Final = 140  # Maximum ATT MTU
FLIC_MAX_PACKET_SIZE: Final = 129  # Maximum packet size (140 - 11 ATT overhead)
FLIC_SIGNATURE_SIZE: Final = 5  # Chaskey-LTS MAC size for packets

# When the button's boot id is not known yet, as after a restart, it re-sends all
# events it holds, including ones already processed; queued events older than
# this at connect are dropped
UNSYNCED_QUEUED_EVENT_MAX_AGE_MS: Final = 15_000

# Frame header bitmasks (Flic 2/Duo framing)
FRAME_HEADER_CONN_ID_MASK: Final = 0x1F
FRAME_HEADER_NEWLY_ASSIGNED: Final = 0x20
FRAME_HEADER_FRAGMENT_FLAG: Final = 0x80

# Event types
EVENT_TYPE_UP: Final = "up"
EVENT_TYPE_DOWN: Final = "down"
EVENT_TYPE_CLICK: Final = "click"
EVENT_TYPE_DOUBLE_CLICK: Final = "double_click"
EVENT_TYPE_HOLD: Final = "hold"

# Gesture event types (Flic Duo only)
EVENT_TYPE_SWIPE_LEFT: Final = "swipe_left"
EVENT_TYPE_SWIPE_RIGHT: Final = "swipe_right"
EVENT_TYPE_SWIPE_UP: Final = "swipe_up"
EVENT_TYPE_SWIPE_DOWN: Final = "swipe_down"

# Rotate event types (Flic Duo and Twist)
EVENT_TYPE_ROTATE_CLOCKWISE: Final = "rotate_clockwise"
EVENT_TYPE_ROTATE_COUNTER_CLOCKWISE: Final = "rotate_counter_clockwise"

# Twist-specific event types
EVENT_TYPE_SELECTOR_CHANGED: Final = "selector_changed"

# Twist DEFAULT mode increment/decrement event types
EVENT_TYPE_TWIST_INCREMENT: Final = "twist_increment"
EVENT_TYPE_TWIST_DECREMENT: Final = "twist_decrement"
EVENT_TYPE_PUSH_TWIST_INCREMENT: Final = "push_twist_increment"
EVENT_TYPE_PUSH_TWIST_DECREMENT: Final = "push_twist_decrement"

# Twist slot position changed event types (one per slot, modes 0-11)
EVENT_TYPE_SLOT_CHANGED: Final = [f"slot_{i}_changed" for i in range(1, 13)]

# Duo dial position changed event type
EVENT_TYPE_DUO_DIAL_CHANGED: Final = "duo_dial_changed"

# Timeouts (seconds)
PAIRING_TIMEOUT: Final = 60
CONNECTION_TIMEOUT: Final = 30
COMMAND_TIMEOUT: Final = 10

# BLE connection parameters
CONN_PARAM_LATENCY: Final = 17
CONN_PARAM_INTERVAL_MIN: Final = 80
CONN_PARAM_INTERVAL_MAX: Final = 90
CONN_PARAM_TIMEOUT: Final = 800

# Protocol opcodes - from official Flic 2 SDK
# Request opcodes (OpcodeToFlic)
OPCODE_FULL_VERIFY_REQUEST_1: Final = 0
OPCODE_FULL_VERIFY_REQUEST_2: Final = 2
OPCODE_QUICK_VERIFY_REQUEST: Final = 5
OPCODE_GET_FIRMWARE_VERSION_REQUEST: Final = 8
OPCODE_GET_BATTERY_LEVEL_REQUEST: Final = 20
OPCODE_INIT_BUTTON_EVENTS_REQUEST: Final = 23
OPCODE_PING_RESPONSE: Final = 14
OPCODE_ACK_BUTTON_EVENTS: Final = 16

# Response opcodes (OpcodeFromFlic)
OPCODE_FULL_VERIFY_RESPONSE_1: Final = 0
OPCODE_FULL_VERIFY_RESPONSE_2: Final = 1
OPCODE_NO_LOGICAL_CONNECTION_SLOTS: Final = 2
OPCODE_FULL_VERIFY_FAIL_RESPONSE: Final = 3
OPCODE_GET_FIRMWARE_VERSION_RESPONSE: Final = 5
OPCODE_QUICK_VERIFY_RESPONSE: Final = 8
OPCODE_DISCONNECT_VERIFIED_LINK: Final = 9
OPCODE_BUTTON_EVENT: Final = 12
OPCODE_PING_REQUEST: Final = 15
OPCODE_GET_BATTERY_LEVEL_RESPONSE: Final = 20

# Flic 2/Duo auto disconnect time in seconds (9 bits); 511 means never
AUTO_DISCONNECT_TIME_NEVER: Final = 511

# FullVerifyFailResponse reasons (Flic 2, Duo and Twist)
FULL_VERIFY_FAIL_REASON_INVALID_VERIFIER: Final = 0
FULL_VERIFY_FAIL_REASON_NOT_IN_PUBLIC_MODE: Final = 1

# Button event types for Flic 2
FLIC2_EVENT_UP: Final = 0
FLIC2_EVENT_DOWN: Final = 1
FLIC2_EVENT_SINGLE_CLICK_TIMEOUT: Final = 2
FLIC2_EVENT_HOLD: Final = 3
FLIC2_EVENT_UP_CLICK_PENDING: Final = 8
FLIC2_EVENT_UP_SINGLE_CLICK: Final = 10
FLIC2_EVENT_UP_DOUBLE_CLICK: Final = 11
FLIC2_EVENT_UP_AFTER_HOLD: Final = 14

# Indication opcodes (fire-and-forget, no response expected)
OPCODE_SET_CONNECTION_PARAMETERS_IND: Final = 12

# Response opcodes for button event initialization
OPCODE_INIT_BUTTON_EVENTS_RESPONSE_WITH_BOOT_ID: Final = 10
OPCODE_INIT_BUTTON_EVENTS_RESPONSE_WITHOUT_BOOT_ID: Final = 11

# Flic Duo specific opcodes
OPCODE_INIT_BUTTON_EVENTS_DUO_REQUEST: Final = 35
OPCODE_ACK_BUTTON_EVENTS_DUO: Final = 36
OPCODE_BUTTON_EVENT_DUO: Final = 32
OPCODE_ENABLE_PUSH_TWIST_IND: Final = 37
OPCODE_PUSH_TWIST_DATA_NOTIFICATION: Final = 33

# Response opcodes for Duo button event initialization
OPCODE_INIT_BUTTON_EVENTS_DUO_RESPONSE_WITH_BOOT_ID: Final = 30
OPCODE_INIT_BUTTON_EVENTS_DUO_RESPONSE_WITHOUT_BOOT_ID: Final = 31

# Flic Twist specific opcodes
TWIST_OPCODE_FULL_VERIFY_REQUEST_1: Final = 0x00
TWIST_OPCODE_FULL_VERIFY_REQUEST_2: Final = 0x02
TWIST_OPCODE_QUICK_VERIFY_REQUEST: Final = 0x05
TWIST_OPCODE_INIT_BUTTON_EVENTS: Final = 0x0C
TWIST_OPCODE_ACK_BUTTON_EVENTS: Final = 0x0D
TWIST_OPCODE_UPDATE_TWIST_POS: Final = 0x0E
TWIST_OPCODE_GET_FIRMWARE_VERSION_REQUEST: Final = 0x07
TWIST_OPCODE_GET_BATTERY_LEVEL_REQUEST: Final = 0x11

# Twist opcodes (Device -> Host)
TWIST_OPCODE_FULL_VERIFY_RESPONSE_1: Final = 0x00
TWIST_OPCODE_FULL_VERIFY_RESPONSE_2: Final = 0x01
TWIST_OPCODE_FULL_VERIFY_FAIL_RESPONSE: Final = 0x02
TWIST_OPCODE_GET_FIRMWARE_VERSION_RESPONSE: Final = 0x04
TWIST_OPCODE_QUICK_VERIFY_NEGATIVE: Final = 0x05
TWIST_OPCODE_QUICK_VERIFY_RESPONSE: Final = 0x06
TWIST_OPCODE_DISCONNECTED_VERIFIED_LINK: Final = 0x07
TWIST_OPCODE_INIT_BUTTON_EVENTS_RESPONSE: Final = 0x08
TWIST_OPCODE_BUTTON_EVENT: Final = 0x09
TWIST_OPCODE_TWIST_EVENT: Final = 0x0A
TWIST_OPCODE_GET_BATTERY_LEVEL_RESPONSE: Final = 0x10

# Twist disconnect reasons
TWIST_DISCONNECT_REASON_INVALID_SIGNATURE: Final = 0
TWIST_DISCONNECT_REASON_OTHER_CLIENT: Final = 1

# Twist mode indices
TWIST_MODE_SLOT_FIRST: Final = 0
TWIST_MODE_SLOT_LAST: Final = 11
TWIST_MODE_SLOT_CHANGING: Final = 12

# Firmware update constants
# Twist firmware update opcodes (Host -> Device)
TWIST_OPCODE_FORCE_BT_DISCONNECT_IND: Final = 0x06
TWIST_OPCODE_START_FIRMWARE_UPDATE_REQUEST: Final = 0x0F
TWIST_OPCODE_FIRMWARE_UPDATE_DATA_IND: Final = 0x10

# Twist firmware update opcodes (Device -> Host)
TWIST_OPCODE_START_FIRMWARE_UPDATE_RESPONSE: Final = 0x0E
TWIST_OPCODE_FIRMWARE_UPDATE_NOTIFICATION: Final = 0x0F

# Flic 2 firmware update opcodes (Host -> Device)
OPCODE_FORCE_BT_DISCONNECT_IND: Final = 6
OPCODE_START_FIRMWARE_UPDATE_REQUEST: Final = 17
OPCODE_FIRMWARE_UPDATE_DATA_IND: Final = 18

# Flic 2 firmware update opcodes (Device -> Host)
OPCODE_START_FIRMWARE_UPDATE_RESPONSE: Final = 18
OPCODE_FIRMWARE_UPDATE_NOTIFICATION: Final = 19

# Flic Duo firmware update opcodes (Host -> Device)
OPCODE_START_FIRMWARE_UPDATE_DUO_REQUEST: Final = 38
OPCODE_FIRMWARE_UPDATE_DATA_DUO_IND: Final = 39

# Firmware binary header
FIRMWARE_HEADER_SIZE: Final = 76

# Twist transfer constants
FIRMWARE_DATA_CHUNK_SIZE: Final = 120
FIRMWARE_MAX_IN_FLIGHT: Final = 480
FIRMWARE_STATUS_INTERVAL: Final = 2
FIRMWARE_UPDATE_TIMEOUT: Final = 300
FIRMWARE_FINAL_ACK_TIMEOUT: Final = 30

# Flic 2 transfer constants
FLIC2_FIRMWARE_WORD_CHUNK_SIZE: Final = 30
FLIC2_FIRMWARE_MAX_IN_FLIGHT_WORDS: Final = 512
FLIC2_FIRMWARE_STATUS_INTERVAL: Final = 60
FLIC2_FIRMWARE_IV_SIZE: Final = 8

# Duo transfer constants
DUO_FIRMWARE_DATA_CHUNK_SIZE: Final = 110
DUO_FIRMWARE_MAX_IN_FLIGHT: Final = 550
DUO_FIRMWARE_STATUS_INTERVAL: Final = 2

# Name management opcodes - Flic 2/Duo (Host -> Device)
OPCODE_SET_NAME_REQUEST: Final = 10
OPCODE_GET_NAME_REQUEST: Final = 11

# Name management opcodes - Flic 2/Duo (Device -> Host)
OPCODE_GET_NAME_RESPONSE: Final = 16
OPCODE_SET_NAME_RESPONSE: Final = 17

# Name management opcodes - Twist (Host -> Device)
TWIST_OPCODE_SET_NAME_REQUEST: Final = 0x09
TWIST_OPCODE_GET_NAME_REQUEST: Final = 0x0A

# Name management opcodes - Twist (Device -> Host)
TWIST_OPCODE_GET_NAME_RESPONSE: Final = 0x0C
TWIST_OPCODE_SET_NAME_RESPONSE: Final = 0x0D

# Name constraints
DEVICE_NAME_MAX_BYTES: Final = 23
