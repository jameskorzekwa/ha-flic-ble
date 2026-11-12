"""pyflic-ble: Python library for Flic smart button BLE communication."""

from .client import (
    FlicAuthenticationError,
    FlicClient,
    FlicFirmwareUpdateError,
    FlicPairingError,
    FlicProtocolError,
    FlicState,
)
from .const import DeviceType, PushTwistMode
from .handlers.base import DeviceCapabilities

__all__ = [
    "DeviceCapabilities",
    "DeviceType",
    "FlicAuthenticationError",
    "FlicClient",
    "FlicFirmwareUpdateError",
    "FlicPairingError",
    "FlicProtocolError",
    "FlicState",
    "PushTwistMode",
]
