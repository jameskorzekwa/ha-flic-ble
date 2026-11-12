"""Exceptions raised by pyflic-ble."""


class FlicProtocolError(Exception):
    """Flic protocol error."""


class FlicPairingError(Exception):
    """Flic pairing error."""


class FlicAuthenticationError(Exception):
    """Flic authentication error."""


class FlicFirmwareUpdateError(Exception):
    """Flic firmware update error."""
