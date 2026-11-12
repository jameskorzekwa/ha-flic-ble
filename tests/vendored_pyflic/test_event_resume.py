"""Test that reconnects only ask the button for events not processed yet."""

import asyncio
from collections.abc import Callable
import struct

import pytest

from custom_components.flic_ble.pyflic_ble.const import (
    OPCODE_BUTTON_EVENT,
    OPCODE_INIT_BUTTON_EVENTS_RESPONSE_WITH_BOOT_ID,
    TWIST_OPCODE_BUTTON_EVENT,
    TWIST_OPCODE_INIT_BUTTON_EVENTS_RESPONSE,
    PushTwistMode,
)
from custom_components.flic_ble.pyflic_ble.handlers.base import DeviceProtocolHandler
from custom_components.flic_ble.pyflic_ble.handlers.flic2 import Flic2ProtocolHandler
from custom_components.flic_ble.pyflic_ble.handlers.twist import TwistProtocolHandler

BOOT_ID = 0x12345678
TICKS_PER_SECOND = 32768
# The button clock when it answers the init request, in seconds
NOW = 1000


class InitTransport:
    """Record packets and answer the init request with a fixed response."""

    def __init__(self, init_response: bytes) -> None:
        """Initialize the transport."""
        self.packets: list[bytes] = []
        self._init_response = init_response

    async def write_gatt(self, uuid: str, data: bytes) -> None:
        """Record a raw GATT write."""
        self.packets.append(data)

    async def write_packet(self, data: bytes, authenticated: bool) -> None:
        """Record a packet."""
        self.packets.append(data)

    async def wait_for_opcode(self, opcode: int) -> bytes:
        """Answer the init request."""
        return self._init_response

    async def wait_for_opcodes(self, opcodes: list[int]) -> bytes:
        """Answer the init request."""
        return self._init_response


def _connect(handler: DeviceProtocolHandler, init_response: bytes) -> bytes:
    """Start a new connection and return the init request that was sent."""
    transport = InitTransport(init_response)
    handler.reset_state()
    handler.bind_transport(
        transport.write_gatt,
        transport.write_packet,
        transport.wait_for_opcode,
        transport.wait_for_opcodes,
    )
    asyncio.run(handler.init_button_events(None, None))
    return transport.packets[0]


def test_twist_reconnect_resumes_after_processed_events() -> None:
    """Test a Twist reconnect hands back the boot id and the last event count."""
    handler = TwistProtocolHandler(PushTwistMode.DEFAULT)
    init_response = (
        bytes([TWIST_OPCODE_INIT_BUTTON_EVENTS_RESPONSE])
        + bytes(6)
        + struct.pack("<II", 5, BOOT_ID)
        + bytes([2])
    )

    first_init = _connect(handler, init_response)
    assert struct.unpack_from("<I", first_init, 1)[0] == 0

    handler.handle_notification(
        bytes([TWIST_OPCODE_BUTTON_EVENT]) + struct.pack("<I", 9)
    )

    second_init = _connect(handler, init_response)
    assert struct.unpack_from("<I", second_init, 1)[0] == 9
    assert struct.unpack_from("<I", second_init, 70)[0] == BOOT_ID


def test_flic2_reconnect_resumes_after_processed_events() -> None:
    """Test a Flic 2 reconnect hands back the boot id and the last event count."""
    handler = Flic2ProtocolHandler()
    init_response = (
        bytes([0x00, OPCODE_INIT_BUTTON_EVENTS_RESPONSE_WITH_BOOT_ID])
        + bytes(6)
        + struct.pack("<II", 5, BOOT_ID)
    )

    first_init = _connect(handler, init_response)
    assert struct.unpack_from("<II", first_init, 2) == (0, 0)

    handler.handle_notification(
        bytes([0x00, OPCODE_BUTTON_EVENT]) + struct.pack("<I", 9)
    )

    second_init = _connect(handler, init_response)
    assert struct.unpack_from("<II", second_init, 2) == (9, BOOT_ID)


def _init_timestamp() -> bytes:
    """Pack has_queued_events and the button clock of an init response."""
    return ((NOW * TICKS_PER_SECOND) << 1 | 1).to_bytes(6, byteorder="little")


def _twist_init_response(boot_id: int) -> bytes:
    """Build a Twist InitButtonEventsResponse."""
    return (
        bytes([TWIST_OPCODE_INIT_BUTTON_EVENTS_RESPONSE])
        + _init_timestamp()
        + struct.pack("<II", 5, boot_id)
        + bytes([2])
    )


def _twist_queued_downs(*seconds: int) -> bytes:
    """Build a Twist notification with a queued down event at each time."""
    return (
        bytes([TWIST_OPCODE_BUTTON_EVENT])
        + struct.pack("<I", 9)
        + b"".join(
            (second * TICKS_PER_SECOND).to_bytes(6, byteorder="little")
            + bytes([0x11, 0x00])
            for second in seconds
        )
    )


def _flic2_init_response(boot_id: int) -> bytes:
    """Build a Flic 2 InitButtonEventsResponseWithBootId."""
    return (
        bytes([0x00, OPCODE_INIT_BUTTON_EVENTS_RESPONSE_WITH_BOOT_ID])
        + _init_timestamp()
        + struct.pack("<II", 5, boot_id)
    )


def _flic2_queued_downs(*seconds: int) -> bytes:
    """Build a Flic 2 notification with a queued down event at each time."""
    return (
        bytes([0x00, OPCODE_BUTTON_EVENT])
        + struct.pack("<I", 9)
        + b"".join(
            (second * TICKS_PER_SECOND).to_bytes(6, byteorder="little") + bytes([0x11])
            for second in seconds
        )
    )


DEVICES = [
    pytest.param(
        lambda: TwistProtocolHandler(PushTwistMode.DEFAULT),
        _twist_init_response,
        _twist_queued_downs,
        id="twist",
    ),
    pytest.param(
        Flic2ProtocolHandler, _flic2_init_response, _flic2_queued_downs, id="flic2"
    ),
]


@pytest.mark.parametrize(("create_handler", "init_response", "queued_downs"), DEVICES)
def test_old_queued_events_dropped_when_boot_id_unknown(
    create_handler: Callable[[], DeviceProtocolHandler],
    init_response: Callable[[int], bytes],
    queued_downs: Callable[..., bytes],
) -> None:
    """Test events queued long before an unsynced connect are not replayed."""
    handler = create_handler()
    _connect(handler, init_response(BOOT_ID))

    button_events, _, _ = handler.handle_notification(queued_downs(NOW - 20, NOW - 5))

    assert [event.timestamp_ms for event in button_events] == [(NOW - 5) * 1000]


@pytest.mark.parametrize(("create_handler", "init_response", "queued_downs"), DEVICES)
def test_queued_events_kept_when_boot_id_known(
    create_handler: Callable[[], DeviceProtocolHandler],
    init_response: Callable[[int], bytes],
    queued_downs: Callable[..., bytes],
) -> None:
    """Test presses made while disconnected still arrive after a reconnect."""
    handler = create_handler()
    _connect(handler, init_response(BOOT_ID))
    _connect(handler, init_response(BOOT_ID))

    button_events, _, _ = handler.handle_notification(queued_downs(NOW - 20, NOW - 5))

    assert len(button_events) == 2
