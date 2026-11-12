"""Test Flic Duo event counts, resumption and acknowledgements."""

import asyncio
import struct

import pytest

from custom_components.flic_ble.pyflic_ble.const import OPCODE_ACK_BUTTON_EVENTS_DUO, OPCODE_BUTTON_EVENT_DUO
from custom_components.flic_ble.pyflic_ble.handlers.duo import DuoProtocolHandler

BOOT_ID = 0x12345678


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


def _init_response(event_counts: tuple[int, int], boot_id: int) -> bytes:
    """Build an init response with a boot id and no queued events."""
    return (
        bytes([0x00, 30])
        + bytes(6)
        + struct.pack("<II", *event_counts)
        + struct.pack("<I", boot_id)
    )


def _connect(handler: DuoProtocolHandler, init_response: bytes) -> bytes:
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


def _event(button: int, event_type: int) -> bytes:
    """Build a Duo notification with one event, encoded as in the spec.

    The event counter delta is 0, so the count goes up by one, and the
    timestamp moves 5 ms. No end of queue marker follows, as the init response
    reported no queued events.
    """
    fields = [(button, 1), (0, 1), (0, 3), (5, 8), (event_type, 3)]
    if event_type in (4, 7):
        fields.append((0, 1))
    if event_type <= 4 or event_type == 6:
        fields.append((0, 1))
    fields.extend([(0, 8), (0, 8), (0, 8)])
    value, offset = 0, 0
    for field, width in fields:
        value |= field << offset
        offset += width
    return bytes([0x00, OPCODE_BUTTON_EVENT_DUO]) + value.to_bytes(
        (offset + 7) // 8, byteorder="little"
    )


# Button 0 starts at 5 and gets one more event, which the spec rounds up to an
# odd count for every type but the single click timeout
ACK_ODD = struct.pack("<BBII", 0, OPCODE_ACK_BUTTON_EVENTS_DUO, 7, 7)
ACK_TIMEOUT = struct.pack("<BBII", 0, OPCODE_ACK_BUTTON_EVENTS_DUO, 6, 7)


@pytest.mark.parametrize(
    ("event_type", "expected_writes"),
    [
        pytest.param(1, [ACK_ODD], id="single_click"),
        pytest.param(2, [ACK_ODD], id="single_click_after_long_press"),
        pytest.param(3, [ACK_ODD], id="double_click"),
        pytest.param(4, [ACK_ODD], id="double_click_with_flag"),
        pytest.param(6, [ACK_TIMEOUT], id="single_click_timeout"),
        pytest.param(0, [], id="up_pending"),
        pytest.param(5, [], id="down"),
        pytest.param(7, [], id="hold"),
    ],
)
def test_duo_acknowledges_clicks_with_both_counts(
    event_type: int, expected_writes: list[bytes]
) -> None:
    """Test clicks are acknowledged with counts that start from the button's."""
    handler = DuoProtocolHandler()
    _connect(handler, _init_response((5, 7), BOOT_ID))

    handler.handle_notification(_event(0, event_type))

    assert handler.pop_pending_writes() == expected_writes


def test_duo_reconnect_resumes_after_processed_events() -> None:
    """Test a Duo reconnect hands back the boot id and both event counts."""
    handler = DuoProtocolHandler()
    first_init = _connect(handler, _init_response((5, 7), BOOT_ID))
    assert struct.unpack_from("<III", first_init, 2) == (0, 0, 0)

    handler.handle_notification(_event(1, 1))

    second_init = _connect(handler, _init_response((5, 9), BOOT_ID))
    assert struct.unpack_from("<III", second_init, 2) == (5, 9, BOOT_ID)
