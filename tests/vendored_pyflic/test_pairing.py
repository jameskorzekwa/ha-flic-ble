"""Test how Flic 2 and Flic Twist pairing failures are reported."""

import asyncio
from collections.abc import Callable
import struct

import pytest

from custom_components.flic_ble.pyflic_ble import FlicAuthenticationError, FlicPairingError, FlicProtocolError
from custom_components.flic_ble.pyflic_ble.const import (
    FULL_VERIFY_FAIL_REASON_INVALID_VERIFIER,
    FULL_VERIFY_FAIL_REASON_NOT_IN_PUBLIC_MODE,
    OPCODE_FULL_VERIFY_FAIL_RESPONSE,
    OPCODE_NO_LOGICAL_CONNECTION_SLOTS,
    TWIST_OPCODE_FULL_VERIFY_FAIL_RESPONSE,
)
from custom_components.flic_ble.pyflic_ble.handlers.base import DeviceProtocolHandler
from custom_components.flic_ble.pyflic_ble.handlers.flic2 import Flic2ProtocolHandler
from custom_components.flic_ble.pyflic_ble.handlers.twist import TwistProtocolHandler
from custom_components.flic_ble.pyflic_ble.security import generate_x25519_keypair

# A response is built from the tmp_id the handler sent in FullVerifyRequest1
Response = Callable[[int], bytes]

_, BUTTON_PUBLIC_KEY = generate_x25519_keypair()


class PairingTransport:
    """Answer a handler's pairing requests with scripted responses."""

    def __init__(self, tmp_id_offset: int, responses: list[Response]) -> None:
        """Initialize the transport."""
        self._tmp_id_offset = tmp_id_offset
        self._responses = responses
        self._tmp_id: int | None = None

    def _record(self, data: bytes) -> None:
        """Remember the tmp_id of the first request."""
        if self._tmp_id is None:
            self._tmp_id = struct.unpack_from("<I", data, self._tmp_id_offset)[0]

    async def write_gatt(self, uuid: str, data: bytes) -> None:
        """Record a raw GATT write."""
        self._record(data)

    async def write_packet(self, data: bytes, authenticated: bool) -> None:
        """Record a packet."""
        self._record(data)

    async def wait_for_opcode(self, opcode: int) -> bytes:
        """Return the next scripted response."""
        assert self._tmp_id is not None
        return self._responses.pop(0)(self._tmp_id)

    async def wait_for_opcodes(self, opcodes: list[int]) -> bytes:
        """Return the next scripted response."""
        assert self._tmp_id is not None
        return self._responses.pop(0)(self._tmp_id)


def _twist_response_1(tmp_id: int) -> bytes:
    """Build a TwistFullVerifyResponse1 for a tmp_id."""
    return (
        bytes([0x00])
        + struct.pack("<I", tmp_id)
        + bytes(64 + 6 + 1)
        + BUTTON_PUBLIC_KEY
        + bytes(8 + 1)
    )


def _flic2_response_1(tmp_id: int) -> bytes:
    """Build a Flic 2 FullVerifyResponse1, which adds a frame header."""
    return bytes([0x00]) + _twist_response_1(tmp_id)


def _pair(
    handler: DeviceProtocolHandler, tmp_id_offset: int, responses: list[Response]
) -> None:
    """Run a pairing attempt against scripted responses."""
    transport = PairingTransport(tmp_id_offset, responses)
    handler.bind_transport(
        transport.write_gatt,
        transport.write_packet,
        transport.wait_for_opcode,
        transport.wait_for_opcodes,
    )
    asyncio.run(handler.full_verify_pairing())


@pytest.fixture
def genuine_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    """Accept the test responses' signature, which only real buttons can produce."""
    for module in ("flic2", "twist"):
        monkeypatch.setattr(
            f"custom_components.flic_ble.pyflic_ble.handlers.{module}.verify_ed25519_signature_with_variant",
            lambda *args: 0,
        )


@pytest.mark.usefixtures("genuine_signature")
@pytest.mark.parametrize(
    ("reason", "error"),
    [
        pytest.param(
            FULL_VERIFY_FAIL_REASON_NOT_IN_PUBLIC_MODE,
            FlicPairingError,
            id="not_in_pairing_mode",
        ),
        pytest.param(
            FULL_VERIFY_FAIL_REASON_INVALID_VERIFIER,
            FlicAuthenticationError,
            id="invalid_verifier",
        ),
    ],
)
def test_twist_full_verify_fail(reason: int, error: type[Exception]) -> None:
    """Test a Twist FullVerifyFailResponse raises an error per reason."""
    with pytest.raises(error):
        _pair(
            TwistProtocolHandler(),
            1,
            [
                _twist_response_1,
                lambda _: bytes([TWIST_OPCODE_FULL_VERIFY_FAIL_RESPONSE, reason]),
            ],
        )


@pytest.mark.usefixtures("genuine_signature")
@pytest.mark.parametrize(
    ("reason", "error"),
    [
        pytest.param(
            FULL_VERIFY_FAIL_REASON_NOT_IN_PUBLIC_MODE,
            FlicPairingError,
            id="not_in_pairing_mode",
        ),
        pytest.param(
            FULL_VERIFY_FAIL_REASON_INVALID_VERIFIER,
            FlicAuthenticationError,
            id="invalid_verifier",
        ),
    ],
)
def test_flic2_full_verify_fail(reason: int, error: type[Exception]) -> None:
    """Test a Flic 2 FullVerifyFailResponse raises an error per reason."""
    with pytest.raises(error):
        _pair(
            Flic2ProtocolHandler(),
            2,
            [
                _flic2_response_1,
                lambda _: bytes([0x00, OPCODE_FULL_VERIFY_FAIL_RESPONSE, reason]),
            ],
        )


@pytest.mark.parametrize(
    ("handler", "tmp_id_offset", "response_1"),
    [
        pytest.param(TwistProtocolHandler(), 1, _twist_response_1, id="twist"),
        pytest.param(Flic2ProtocolHandler(), 2, _flic2_response_1, id="flic2"),
    ],
)
def test_invalid_signature(
    handler: DeviceProtocolHandler, tmp_id_offset: int, response_1: Response
) -> None:
    """Test a button that is not signed by Shortcut Labs fails authentication."""
    with pytest.raises(FlicAuthenticationError):
        _pair(handler, tmp_id_offset, [response_1])


@pytest.mark.usefixtures("genuine_signature")
def test_twist_ignores_response_for_other_tmp_id() -> None:
    """Test a late response to an earlier attempt is skipped, not fatal."""
    with pytest.raises(FlicPairingError):
        _pair(
            TwistProtocolHandler(),
            1,
            [
                lambda tmp_id: _twist_response_1(tmp_id ^ 1),
                _twist_response_1,
                lambda _: bytes(
                    [
                        TWIST_OPCODE_FULL_VERIFY_FAIL_RESPONSE,
                        FULL_VERIFY_FAIL_REASON_NOT_IN_PUBLIC_MODE,
                    ]
                ),
            ],
        )


def test_flic2_no_free_connection_slots() -> None:
    """Test a Flic 2 without free connection slots for us is a protocol error."""
    with pytest.raises(FlicProtocolError):
        _pair(
            Flic2ProtocolHandler(),
            2,
            [
                lambda tmp_id: (
                    bytes([0x00, OPCODE_NO_LOGICAL_CONNECTION_SLOTS])
                    + struct.pack("<II", tmp_id ^ 1, tmp_id)
                )
            ],
        )


@pytest.mark.parametrize(
    ("handler", "tmp_id_offset", "response_1"),
    [
        pytest.param(TwistProtocolHandler(), 1, lambda tmp_id: bytes(3), id="twist"),
        pytest.param(Flic2ProtocolHandler(), 2, lambda tmp_id: bytes(3), id="flic2"),
    ],
)
def test_short_response_is_protocol_error(
    handler: DeviceProtocolHandler, tmp_id_offset: int, response_1: Response
) -> None:
    """Test a truncated FullVerifyResponse1 is a protocol error."""
    with pytest.raises(FlicProtocolError):
        _pair(handler, tmp_id_offset, [response_1])
