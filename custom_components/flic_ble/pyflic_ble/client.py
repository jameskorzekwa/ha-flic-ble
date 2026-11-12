"""Flic 2 BLE protocol client implementation."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
import contextlib
from dataclasses import dataclass
from enum import IntEnum
import logging
from typing import Any

from bleak import BleakError
from bleak.backends.device import BLEDevice
from bleak_retry_connector import (
    close_stale_connections_by_address,
    establish_connection,
    BleakClientWithServiceCache,
)

from .const import (
    COMMAND_TIMEOUT,
    CONN_PARAM_INTERVAL_MAX,
    CONN_PARAM_INTERVAL_MIN,
    CONN_PARAM_LATENCY,
    CONN_PARAM_TIMEOUT,
    FLIC_MAX_PACKET_SIZE,
    FLIC_MTU,
    FLIC_SIGNATURE_SIZE,
    FRAME_HEADER_CONN_ID_MASK,
    FRAME_HEADER_FRAGMENT_FLAG,
    FRAME_HEADER_NEWLY_ASSIGNED,
    OPCODE_DISCONNECT_VERIFIED_LINK,
    OPCODE_FIRMWARE_UPDATE_NOTIFICATION,
    OPCODE_PING_REQUEST,
    OPCODE_PING_RESPONSE,
    TWIST_DISCONNECT_REASON_INVALID_SIGNATURE,
    TWIST_DISCONNECT_REASON_OTHER_CLIENT,
    TWIST_OPCODE_BUTTON_EVENT,
    TWIST_OPCODE_DISCONNECTED_VERIFIED_LINK,
    TWIST_OPCODE_FIRMWARE_UPDATE_NOTIFICATION,
    TWIST_OPCODE_TWIST_EVENT,
    DeviceType,
    PushTwistMode,
)
from .exceptions import (
    FlicAuthenticationError,
    FlicFirmwareUpdateError,
    FlicPairingError,
    FlicProtocolError,
)
from .security import chaskey_with_dir_and_counter
from .handlers import (
    DeviceCapabilities,
    DeviceProtocolHandler,
    DuoProtocolHandler,
    TwistProtocolHandler,
    create_handler,
)

_LOGGER = logging.getLogger(__name__)


class SessionState(IntEnum):
    """Flic session states."""

    DISCONNECTED = 0
    CONNECTED = 1
    WAIT_FULL_VERIFY_1 = 2
    WAIT_FULL_VERIFY_2 = 3
    WAIT_QUICK_VERIFY = 4
    SESSION_ESTABLISHED = 5
    FAILED = 6


@dataclass
class FlicState:
    """State of a Flic device."""

    connected: bool
    battery_voltage: float | None
    firmware_version: int | None
    device_name: str | None


class FlicClient:
    """Flic 2/Duo/Twist BLE client implementing the Flic protocol.

    This class orchestrates BLE communication and delegates device-specific
    protocol handling to DeviceProtocolHandler implementations.
    """

    # Class-level set of BLE addresses with active firmware updates.
    # Prevents ANY FlicClient instance (including config flow clients)
    # from connecting to an address while firmware is being transferred.
    _firmware_update_addresses: set[str] = set()

    def __init__(
        self,
        address: str,
        ble_device: BLEDevice | None = None,
        pairing_id: int | None = None,
        pairing_key: bytes | None = None,
        serial_number: str | None = None,
        device_type: DeviceType | None = None,
        sig_bits: int = 0,
        push_twist_mode: PushTwistMode = PushTwistMode.DEFAULT,
    ) -> None:
        """Initialize Flic client."""
        self.ble_device = ble_device
        self.address = address
        self._client: BleakClientWithServiceCache | None = None
        self._state = SessionState.DISCONNECTED
        self._connection_id = 0

        # Pairing credentials
        self._pairing_id = pairing_id
        self._pairing_key = pairing_key
        self._sig_bits = sig_bits

        # Serial number for device detection
        self._serial_number = serial_number

        # Determine device type
        if device_type is not None:
            self._device_type = device_type
        elif serial_number:
            self._device_type = DeviceType.from_serial_number(serial_number)
        else:
            self._device_type = DeviceType.FLIC2

        # Create protocol handler for this device type
        self._handler: DeviceProtocolHandler = create_handler(
            self._device_type, push_twist_mode
        )

        # Session state
        self._session_key: bytes | None = None
        self._chaskey_keys: list[int] | None = None
        self._packet_counter_to_button = 0
        self._packet_counter_from_button = 0

        # Response handling
        self._response_queue: asyncio.Queue[bytes] = asyncio.Queue()

        # Fragment reassembly (for Flic 2/Duo with frame headers)
        self._fragment_buffer: bytearray = bytearray()
        self._expecting_fragment = False

        # Button event callback
        self.on_button_event: Callable[[str, dict[str, Any]], None] | None = None

        # Rotate event callback (for Flic Duo/Twist)
        self.on_rotate_event: Callable[[str, dict[str, Any]], None] | None = None

        # Selector change callback (for Twist only)
        self.on_selector_change: Callable[[int, dict[str, Any]], None] | None = None

        # Disconnect callback (called when BLE connection drops unexpectedly)
        self.on_disconnect: Callable[[], None] | None = None
        self._intentional_disconnect = False

        # Firmware update active flag (gates 0x0F notification queueing)
        self._firmware_update_active = False

        # Guards against reconnect during an active start() call
        self._starting = False

        # Prevents auto-reconnect after stop()
        self._stopped = False

        # Callback registrations for multi-subscriber pattern
        self._button_event_callbacks: list[Callable[[str, dict[str, Any]], None]] = []
        self._rotate_event_callbacks: list[Callable[[str, dict[str, Any]], None]] = []
        self._state_callbacks: list[Callable[[FlicState], None]] = []

        # Connection lifecycle state
        self._reconnect_lock = asyncio.Lock()
        self._reconnect_event = asyncio.Event()
        self._reconnect_task: asyncio.Task[None] | None = None
        self._background_tasks: set[asyncio.Task[Any]] = set()
        self._flic_state = FlicState(
            connected=False,
            battery_voltage=None,
            firmware_version=None,
            device_name=None,
        )

    @property
    def handler(self) -> DeviceProtocolHandler:
        """Return the protocol handler."""
        return self._handler

    @property
    def capabilities(self) -> DeviceCapabilities:
        """Return the device capabilities."""
        return self._handler.capabilities

    async def connect(self) -> None:
        """Connect to the Flic button via BLE."""
        if self._firmware_update_active:
            _LOGGER.debug(
                "Refusing connect to %s during active firmware update",
                self.address,
            )
            return

        # Block connections from ANY FlicClient instance while another
        # instance is performing a firmware update on this address.
        # This prevents config flow or reconnect clients from killing
        # an active firmware transfer via close_stale_connections_by_address.
        if self.address in FlicClient._firmware_update_addresses:
            _LOGGER.debug(
                "Refusing connect to %s: firmware update active on another client",
                self.address,
            )
            return

        if self._client and self._client.is_connected:
            _LOGGER.debug("Already connected to %s", self.address)
            return

        if not self.ble_device:
            raise FlicProtocolError(f"No BLE device available for {self.address}")

        # Clean up stale state from a previous disconnected session
        # (e.g. after firmware update reboot or unexpected disconnect)
        if self._client:
            _LOGGER.debug("Cleaning up stale connection to %s", self.address)
            # Mark intentional to prevent _handle_disconnected from firing
            # during stale cleanup (it would re-enter reconnect logic).
            self._intentional_disconnect = True
            with contextlib.suppress(BleakError):
                await self._client.disconnect()
            self._intentional_disconnect = False

            # Re-check after await: a firmware update may have started on
            # another FlicClient for this address during the disconnect.
            if self.address in FlicClient._firmware_update_addresses:
                _LOGGER.debug(
                    "Firmware update started during cleanup, aborting connect to %s",
                    self.address,
                )
                self._client = None
                self._state = SessionState.FAILED
                return

            self._client = None
            self._state = SessionState.DISCONNECTED
            self._handler.reset_state()

        # Drain any stale messages from the response queue
        while not self._response_queue.empty():
            try:
                self._response_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

        # Reset fragment reassembly state
        self._fragment_buffer = bytearray()
        self._expecting_fragment = False

        try:
            _LOGGER.debug("Connecting to Flic button at %s", self.address)
            await close_stale_connections_by_address(self.address)
            self._client = await establish_connection(
                BleakClientWithServiceCache,
                self.ble_device,
                self.address,
                disconnected_callback=self._handle_disconnected,
                max_attempts=1,
            )
            _LOGGER.debug("BLE connection established to %s", self.address)

            # Abort if a firmware update started while we were connecting.
            # The transfer uses the old BleakClient; replacing it would
            # corrupt the session and break the transfer.
            if (
                self._firmware_update_active
                or self.address in FlicClient._firmware_update_addresses
            ):
                _LOGGER.info(
                    "Firmware update started during reconnect to %s, aborting",
                    self.address,
                )
                with contextlib.suppress(BleakError):
                    await self._client.disconnect()
                self._client = None
                self._state = SessionState.FAILED
                raise FlicProtocolError(
                    "Aborted reconnect: firmware update in progress"
                )

            # Check MTU size
            if hasattr(self._client, "mtu_size"):
                current_mtu = self._client.mtu_size
                _LOGGER.debug("Current MTU size: %d bytes", current_mtu)
                if current_mtu < FLIC_MTU:
                    _LOGGER.warning(
                        "MTU size %d is below recommended %d bytes",
                        current_mtu,
                        FLIC_MTU,
                    )

            # Request connection parameters for better responsiveness
            await self._request_connection_parameters()

            # Start notifications using handler's characteristic UUID
            _LOGGER.debug(
                "Starting notifications on characteristic %s",
                self._handler.notify_char_uuid,
            )
            await self._client.start_notify(
                self._handler.notify_char_uuid, self._notification_handler
            )
            _LOGGER.debug("Notifications started successfully for %s", self.address)

            self._state = SessionState.CONNECTED
            self._connection_id = 0
            self._handler.connection_id = 0
            self._packet_counter_to_button = 0
            self._packet_counter_from_button = 0

            # Bind transport callbacks so handler methods can use self._write_packet etc.
            self._handler.bind_transport(
                write_gatt=self._write_gatt,
                write_packet=self._write_packet,
                wait_for_opcode=self._wait_for_handler_opcode,
                wait_for_opcodes=self._wait_for_handler_opcodes,
            )
            _LOGGER.debug("Session state set to CONNECTED")

            # Small delay to let notifications stabilize
            await asyncio.sleep(0.5)
            _LOGGER.debug("Connection stabilized, ready for pairing")

        except (TimeoutError, BleakError) as err:
            self._state = SessionState.FAILED
            # Expected while the button is out of range; the reconnect loop retries
            _LOGGER.debug("Failed to connect to %s: %s", self.address, err)
            raise FlicProtocolError(f"Failed to connect: {err}") from err

    async def disconnect(self) -> None:
        """Disconnect from the Flic button."""
        self._intentional_disconnect = True
        if self._client:
            try:
                await self._client.disconnect()
            except BleakError as err:
                _LOGGER.debug("Error disconnecting: %s", err)
            finally:
                self._client = None
                self._state = SessionState.DISCONNECTED
                self._handler.reset_state()

    def _handle_disconnected(self, _client: BleakClientWithServiceCache) -> None:
        """Handle BLE disconnection event from Bleak."""
        if self._intentional_disconnect:
            self._intentional_disconnect = False
            return
        _LOGGER.info("BLE connection lost to %s", self.address)
        self._state = SessionState.DISCONNECTED
        self._handler.reset_state()
        if self._flic_state.connected:
            self._flic_state.connected = False
            self._notify_state_callbacks()
        if self.on_disconnect:
            self.on_disconnect()
        # Attempt reconnection unless start() is already running or stopped
        if not self._starting and not self._stopped:
            self._schedule_reconnect()

    async def _request_connection_parameters(self) -> None:
        """Request BLE connection parameters for optimal communication."""
        if not self._client:
            return
        if not hasattr(self._client, "set_connection_params"):
            _LOGGER.debug("set_connection_params not available on BLE client")
            return
        try:
            await self._client.set_connection_params(
                CONN_PARAM_INTERVAL_MIN,
                CONN_PARAM_INTERVAL_MAX,
                CONN_PARAM_LATENCY,
                CONN_PARAM_TIMEOUT,
            )
        except (BleakError, NotImplementedError) as err:
            _LOGGER.debug("Failed to request connection parameters: %s", err)

    @property
    def is_connected(self) -> bool:
        """Return if client is connected."""
        return self._client is not None and self._client.is_connected

    @property
    def is_duo(self) -> bool:
        """Return if connected button is a Flic Duo."""
        return isinstance(self._handler, DuoProtocolHandler)

    @property
    def is_twist(self) -> bool:
        """Return if connected button is a Flic Twist."""
        return isinstance(self._handler, TwistProtocolHandler)

    @property
    def device_type(self) -> DeviceType:
        """Return the device type."""
        return self._device_type

    async def full_verify_pairing(
        self,
    ) -> tuple[int, bytes, str, int, int, bytes, int]:
        """Perform full pairing verification (for new pairings)."""
        if self._state != SessionState.CONNECTED:
            raise FlicProtocolError("Not connected")

        self._state = SessionState.WAIT_FULL_VERIFY_1

        try:
            (
                pairing_id,
                pairing_key,
                serial_number,
                battery_level,
                sig_bits,
                button_uuid,
                firmware_version,
            ) = await self._handler.full_verify_pairing()

            # Handler resets its connection_id to 0 after pairing; sync client
            self._connection_id = 0
            self._pairing_id = pairing_id
            self._pairing_key = pairing_key
            self._sig_bits = sig_bits
            self._state = SessionState.SESSION_ESTABLISHED
        except TimeoutError as err:
            self._state = SessionState.FAILED
            _LOGGER.error("Pairing timeout")
            raise FlicPairingError("Pairing timeout") from err
        except (FlicAuthenticationError, FlicPairingError, FlicProtocolError):
            self._state = SessionState.FAILED
            raise
        else:
            return (
                pairing_id,
                pairing_key,
                serial_number,
                battery_level,
                sig_bits,
                button_uuid,
                firmware_version,
            )

    async def quick_verify(self) -> None:
        """Perform quick verification using stored credentials."""
        if self._state != SessionState.CONNECTED:
            raise FlicProtocolError("Not connected")

        if not self._pairing_id or not self._pairing_key:
            raise FlicProtocolError("No pairing credentials available")

        self._state = SessionState.WAIT_QUICK_VERIFY

        try:
            session_key, chaskey_keys = await self._handler.quick_verify(
                pairing_id=self._pairing_id,
                pairing_key=self._pairing_key,
                sig_bits=self._sig_bits,
            )

            self._session_key = session_key
            self._chaskey_keys = chaskey_keys
            self._packet_counter_to_button = 0
            self._packet_counter_from_button = 1

            self._state = SessionState.SESSION_ESTABLISHED
            _LOGGER.debug("Quick verification successful for %s", self.address)

        except TimeoutError as err:
            self._state = SessionState.FAILED
            raise FlicAuthenticationError("Quick verify timeout") from err

    async def init_button_events(self) -> None:
        """Initialize button event delivery."""
        if self._state != SessionState.SESSION_ESTABLISHED:
            raise FlicProtocolError("Session not established")

        _LOGGER.debug(
            "Initializing button events for %s (device_type=%s, serial=%s)",
            self.address,
            self._device_type.value,
            self._serial_number,
        )

        self._handler.connection_id = self._connection_id
        await self._handler.init_button_events(
            session_key=self._session_key,
            chaskey_keys=self._chaskey_keys,
        )

    async def _send_connection_parameters(self) -> None:
        """Send Flic protocol connection parameters to the button."""
        await self._handler.set_connection_parameters(
            CONN_PARAM_INTERVAL_MIN,
            CONN_PARAM_INTERVAL_MAX,
            CONN_PARAM_LATENCY,
            CONN_PARAM_TIMEOUT,
        )

    async def get_firmware_version(self) -> int:
        """Request the firmware version from the device."""
        if self._state != SessionState.SESSION_ESTABLISHED:
            raise FlicProtocolError("Session not established")

        return await self._handler.get_firmware_version()

    async def get_battery_level(self) -> int:
        """Request the battery level from the device."""
        if self._state != SessionState.SESSION_ESTABLISHED:
            raise FlicProtocolError("Session not established")

        return await self._handler.get_battery_level()

    @staticmethod
    def battery_raw_to_voltage(raw: int, device_type: DeviceType) -> float:
        """Convert raw battery level to voltage.

        Twist returns millivolts directly (2 AAA batteries).
        Flic 2/Duo return a 10-bit ADC value (0-1024, 3.6V reference).
        """
        if device_type == DeviceType.TWIST:
            return raw / 1000.0
        return raw * 3.6 / 1024.0

    async def get_battery_voltage(self) -> float:
        """Request the battery level and return it as voltage."""
        raw = await self.get_battery_level()
        return self.battery_raw_to_voltage(raw, self._device_type)

    async def get_name(self) -> tuple[str, int]:
        """Request the device name."""
        if self._state != SessionState.SESSION_ESTABLISHED:
            raise FlicProtocolError("Session not established")

        return await self._handler.get_name()

    async def set_name(self, name: str) -> tuple[str, int]:
        """Set the device name."""
        if self._state != SessionState.SESSION_ESTABLISHED:
            raise FlicProtocolError("Session not established")

        return await self._handler.set_name(name=name)

    @property
    def state(self) -> FlicState:
        """Return current device state."""
        return self._flic_state

    def register_button_event_callback(
        self, callback: Callable[[str, dict[str, Any]], None]
    ) -> Callable[[], None]:
        """Register a button event callback. Returns an unsubscribe function."""
        self._button_event_callbacks.append(callback)

        def unsubscribe() -> None:
            with contextlib.suppress(ValueError):
                self._button_event_callbacks.remove(callback)

        return unsubscribe

    def register_rotate_event_callback(
        self, callback: Callable[[str, dict[str, Any]], None]
    ) -> Callable[[], None]:
        """Register a rotate event callback. Returns an unsubscribe function."""
        self._rotate_event_callbacks.append(callback)

        def unsubscribe() -> None:
            with contextlib.suppress(ValueError):
                self._rotate_event_callbacks.remove(callback)

        return unsubscribe

    def register_state_callback(
        self, callback: Callable[[FlicState], None]
    ) -> Callable[[], None]:
        """Register a state change callback. Returns an unsubscribe function."""
        self._state_callbacks.append(callback)

        def unsubscribe() -> None:
            with contextlib.suppress(ValueError):
                self._state_callbacks.remove(callback)

        return unsubscribe

    def _notify_state_callbacks(self) -> None:
        """Notify all registered state callbacks."""
        for cb in self._state_callbacks:
            try:
                cb(self._flic_state)
            except Exception:  # noqa: BLE001
                _LOGGER.debug("Error in state callback", exc_info=True)

    async def start(self) -> None:
        """Connect, authenticate, and initialize button events.

        This internalizes the full connection lifecycle:
        connect → quick_verify → init_button_events → get_battery → get_firmware → get_name.
        Non-fatal failures for battery/firmware/name are logged but do not prevent startup.
        """
        async with self._reconnect_lock:
            self._stopped = False
            await self._start_inner()

    async def _start_inner(self) -> None:
        """Inner start logic, must be called with _reconnect_lock held."""
        self._starting = True
        try:
            await self.connect()
            await self.quick_verify()
            await self.init_button_events()
            await self._send_connection_parameters()

            # Request battery level (non-fatal)
            try:
                voltage = await self.get_battery_voltage()
                self._flic_state.battery_voltage = voltage
                _LOGGER.debug("Battery voltage for %s: %.3fV", self.address, voltage)
            except Exception:  # noqa: BLE001
                _LOGGER.warning(
                    "Failed to retrieve battery level from %s", self.address
                )

            # Request firmware version (non-fatal)
            try:
                fw = await self.get_firmware_version()
                self._flic_state.firmware_version = fw
                _LOGGER.debug("Firmware version for %s: %d", self.address, fw)
            except Exception:  # noqa: BLE001
                _LOGGER.warning(
                    "Failed to retrieve firmware version from %s", self.address
                )

            # Read device name (non-fatal)
            try:
                name, _ = await self.get_name()
                self._flic_state.device_name = name if name else None
            except Exception:  # noqa: BLE001
                _LOGGER.debug("Failed to retrieve device name from %s", self.address)

            self._flic_state.connected = True
            self._notify_state_callbacks()
            _LOGGER.info("Successfully started session with %s", self.address)

        except Exception as err:
            self._flic_state.connected = False
            _LOGGER.debug("Failed to start session with %s: %s", self.address, err)
            # A link left up makes the next attempt return early as already
            # connected, which also ends the reconnect loop
            if self.is_connected:
                await self.disconnect()
            raise
        finally:
            self._starting = False

    async def stop(self) -> None:
        """Disconnect and clean up."""
        self._stopped = True
        self._flic_state.connected = False
        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            self._reconnect_task = None
        await self.disconnect()

    def set_ble_device(self, ble_device: BLEDevice) -> None:
        """Update the BLE device reference.

        If disconnected, automatically triggers a reconnection attempt.
        Wakes any sleeping reconnect loop to retry immediately.
        """
        self.ble_device = ble_device
        self._reconnect_event.set()
        if not self.is_connected and not self._starting and not self._stopped:
            self._schedule_reconnect()

    def _schedule_reconnect(self) -> None:
        """Schedule a reconnect task if one is not already running."""
        if self._reconnect_task and not self._reconnect_task.done():
            _LOGGER.debug(
                "Reconnect task already running for %s, skipping", self.address
            )
            return
        loop = asyncio.get_running_loop()
        self._reconnect_task = loop.create_task(
            self._async_reconnect_loop(),
            name=f"flic-reconnect-{self.address}",
        )

    async def _async_reconnect_loop(self) -> None:
        """Reconnect loop wrapper that catches all exceptions."""
        try:
            await self.async_reconnect()
        except asyncio.CancelledError:
            _LOGGER.info(
                "Reconnect task for %s was cancelled", self.address
            )
        except BaseException:
            _LOGGER.exception(
                "Unexpected error in reconnect loop for %s", self.address
            )

    async def async_reconnect(self) -> None:
        """Attempt reconnection with exponential backoff.

        Safe to call repeatedly — the lock ensures only one attempt runs
        at a time. set_ble_device() wakes the backoff sleep to retry
        immediately with the fresh BLEDevice.
        """
        delay = 5
        max_delay = 300
        _LOGGER.debug(
            "Starting reconnect loop for %s", self.address
        )
        while not self.is_connected and not self._stopped:
            async with self._reconnect_lock:
                if self.is_connected or self._stopped:
                    return
                if self._flic_state.connected:
                    self._flic_state.connected = False
                    self._notify_state_callbacks()
                try:
                    _LOGGER.debug(
                        "Attempting to reconnect to %s", self.address
                    )
                    await self._start_inner()
                    return
                except Exception:  # noqa: BLE001
                    _LOGGER.debug(
                        "Reconnection to %s failed, retrying in %ds",
                        self.address,
                        delay,
                        exc_info=True,
                    )

            # Sleep outside the lock; woken early by set_ble_device()
            # Clear AFTER wait so a signal set during _start_inner() is not lost.
            try:
                await asyncio.wait_for(
                    self._reconnect_event.wait(), timeout=delay
                )
                # Woken by new advertisement — reset backoff
                delay = 5
            except TimeoutError:
                delay = min(delay * 2, max_delay)
            finally:
                self._reconnect_event.clear()

    async def async_send_update_twist_position(
        self, mode_index: int, percentage: float
    ) -> None:
        """Send position update via UpdateTwistPositionRequest.

        Without a session, the position is kept and handed to the device with the
        next InitButtonEvents, which is how the device gets positions anyway.
        """
        if not isinstance(self._handler, TwistProtocolHandler):
            raise FlicProtocolError("Not a Twist device")

        # Convert percentage to raw units (D360 = 49152 = 100%)
        from .rotate_tracker import D360  # noqa: PLC0415

        new_position_units = round(percentage / 100.0 * D360)

        if self._state != SessionState.SESSION_ESTABLISHED:
            self._handler.set_position_for_next_init(mode_index, new_position_units)
            _LOGGER.debug(
                "No session, keeping position for the next init: mode=%d, units=%d",
                mode_index,
                new_position_units,
            )
            return

        request_bytes = self._handler.build_update_twist_position(
            mode_index, new_position_units
        )

        _LOGGER.debug(
            "UpdateTwistPosition: mode=%d, percentage=%.1f, units=%d",
            mode_index,
            percentage,
            new_position_units,
        )

        await self._write_packet(request_bytes)

    async def async_firmware_update(
        self,
        firmware_binary: bytes,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> bool:
        """Perform OTA firmware update on the device."""
        if self._state != SessionState.SESSION_ESTABLISHED:
            raise FlicProtocolError("Session not established")

        self._firmware_update_active = True
        FlicClient._firmware_update_addresses.add(self.address)
        try:
            try:
                start_pos = await self._handler.start_firmware_update(
                    firmware_binary=firmware_binary,
                )
            except ValueError as err:
                raise FlicFirmwareUpdateError(str(err)) from err

            success = await self._handler.send_firmware_data(
                firmware_binary=firmware_binary,
                start_pos=start_pos,
                progress_callback=progress_callback,
            )

            if not success:
                raise FlicFirmwareUpdateError(
                    "Firmware signature verification failed on device"
                )

            await self._handler.send_force_disconnect(restart_adv=True)

            return True
        finally:
            self._firmware_update_active = False
            FlicClient._firmware_update_addresses.discard(self.address)

    async def _write_gatt(self, char_uuid: str, data: bytes) -> None:
        """Write data to a GATT characteristic."""
        if not self._client:
            raise FlicProtocolError("Not connected")

        await self._client.write_gatt_char(char_uuid, data)

    def _fragment_packet(
        self, packet: bytes, max_fragment_size: int = 20
    ) -> list[bytes]:
        """Fragment a large packet into smaller chunks that fit within MTU."""
        if len(packet) <= max_fragment_size:
            return [packet]

        original_frame_header = packet[0]
        original_payload = packet[1:]

        conn_id = original_frame_header & FRAME_HEADER_CONN_ID_MASK
        newly_assigned = bool(original_frame_header & FRAME_HEADER_NEWLY_ASSIGNED)

        fragments = []
        offset = 0
        fragment_data_size = max_fragment_size - 2

        while offset < len(original_payload):
            remaining_size = len(original_payload) - offset
            fragment_size = min(fragment_data_size, remaining_size)
            is_last_fragment = (offset + fragment_size) >= len(original_payload)

            fragment_frame_header = (
                (conn_id & FRAME_HEADER_CONN_ID_MASK)
                | (FRAME_HEADER_NEWLY_ASSIGNED if newly_assigned else 0)
                | (0 if is_last_fragment else FRAME_HEADER_FRAGMENT_FLAG)
            )

            fragment_data = original_payload[offset : offset + fragment_size]
            fragment_packet = bytes([fragment_frame_header, 0x00]) + fragment_data
            fragments.append(fragment_packet)

            _LOGGER.debug(
                "Fragment %d: size=%d bytes, is_last=%s",
                len(fragments),
                len(fragment_packet),
                is_last_fragment,
            )

            offset += fragment_size

        _LOGGER.debug(
            "Fragmented %d-byte packet into %d fragments",
            len(packet),
            len(fragments),
        )

        return fragments

    async def _write_packet(self, data: bytes, authenticated: bool = True) -> None:
        """Write a packet to the button."""
        if not self._client:
            raise FlicProtocolError("Not connected")

        packet = bytearray(data)

        if authenticated:
            if not self._chaskey_keys:
                raise FlicProtocolError("No session key available")

            # For Twist (no frame header), MAC the entire packet
            # For Flic 2/Duo (with frame header), MAC only opcode + payload
            if self._handler.capabilities.has_frame_header:
                mac_data = bytes(packet[1:])  # Skip frame_header
            else:
                mac_data = bytes(packet)  # Entire packet

            mac = chaskey_with_dir_and_counter(
                self._chaskey_keys,
                direction=1,  # client-to-button
                counter=self._packet_counter_to_button,
                data=mac_data,
            )
            packet.extend(mac)
            _LOGGER.debug(
                "Added MAC to packet (counter=%d)", self._packet_counter_to_button
            )

            self._packet_counter_to_button += 1

        # Fragment only for devices with frame headers and large packets
        if (
            self._handler.capabilities.has_frame_header
            and len(packet) > FLIC_MAX_PACKET_SIZE
        ):
            _LOGGER.debug(
                "Packet size %d exceeds max, fragmenting",
                len(packet),
            )
            fragments = self._fragment_packet(bytes(packet), 20)

            for i, fragment in enumerate(fragments):
                _LOGGER.debug(
                    "Sending fragment %d/%d (%d bytes)",
                    i + 1,
                    len(fragments),
                    len(fragment),
                )
                await self._client.write_gatt_char(
                    self._handler.write_char_uuid, fragment
                )
                if i < len(fragments) - 1:
                    await asyncio.sleep(0.01)

            _LOGGER.debug("All %d fragments sent successfully", len(fragments))
        else:
            _LOGGER.debug(
                "Writing packet (%d bytes) to %s",
                len(packet),
                self._handler.write_char_uuid,
            )
            await self._client.write_gatt_char(self._handler.write_char_uuid, packet)
            _LOGGER.debug("Packet written successfully")

    def _notification_handler(self, _sender: Any, data: bytearray) -> None:
        """Handle notifications from the button."""
        try:
            _LOGGER.debug(
                "BLE notification received: %d bytes, state=%s, device_type=%s",
                len(data),
                self._state.name,
                self._device_type.value,
            )
            _LOGGER.debug(
                "Received notification: %s (%d bytes)", bytes(data).hex(), len(data)
            )

            if len(data) < 1:
                _LOGGER.warning("Received packet too short: %d bytes", len(data))
                return

            # Route to appropriate handler based on frame header presence
            if self._handler.capabilities.has_frame_header:
                self._handle_framed_notification(data)
            else:
                self._handle_unframed_notification(data)

        except Exception:
            _LOGGER.exception("Error handling notification")

    def _handle_framed_notification(self, data: bytearray) -> None:
        """Handle notification with frame header (Flic 2/Duo)."""
        header = data[0]
        conn_id = header & FRAME_HEADER_CONN_ID_MASK
        newly_assigned = bool(header & FRAME_HEADER_NEWLY_ASSIGNED)
        is_fragment = bool(header & FRAME_HEADER_FRAGMENT_FLAG)

        _LOGGER.debug(
            "Packet header: conn_id=%d, newly_assigned=%s, is_fragment=%s",
            conn_id,
            newly_assigned,
            is_fragment,
        )

        if newly_assigned:
            self._connection_id = conn_id
            self._handler.connection_id = conn_id
            _LOGGER.debug("Connection ID assigned by button: %d", conn_id)

        # Handle fragmented packets
        if is_fragment:
            fragment_data = data[1:]
            self._fragment_buffer.extend(fragment_data)
            self._expecting_fragment = True
            _LOGGER.debug(
                "Received fragment (%d bytes), total buffered: %d bytes",
                len(fragment_data),
                len(self._fragment_buffer),
            )
            return

        if self._expecting_fragment:
            fragment_data = data[1:]
            self._fragment_buffer.extend(fragment_data)
            _LOGGER.debug(
                "Received final fragment (%d bytes), reassembling %d total bytes",
                len(fragment_data),
                len(self._fragment_buffer),
            )

            reassembled = bytearray([data[0]]) + self._fragment_buffer
            data = reassembled

            self._fragment_buffer = bytearray()
            self._expecting_fragment = False

        if len(data) < 2:
            _LOGGER.warning("Reassembled packet too short: %d bytes", len(data))
            return

        opcode = data[1]
        _LOGGER.debug(
            "Notification: opcode=0x%02x, conn_id=%d, state=%s",
            opcode,
            conn_id,
            self._state.name,
        )

        # Verify connection ID
        if (
            not newly_assigned
            and conn_id not in (self._connection_id, 0)
            and self._state >= SessionState.WAIT_QUICK_VERIFY
        ):
            _LOGGER.debug(
                "Packet for different connection ID (%d != %d), ignoring",
                conn_id,
                self._connection_id,
            )
            return

        # Strip MAC from authenticated packets
        # Note: MAC verification is disabled for reliability (like official Twist SDK)
        # When packets arrive rapidly, counter sync issues cause verification failures
        if self._state == SessionState.SESSION_ESTABLISHED:
            if len(data) < FLIC_SIGNATURE_SIZE + 2:
                _LOGGER.warning("Authenticated packet too short: %d bytes", len(data))
                return

            # Strip the 5-byte MAC tail
            packet_data = data[:-FLIC_SIGNATURE_SIZE]
            data = packet_data

            # MAC verification is disabled for reliability (matches official SDK behavior)

            if opcode == OPCODE_PING_REQUEST:
                # The button ends the session when its pings go unanswered
                self._run_in_background(
                    self._write_packet(
                        bytes(
                            [
                                self._connection_id & FRAME_HEADER_CONN_ID_MASK,
                                OPCODE_PING_RESPONSE,
                            ]
                        )
                    )
                )
                return

            if opcode == OPCODE_DISCONNECT_VERIFIED_LINK:
                _LOGGER.warning(
                    "%s ended the verified session: reason=%d",
                    self.address,
                    data[2] if len(data) > 2 else -1,
                )
                self._state = SessionState.DISCONNECTED
                # Dropping the link runs the normal disconnect handling, which
                # marks the button unavailable and reconnects
                if self._client is not None:
                    self._run_in_background(self._client.disconnect())
                return

        # Delegate to handler for event processing
        button_events, rotate_events, _selector_index = (
            self._handler.handle_notification(bytes(data))
        )

        # Emit events
        self._emit_button_events(button_events)
        self._emit_rotate_events(rotate_events)

        for request in self._handler.pop_pending_writes():
            self._run_in_background(self._write_packet(request))

        # If no events, this might be a command response
        if not button_events and not rotate_events:
            # Discard firmware update notifications when no update is active.
            # The device may send stale notifications from a previous
            # update attempt; queueing them would block other command responses.
            if (
                opcode == OPCODE_FIRMWARE_UPDATE_NOTIFICATION
                and not self._firmware_update_active
            ):
                _LOGGER.debug(
                    "Discarding stale firmware notification (no update active)"
                )
                return
            _LOGGER.debug("Putting response opcode=0x%02x in queue", opcode)
            self._response_queue.put_nowait(bytes(data))

    def _handle_unframed_notification(self, data: bytearray) -> None:
        """Handle notification without frame header (Twist)."""
        opcode = data[0]

        _LOGGER.debug(
            "Twist notification: opcode=0x%02x, data_len=%d, state=%s",
            opcode,
            len(data),
            self._state.name,
        )

        # Strip MAC from authenticated packets (Twist SDK doesn't verify incoming MACs)
        # The official Twist SDK just strips the 5-byte MAC tail without verification
        if self._state == SessionState.SESSION_ESTABLISHED:
            if len(data) > FLIC_SIGNATURE_SIZE + 1:
                # Strip the 5-byte MAC tail
                packet_data = data[:-FLIC_SIGNATURE_SIZE]
                _LOGGER.debug(
                    "Twist: stripped MAC from packet (opcode=0x%02x, %d -> %d bytes)",
                    opcode,
                    len(data),
                    len(packet_data),
                )
                data = bytearray(packet_data)

        # Handle disconnect notification (button rejected our request)
        if opcode == TWIST_OPCODE_DISCONNECTED_VERIFIED_LINK:
            reason = data[1] if len(data) > 1 else 0
            reason_str = {
                TWIST_DISCONNECT_REASON_INVALID_SIGNATURE: "INVALID_SIGNATURE",
                TWIST_DISCONNECT_REASON_OTHER_CLIENT: "OTHER_CLIENT",
            }.get(reason, f"UNKNOWN({reason})")
            _LOGGER.error(
                "Twist disconnected verified link: reason=%s (code=%d)",
                reason_str,
                reason,
            )
            self._state = SessionState.DISCONNECTED
            # Without a session the link is useless; dropping it runs the normal
            # disconnect handling, which marks the button unavailable and reconnects
            if self._client is not None:
                self._run_in_background(self._client.disconnect())
            return

        # Delegate to handler
        button_events, rotate_events, selector_index = (
            self._handler.handle_notification(bytes(data))
        )

        # Emit events
        self._emit_button_events(button_events)
        self._emit_rotate_events(rotate_events)

        for request in self._handler.pop_pending_writes():
            self._run_in_background(self._write_packet(request))

        # Emit selector change (Twist only)
        if selector_index is not None and self.on_selector_change:
            try:
                self.on_selector_change(selector_index, {})
            except Exception:
                _LOGGER.exception("Error in selector change callback")

        # If no events and not an event notification opcode, it's a command response.
        # Event opcodes (button=0x09, twist=0x0a) can produce zero events
        # (e.g. rotation with no detent crossings) but are never command responses.
        if (
            not button_events
            and not rotate_events
            and opcode not in (TWIST_OPCODE_BUTTON_EVENT, TWIST_OPCODE_TWIST_EVENT)
        ):
            # Discard firmware update notifications when no update is active.
            # The device may send stale 0x0F notifications from a previous
            # update attempt; queueing them would block other command responses.
            if (
                opcode == TWIST_OPCODE_FIRMWARE_UPDATE_NOTIFICATION
                and not self._firmware_update_active
            ):
                _LOGGER.debug(
                    "Discarding stale firmware notification (no update active)"
                )
                return
            _LOGGER.debug("Putting Twist response opcode=0x%02x in queue", opcode)
            self._response_queue.put_nowait(bytes(data))

    def _run_in_background(self, coro: Coroutine[Any, Any, Any]) -> None:
        """Run a coroutine without waiting for it, from a notification callback."""
        task = asyncio.get_running_loop().create_task(coro)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_task_done)

    def _background_task_done(self, task: asyncio.Task[Any]) -> None:
        """Forget a finished background task and log why it failed."""
        self._background_tasks.discard(task)
        if not task.cancelled() and (err := task.exception()) is not None:
            _LOGGER.debug("Background task for %s failed: %s", self.address, err)

    def _emit_button_events(self, button_events: list) -> None:
        """Process and emit button events."""
        for event in button_events:
            event_data: dict[str, Any] = {
                "timestamp_ms": event.timestamp_ms,
                "was_queued": event.was_queued,
                **event.extra_data,
            }
            if event.button_index is not None:
                event_data["button_index"] = event.button_index

            if self.on_button_event:
                try:
                    self.on_button_event(event.event_type, event_data)
                except Exception:
                    _LOGGER.exception("Error in button event callback")

            for cb in self._button_event_callbacks:
                try:
                    cb(event.event_type, event_data)
                except Exception:
                    _LOGGER.exception("Error in registered button event callback")

    def _emit_rotate_events(self, rotate_events: list) -> None:
        """Process and emit rotate events."""
        for event in rotate_events:
            event_data: dict[str, Any] = {
                "angle_degrees": event.angle_degrees,
                "detent_crossings": event.detent_crossings,
                **event.extra_data,
            }
            if event.button_index is not None:
                event_data["button_index"] = event.button_index

            if self.on_rotate_event:
                try:
                    self.on_rotate_event(event.event_type, event_data)
                except Exception:
                    _LOGGER.exception("Error in rotate event callback")

            for cb in self._rotate_event_callbacks:
                try:
                    cb(event.event_type, event_data)
                except Exception:
                    _LOGGER.exception("Error in registered rotate event callback")

    async def _wait_for_handler_opcode(self, opcode: int) -> bytes:
        """Wait for a response with specific opcode."""
        return await self._wait_for_handler_opcodes([opcode])

    async def _wait_for_handler_opcodes(self, opcodes: list[int]) -> bytes:
        """Wait for a response with one of specified opcodes."""
        has_frame_header = self._handler.capabilities.has_frame_header
        opcode_offset = 1 if has_frame_header else 0
        min_len = 2 if has_frame_header else 1

        _LOGGER.debug("Waiting for opcodes %s", [hex(o) for o in opcodes])
        deadline = asyncio.get_event_loop().time() + COMMAND_TIMEOUT
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timeout waiting for opcodes {[hex(o) for o in opcodes]}"
                )
            response = await asyncio.wait_for(
                self._response_queue.get(), timeout=remaining
            )
            if len(response) >= min_len:
                received_opcode = response[opcode_offset]
                if received_opcode in opcodes:
                    _LOGGER.debug("Found matching opcode 0x%02x", received_opcode)
                    return response
                _LOGGER.debug(
                    "Received opcode 0x%02x, not in %s - putting back in queue",
                    received_opcode,
                    [hex(o) for o in opcodes],
                )
            else:
                _LOGGER.debug("Response too short, putting back in queue")
            await self._response_queue.put(response)
            await asyncio.sleep(0.01)
