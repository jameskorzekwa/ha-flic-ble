"""Flic Twist protocol handler implementation."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import logging
import secrets
import struct
import time
from typing import Any

from ..const import (
    COMMAND_TIMEOUT,
    EVENT_TYPE_CLICK,
    EVENT_TYPE_DOUBLE_CLICK,
    EVENT_TYPE_DOWN,
    EVENT_TYPE_HOLD,
    EVENT_TYPE_PUSH_TWIST_DECREMENT,
    EVENT_TYPE_PUSH_TWIST_INCREMENT,
    EVENT_TYPE_ROTATE_CLOCKWISE,
    EVENT_TYPE_ROTATE_COUNTER_CLOCKWISE,
    EVENT_TYPE_SELECTOR_CHANGED,
    EVENT_TYPE_TWIST_DECREMENT,
    EVENT_TYPE_TWIST_INCREMENT,
    EVENT_TYPE_UP,
    FIRMWARE_DATA_CHUNK_SIZE,
    FIRMWARE_FINAL_ACK_TIMEOUT,
    FIRMWARE_HEADER_SIZE,
    FIRMWARE_MAX_IN_FLIGHT,
    FIRMWARE_UPDATE_TIMEOUT,
    PAIRING_TIMEOUT,
    TWIST_ED25519_PUBLIC_KEY,
    TWIST_MODE_SLOT_CHANGING,
    TWIST_OPCODE_BUTTON_EVENT,
    TWIST_OPCODE_FIRMWARE_UPDATE_NOTIFICATION,
    TWIST_OPCODE_FULL_VERIFY_FAIL_RESPONSE,
    TWIST_OPCODE_FULL_VERIFY_RESPONSE_1,
    TWIST_OPCODE_FULL_VERIFY_RESPONSE_2,
    TWIST_OPCODE_GET_BATTERY_LEVEL_REQUEST,
    TWIST_OPCODE_GET_BATTERY_LEVEL_RESPONSE,
    TWIST_OPCODE_GET_FIRMWARE_VERSION_REQUEST,
    TWIST_OPCODE_GET_FIRMWARE_VERSION_RESPONSE,
    TWIST_OPCODE_GET_NAME_REQUEST,
    TWIST_OPCODE_GET_NAME_RESPONSE,
    TWIST_OPCODE_INIT_BUTTON_EVENTS_RESPONSE,
    TWIST_OPCODE_QUICK_VERIFY_RESPONSE,
    TWIST_OPCODE_SET_NAME_REQUEST,
    TWIST_OPCODE_SET_NAME_RESPONSE,
    TWIST_OPCODE_START_FIRMWARE_UPDATE_RESPONSE,
    TWIST_OPCODE_TWIST_EVENT,
    TWIST_RX_CHAR_UUID,
    TWIST_SERVICE_UUID,
    TWIST_TX_CHAR_UUID,
    UNSYNCED_QUEUED_EVENT_MAX_AGE_MS,
    PushTwistMode,
)
from ..protocol import (
    FirmwareUpdateDataInd,
    FirmwareUpdateNotification,
    ForceBtDisconnectInd,
    InitButtonEventsResponseV2,
    InitButtonEventsTwistRequest,
    StartFirmwareUpdateRequest,
    StartFirmwareUpdateResponse,
    TwistButtonEventNotification,
    TwistEventNotification,
    TwistFullVerifyRequest1,
    TwistFullVerifyRequest2,
    TwistFullVerifyResponse2,
    TwistModeConfig,
    TwistQuickVerifyRequest,
    TwistQuickVerifyResponse,
    UpdateTwistPositionRequest,
)
from ..security import (
    chaskey_16_bytes,
    chaskey_generate_subkeys,
    derive_full_verify_keys,
    generate_x25519_keypair,
    verify_ed25519_signature_with_variant,
    x25519_key_exchange,
)
from ..exceptions import FlicAuthenticationError, FlicProtocolError
from ..rotate_tracker import MultiModeRotateTracker
from .base import (
    ButtonEvent,
    DeviceCapabilities,
    DeviceProtocolHandler,
    RotateEvent,
    raise_full_verify_failure,
)

_LOGGER = logging.getLogger(__name__)


class TwistProtocolHandler(DeviceProtocolHandler):
    """Protocol handler for Flic Twist buttons.

    Twist uses a simpler packet format than Flic 2/Duo:
    - No frame header (no connId, no fragment flags)
    - Format: [opcode:1][payload:N][mac:5 if session active]
    """

    _CAPABILITIES = DeviceCapabilities(
        button_count=1,
        has_rotation=True,
        has_selector=True,
        has_gestures=False,
        has_frame_header=False,
    )

    def __init__(self, push_twist_mode: PushTwistMode = PushTwistMode.DEFAULT) -> None:
        """Initialize the Twist handler."""
        super().__init__()
        self._twist_mode_index: int = 0
        self._twist_packet_counter: int = 0
        self._push_twist_mode = push_twist_mode
        self._multi_mode_tracker = MultiModeRotateTracker(
            bound_mode_12=(
                push_twist_mode in (PushTwistMode.DEFAULT, PushTwistMode.CONTINUOUS)
            ),
            wrap_position=(push_twist_mode == PushTwistMode.CONTINUOUS),
        )
        # Kept across reconnects so the device only replays events we have not
        # processed yet
        self._last_event_count: int = 0
        self._last_boot_id: int = 0
        # Set when the device's boot id was not known at the last init
        self._queued_event_cutoff_ms: int | None = None
        self._prev_int_pct: dict[int, int] = {}
        self._position_resends: dict[int, bytes] = {}

    @property
    def service_uuid(self) -> str:
        """Return the BLE service UUID."""
        return TWIST_SERVICE_UUID

    @property
    def write_char_uuid(self) -> str:
        """Return the BLE write characteristic UUID."""
        return TWIST_TX_CHAR_UUID

    @property
    def notify_char_uuid(self) -> str:
        """Return the BLE notify characteristic UUID."""
        return TWIST_RX_CHAR_UUID

    @property
    def ed25519_public_key(self) -> bytes:
        """Return the Ed25519 public key for signature verification."""
        return TWIST_ED25519_PUBLIC_KEY

    @property
    def capabilities(self) -> DeviceCapabilities:
        """Return the device capabilities."""
        return self._CAPABILITIES

    @property
    def twist_mode_index(self) -> int:
        """Return the current twist mode index."""
        return self._twist_mode_index

    @property
    def push_twist_mode(self) -> PushTwistMode:
        """Return the push twist mode."""
        return self._push_twist_mode

    def reset_state(self) -> None:
        """Reset handler state."""
        super().reset_state()
        self._twist_mode_index = 0
        self._twist_packet_counter = 0
        self._prev_int_pct = {}
        self._position_resends = {}

    async def full_verify_pairing(
        self,
    ) -> tuple[int, bytes, str, int, int, bytes, int]:
        """Perform full pairing verification for Flic Twist."""
        temp_conn_id = secrets.randbelow(2**32)
        _LOGGER.debug(
            "Starting Twist full pairing with tmp_id=%d (0x%08x)",
            temp_conn_id,
            temp_conn_id,
        )

        # Twist uses no frame header - just opcode + data
        request1 = TwistFullVerifyRequest1(tmp_id=temp_conn_id).to_bytes()
        _LOGGER.debug(
            "Sending TwistFullVerifyRequest1 (length=%d bytes)", len(request1)
        )

        await self._write_gatt(self.write_char_uuid, request1)
        _LOGGER.debug("TwistFullVerifyRequest1 sent, waiting for response")

        # Parse Twist response (no frame header)
        expected_len = 1 + 4 + 64 + 6 + 1 + 32 + 8 + 1  # 117 bytes
        async with asyncio.timeout(PAIRING_TIMEOUT):
            while True:
                response1 = await self._wait_for_opcode(
                    TWIST_OPCODE_FULL_VERIFY_RESPONSE_1
                )
                if len(response1) < expected_len:
                    raise FlicProtocolError(
                        f"Invalid TwistFullVerifyResponse1 length: {len(response1)} "
                        f"(expected {expected_len})"
                    )
                received_tmp_id = struct.unpack_from("<I", response1, 1)[0]
                if received_tmp_id == temp_conn_id:
                    break
                # A late response to an earlier attempt; the official libraries
                # also ignore it and keep waiting
                _LOGGER.debug(
                    "Ignoring TwistFullVerifyResponse1 for tmp_id 0x%08x",
                    received_tmp_id,
                )
        _LOGGER.debug(
            "Received TwistFullVerifyResponse1 (length=%d bytes)",
            len(response1),
        )

        offset = 5  # Skip opcode and tmp_id

        signature = response1[offset : offset + 64]
        offset += 64
        button_address = response1[offset : offset + 6]
        offset += 6
        address_type = response1[offset]
        offset += 1
        button_pubkey = response1[offset : offset + 32]
        offset += 32
        device_random = response1[offset : offset + 8]

        _LOGGER.debug(
            "Parsed TwistFullVerifyResponse1: tmpId=0x%08x, addr=%s, addr_type=0x%02x",
            received_tmp_id,
            button_address.hex(),
            address_type,
        )
        # Verify Ed25519 signature
        signed_data = button_address + bytes([address_type]) + button_pubkey
        signature_variant = verify_ed25519_signature_with_variant(
            self.ed25519_public_key, signed_data, signature
        )
        if signature_variant is None:
            raise FlicAuthenticationError(
                "Invalid Twist signature - all variants failed"
            )

        _LOGGER.debug(
            "Twist Ed25519 signature verified with sigBits=%d",
            signature_variant,
        )

        # Generate keypair and derive keys
        app_private_key, app_public_key = generate_x25519_keypair()
        shared_secret = x25519_key_exchange(app_private_key, button_pubkey)
        client_random = secrets.token_bytes(8)

        verifier, _session_key, pairing_key, pairing_id, _full_verify_secret = (
            derive_full_verify_keys(
                shared_secret,
                signature_variant,
                device_random,
                client_random,
                is_twist=True,
            )
        )

        _LOGGER.debug("Key derivation complete (pairing_id=%d)", pairing_id)

        # Step 2: Send FullVerifyRequest2
        # NOTE: The signature_variant in the request is ALWAYS 0 for Twist.
        # The sigBits from Ed25519 verification is only used for key derivation,
        # not in the request flags. This matches the official Twist SDK behavior.
        request2 = TwistFullVerifyRequest2(
            ecdh_public_key=app_public_key,
            client_random=client_random,
            signature_variant=0,  # Always 0 for Twist (per SDK)
            verifier=verifier,
        ).to_bytes()

        _LOGGER.debug(
            "Sending TwistFullVerifyRequest2 (%d bytes)",
            len(request2),
        )
        await self._write_gatt(self.write_char_uuid, request2)

        # Wait for response
        response2_data = await asyncio.wait_for(
            self._wait_for_opcodes(
                [
                    TWIST_OPCODE_FULL_VERIFY_RESPONSE_2,
                    TWIST_OPCODE_FULL_VERIFY_FAIL_RESPONSE,
                ]
            ),
            timeout=PAIRING_TIMEOUT,
        )
        _LOGGER.debug(
            "Received Twist response (opcode=0x%02x, length=%d bytes)",
            response2_data[0] if response2_data else -1,
            len(response2_data),
        )

        if response2_data[0] == TWIST_OPCODE_FULL_VERIFY_FAIL_RESPONSE:
            reason = response2_data[1] if len(response2_data) > 1 else -1
            raise_full_verify_failure(reason)

        try:
            response2 = TwistFullVerifyResponse2.from_bytes(response2_data)
        except ValueError as err:
            raise FlicProtocolError(str(err)) from err

        _LOGGER.info("Twist paired (serial=%s)", response2.serial_number)

        return (
            pairing_id,
            pairing_key,
            response2.serial_number,
            response2.battery_level,
            signature_variant,
            response2.button_uuid,
            response2.firmware_version,
        )

    async def quick_verify(
        self,
        pairing_id: int,
        pairing_key: bytes,
        sig_bits: int = 0,
    ) -> tuple[bytes, list[int]]:
        """Perform quick verification for Flic Twist."""
        tmp_id = secrets.randbelow(0xFFFFFFFF)
        client_random_bytes = secrets.token_bytes(7)

        # Twist SDK always uses signatureVariant=0 and encryptionVariant=0 for quick verify
        # (unlike Flic 2 which uses stored sig_bits)
        request_msg = TwistQuickVerifyRequest(
            tmp_id=tmp_id,
            pairing_id=pairing_id,
            client_random=client_random_bytes,
            signature_variant=0,  # Always 0 for Twist (per SDK)
            encryption_variant=0,  # No encryption
        )
        request = request_msg.to_bytes()

        _LOGGER.debug(
            "Sending TwistQuickVerifyRequest (tmp_id=0x%08x, pairing_id=0x%08x, length=%d bytes)",
            tmp_id,
            pairing_id,
            len(request),
        )

        await self._write_gatt(self.write_char_uuid, request)
        _LOGGER.debug("TwistQuickVerifyRequest sent, waiting for response")

        response_data = await asyncio.wait_for(
            self._wait_for_opcode(TWIST_OPCODE_QUICK_VERIFY_RESPONSE),
            timeout=COMMAND_TIMEOUT,
        )
        _LOGGER.debug(
            "Received TwistQuickVerifyResponse (length=%d bytes)",
            len(response_data),
        )

        response = TwistQuickVerifyResponse.from_bytes(response_data)

        # Derive session key (Twist: no supportsDuo flag)
        kdf_data = bytearray(16)
        kdf_data[0:7] = client_random_bytes
        kdf_data[7] = 0x00  # No supportsDuo flag for Twist
        kdf_data[8:16] = response.button_random

        _LOGGER.debug("Twist QuickVerify KDF data: %s", bytes(kdf_data).hex())

        pairing_subkeys = chaskey_generate_subkeys(pairing_key)
        session_key = chaskey_16_bytes(pairing_subkeys, bytes(kdf_data))
        chaskey_keys = chaskey_generate_subkeys(session_key)

        _LOGGER.debug("Twist quick verify session key derived")

        return session_key, chaskey_keys

    async def init_button_events(
        self,
        session_key: bytes | None,
        chaskey_keys: list[int] | None,
    ) -> None:
        """Initialize button events for Flic Twist."""
        # The device does not persist rotation positions across a connection; the
        # hub restores them through the position field below. Keep the tracker
        # across reconnects so a reconnect resumes where the dial actually is.
        positions = [
            self._multi_mode_tracker.get_mode_units(index) for index in range(13)
        ]

        # Build 13 mode configs based on push_twist_mode setting
        mode_configs = []

        if self._push_twist_mode == PushTwistMode.SELECTOR:
            # Selector mode: enable click events and slots functionality
            for i in range(13):
                if i == 12:
                    config = TwistModeConfig(
                        led_mode=3,  # SDK default
                        has_click=False,
                        has_double_click=False,
                        extra_leds_after=0,
                        position=positions[i],
                        timeout_seconds=0,
                    )
                else:
                    config = TwistModeConfig(
                        led_mode=1,  # SDK default
                        has_click=True,
                        has_double_click=True,
                        extra_leds_after=0,
                        position=positions[i],
                        timeout_seconds=60,
                    )
                mode_configs.append(config)
        elif self._push_twist_mode == PushTwistMode.CONTINUOUS:
            # Continuous mode: like default but with wrapping LED mode
            for i in range(13):
                config = TwistModeConfig(
                    led_mode=2,  # Continuous LED mode
                    has_click=False,
                    has_double_click=False,
                    extra_leds_after=0,
                    position=positions[i],
                    timeout_seconds=0,
                )
                mode_configs.append(config)
        else:
            # Default mode: basic rotation without click events
            for i in range(13):
                config = TwistModeConfig(
                    led_mode=1,  # SDK default
                    has_click=False,
                    has_double_click=False,
                    extra_leds_after=0,
                    position=positions[i],
                    timeout_seconds=0,
                )
                mode_configs.append(config)

        request_msg = InitButtonEventsTwistRequest(
            mode_configs=mode_configs,
            event_count=self._last_event_count,
            boot_id=self._last_boot_id,
            api_version=2,
        )
        request = request_msg.to_bytes()

        # The device re-bases every mode on this request, and rotation updates can
        # arrive before the write returns
        for index, position in enumerate(positions):
            self._multi_mode_tracker.rebase(index, position)
            self._reset_increment_baseline(index)

        _LOGGER.debug(
            "Sending InitButtonEventsTwistRequest (%d bytes)",
            len(request),
        )

        authenticated = session_key is not None and chaskey_keys is not None
        sent_boot_id = self._last_boot_id
        self._queued_event_cutoff_ms = None
        await self._write_packet(request, authenticated)

        try:
            response = await asyncio.wait_for(
                self._wait_for_opcode(TWIST_OPCODE_INIT_BUTTON_EVENTS_RESPONSE),
                timeout=COMMAND_TIMEOUT,
            )

            try:
                init_response = InitButtonEventsResponseV2.from_bytes(response)
                self._last_event_count = init_response.event_count
                self._last_boot_id = init_response.boot_id
                if init_response.boot_id != sent_boot_id:
                    self._queued_event_cutoff_ms = (
                        init_response.timestamp * 1000 // 32768
                        - UNSYNCED_QUEUED_EVENT_MAX_AGE_MS
                    )
                _LOGGER.debug(
                    "Twist button events initialized: has_queued=%s, "
                    "event_count=%d, boot_id=%d, api_version=%d",
                    init_response.has_queued_events,
                    init_response.event_count,
                    init_response.boot_id,
                    init_response.api_version,
                )
            except ValueError as err:
                _LOGGER.debug(
                    "Could not parse InitButtonEventsResponse (%d bytes): %s",
                    len(response),
                    err,
                )
        except TimeoutError:
            _LOGGER.warning(
                "No response to InitButtonEventsTwistRequest, continuing anyway"
            )

    async def get_firmware_version(self) -> int:
        """Request and return the firmware version from a Flic Twist device."""
        request = struct.pack("<B", TWIST_OPCODE_GET_FIRMWARE_VERSION_REQUEST)
        await self._write_packet(request, True)

        response = await asyncio.wait_for(
            self._wait_for_opcode(TWIST_OPCODE_GET_FIRMWARE_VERSION_RESPONSE),
            timeout=COMMAND_TIMEOUT,
        )
        return int(struct.unpack("<I", response[1:5])[0])

    async def get_battery_level(self) -> int:
        """Request and return the battery level from a Flic Twist device."""
        request = struct.pack("<B", TWIST_OPCODE_GET_BATTERY_LEVEL_REQUEST)
        await self._write_packet(request, True)

        response = await asyncio.wait_for(
            self._wait_for_opcode(TWIST_OPCODE_GET_BATTERY_LEVEL_RESPONSE),
            timeout=COMMAND_TIMEOUT,
        )
        # Response: [opcode:1][battery_level:2]
        return int(struct.unpack("<H", response[1:3])[0])

    async def get_name(self) -> tuple[str, int]:
        """Request and return the device name from a Flic Twist device."""
        request = struct.pack("<B", TWIST_OPCODE_GET_NAME_REQUEST)
        await self._write_packet(request, True)

        response = await asyncio.wait_for(
            self._wait_for_opcode(TWIST_OPCODE_GET_NAME_RESPONSE),
            timeout=COMMAND_TIMEOUT,
        )
        # Response: [opcode:1][timestamp:6][name:var]
        timestamp_ms = int.from_bytes(response[1:7], "little")
        name = response[7:].decode("utf-8", errors="replace")
        return name, timestamp_ms

    async def set_name(
        self,
        name: str,
    ) -> tuple[str, int]:
        """Set the device name on a Flic Twist device."""
        name_bytes = self._truncate_name_bytes(name)

        # Build 6-byte timestamp_force: 47-bit UTC ms | force_update=1
        timestamp_ms = int(time.time() * 1000)
        timestamp_force = (timestamp_ms << 1) | 1
        timestamp_force_bytes = timestamp_force.to_bytes(6, "little")

        request = (
            struct.pack("<B", TWIST_OPCODE_SET_NAME_REQUEST)
            + timestamp_force_bytes
            + name_bytes
        )
        await self._write_packet(request, True)

        response = await asyncio.wait_for(
            self._wait_for_opcode(TWIST_OPCODE_SET_NAME_RESPONSE),
            timeout=COMMAND_TIMEOUT,
        )
        # Response: [opcode:1][timestamp:6][name:var]
        resp_timestamp_ms = int.from_bytes(response[1:7], "little")
        resp_name = response[7:].decode("utf-8", errors="replace")
        return resp_name, resp_timestamp_ms

    def handle_notification(
        self,
        data: bytes,
    ) -> tuple[list[ButtonEvent], list[RotateEvent], int | None]:
        """Handle a notification from a Flic Twist button."""
        button_events: list[ButtonEvent] = []
        rotate_events: list[RotateEvent] = []
        selector_change: int | None = None

        if len(data) < 1:
            return button_events, rotate_events, selector_change

        opcode = data[0]

        if opcode == TWIST_OPCODE_BUTTON_EVENT:
            _LOGGER.debug(
                "Twist button event received (opcode=0x%02x, data_len=%d)",
                opcode,
                len(data),
            )
            button_events, selector_change = self._parse_twist_button_events(data)
        elif opcode == TWIST_OPCODE_TWIST_EVENT:
            _LOGGER.debug(
                "Twist rotation event received (opcode=0x%02x, data_len=%d)",
                opcode,
                len(data),
            )
            rotate_events = self._parse_twist_rotation_event(data)

        return button_events, rotate_events, selector_change

    # Twist base-type lookup (bits [1:0] of event_encoded)
    _TWIST_BASE_TYPE_MAP: dict[int, str] = {
        0: EVENT_TYPE_UP,
        1: EVENT_TYPE_DOWN,
        2: EVENT_TYPE_CLICK,
        3: EVENT_TYPE_HOLD,
    }

    def _get_event_name(self, event_type: int) -> str:
        """Get human-readable name for Twist event_encoded value."""
        base = event_type & 0x03
        base_names = {0: "UP", 1: "DOWN", 2: "SINGLE_CLICK_TIMEOUT", 3: "HOLD"}
        name = base_names.get(base, f"UNKNOWN_BASE({base})")
        if event_type & 0x04:
            name += "+SECOND"
        if event_type & 0x08:
            name += "+DBL"
        return name

    def _map_event_type(self, event_type: int) -> str | None:
        """Map Twist event_encoded to HA event type.

        Twist encodes button events in 4 bits:
          bits [1:0] = base type (0=UP, 1=DOWN, 2=SINGLE_CLICK_TIMEOUT, 3=HOLD)
          bit 2      = conflated flag (second press / quick / also_single_click_first)
          bit 3      = dbl (this UP concludes a double-click)
        """
        if event_type & 0x08:  # bit 3 set → double-click concluding release
            base = event_type & 0x03
            if base == 0:  # UP + dbl
                return EVENT_TYPE_DOUBLE_CLICK
            # DOWN/other + dbl: treat as the base type
            return self._TWIST_BASE_TYPE_MAP.get(base)
        return self._TWIST_BASE_TYPE_MAP.get(event_type & 0x03)

    def _parse_twist_button_events(
        self, event_data: bytes
    ) -> tuple[list[ButtonEvent], int | None]:
        """Parse Twist button events from notification data."""
        events: list[ButtonEvent] = []
        selector_change: int | None = None

        try:
            notification = TwistButtonEventNotification.from_bytes(event_data[1:])
        except ValueError as err:
            _LOGGER.debug("Failed to parse Twist button event: %s", err)
            return events, selector_change

        _LOGGER.debug(
            "Processing %d Twist button events",
            len(notification.events),
        )
        # The counter belongs to the last event, and all events are processed
        self._last_event_count = notification.event_count

        for idx, event in enumerate(notification.events):
            event_name = self._get_event_name(event.event_type)
            _LOGGER.debug(
                "Twist button event %d: type=%d (%s), mode=%d, timestamp_ms=%d, "
                "wasQueued=%s",
                idx,
                event.event_type,
                event_name,
                event.twist_mode_index,
                event.timestamp_ms,
                event.was_queued,
            )

            if (
                event.was_queued
                and self._queued_event_cutoff_ms is not None
                and event.timestamp_ms < self._queued_event_cutoff_ms
            ):
                _LOGGER.debug("Dropping old queued Twist button event %d", idx)
                continue

            # Track mode changes (selector position)
            if event.twist_mode_index != self._twist_mode_index:
                old_mode = self._twist_mode_index
                self._twist_mode_index = event.twist_mode_index
                _LOGGER.debug(
                    "Twist mode changed: %d -> %d",
                    old_mode,
                    event.twist_mode_index,
                )

                # Emit selector change event for slot modes (0-11)
                # Suppress in DEFAULT/CONTINUOUS mode where selector is not used
                if event.twist_mode_index < 12 and self._push_twist_mode not in (
                    PushTwistMode.DEFAULT,
                    PushTwistMode.CONTINUOUS,
                ):
                    events.append(
                        ButtonEvent(
                            event_type=EVENT_TYPE_SELECTOR_CHANGED,
                            button_index=None,
                            timestamp_ms=event.timestamp_ms,
                            was_queued=event.was_queued,
                            extra_data={
                                "selector_index": event.twist_mode_index,
                                "previous_index": old_mode,
                                "twist_mode_index": event.twist_mode_index,
                            },
                        )
                    )
                    selector_change = event.twist_mode_index

            # Map event type to HA event
            ha_event = self._map_event_type(event.event_type)
            if ha_event:
                events.append(
                    ButtonEvent(
                        event_type=ha_event,
                        button_index=None,
                        timestamp_ms=event.timestamp_ms,
                        was_queued=event.was_queued,
                        extra_data={"twist_mode_index": event.twist_mode_index},
                    )
                )

        return events, selector_change

    def _reset_increment_baseline(self, mode_index: int) -> None:
        """Count increment events from the current position of a mode."""
        self._prev_int_pct[mode_index] = round(
            self._multi_mode_tracker.get_mode_percentage(mode_index)
        )

    def pop_pending_writes(self) -> list[bytes]:
        """Return the position updates to send again because the device dropped one."""
        resends = list(self._position_resends.values())
        self._position_resends = {}
        return resends

    def set_position_for_next_init(self, mode_index: int, position: int) -> None:
        """Store a position to hand to the device with the next InitButtonEvents."""
        self._multi_mode_tracker.rebase(mode_index, position)

    def build_update_twist_position(
        self, mode_index: int, desired_position: int
    ) -> bytes:
        """Build an UpdateTwistPositionRequest."""
        absolute_position = self._multi_mode_tracker.get_absolute_position(mode_index)

        new_min = absolute_position - desired_position

        # Update local min to match what the device will have
        self._multi_mode_tracker.set_mode_min(mode_index, new_min)
        self._reset_increment_baseline(mode_index)

        request = UpdateTwistPositionRequest(
            twist_mode_index=mode_index,
            new_min=new_min,
            num_received_update_packets=self._twist_packet_counter,
        )
        return request.to_bytes()

    async def start_firmware_update(
        self,
        firmware_binary: bytes,
    ) -> int:
        """Start a firmware update on the device."""
        request = StartFirmwareUpdateRequest.from_firmware_binary(firmware_binary)
        await self._write_packet(request.to_bytes(), True)

        # Wait for either StartFirmwareUpdateResponse (0x0E) or
        # FirmwareUpdateNotification (0x0F). The device may send 0x0F
        # immediately if resuming a previous transfer.
        response_data = await asyncio.wait_for(
            self._wait_for_opcodes(
                [
                    TWIST_OPCODE_START_FIRMWARE_UPDATE_RESPONSE,
                    TWIST_OPCODE_FIRMWARE_UPDATE_NOTIFICATION,
                ]
            ),
            timeout=COMMAND_TIMEOUT,
        )

        opcode = response_data[0]
        if opcode == TWIST_OPCODE_FIRMWARE_UPDATE_NOTIFICATION:
            # Device is already sending progress from a previous/resumed transfer
            notification = FirmwareUpdateNotification.from_bytes(response_data)
            _LOGGER.debug(
                "Received FirmwareUpdateNotification instead of StartResponse: pos=%d",
                notification.pos,
            )
            return notification.pos

        response = StartFirmwareUpdateResponse.from_bytes(response_data)

        _LOGGER.debug("StartFirmwareUpdateResponse: start_pos=%d", response.start_pos)

        return self._validate_firmware_start_pos(response.start_pos)

    async def send_firmware_data(
        self,
        firmware_binary: bytes,
        start_pos: int,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> bool:
        """Send firmware data chunks to the device with flow control."""
        compressed_data = firmware_binary[FIRMWARE_HEADER_SIZE:]
        total_bytes = len(compressed_data)
        sent_pos = start_pos
        acked_pos = start_pos

        _LOGGER.debug(
            "Starting firmware data transfer: total=%d bytes, start_pos=%d",
            total_bytes,
            start_pos,
        )

        while sent_pos < total_bytes:
            # Flow control: wait if too many bytes in flight
            while sent_pos - acked_pos >= FIRMWARE_MAX_IN_FLIGHT:
                notification_data = await asyncio.wait_for(
                    self._wait_for_opcode(TWIST_OPCODE_FIRMWARE_UPDATE_NOTIFICATION),
                    timeout=FIRMWARE_UPDATE_TIMEOUT,
                )
                notification = FirmwareUpdateNotification.from_bytes(notification_data)

                if notification.pos == 0:
                    _LOGGER.error("Firmware signature verification failed")
                    return False

                acked_pos = notification.pos
                if progress_callback:
                    progress_callback(acked_pos, total_bytes)

                if acked_pos >= total_bytes:
                    _LOGGER.info("Firmware transfer complete")
                    return True

            # Send next chunk, capped to remaining in-flight window
            remaining_window = FIRMWARE_MAX_IN_FLIGHT - (sent_pos - acked_pos)
            chunk_size = min(
                FIRMWARE_DATA_CHUNK_SIZE, remaining_window, total_bytes - sent_pos
            )
            chunk = compressed_data[sent_pos : sent_pos + chunk_size]

            data_ind = FirmwareUpdateDataInd(chunk_data=chunk)
            await self._write_packet(data_ind.to_bytes(), True)
            sent_pos += chunk_size

        # Wait for remaining acknowledgments.
        # After all data is sent the device verifies the signature and reboots.
        # The reboot often drops the BLE connection before the final ACK
        # arrives, so use a shorter timeout and treat it as success.
        try:
            while acked_pos < total_bytes:
                notification_data = await asyncio.wait_for(
                    self._wait_for_opcode(TWIST_OPCODE_FIRMWARE_UPDATE_NOTIFICATION),
                    timeout=FIRMWARE_FINAL_ACK_TIMEOUT,
                )
                notification = FirmwareUpdateNotification.from_bytes(notification_data)

                if notification.pos == 0:
                    _LOGGER.error("Firmware signature verification failed")
                    return False

                acked_pos = notification.pos
                if progress_callback:
                    progress_callback(acked_pos, total_bytes)
        except TimeoutError:
            _LOGGER.info(
                "Final ACK timed out after all data sent — "
                "device likely rebooted with new firmware"
            )
            return True

        _LOGGER.info("Firmware transfer complete")
        return True

    async def send_force_disconnect(
        self,
        restart_adv: bool = True,
    ) -> None:
        """Send force disconnect to trigger device reboot."""
        ind = ForceBtDisconnectInd(restart_adv=restart_adv)
        await self._write_packet(ind.to_bytes(), True)
        _LOGGER.debug("Sent ForceBtDisconnectInd (restart_adv=%s)", restart_adv)

    def _parse_twist_rotation_event(self, event_data: bytes) -> list[RotateEvent]:
        """Parse Twist rotation event."""
        events: list[RotateEvent] = []

        try:
            notification = TwistEventNotification.from_bytes(event_data)
        except ValueError as err:
            _LOGGER.warning("Failed to parse Twist rotation event: %s", err)
            return events

        _LOGGER.debug(
            "TwistEventNotification: mode_index=%d, total_delta=%d, "
            "min_delta=%d, max_delta=%d, hub_counter=%d, "
            "min_update_was_top=%s, hub_update_too_old=%s",
            notification.twist_mode_index,
            notification.total_delta,
            notification.min_delta,
            notification.max_delta,
            notification.last_hub_packet_counter,
            notification.last_min_update_was_top,
            notification.last_hub_update_packet_too_old,
        )

        self._twist_packet_counter += 1

        # Apply rotation to the specific mode's tracker
        result = self._multi_mode_tracker.apply(
            notification.twist_mode_index,
            notification.total_delta,
            notification.min_delta,
            notification.max_delta,
            notification.last_min_update_was_top,
        )

        # The device drops a position update whose packet count is too far
        # behind; send the current min again so both sides converge, like the hub
        if notification.last_hub_update_packet_too_old:
            _LOGGER.debug("Resending a Twist position update the device dropped")
            self._position_resends[notification.twist_mode_index] = (
                UpdateTwistPositionRequest(
                    twist_mode_index=notification.twist_mode_index,
                    new_min=self._multi_mode_tracker.get_mode_min(
                        notification.twist_mode_index
                    ),
                    num_received_update_packets=self._twist_packet_counter,
                ).to_bytes()
            )

        # Get mode percentage for slot entity updates
        mode_percentage = self._multi_mode_tracker.get_mode_percentage(
            notification.twist_mode_index
        )

        _LOGGER.debug(
            "Twist rotate result: detent_crossings=%d, angle=%.1f, rpm=%.1f, mode_pct=%.1f",
            result.detent_crossings,
            result.angle_degrees,
            result.rpm,
            mode_percentage,
        )

        if result.detent_crossings != 0:
            event_type = (
                EVENT_TYPE_ROTATE_CLOCKWISE
                if result.detent_crossings > 0
                else EVENT_TYPE_ROTATE_COUNTER_CLOCKWISE
            )

            extra_data = {
                "selector_index": result.selector_index,
                "total_turns": result.total_turns,
                "total_detent_crossings": result.current_detent_crossings,
                "acceleration_multiplier": result.acceleration_multiplier,
                "rpm": result.rpm,
                "twist_mode_index": notification.twist_mode_index,
                "mode_percentage": mode_percentage,
            }

            is_default_or_continuous = self._push_twist_mode in (
                PushTwistMode.DEFAULT,
                PushTwistMode.CONTINUOUS,
            )

            if is_default_or_continuous:
                # Emit quantized increment/decrement events (one per 1% crossing)
                events.extend(
                    self._quantize_rotation(
                        notification.twist_mode_index,
                        mode_percentage,
                        event_type,
                        extra_data,
                    )
                )
            else:
                # SELECTOR mode: emit raw rotate events
                _LOGGER.debug(
                    "Emitting Twist rotate event: %s, mode=%d, detents=%d, angle=%.1f",
                    event_type,
                    notification.twist_mode_index,
                    result.detent_crossings,
                    result.angle_degrees,
                )
                events.append(
                    RotateEvent(
                        event_type=event_type,
                        button_index=None,
                        angle_degrees=result.angle_degrees,
                        detent_crossings=abs(result.detent_crossings),
                        extra_data=extra_data,
                    )
                )

        return events

    def _quantize_rotation(
        self,
        twist_mode_index: int,
        mode_percentage: float,
        event_type: str,
        extra_data: dict[str, Any],
    ) -> list[RotateEvent]:
        """Convert a rotation event into discrete increment/decrement events.

        Fires one RotateEvent per 1% boundary crossing so a jump from 1% to 4%
        produces 3 events. Uses shorter path around wrap in CONTINUOUS mode.
        """
        events: list[RotateEvent] = []
        int_pct = round(mode_percentage)

        prev_pct = self._prev_int_pct.get(twist_mode_index)
        self._prev_int_pct[twist_mode_index] = int_pct

        if prev_pct is None or int_pct == prev_pct:
            return events

        is_push_twist = twist_mode_index == TWIST_MODE_SLOT_CHANGING
        if event_type == EVENT_TYPE_ROTATE_CLOCKWISE:
            inc_event = (
                EVENT_TYPE_PUSH_TWIST_INCREMENT
                if is_push_twist
                else EVENT_TYPE_TWIST_INCREMENT
            )
        else:
            inc_event = (
                EVENT_TYPE_PUSH_TWIST_DECREMENT
                if is_push_twist
                else EVENT_TYPE_TWIST_DECREMENT
            )

        diff = abs(int_pct - prev_pct)
        # In continuous mode, use the shorter path around the wrap
        if self._push_twist_mode == PushTwistMode.CONTINUOUS and diff > 50:
            steps = 100 - diff
        else:
            steps = diff

        _LOGGER.debug(
            "Quantized rotation: %s x%d (mode=%d, pct=%d->%d)",
            inc_event,
            steps,
            twist_mode_index,
            prev_pct,
            int_pct,
        )

        for _ in range(steps):
            events.append(
                RotateEvent(
                    event_type=inc_event,
                    button_index=None,
                    angle_degrees=0.0,
                    detent_crossings=1,
                    extra_data=extra_data,
                )
            )

        return events
