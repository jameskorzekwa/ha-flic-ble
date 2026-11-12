"""Flic Duo push-twist rotation events.

While a Duo button is held, the Duo reports how far it has been turned
(push-twist). This module turns those reports into ``rotate_clockwise`` and
``rotate_counter_clockwise`` events using the rotation tracker from the vendored
pyflic-ble library, and filters out the small turns that happen during a swipe.
The filtering is adapted from pyflic-ble's Flic Duo handler (Apache-2.0,
Shortcut Labs AB); see NOTICE.
"""

from __future__ import annotations

import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .pyflic_ble.rotate_tracker import D120, RotateTracker

# Rotation reported within this long after a press is held back: a swipe press
# lasts about 195 ms, a deliberate push-and-twist much longer.
ROTATION_GATE_SECONDS = 0.25
# After a swipe, ignore rotation for this long; the dial keeps moving briefly.
SWIPE_SUPPRESS_SECONDS = 0.3

BUTTONS = ("big", "small")


@dataclass(slots=True)
class PushTwistData:
    """One push-twist notification from a Flic Duo."""

    buttons_pressed: int
    is_first_event: int
    pressed_half_second: int
    angle_diff: int

    @classmethod
    def from_payload(cls, data: bytes) -> PushTwistData:
        """Parse the bytes after the opcode."""
        if len(data) < 5:
            raise ValueError("Truncated Flic Duo push-twist notification")
        flags = data[0]
        return cls(
            flags & 0x03,
            (flags >> 2) & 0x03,
            (flags >> 4) & 0x03,
            struct.unpack_from("<i", data, 1)[0],
        )


@dataclass(slots=True)
class RotationEvent:
    """A rotation of one Duo button's virtual dial."""

    event_type: str
    button: str
    data: dict[str, Any]


class DuoRotation:
    """Track both Duo dials and decide which rotation reports to surface."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        # One virtual dial per button: 120 degrees spans 0-100 %.
        self._trackers = {
            index: RotateTracker(
                enable_backlash_suppression=True,
                full_range_units=D120,
                clamp_position=True,
            )
            for index in (0, 1)
        }
        self._down_at: dict[int, float] = {}
        self._suppress_until: dict[int, float] = {}
        self._buffer: dict[int, list[PushTwistData]] = {}

    def reset(self) -> None:
        """Forget press timing after a reconnect; dial positions are kept."""
        self._down_at.clear()
        self._suppress_until.clear()
        self._buffer.clear()

    def button_down(self, index: int) -> None:
        """Start the gate window for a newly pressed button."""
        self._down_at[index] = self._clock()
        self._buffer[index] = []

    def button_up(self, index: int, *, swiped: bool) -> None:
        """End a press; a swipe discards its rotation and mutes the dial briefly."""
        if swiped:
            self._suppress_until[index] = self._clock() + SWIPE_SUPPRESS_SECONDS
        self._buffer.pop(index, None)
        self._down_at.pop(index, None)

    def push_twist(self, report: PushTwistData) -> list[RotationEvent]:
        """Return the rotation events to emit for one push-twist report."""
        if report.angle_diff == 0:
            return []
        # 1 = big, 2 = small, 3 = both (attributed to the big button)
        index = {1: 0, 2: 1, 3: 0}.get(report.buttons_pressed)
        if index is None:
            return []
        now = self._clock()
        if now < self._suppress_until.get(index, 0.0):
            return []
        down_at = self._down_at.get(index)
        if down_at is not None and now - down_at < ROTATION_GATE_SECONDS:
            if index in self._buffer:
                self._buffer[index].append(report)
            return []
        events = [
            event
            for buffered in self._buffer.pop(index, [])
            if (event := self._emit(index, buffered)) is not None
        ]
        if (event := self._emit(index, report)) is not None:
            events.append(event)
        return events

    def _emit(self, index: int, report: PushTwistData) -> RotationEvent | None:
        tracker = self._trackers[index]
        result = tracker.apply(report.angle_diff)
        if result.backlash_suppressed:
            return None
        direction = "clockwise" if report.angle_diff > 0 else "counter_clockwise"
        prefix = "small_" if index else ""
        return RotationEvent(
            f"{prefix}rotate_{direction}",
            BUTTONS[index],
            {
                "angle_degrees": round(result.angle_degrees, 2),
                "detent_crossings": abs(result.detent_crossings),
                "dial_percentage": round(tracker.percentage, 1),
                "total_turns": result.total_turns,
                "rpm": round(result.rpm, 1),
                "is_first_event": bool(report.is_first_event),
            },
        )
