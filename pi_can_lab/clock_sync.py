"""Clock validation and non-destructive cross-host timestamp alignment.

The sender writes phase markers using the source Raspberry Pi's wall clock,
while each receiver writes CAN timestamps using its own wall clock.  This
module derives source-relative corrections from the SSH midpoint samples.  It
never rewrites a captured log; callers apply the returned correction only
while selecting analysis windows.
"""

from __future__ import annotations

import math
from typing import Any, Mapping, Optional


ALIGNMENT_METHOD = "ssh_midpoint_relative_v1"


class ClockSyncError(ValueError):
    """Raised when clock evidence is missing, invalid, or too uncertain."""


def _finite_number(value: Any, name: str) -> float:
    if isinstance(value, bool):
        raise ClockSyncError(f"{name} must be a finite number")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ClockSyncError(f"{name} must be a finite number") from exc
    if not math.isfinite(number):
        raise ClockSyncError(f"{name} must be a finite number")
    return number


def _optional_nonnegative(config: Mapping[str, Any], name: str) -> Optional[float]:
    value = config.get(name)
    if value is None:
        return None
    number = _finite_number(value, f"time_sync.{name}")
    if number < 0:
        raise ClockSyncError(f"time_sync.{name} must be >= 0")
    return number


def validate_clock_sample(
    sample: Mapping[str, Any],
    *,
    bus: str = "clock",
    max_absolute_offset_ms: Optional[float] = None,
    max_round_trip_ms: Optional[float] = None,
) -> dict[str, Any]:
    """Validate and normalize one selected SSH clock sample.

    ``offset_ms`` follows the convention ``remote - control``.  Uncertainty is
    deliberately derived from half the round trip, even for legacy samples
    which do not contain the newer ``uncertainty_ms`` field.
    """

    if not isinstance(sample, Mapping):
        raise ClockSyncError(f"{bus} clock sample must be a mapping")
    offset_ms = _finite_number(sample.get("offset_ms"), f"{bus}.offset_ms")
    round_trip_ms = _finite_number(
        sample.get("round_trip_ms"), f"{bus}.round_trip_ms"
    )
    if round_trip_ms < 0:
        raise ClockSyncError(f"{bus}.round_trip_ms must be >= 0")
    if max_absolute_offset_ms is not None and abs(offset_ms) > max_absolute_offset_ms:
        raise ClockSyncError(
            f"{bus} absolute clock offset {abs(offset_ms):.3f} ms exceeds "
            f"{max_absolute_offset_ms:.3f} ms"
        )
    if max_round_trip_ms is not None and round_trip_ms > max_round_trip_ms:
        raise ClockSyncError(
            f"{bus} clock round trip {round_trip_ms:.3f} ms exceeds "
            f"{max_round_trip_ms:.3f} ms"
        )

    normalized: dict[str, Any] = {
        "offset_ms": offset_ms,
        "round_trip_ms": round_trip_ms,
        "uncertainty_ms": round_trip_ms / 2.0,
    }
    sampled_at = sample.get("sampled_at_control_ns")
    if sampled_at is not None:
        if isinstance(sampled_at, bool):
            raise ClockSyncError(f"{bus}.sampled_at_control_ns must be an integer")
        try:
            sampled_at_int = int(sampled_at)
        except (TypeError, ValueError) as exc:
            raise ClockSyncError(
                f"{bus}.sampled_at_control_ns must be an integer"
            ) from exc
        if sampled_at_int < 0:
            raise ClockSyncError(f"{bus}.sampled_at_control_ns must be >= 0")
        normalized["sampled_at_control_ns"] = sampled_at_int
    return normalized


def build_clock_alignment(
    clock_offsets: Mapping[str, Mapping[str, Any]],
    source_bus: str,
    config: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    """Build per-bus corrections into the source Pi's clock domain.

    For a receiver bus ``h`` and source bus ``s``::

        aligned_timestamp = raw_timestamp + (offset_s - offset_h)

    Relative uncertainty is the conservative sum of both half-RTT bounds.
    The source bus needs no SSH-derived relative correction or uncertainty,
    because its frames and phase markers use the same wall clock.

    Supported config keys are ``boundary_guard_ms``,
    ``max_absolute_offset_ms``, ``max_round_trip_ms``, and
    ``max_relative_uncertainty_ms``.  Limits are opt-in to preserve legacy
    behavior; malformed evidence always fails closed.
    """

    if not isinstance(clock_offsets, Mapping) or not clock_offsets:
        raise ClockSyncError("clock_offsets must contain at least one bus")
    sync = dict(config or {})
    boundary_guard_ms = _finite_number(
        sync.get("boundary_guard_ms", 0.0), "time_sync.boundary_guard_ms"
    )
    if boundary_guard_ms < 0:
        raise ClockSyncError("time_sync.boundary_guard_ms must be >= 0")
    max_absolute_offset_ms = _optional_nonnegative(sync, "max_absolute_offset_ms")
    max_round_trip_ms = _optional_nonnegative(sync, "max_round_trip_ms")
    max_relative_uncertainty_ms = _optional_nonnegative(
        sync, "max_relative_uncertainty_ms"
    )

    canonical = {str(bus).strip().lower(): value for bus, value in clock_offsets.items()}
    source = str(source_bus).strip().lower()
    if source not in canonical:
        raise ClockSyncError(f"source bus clock sample is missing: {source}")

    validated = {
        bus: validate_clock_sample(
            sample,
            bus=bus,
            max_absolute_offset_ms=max_absolute_offset_ms,
            max_round_trip_ms=max_round_trip_ms,
        )
        for bus, sample in canonical.items()
    }
    source_sample = validated[source]
    per_bus: dict[str, dict[str, Any]] = {}
    for bus, sample in sorted(validated.items()):
        if bus == source:
            correction_ms = 0.0
            relative_uncertainty_ms = 0.0
        else:
            correction_ms = source_sample["offset_ms"] - sample["offset_ms"]
            relative_uncertainty_ms = (
                source_sample["uncertainty_ms"] + sample["uncertainty_ms"]
            )
        if (
            max_relative_uncertainty_ms is not None
            and relative_uncertainty_ms > max_relative_uncertainty_ms
        ):
            raise ClockSyncError(
                f"{bus} relative clock uncertainty "
                f"{relative_uncertainty_ms:.3f} ms exceeds "
                f"{max_relative_uncertainty_ms:.3f} ms"
            )
        effective_guard_ms = boundary_guard_ms + relative_uncertainty_ms
        per_bus[bus] = {
            **sample,
            "correction_ms": correction_ms,
            "correction_ns": int(round(correction_ms * 1_000_000.0)),
            "relative_uncertainty_ms": relative_uncertainty_ms,
            "effective_guard_ms": effective_guard_ms,
            "effective_guard_ns": int(round(effective_guard_ms * 1_000_000.0)),
        }

    return {
        "method": ALIGNMENT_METHOD,
        "reference_bus": source,
        "boundary_guard_ms": boundary_guard_ms,
        "per_bus": per_bus,
    }


def align_timestamp_ns(timestamp_ns: int, bus_alignment: Mapping[str, Any]) -> int:
    """Return an analysis-only timestamp in the source Pi clock domain."""

    if isinstance(timestamp_ns, bool):
        raise ClockSyncError("timestamp_ns must be an integer")
    try:
        raw = int(timestamp_ns)
    except (TypeError, ValueError) as exc:
        raise ClockSyncError("timestamp_ns must be an integer") from exc
    correction = bus_alignment.get("correction_ns")
    if isinstance(correction, bool):
        raise ClockSyncError("correction_ns must be an integer")
    try:
        correction_ns = int(correction)
    except (TypeError, ValueError) as exc:
        raise ClockSyncError("correction_ns must be an integer") from exc
    return raw + correction_ns


def guarded_phase_bounds(
    start_ns: int,
    end_ns: int,
    bus_alignment: Mapping[str, Any],
) -> tuple[int, int]:
    """Shrink a source-clock phase by this bus's alignment uncertainty."""

    if isinstance(start_ns, bool) or isinstance(end_ns, bool):
        raise ClockSyncError("phase bounds must be integers")
    try:
        start = int(start_ns)
        end = int(end_ns)
        guard = int(bus_alignment.get("effective_guard_ns"))
    except (TypeError, ValueError) as exc:
        raise ClockSyncError("phase bounds and effective_guard_ns must be integers") from exc
    if end <= start:
        raise ClockSyncError("phase end must be greater than phase start")
    if guard < 0:
        raise ClockSyncError("effective_guard_ns must be >= 0")
    guarded_start = start + guard
    guarded_end = end - guard
    if guarded_end <= guarded_start:
        raise ClockSyncError(
            "phase is too short for the configured clock uncertainty guard"
        )
    return guarded_start, guarded_end
