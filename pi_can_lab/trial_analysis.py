"""Phase-aware offline anomaly detection for completed CAN fuzzing trials.

The analyzer deliberately remains offline: it consumes a complete Trial and
produces evidence for a later Trial.  The primary comparison is a duration-
matched normal-frame control window versus the mutation window.  Baseline and
recovery are retained as diagnostics and as clean reference observations, but
do not replace the active normal-frame control when it is available.
"""

from __future__ import annotations

import json
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from can_common import load_dbc, protected_signal_names
from trial_models import MutationCase


FrameKey = tuple[str, int, bool]


def validate_capture_log(path: Path, expected_experiment_id: int) -> dict[str, Any]:
    """Reject incomplete remote captures before they can influence feedback."""
    starts = ends = frames = 0
    mismatches = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            text = line.strip()
            if not text:
                continue
            try:
                record = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSONL") from exc
            record_type = record.get("record_type")
            starts += int(record_type == "session_start")
            ends += int(record_type == "session_end")
            frames += int(record_type == "can_rx")
            recorded_id = record.get("experiment_id")
            if recorded_id is not None and str(recorded_id) != str(expected_experiment_id):
                mismatches.append(str(recorded_id))
    if starts != 1 or ends != 1 or frames < 1 or mismatches:
        raise ValueError(
            f"Incomplete capture {path.name}: starts={starts}, frames={frames}, "
            f"ends={ends}, experiment_mismatches={sorted(set(mismatches))}"
        )
    return {"session_start_count": starts, "frame_count": frames, "session_end_count": ends}


def _normalise_bus(value: str) -> str:
    return str(value).strip().lower().replace("-", "_")


def _load_frames(path: Path, bus_name: str) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            text = line.strip()
            if not text:
                continue
            try:
                record = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSONL") from exc
            if record.get("record_type") != "can_rx":
                continue
            if record.get("is_error_frame") or record.get("is_remote_frame"):
                continue
            timestamp = record.get("wall_time_ns", record.get("epoch_ns"))
            if timestamp is None:
                continue
            payload = record.get("data_hex", record.get("payload"))
            if not isinstance(payload, str):
                continue
            raw_id = record.get("arbitration_id", record.get("can_id"))
            if raw_id is None:
                continue
            try:
                arbitration_id = int(raw_id, 0) if isinstance(raw_id, str) else int(raw_id)
                data = bytes.fromhex(payload)
            except (TypeError, ValueError):
                continue
            frames.append({
                "bus": _normalise_bus(str(record.get("bus") or bus_name)),
                "id": arbitration_id,
                "extended": bool(record.get("is_extended_id", False)),
                "time_ns": int(timestamp),
                "raw_time_ns": int(timestamp),
                "payload": data,
            })
    return sorted(frames, key=lambda item: item["time_ns"])


def _phase(
    frames: Iterable[dict[str, Any]], start_ns: int, end_ns: int,
) -> list[dict[str, Any]]:
    if end_ns <= start_ns:
        return []
    return [item for item in frames if start_ns <= item["time_ns"] < end_ns]


def _empty_metrics() -> dict[str, Any]:
    return {
        "message_count": 0,
        "frequency_hz": 0.0,
        "mean_cycle_time_ms": None,
        "median_cycle_time_ms": None,
        "cycle_time_stddev_ms": None,
        "minimum_cycle_time_ms": None,
        "maximum_cycle_time_ms": None,
        "payload_unique_count": 0,
        "payload_change_count": 0,
        "payloads": [],
    }


def _metrics(frames: Sequence[dict[str, Any]], duration_seconds: float) -> dict[str, Any]:
    if not frames:
        return _empty_metrics()
    timestamps = [item["time_ns"] for item in frames]
    intervals = [
        (right - left) / 1_000_000.0
        for left, right in zip(timestamps, timestamps[1:])
    ]
    payloads = [item["payload"] for item in frames]
    changes = sum(before != after for before, after in zip(payloads, payloads[1:]))
    return {
        "message_count": len(frames),
        "frequency_hz": len(frames) / duration_seconds if duration_seconds > 0 else 0.0,
        "mean_cycle_time_ms": statistics.fmean(intervals) if intervals else None,
        "median_cycle_time_ms": statistics.median(intervals) if intervals else None,
        "cycle_time_stddev_ms": (
            statistics.pstdev(intervals)
            if len(intervals) > 1 else (0.0 if intervals else None)
        ),
        "minimum_cycle_time_ms": min(intervals) if intervals else None,
        "maximum_cycle_time_ms": max(intervals) if intervals else None,
        "payload_unique_count": len(set(payloads)),
        "payload_change_count": changes,
        "payloads": sorted({payload.hex().upper() for payload in payloads}),
    }


def _relative(before: float | None, after: float | None) -> float | None:
    if before is None or after is None or before <= 0:
        return None
    return abs(after - before) / before


def _phase_diagnostic(
    before: Mapping[str, Any], after: Mapping[str, Any], comparison: str,
) -> dict[str, Any]:
    """Describe a secondary phase transition without feeding mutation scoring."""

    before_frequency = float(before.get("frequency_hz", 0.0))
    after_frequency = float(after.get("frequency_hz", 0.0))
    return {
        "comparison": comparison,
        "diagnostic_only": True,
        "message_count_delta": int(after.get("message_count", 0))
        - int(before.get("message_count", 0)),
        "frequency_hz_delta": after_frequency - before_frequency,
        "frequency_relative_change": _relative(before_frequency, after_frequency),
        "mean_cycle_time_relative_change": _relative(
            before.get("mean_cycle_time_ms"), after.get("mean_cycle_time_ms")
        ),
        "payload_unique_count_delta": int(after.get("payload_unique_count", 0))
        - int(before.get("payload_unique_count", 0)),
    }


def _score(relative: float, threshold: float) -> float:
    return round(
        min(1.0, 0.5 + 0.5 * max(0.0, relative - threshold) / max(threshold, 1e-9)),
        6,
    )


def _best_clock_sample(value: Any) -> tuple[float, float]:
    """Return (remote offset ms, RTT ms), accepting runner and compact formats."""
    if isinstance(value, (int, float)):
        return float(value), 0.0
    if not isinstance(value, Mapping):
        return 0.0, 0.0
    candidates: list[Mapping[str, Any]] = []
    if value.get("offset_ms") is not None:
        candidates.append(value)
    candidates.extend(
        item for item in value.get("samples", [])
        if isinstance(item, Mapping) and item.get("offset_ms") is not None
    )
    if not candidates:
        return 0.0, 0.0
    best = min(candidates, key=lambda item: float(item.get("round_trip_ms", float("inf"))))
    return float(best.get("offset_ms", 0.0)), max(0.0, float(best.get("round_trip_ms", 0.0)))


def _clock_for_bus(clock_offsets: Mapping[str, Any] | None, bus: str) -> tuple[float, float]:
    if not clock_offsets:
        return 0.0, 0.0
    normalised = {_normalise_bus(str(key)): value for key, value in clock_offsets.items()}
    return _best_clock_sample(normalised.get(_normalise_bus(bus)))


def _signal_bit_positions(start: int, length: int, byte_order: str) -> tuple[int, ...]:
    if length < 1:
        return ()
    if byte_order == "little_endian":
        return tuple(range(start, start + length))
    bit = start
    positions = []
    for _ in range(length):
        positions.append(bit)
        bit = bit + 15 if bit % 8 == 0 else bit - 1
    return tuple(positions)


_TIME_LIKE = re.compile(
    r"(?:timestamp|time_stamp|mastertime|masterzeit|messzeitpunkt|zeitstempel)", re.IGNORECASE
)


def _dynamic_signal_names(message: Any, variable: set[str]) -> tuple[set[str], dict[str, str]]:
    protected = set(protected_signal_names(message))
    reasons = {name: "crc_counter_or_checksum" for name in protected}
    for signal in message.signals:
        if _TIME_LIKE.search(signal.name):
            protected.add(signal.name)
            reasons[signal.name] = "time_like"
    for name in variable:
        protected.add(name)
        reasons.setdefault(name, "varied_during_normal_control")
    return protected, reasons


def _decode_control_values(message: Any, frames: Sequence[dict[str, Any]]) -> dict[str, Counter[str]]:
    values: dict[str, Counter[str]] = defaultdict(Counter)
    for frame in frames:
        try:
            decoded = message.decode(
                frame["payload"], decode_choices=False, scaling=False,
            )
        except Exception:
            continue
        for name, value in decoded.items():
            values[name][json.dumps(value, sort_keys=True, default=str)] += 1
    return values


def _stable_bit_profile(frames: Sequence[dict[str, Any]]) -> tuple[bytes | None, bytes]:
    if not frames:
        return None, b""
    counts = Counter(frame["payload"] for frame in frames)
    reference = counts.most_common(1)[0][0]
    mask = bytearray([0xFF] * len(reference))
    for payload in counts:
        if len(payload) != len(reference):
            return reference, bytes(len(reference))
        for index, (before, observed) in enumerate(zip(reference, payload)):
            mask[index] &= (~(before ^ observed)) & 0xFF
    return reference, bytes(mask)


def _undefined_mask(message: Any, payload_length: int) -> bytes:
    occupied: set[int] = set()
    for signal in message.signals:
        occupied.update(_signal_bit_positions(
            int(signal.start), int(signal.length), str(signal.byte_order)
        ))
    mask = bytearray(payload_length)
    for bit in range(payload_length * 8):
        if bit not in occupied:
            mask[bit // 8] |= 1 << (bit % 8)
    return bytes(mask)


def _payload_evidence(
    *,
    comparison_control: Sequence[dict[str, Any]],
    stability_control: Sequence[dict[str, Any]],
    mutation_frames: Sequence[dict[str, Any]],
    message: Any | None,
    ratio_threshold: float,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Compare stable semantic fields, never raw whole-payload novelty."""
    diagnostics: dict[str, Any] = {
        "method": "stable_bits",
        "ignored_dynamic_fields": [],
    }
    if not comparison_control or not mutation_frames:
        return None, diagnostics

    stable_reference, stable_mask = _stable_bit_profile(stability_control or comparison_control)
    if stable_reference is None:
        return None, diagnostics

    stable_signal_changes: list[dict[str, Any]] = []
    raw_mask = stable_mask
    if message is not None:
        control_values = _decode_control_values(message, stability_control or comparison_control)
        variable = {name for name, values in control_values.items() if len(values) != 1}
        dynamic, reasons = _dynamic_signal_names(message, variable)
        diagnostics["method"] = "dbc_stable_signals_and_undefined_bits"
        diagnostics["ignored_dynamic_fields"] = [
            {"signal": name, "reason": reasons[name]}
            for name in sorted(dynamic)
        ]
        mutation_values = _decode_control_values(message, mutation_frames)
        for signal in message.signals:
            name = signal.name
            baseline_values = control_values.get(name, Counter())
            if name in dynamic or len(baseline_values) != 1:
                continue
            baseline_serialised = next(iter(baseline_values))
            changed_count = sum(
                count for value, count in mutation_values.get(name, Counter()).items()
                if value != baseline_serialised
            )
            ratio = changed_count / len(mutation_frames)
            if changed_count and ratio >= ratio_threshold:
                changed_values = [
                    json.loads(value)
                    for value in mutation_values.get(name, Counter())
                    if value != baseline_serialised
                ]
                stable_signal_changes.append({
                    "signal": name,
                    "control_value": json.loads(baseline_serialised),
                    "mutation_values": changed_values,
                    "changed_frames": changed_count,
                    "changed_frame_ratio": ratio,
                })
        # DBC signals are interpreted semantically above. Raw-bit fallback is
        # deliberately restricted to bits not described by the DBC.
        undefined = _undefined_mask(message, len(stable_reference))
        raw_mask = bytes(left & right for left, right in zip(stable_mask, undefined))

    changed_bits: Counter[int] = Counter()
    changed_frames = 0
    length_change_frames = 0
    for frame in mutation_frames:
        payload = frame["payload"]
        if len(payload) != len(stable_reference):
            length_change_frames += 1
            continue
        delta = bytes(
            (before ^ observed) & mask
            for before, observed, mask in zip(stable_reference, payload, raw_mask)
        )
        if not any(delta):
            continue
        changed_frames += 1
        for byte_index, value in enumerate(delta):
            for bit_index in range(8):
                if value & (1 << bit_index):
                    changed_bits[byte_index * 8 + bit_index] += 1
    raw_ratio = changed_frames / len(mutation_frames)
    length_ratio = length_change_frames / len(mutation_frames)
    raw_triggered = raw_ratio >= ratio_threshold or length_ratio >= ratio_threshold
    if not stable_signal_changes and not raw_triggered:
        return None, diagnostics

    strongest = max(
        [item["changed_frame_ratio"] for item in stable_signal_changes]
        + ([raw_ratio] if raw_triggered else [])
        + ([length_ratio] if length_ratio >= ratio_threshold else [])
    )
    return {
        "comparison": "NORMAL_VS_MUTATION",
        "stable_signal_changes": stable_signal_changes,
        "stable_undefined_bit_changes": [
            {"global_bit": bit, "changed_frames": count}
            for bit, count in changed_bits.most_common()
        ],
        "stable_bit_changed_frames": changed_frames,
        "stable_bit_change_ratio": raw_ratio,
        "length_change_frames": length_change_frames,
        "change_ratio": strongest,
        **diagnostics,
    }, diagnostics


def _catalog_bus(reference_catalog: Mapping[str, Any] | None, bus: str) -> Mapping[str, Any]:
    if not reference_catalog:
        return {}
    buses = reference_catalog.get("buses", reference_catalog)
    if not isinstance(buses, Mapping):
        return {}
    for key, value in buses.items():
        if _normalise_bus(str(key)) == _normalise_bus(bus) and isinstance(value, Mapping):
            return value
    return {}


def _catalog_known(
    reference_catalog: Mapping[str, Any] | None, bus: str, can_id: int, extended: bool,
) -> bool:
    entry = _catalog_bus(reference_catalog, bus)
    canonical = f"{'EXT' if extended else 'STD'}:0x{can_id:X}"
    known_ids = entry.get("known_ids", [])
    iterable = known_ids if isinstance(known_ids, Sequence) and not isinstance(known_ids, str) else []
    for value in iterable:
        try:
            if isinstance(value, str) and ":" in value:
                if value.upper() == canonical.upper():
                    return True
            elif (int(value, 0) if isinstance(value, str) else int(value)) == can_id:
                return True
        except (TypeError, ValueError):
            continue
    for field in ("frames", "known_frames"):
        frames = entry.get(field, {})
        if not isinstance(frames, Mapping):
            continue
        for key, value in frames.items():
            if str(key).upper() == canonical.upper():
                return True
            if isinstance(value, Mapping):
                raw_id = value.get("can_id")
                try:
                    parsed = int(raw_id, 0) if isinstance(raw_id, str) else int(raw_id)
                except (TypeError, ValueError):
                    continue
                if parsed == can_id and bool(value.get("is_extended_id", extended)) == extended:
                    return True
    return False


def _catalog_exposure(reference_catalog: Mapping[str, Any] | None, bus: str) -> float:
    entry = _catalog_bus(reference_catalog, bus)
    for key in ("control_exposure_seconds", "exposure_seconds"):
        if entry.get(key) is not None:
            try:
                return max(0.0, float(entry[key]))
            except (TypeError, ValueError):
                pass
    return 0.0


def _reference_update(
    grouped: Mapping[FrameKey, Mapping[str, Sequence[dict[str, Any]]]],
    exposures: Mapping[str, float],
) -> dict[str, Any]:
    buses: dict[str, Any] = {}
    for bus, exposure in sorted(exposures.items()):
        frames: dict[str, Any] = {}
        for (item_bus, can_id, extended), windows in sorted(grouped.items()):
            if item_bus != bus:
                continue
            controls = list(windows["baseline"]) + list(windows["normal"])
            if not controls:
                continue
            key = f"{'EXT' if extended else 'STD'}:0x{can_id:X}"
            lengths = Counter(len(item["payload"]) for item in controls)
            frames[key] = {
                "can_id": f"0x{can_id:X}",
                "is_extended_id": extended,
                "frame_count": len(controls),
                "dlc_counts": {str(length): count for length, count in sorted(lengths.items())},
            }
        buses[bus.upper()] = {
            "control_exposure_seconds": round(max(0.0, exposure), 9),
            "frames": frames,
        }
    return {"schema_version": 1, "buses": buses}


def analyze_trial(
    *,
    rx_paths: Mapping[str, Path],
    phase_times_ns: Mapping[str, int],
    mutation: MutationCase,
    thresholds: Mapping[str, Any],
    dbc_path: Path | str | None = None,
    reference_catalog: Mapping[str, Any] | None = None,
    clock_offsets: Mapping[str, Any] | None = None,
    source_bus: str | None = None,
    boundary_guard_ms: float = 0.0,
) -> dict[str, Any]:
    """Analyze one completed Trial without changing the next mutation online."""
    baseline_start = int(phase_times_ns["baseline_start"])
    baseline_end = int(phase_times_ns["baseline_end"])
    mutation_start = int(phase_times_ns["mutation_start"])
    mutation_end = int(phase_times_ns["mutation_end"])
    has_normal = "normal_start" in phase_times_ns and "normal_end" in phase_times_ns
    has_recovery = "recovery_start" in phase_times_ns and "recovery_end" in phase_times_ns
    normal_start = int(phase_times_ns.get("normal_start", baseline_start))
    normal_end = int(phase_times_ns.get("normal_end", baseline_end))
    recovery_start = int(phase_times_ns.get("recovery_start", mutation_end))
    recovery_end = int(phase_times_ns.get("recovery_end", mutation_end))
    control_duration_ns = (
        normal_end - normal_start if has_normal else baseline_end - baseline_start
    )
    duration_matched = control_duration_ns >= (mutation_end - mutation_start)

    timing_relative = float(thresholds.get("timing_relative_change", 0.25))
    timing_stddev_absolute = float(thresholds.get("timing_stddev_absolute_ms", 2.0))
    frequency_relative = float(thresholds.get("frequency_relative_change", 0.5))
    loss_ratio = float(thresholds.get("message_loss_ratio", 0.1))
    payload_ratio_threshold = float(thresholds.get(
        "payload_change_ratio", thresholds.get("payload_novel_ratio", 0.2)
    ))
    min_control = int(thresholds.get(
        "minimum_control_frames", thresholds.get("minimum_baseline_frames", 5)
    ))
    min_mutation = int(thresholds.get("minimum_mutation_frames", 3))
    min_expected = float(thresholds.get("minimum_expected_frames", 3))
    min_timing_intervals = int(thresholds.get("minimum_timing_intervals", 3))
    new_message_min = int(thresholds.get("new_message_minimum_frames", 3))
    min_reference_seconds = float(thresholds.get(
        "new_message_minimum_reference_seconds",
        thresholds.get("new_message_minimum_control_seconds", 60.0),
    ))

    database = load_dbc(Path(dbc_path).expanduser().resolve()) if dbc_path else None
    source = _normalise_bus(source_bus or mutation.source_bus)
    source_offset_ms, source_rtt_ms = _clock_for_bus(clock_offsets, source)
    configured_guard_ms = max(0.0, float(boundary_guard_ms))

    grouped: dict[FrameKey, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: {
            "baseline": [], "normal": [], "reference": [],
            "mutation": [], "recovery": [],
        }
    )
    phase_durations: dict[str, dict[str, float]] = {}
    time_alignment: dict[str, dict[str, float]] = {}
    bus_exposure: dict[str, float] = {}

    for configured_bus, path in rx_paths.items():
        bus = _normalise_bus(configured_bus)
        bus_offset_ms, bus_rtt_ms = _clock_for_bus(clock_offsets, bus)
        if bus == source:
            correction_ms = 0.0
            relative_uncertainty_ms = 0.0
        else:
            correction_ms = source_offset_ms - bus_offset_ms
            relative_uncertainty_ms = source_rtt_ms / 2.0 + bus_rtt_ms / 2.0
        uncertainty_ms = configured_guard_ms + relative_uncertainty_ms
        guard_ns = int(round(uncertainty_ms * 1_000_000.0))
        correction_ns = int(round(correction_ms * 1_000_000.0))
        frames = _load_frames(path, bus)
        for item in frames:
            item["time_ns"] = item["raw_time_ns"] + correction_ns
        frames.sort(key=lambda item: item["time_ns"])

        def bounds(start: int, end: int) -> tuple[int, int]:
            guarded_start, guarded_end = start + guard_ns, end - guard_ns
            if guarded_end <= guarded_start:
                raise ValueError(
                    f"{bus} phase {start}..{end} is too short for "
                    f"{uncertainty_ms:.3f} ms clock boundary guard"
                )
            return guarded_start, guarded_end

        base_bounds = bounds(baseline_start, baseline_end)
        normal_bounds = bounds(normal_start, normal_end) if has_normal else (normal_start, normal_start)
        mutation_bounds = bounds(mutation_start, mutation_end)
        recovery_bounds = bounds(recovery_start, recovery_end) if has_recovery else (recovery_start, recovery_start)
        mutation_effective_ns = max(0, mutation_bounds[1] - mutation_bounds[0])
        control_full_bounds = normal_bounds if has_normal else base_bounds
        reference_end = control_full_bounds[1]
        reference_start = max(control_full_bounds[0], reference_end - mutation_effective_ns)

        selected = {
            "baseline": _phase(frames, *base_bounds),
            "normal": _phase(frames, *normal_bounds),
            "reference": _phase(frames, reference_start, reference_end),
            "mutation": _phase(frames, *mutation_bounds),
            "recovery": _phase(frames, *recovery_bounds),
        }
        for phase_name, phase_frames in selected.items():
            for item in phase_frames:
                grouped[(item["bus"], item["id"], item["extended"])][phase_name].append(item)

        durations = {
            "baseline": max(0, base_bounds[1] - base_bounds[0]) / 1e9,
            "normal": max(0, normal_bounds[1] - normal_bounds[0]) / 1e9,
            "reference": max(0, reference_end - reference_start) / 1e9,
            "mutation": max(0, mutation_bounds[1] - mutation_bounds[0]) / 1e9,
            "recovery": max(0, recovery_bounds[1] - recovery_bounds[0]) / 1e9,
        }
        phase_durations[bus] = durations
        bus_exposure[bus] = durations["baseline"] + durations["normal"]
        time_alignment[bus.upper()] = {
            "source_offset_ms": source_offset_ms,
            "bus_offset_ms": bus_offset_ms,
            "applied_correction_ms": correction_ms,
            "source_best_rtt_ms": source_rtt_ms,
            "bus_best_rtt_ms": bus_rtt_ms,
            "relative_uncertainty_ms": relative_uncertainty_ms,
            "boundary_guard_ms": uncertainty_ms,
        }

    metrics: list[dict[str, Any]] = []
    anomalies: list[dict[str, Any]] = []
    insufficient: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []

    def add_anomaly(
        bus: str, can_id: int, kind: str, score: float, evidence: Mapping[str, Any],
    ) -> None:
        anomalies.append({
            "target_bus": bus.upper(),
            "target_id": f"0x{can_id:X}",
            "type": kind,
            "score": round(max(0.0, min(1.0, score)), 6),
            "cross_bus": _normalise_bus(bus) != source,
            "comparison": "NORMAL_VS_MUTATION" if has_normal else "BASELINE_VS_MUTATION_LEGACY",
            "eligible_for_feedback": True,
            "evidence": dict(evidence),
        })

    def add_insufficient(
        bus: str, can_id: int, metric: str, reason: str, evidence: Mapping[str, Any],
    ) -> None:
        insufficient.append({
            "target_bus": bus.upper(), "target_id": f"0x{can_id:X}",
            "metric": metric, "status": "INSUFFICIENT_EVIDENCE",
            "reason": reason, "evidence": dict(evidence),
        })

    message_cache: dict[int, Any | None] = {}
    for (bus, can_id, extended), windows in sorted(grouped.items()):
        durations = phase_durations.get(bus, {})
        phase_metrics = {
            name: _metrics(windows[name], float(durations.get(name, 0.0)))
            for name in ("baseline", "normal", "reference", "mutation", "recovery")
        }
        control_name = "normal" if has_normal else "baseline"
        stability_control = windows[control_name]
        if can_id not in message_cache:
            try:
                message_cache[can_id] = database.get_message_by_frame_id(can_id) if database else None
            except KeyError:
                message_cache[can_id] = None
        message = message_cache[can_id]
        if message is not None:
            expected_length = int(getattr(message, "length", -1))
            if expected_length >= 0 and any(
                len(item["payload"]) != expected_length
                for item in stability_control + windows["mutation"]
            ):
                message = None

        payload_evidence, payload_diagnostics = _payload_evidence(
            comparison_control=windows["reference"],
            stability_control=stability_control,
            mutation_frames=windows["mutation"],
            message=message,
            ratio_threshold=payload_ratio_threshold,
        )
        metrics.append({
            "bus": bus.upper(), "can_id": f"0x{can_id:X}",
            "is_extended_id": extended,
            **phase_metrics,
            "reference_phase": "normal" if has_normal else "baseline",
            "payload_analysis": payload_diagnostics,
            "phase_diagnostics": {
                "baseline_to_normal": (
                    _phase_diagnostic(
                        phase_metrics["baseline"], phase_metrics["normal"],
                        "BASELINE_VS_NORMAL",
                    ) if has_normal else None
                ),
                "mutation_to_recovery": (
                    _phase_diagnostic(
                        phase_metrics["mutation"], phase_metrics["recovery"],
                        "MUTATION_VS_RECOVERY",
                    ) if has_recovery else None
                ),
            },
        })

        # The injected ID is routing evidence, not by itself a functional response.
        if can_id == mutation.can_id:
            continue

        reference = phase_metrics["reference"]
        mutation_metric = phase_metrics["mutation"]
        full_control = phase_metrics[control_name]
        control_count = full_control["message_count"]
        reference_count = reference["message_count"]
        mutation_count = mutation_metric["message_count"]
        mutation_duration = float(durations.get("mutation", 0.0))
        expected_frames = full_control["frequency_hz"] * mutation_duration

        current_control_count = (
            phase_metrics["baseline"]["message_count"]
            + phase_metrics["normal"]["message_count"]
        )
        if current_control_count == 0 and mutation_count >= new_message_min:
            known = _catalog_known(reference_catalog, bus, can_id, extended)
            prior_exposure = _catalog_exposure(reference_catalog, bus)
            total_exposure = prior_exposure + bus_exposure.get(bus, 0.0)
            evidence = {
                "mutation_message_count": mutation_count,
                "prior_control_exposure_seconds": prior_exposure,
                "current_control_exposure_seconds": bus_exposure.get(bus, 0.0),
                "total_control_exposure_seconds": total_exposure,
            }
            if known:
                suppressed.append({
                    "target_bus": bus.upper(), "target_id": f"0x{can_id:X}",
                    "type": "NEW_MESSAGE", "reason": "SEEN_IN_PRIOR_CONTROL",
                    "evidence": evidence,
                })
            elif total_exposure < min_reference_seconds:
                add_insufficient(
                    bus, can_id, "NEW_MESSAGE", "control_reference_exposure_below_minimum",
                    {**evidence, "minimum_reference_seconds": min_reference_seconds},
                )
            else:
                add_anomaly(
                    bus, can_id, "NEW_MESSAGE",
                    min(1.0, 0.6 + mutation_count / 50.0), evidence,
                )

        rate_difference = reference_count != mutation_count
        frequency_sufficient = (
            control_count >= min_control
            and expected_frames >= min_expected
            and reference_count > 0
        )
        if not frequency_sufficient and rate_difference and control_count:
            add_insufficient(
                bus, can_id, "FREQUENCY_CHANGE",
                "expected_mutation_frames_below_minimum"
                if expected_frames < min_expected else "control_sample_below_minimum",
                {
                    "control_count": control_count, "reference_count": reference_count,
                    "mutation_count": mutation_count, "expected_mutation_frames": expected_frames,
                    "minimum_expected_frames": min_expected,
                },
            )
        if frequency_sufficient:
            rate_ratio = (
                mutation_metric["frequency_hz"] / reference["frequency_hz"]
                if reference["frequency_hz"] else 0.0
            )
            if rate_ratio <= loss_ratio:
                add_anomaly(bus, can_id, "MESSAGE_LOSS", 1.0 - rate_ratio, {
                    "reference_count": reference_count, "mutation_count": mutation_count,
                    "frequency_ratio": rate_ratio, "expected_mutation_frames": expected_frames,
                })
            frequency_change = _relative(
                reference["frequency_hz"], mutation_metric["frequency_hz"]
            )
            if frequency_change is not None and frequency_change >= frequency_relative:
                add_anomaly(
                    bus, can_id, "FREQUENCY_CHANGE",
                    _score(frequency_change, frequency_relative),
                    {
                        "relative_change": frequency_change,
                        "reference_hz": reference["frequency_hz"],
                        "mutation_hz": mutation_metric["frequency_hz"],
                        "expected_mutation_frames": expected_frames,
                    },
                )

        reference_intervals = max(0, reference_count - 1)
        mutation_intervals = max(0, mutation_count - 1)
        if reference_intervals >= min_timing_intervals and mutation_intervals >= min_timing_intervals:
            timing_changes = {
                name: _relative(reference[name], mutation_metric[name])
                for name in ("mean_cycle_time_ms", "median_cycle_time_ms")
            }
            maximum = max(
                (value for value in timing_changes.values() if value is not None), default=0.0
            )
            reference_stddev = float(reference["cycle_time_stddev_ms"] or 0.0)
            mutation_stddev = float(mutation_metric["cycle_time_stddev_ms"] or 0.0)
            stddev_increase = max(0.0, mutation_stddev - reference_stddev)
            relative_triggered = maximum >= timing_relative
            stddev_triggered = stddev_increase >= timing_stddev_absolute
            if relative_triggered or stddev_triggered:
                scores = []
                if relative_triggered:
                    scores.append(_score(maximum, timing_relative))
                if stddev_triggered:
                    scores.append(_score(stddev_increase, timing_stddev_absolute))
                add_anomaly(bus, can_id, "TIMING", max(scores), {
                    "relative_changes": timing_changes,
                    # Keep the schema-v1 names as aliases for existing report
                    # consumers while making the active reference explicit.
                    "baseline_mean_ms": reference["mean_cycle_time_ms"],
                    "baseline_stddev_ms": reference_stddev,
                    "reference_mean_ms": reference["mean_cycle_time_ms"],
                    "mutation_mean_ms": mutation_metric["mean_cycle_time_ms"],
                    "reference_stddev_ms": reference_stddev,
                    "mutation_stddev_ms": mutation_stddev,
                    "stddev_absolute_increase_ms": stddev_increase,
                })
        elif reference_count or mutation_count:
            add_insufficient(bus, can_id, "TIMING", "timing_interval_sample_below_minimum", {
                "reference_intervals": reference_intervals,
                "mutation_intervals": mutation_intervals,
                "minimum_timing_intervals": min_timing_intervals,
            })

        if payload_evidence is not None:
            if control_count < min_control or mutation_count < min_mutation:
                add_insufficient(bus, can_id, "PAYLOAD_CHANGE", "payload_sample_below_minimum", {
                    "control_count": control_count, "mutation_count": mutation_count,
                    "minimum_control_frames": min_control,
                    "minimum_mutation_frames": min_mutation,
                })
            else:
                add_anomaly(
                    bus, can_id, "PAYLOAD_CHANGE",
                    _score(float(payload_evidence["change_ratio"]), payload_ratio_threshold),
                    payload_evidence,
                )

    propagated = []
    for bus, path in rx_paths.items():
        normalised_bus = _normalise_bus(bus)
        if normalised_bus == source:
            continue
        bus_offset_ms, _ = _clock_for_bus(clock_offsets, normalised_bus)
        correction_ns = int(round((source_offset_ms - bus_offset_ms) * 1_000_000.0))
        frames = _load_frames(path, normalised_bus)
        for item in frames:
            item["time_ns"] = item["raw_time_ns"] + correction_ns
        # Propagation is informational; use the exact mutation window rather
        # than its conservative guarded interior so boundary matches are shown.
        matches = sum(
            item["id"] == mutation.can_id and item["payload"] == mutation.mutated_payload
            for item in _phase(frames, mutation_start, mutation_end)
        )
        if matches:
            propagated.append({"bus": normalised_bus.upper(), "matches": matches})

    anomalies.sort(
        key=lambda item: (-item["score"], item["target_bus"], item["target_id"], item["type"])
    )
    insufficient.sort(key=lambda item: (item["target_bus"], item["target_id"], item["metric"]))
    suppressed.sort(key=lambda item: (item["target_bus"], item["target_id"], item["type"]))
    warnings = [] if has_normal else ["LEGACY_BASELINE_REFERENCE"]
    if has_normal and not duration_matched:
        warnings.append("NORMAL_SHORTER_THAN_MUTATION")
    return {
        "schema_version": 2,
        "thresholds": dict(thresholds),
        "phase_times_ns": dict(phase_times_ns),
        "comparison_policy": {
            "primary": "NORMAL_VS_MUTATION" if has_normal else "BASELINE_VS_MUTATION_LEGACY",
            "duration_matched_reference": duration_matched,
            "legacy_fallback": not has_normal,
            "warnings": warnings,
        },
        "time_alignment": time_alignment,
        "metrics": metrics,
        "anomalies": anomalies,
        "insufficient_evidence": insufficient,
        "suppressed_findings": suppressed,
        "reference_update": _reference_update(grouped, bus_exposure),
        "summary": {
            "anomaly_count": len(anomalies),
            "maximum_score": max((item["score"] for item in anomalies), default=0.0),
            "cross_bus": any(bool(item["cross_bus"]) for item in anomalies),
            "cross_bus_anomaly_count": sum(bool(item["cross_bus"]) for item in anomalies),
            "insufficient_evidence_count": len(insufficient),
            "suppressed_finding_count": len(suppressed),
            "propagated_payloads": propagated,
        },
    }
