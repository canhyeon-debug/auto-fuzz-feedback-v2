"""Filesystem repository for immutable raw trials and cumulative feedback."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

from mutation_feedback import canonical_anomaly_key
from trial_models import MutationCase, utc_now


FEEDBACK_SCHEMA_VERSION = 2


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


class ExperimentStore:
    def __init__(self, root: Path, experiment_id: int, config_snapshot: Mapping[str, Any]):
        self.experiment_id = int(experiment_id)
        self.path = root.expanduser().resolve() / f"experiment_{self.experiment_id:04d}"
        self.path.mkdir(parents=True, exist_ok=True)
        self.feedback_path = self.path / "feedback_state.json"
        experiment_path = self.path / "experiment.json"
        if not experiment_path.exists():
            _atomic_json(experiment_path, {
                "schema_version": 1,
                "experiment_id": self.experiment_id,
                "created_at": utc_now(),
                "status": "running",
                "config": dict(config_snapshot),
            })
        if not self.feedback_path.exists():
            _atomic_json(self.feedback_path, self.empty_feedback_state())

    def empty_feedback_state(self) -> dict[str, Any]:
        return {
            "schema_version": FEEDBACK_SCHEMA_VERSION,
            "experiment_id": self.experiment_id,
            "total_trials": 0,
            "next_mutation_id": 1,
            "completed_trial_ids": [],
            "interesting_mutations": [],
            "candidate_mutations": [],
            "confirmed_mutations": [],
            "rejected_mutations": [],
            "pending_confirmation": None,
            "legacy_unconfirmed_mutations": [],
            "mutation_history": [],
            "mutation_statistics": {},
            "reference_catalog": {
                "schema_version": 1,
                "contributing_trial_ids": [],
                "buses": {},
            },
            "last_feedback": None,
            "updated_at": utc_now(),
        }

    def load_feedback_state(self) -> dict[str, Any]:
        with self.feedback_path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
        if int(state.get("experiment_id", -1)) != self.experiment_id:
            raise ValueError("feedback_state experiment_id mismatch")
        state, changed = self._migrate_feedback_state(state)
        if changed:
            state["updated_at"] = utc_now()
            _atomic_json(self.feedback_path, state)
        return state

    def _migrate_feedback_state(
        self, state: Mapping[str, Any]
    ) -> tuple[dict[str, Any], bool]:
        """Upgrade state without trusting pre-confirmation interesting results."""

        migrated = dict(state)
        version = int(migrated.get("schema_version", 1))
        if version > FEEDBACK_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported feedback schema {version}; maximum is "
                f"{FEEDBACK_SCHEMA_VERSION}"
            )
        changed = version != FEEDBACK_SCHEMA_VERSION
        if version < 2:
            legacy = list(migrated.get("legacy_unconfirmed_mutations", []))
            legacy.extend(migrated.get("interesting_mutations", []))
            migrated["legacy_unconfirmed_mutations"] = legacy
            migrated["interesting_mutations"] = []
            if migrated.get("last_feedback") is not None:
                migrated["legacy_last_feedback"] = migrated["last_feedback"]
                migrated["last_feedback"] = {
                    "interesting": False,
                    "eligible_for_exploitation": False,
                    "confirmation_status": "LEGACY_UNCONFIRMED",
                }
        defaults = {
            "candidate_mutations": [],
            "confirmed_mutations": [],
            "rejected_mutations": [],
            "pending_confirmation": None,
            "legacy_unconfirmed_mutations": [],
            "reference_catalog": {
                "schema_version": 1,
                "contributing_trial_ids": [],
                "buses": {},
            },
        }
        for key, value in defaults.items():
            if key not in migrated:
                migrated[key] = value
                changed = True
        catalog = migrated.get("reference_catalog")
        if isinstance(catalog, Mapping) and "contributing_trial_ids" not in catalog:
            migrated["reference_catalog"] = {
                **dict(catalog),
                "contributing_trial_ids": [],
            }
            changed = True
        if migrated.get("schema_version") != FEEDBACK_SCHEMA_VERSION:
            migrated["schema_version"] = FEEDBACK_SCHEMA_VERSION
            changed = True
        return migrated, changed

    def save_feedback_state(self, state: Mapping[str, Any]) -> None:
        updated = dict(state)
        updated["updated_at"] = utc_now()
        _atomic_json(self.feedback_path, updated)

    @staticmethod
    def _merge_reference_catalog(
        current: Mapping[str, Any] | None,
        update: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Accumulate clean Baseline/Normal exposure without mutation data.

        The analyzer emits a compact per-trial update.  Keeping it in the
        feedback state lets a later Trial distinguish a genuinely new CAN ID
        from a low-rate ID which appeared in an earlier clean control window.
        """

        merged: dict[str, Any] = {
            "schema_version": 1,
            "contributing_trial_ids": [],
            "buses": {},
        }
        for source in (current or {}, update or {}):
            if not isinstance(source, Mapping):
                continue
            for value in source.get("contributing_trial_ids", []):
                trial_id = int(value)
                if trial_id not in merged["contributing_trial_ids"]:
                    merged["contributing_trial_ids"].append(trial_id)
            buses = source.get("buses", {})
            if not isinstance(buses, Mapping):
                continue
            for raw_bus, raw_bus_data in buses.items():
                if not isinstance(raw_bus_data, Mapping):
                    continue
                bus = str(raw_bus).strip().upper()
                target = merged["buses"].setdefault(bus, {
                    "control_exposure_seconds": 0.0,
                    "frames": {},
                })
                target["control_exposure_seconds"] = round(
                    float(target.get("control_exposure_seconds", 0.0))
                    + max(0.0, float(raw_bus_data.get("control_exposure_seconds", 0.0))),
                    9,
                )
                raw_frames = raw_bus_data.get("frames", {})
                if not isinstance(raw_frames, Mapping):
                    continue
                for raw_key, raw_frame in raw_frames.items():
                    if not isinstance(raw_frame, Mapping):
                        continue
                    key = str(raw_key)
                    existing = dict(target["frames"].get(key, {}))
                    frame = dict(raw_frame)
                    frame["frame_count"] = int(existing.get("frame_count", 0)) + int(
                        raw_frame.get("frame_count", 0)
                    )
                    dlc_counts: dict[str, int] = {
                        str(length): int(count)
                        for length, count in existing.get("dlc_counts", {}).items()
                    }
                    for length, count in raw_frame.get("dlc_counts", {}).items():
                        dlc_counts[str(length)] = dlc_counts.get(str(length), 0) + int(count)
                    if dlc_counts:
                        frame["dlc_counts"] = dict(sorted(dlc_counts.items()))
                    target["frames"][key] = frame
        merged["contributing_trial_ids"].sort()
        return merged

    def next_trial_id(self) -> int:
        indexes = []
        for path in self.path.glob("trial_*"):
            if path.is_dir() and path.name.removeprefix("trial_").isdigit():
                indexes.append(int(path.name.removeprefix("trial_")))
        return max(indexes, default=0) + 1

    def next_mutation_id(self) -> int:
        identifiers = [int(self.load_feedback_state().get("next_mutation_id", 1)) - 1]
        for path in self.path.glob("trial_*/mutation.json"):
            try:
                with path.open("r", encoding="utf-8") as handle:
                    identifiers.append(int(json.load(handle)["mutation_id"]))
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                continue
        return max(identifiers, default=0) + 1

    def create_trial(self, trial_id: int) -> Path:
        path = self.path / f"trial_{int(trial_id):04d}"
        path.mkdir(parents=False, exist_ok=False)
        return path

    def write_json(self, path: Path, value: Mapping[str, Any]) -> None:
        if path.exists():
            _atomic_json(path, value)
        else:
            _atomic_json(path, value)

    @staticmethod
    def _feedback_observations(feedback: Mapping[str, Any]) -> list[dict[str, Any]]:
        observations = feedback.get("observed_anomalies", [])
        if "observed_anomalies" in feedback and isinstance(observations, list):
            normalized = []
            for item in observations:
                if not isinstance(item, Mapping) or not item.get("key"):
                    continue
                normalized.append({
                    **dict(item),
                    "key": str(item["key"]),
                    "score": float(item.get("score", 0.0)),
                })
            return sorted(normalized, key=lambda item: item["key"])

        # Compatibility with feedback produced before observed_anomalies was
        # introduced.  The anomaly mapping contains the full original record.
        by_key: dict[str, dict[str, Any]] = {}
        for mapping in feedback.get("mutation_anomaly_mappings", []):
            if not isinstance(mapping, Mapping):
                continue
            anomaly = mapping.get("anomaly", {})
            if not isinstance(anomaly, Mapping):
                continue
            key = canonical_anomaly_key(anomaly)
            score = float(anomaly.get("score", 0.0))
            previous = by_key.get(key)
            if previous is None or score > float(previous["score"]):
                by_key[key] = {
                    "key": key,
                    "score": score,
                    "target_bus": str(anomaly.get("target_bus", "UNKNOWN")).upper(),
                    "target_id": str(anomaly.get("target_id", "UNKNOWN")),
                    "type": str(anomaly.get("type", "UNKNOWN")).upper(),
                }
        return [by_key[key] for key in sorted(by_key)]

    @staticmethod
    def _confirmation_options(config: Mapping[str, Any] | None) -> dict[str, Any]:
        value: Mapping[str, Any] = config or {}
        nested = value.get("confirmation")
        if isinstance(nested, Mapping):
            value = nested
        enabled = bool(value.get("enabled", True))
        overlap = float(value.get("minimum_overlap_ratio", 0.5))
        if not 0.0 < overlap <= 1.0:
            raise ValueError("confirmation.minimum_overlap_ratio must be in (0, 1]")
        repetitions = int(value.get("required_reproductions", 1))
        if repetitions < 1:
            raise ValueError("confirmation.required_reproductions must be at least 1")
        return {
            "enabled": enabled,
            "minimum_overlap_ratio": overlap,
            "required_reproductions": repetitions,
        }

    def prepare_feedback(
        self,
        mutation: MutationCase,
        feedback: Mapping[str, Any],
        confirmation_config: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Classify raw analysis before it is persisted and committed.

        This method is intentionally side-effect free.  Writing the returned
        document before ``record_completed_trial`` makes interrupted commits
        reconcilable using exactly the same already-classified transition.
        """

        prepared = dict(feedback)
        status = str(prepared.get("confirmation_status", "UNCLASSIFIED")).upper()
        if status != "UNCLASSIFIED":
            return prepared

        state = self.load_feedback_state()
        options = self._confirmation_options(confirmation_config)
        observations = self._feedback_observations(prepared)
        observed_by_key = {str(item["key"]): item for item in observations}
        observed_keys = sorted(observed_by_key)
        prepared["observed_anomalies"] = observations
        prepared["observed_interesting"] = bool(observed_keys)
        prepared["interesting"] = False
        prepared["eligible_for_exploitation"] = False
        prepared["confirmation_of_mutation_id"] = None

        pending = state.get("pending_confirmation")
        if not options["enabled"]:
            prepared["confirmation_status"] = (
                "CONFIRMED" if observed_keys else "NOT_INTERESTING"
            )
            prepared["interesting"] = bool(observed_keys)
            prepared["eligible_for_exploitation"] = bool(observed_keys)
            prepared["confirmation_of_mutation_id"] = (
                mutation.mutation_id if observed_keys else None
            )
            prepared["confirmation"] = {
                **options,
                "candidate_anomaly_keys": observed_keys,
                "matched_anomaly_keys": observed_keys,
                "overlap_ratio": 1.0 if observed_keys else 0.0,
                "successful_reproductions": 0,
            }
            return prepared

        if pending is None:
            if mutation.reproduction_of_mutation_id is not None:
                prepared["confirmation_status"] = "UNSCHEDULED_REPRODUCTION"
                prepared["confirmation_of_mutation_id"] = (
                    mutation.reproduction_of_mutation_id
                )
                prepared["confirmation"] = {
                    **options,
                    "candidate_anomaly_keys": [],
                    "matched_anomaly_keys": [],
                    "overlap_ratio": 0.0,
                    "successful_reproductions": 0,
                }
            elif observed_keys:
                prepared["confirmation_status"] = "CANDIDATE"
                prepared["confirmation_of_mutation_id"] = mutation.mutation_id
                prepared["confirmation"] = {
                    **options,
                    "candidate_anomaly_keys": observed_keys,
                    "matched_anomaly_keys": observed_keys,
                    "overlap_ratio": 1.0,
                    "successful_reproductions": 0,
                }
            else:
                prepared["confirmation_status"] = "NOT_INTERESTING"
                prepared["confirmation"] = {
                    **options,
                    "candidate_anomaly_keys": [],
                    "matched_anomaly_keys": [],
                    "overlap_ratio": 0.0,
                    "successful_reproductions": 0,
                }
            return prepared

        root_id = int(pending["mutation_id"])
        if mutation.reproduction_of_mutation_id != root_id:
            raise ValueError(
                f"Pending confirmation requires exact reproduction of mutation {root_id}"
            )
        candidate_keys = [str(key) for key in pending.get("matched_anomaly_keys", [])]
        if not candidate_keys:
            candidate_keys = [
                str(item["key"]) for item in pending.get("candidate_observations", [])
            ]
        matched_keys = sorted(set(candidate_keys) & set(observed_keys))
        overlap = len(matched_keys) / len(candidate_keys) if candidate_keys else 0.0
        successful = int(pending.get("successful_reproductions", 0))
        minimum_overlap = float(pending.get(
            "minimum_overlap_ratio", options["minimum_overlap_ratio"]
        ))
        passed = overlap >= minimum_overlap
        if passed:
            successful += 1
        required = int(pending.get(
            "required_reproductions", options["required_reproductions"]
        ))
        if not passed:
            result_status = "REJECTED"
        elif successful >= required:
            result_status = "CONFIRMED"
        else:
            result_status = "REPRODUCED"

        candidate_scores = {
            str(item["key"]): float(item.get("score", 0.0))
            for item in pending.get("candidate_observations", [])
        }
        confirmed_observations = []
        for key in matched_keys:
            observed = dict(observed_by_key[key])
            observed["score"] = round(min(
                float(observed.get("score", 0.0)),
                float(candidate_scores.get(key, observed.get("score", 0.0))),
            ), 6)
            confirmed_observations.append(observed)

        prepared["confirmation_status"] = result_status
        prepared["confirmation_of_mutation_id"] = root_id
        prepared["interesting"] = result_status == "CONFIRMED"
        prepared["eligible_for_exploitation"] = result_status == "CONFIRMED"
        prepared["confirmation"] = {
            **options,
            "minimum_overlap_ratio": minimum_overlap,
            "candidate_anomaly_keys": candidate_keys,
            "matched_anomaly_keys": matched_keys,
            "matched_observations": confirmed_observations,
            "overlap_ratio": round(overlap, 6),
            "successful_reproductions": successful,
            "required_reproductions": required,
        }
        return prepared

    def record_completed_trial(
        self,
        mutation: MutationCase,
        feedback: Mapping[str, Any],
        reference_update: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if str(feedback.get("confirmation_status", "UNCLASSIFIED")).upper() == "UNCLASSIFIED":
            # Backward-compatible direct API: callers that have not adopted the
            # prepare/write/commit sequence keep their historical behavior.
            # Production runners persist ``prepare_feedback`` output first, so
            # the confirmation gate is never bypassed in the new pipeline.
            feedback = self.prepare_feedback(
                mutation, feedback, {"enabled": False}
            )
        else:
            feedback = dict(feedback)
        state = self.load_feedback_state()
        trial_id = int(feedback["trial_id"])
        completed_trial_ids = {
            int(value) for value in state.get("completed_trial_ids", [])
        }
        mutation_already_recorded = any(
            int(item.get("mutation_id", -1)) == mutation.mutation_id
            for item in state.get("mutation_history", [])
        )
        if trial_id in completed_trial_ids or mutation_already_recorded:
            return state
        history = list(state.get("mutation_history", []))
        history.append(mutation.to_dict())
        state["mutation_history"] = history
        state["total_trials"] = int(state.get("total_trials", 0)) + 1
        state["next_mutation_id"] = max(
            int(state.get("next_mutation_id", 1)), mutation.mutation_id + 1
        )
        operator_stats = dict(state.get("mutation_statistics", {}))
        entry = dict(operator_stats.get(mutation.operator, {}))
        entry["executed"] = int(entry.get("executed", 0)) + 1
        entry.setdefault("interesting", 0)
        operator_stats[mutation.operator] = entry

        confirmation_status = str(
            feedback.get("confirmation_status", "NOT_INTERESTING")
        ).upper()
        details = feedback.get("confirmation", {})
        if not isinstance(details, Mapping):
            details = {}
        observations = self._feedback_observations(feedback)
        pending = state.get("pending_confirmation")

        def update_candidate(root_id: int, status: str) -> None:
            values = []
            for item in state.get("candidate_mutations", []):
                value = dict(item)
                if int(value.get("mutation_id", -1)) == root_id:
                    value["status"] = status
                    value["resolved_trial_id"] = trial_id
                values.append(value)
            state["candidate_mutations"] = values

        if confirmation_status == "CANDIDATE":
            entry["candidates"] = int(entry.get("candidates", 0)) + 1
            candidate = {
                "mutation_id": mutation.mutation_id,
                "trial_id": trial_id,
                "score": float(feedback.get("anomaly_score", 0.0)),
                "mutation": mutation.to_dict(),
                "anomaly_types": list(feedback.get("anomaly_types", [])),
                "anomaly_keys": [str(item["key"]) for item in observations],
                "status": "CANDIDATE",
            }
            candidates = list(state.get("candidate_mutations", []))
            candidates.append(candidate)
            state["candidate_mutations"] = candidates
            state["pending_confirmation"] = {
                "mutation_id": mutation.mutation_id,
                "trial_id": trial_id,
                "candidate_observations": observations,
                "matched_anomaly_keys": [str(item["key"]) for item in observations],
                "successful_reproductions": 0,
                "required_reproductions": int(
                    details.get("required_reproductions", 1)
                ),
                "minimum_overlap_ratio": float(
                    details.get("minimum_overlap_ratio", 0.5)
                ),
                "reproduction_trial_ids": [],
            }

        elif confirmation_status == "REPRODUCED":
            if pending is None:
                raise ValueError("REPRODUCED feedback has no pending candidate")
            pending = dict(pending)
            pending["matched_anomaly_keys"] = list(
                details.get("matched_anomaly_keys", [])
            )
            pending["candidate_observations"] = list(
                details.get("matched_observations", observations)
            )
            pending["successful_reproductions"] = int(
                details.get("successful_reproductions", 0)
            )
            reproduction_ids = list(pending.get("reproduction_trial_ids", []))
            reproduction_ids.append(trial_id)
            pending["reproduction_trial_ids"] = reproduction_ids
            state["pending_confirmation"] = pending

        elif confirmation_status in {"CONFIRMED", "REJECTED"}:
            root_id = int(feedback.get(
                "confirmation_of_mutation_id", mutation.mutation_id
            ))
            update_candidate(root_id, confirmation_status)
            root_data = next((
                item for item in state["mutation_history"]
                if int(item.get("mutation_id", -1)) == root_id
            ), None)
            if root_data is None:
                raise ValueError(f"Confirmation root mutation {root_id} is missing")
            reproduction_trial_ids = (
                list(pending.get("reproduction_trial_ids", []))
                if isinstance(pending, Mapping) else []
            )
            if mutation.mutation_id != root_id:
                reproduction_trial_ids.append(trial_id)

            if confirmation_status == "CONFIRMED":
                matched = list(details.get("matched_observations", observations))
                score = max(
                    (float(item.get("score", 0.0)) for item in matched),
                    default=float(feedback.get("anomaly_score", 0.0)),
                )
                anomaly_types = sorted({
                    str(item.get("type", "UNKNOWN")) for item in matched
                }) or list(feedback.get("anomaly_types", []))
                confirmed = {
                    "mutation_id": root_id,
                    "score": score,
                    "mutation": dict(root_data),
                    "anomaly_types": anomaly_types,
                    "trial_id": (
                        int(pending.get("trial_id"))
                        if isinstance(pending, Mapping) else trial_id
                    ),
                    "confirmation_trial_ids": reproduction_trial_ids,
                    "confirmed_anomaly_keys": [
                        str(item["key"]) for item in matched
                    ],
                }
                if not any(
                    int(item.get("mutation_id", -1)) == root_id
                    for item in state.get("confirmed_mutations", [])
                ):
                    state["confirmed_mutations"] = [
                        *state.get("confirmed_mutations", []), confirmed,
                    ]
                    interesting = [
                        *state.get("interesting_mutations", []), confirmed,
                    ]
                    interesting.sort(key=lambda item: (
                        -float(item["score"]), int(item["mutation_id"])
                    ))
                    state["interesting_mutations"] = interesting
                    root_operator = str(root_data.get("operator", mutation.operator))
                    root_stats = dict(operator_stats.get(root_operator, {}))
                    root_stats["interesting"] = int(
                        root_stats.get("interesting", 0)
                    ) + 1
                    root_stats["confirmed"] = int(
                        root_stats.get("confirmed", 0)
                    ) + 1
                    operator_stats[root_operator] = root_stats
            else:
                rejected = {
                    "mutation_id": root_id,
                    "trial_id": (
                        int(pending.get("trial_id"))
                        if isinstance(pending, Mapping) else trial_id
                    ),
                    "verification_trial_ids": reproduction_trial_ids,
                    "reason": "anomaly overlap below confirmation threshold",
                    "overlap_ratio": float(details.get("overlap_ratio", 0.0)),
                }
                if not any(
                    int(item.get("mutation_id", -1)) == root_id
                    for item in state.get("rejected_mutations", [])
                ):
                    state["rejected_mutations"] = [
                        *state.get("rejected_mutations", []), rejected,
                    ]
                    root_operator = str(root_data.get("operator", mutation.operator))
                    root_stats = dict(operator_stats.get(root_operator, {}))
                    root_stats["rejected"] = int(root_stats.get("rejected", 0)) + 1
                    operator_stats[root_operator] = root_stats
            state["pending_confirmation"] = None

        state["mutation_statistics"] = operator_stats
        state["reference_catalog"] = self._merge_reference_catalog(
            state.get("reference_catalog"), reference_update,
        )
        if reference_update is not None:
            contributors = state["reference_catalog"]["contributing_trial_ids"]
            if trial_id not in contributors:
                contributors.append(trial_id)
                contributors.sort()
        state["last_feedback"] = dict(feedback)
        completed_trial_ids.add(trial_id)
        state["completed_trial_ids"] = sorted(completed_trial_ids)
        self.save_feedback_state(state)
        return self.load_feedback_state()

    def reconcile_analyzed_trials(
        self, feedback_config: Mapping[str, Any] | None = None,
    ) -> list[int]:
        """Finish analyzed trials idempotently after an interrupted commit."""
        reconciled = []
        for trial_dir in sorted(self.path.glob("trial_*")):
            metadata_path = trial_dir / "metadata.json"
            mutation_path = trial_dir / "mutation.json"
            feedback_path = trial_dir / "feedback.json"
            anomalies_path = trial_dir / "anomalies.json"
            if not all(path.is_file() for path in (metadata_path, mutation_path, feedback_path)):
                continue
            with metadata_path.open("r", encoding="utf-8") as handle:
                metadata = json.load(handle)
            status = str(metadata.get("status", ""))
            recoverable = {"analyzed", "captured", "prepared_offline", "failed"}
            if status not in recoverable:
                continue
            # Non-analyzed states are recoverable only when the complete
            # derived analysis artifact exists.  This covers a hard stop after
            # feedback.json was atomically written but before metadata could be
            # advanced, without treating an ordinary failed capture as done.
            if status != "analyzed" and not anomalies_path.is_file():
                continue
            with mutation_path.open("r", encoding="utf-8") as handle:
                mutation = MutationCase.from_dict(json.load(handle))
            with feedback_path.open("r", encoding="utf-8") as handle:
                feedback = json.load(handle)
            if str(feedback.get("confirmation_status", "UNCLASSIFIED")).upper() == "UNCLASSIFIED":
                feedback = self.prepare_feedback(
                    mutation, feedback, feedback_config,
                )
                _atomic_json(feedback_path, feedback)
            reference_update = None
            if anomalies_path.is_file():
                with anomalies_path.open("r", encoding="utf-8") as handle:
                    anomalies = json.load(handle)
                if isinstance(anomalies.get("reference_update"), Mapping):
                    reference_update = anomalies["reference_update"]
            self.record_completed_trial(mutation, feedback, reference_update)
            metadata["status"] = "completed"
            metadata.pop("completion_error", None)
            _atomic_json(metadata_path, metadata)
            reconciled.append(int(metadata["trial_id"]))
        return reconciled

    def complete(self) -> None:
        path = self.path / "experiment.json"
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        pending = self.load_feedback_state().get("pending_confirmation")
        value["status"] = "awaiting_confirmation" if pending else "completed"
        value["completed_at"] = None if pending else utc_now()
        value["pending_confirmation"] = pending
        _atomic_json(path, value)
