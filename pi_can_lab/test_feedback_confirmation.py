from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from experiment_store import ExperimentStore
from mutation_feedback import create_trial_feedback
from strategy_selector import TrialStrategySelector
from trial_models import MutationCase


BASE = bytes.fromhex("00000000200000F0")


def make_mutation(mutation_id: int = 1) -> MutationCase:
    changed = bytearray(BASE)
    changed[3] ^= 0x20
    return MutationCase(
        mutation_id=mutation_id,
        source_bus="b_can",
        can_id=0x366,
        operator="BIT_FLIP",
        original_payload=BASE,
        mutated_payload=bytes(changed),
        random_seed=366,
    )


def anomaly(can_id: str = "0x123", kind: str = "TIMING", score: float = 0.8):
    return {
        "target_bus": "I_CAN",
        "target_id": can_id,
        "type": kind,
        "score": score,
    }


def selector() -> TrialStrategySelector:
    return TrialStrategySelector({
        "no_anomaly": {"exploration_probability": 1.0},
        "interesting": {"exploitation_probability": 1.0},
    })


class ConfirmationLifecycleTests(unittest.TestCase):
    def test_candidate_forces_exact_reproduction_and_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ExperimentStore(Path(directory), 1, {})
            root = make_mutation()
            raw = create_trial_feedback(1, root, [anomaly()], 0.6)
            prepared = store.prepare_feedback(root, raw)
            self.assertEqual(prepared["confirmation_status"], "CANDIDATE")
            self.assertFalse(prepared["interesting"])
            state = store.record_completed_trial(root, prepared)

            self.assertEqual(state["pending_confirmation"]["mutation_id"], 1)
            self.assertEqual(state["interesting_mutations"], [])
            first, decision = selector().select_mutation(
                state=state,
                original_payload=BASE,
                source_bus="b_can",
                can_id=0x366,
                random_seed=366,
            )
            second, _ = selector().select_mutation(
                state=state,
                original_payload=BASE,
                source_bus="b_can",
                can_id=0x366,
                random_seed=366,
            )
            self.assertEqual(decision.mode, "VERIFY")
            self.assertEqual(decision.strategy, "EXACT_REPRODUCTION")
            self.assertEqual(first.mutation_id, 2)
            self.assertEqual(first.reproduction_of_mutation_id, 1)
            self.assertEqual(first.original_payload, root.original_payload)
            self.assertEqual(first.mutated_payload, root.mutated_payload)
            self.assertEqual(first.mutated_payload, second.mutated_payload)
            self.assertEqual(first.reproduction_of_mutation_id, second.reproduction_of_mutation_id)
            self.assertEqual(first.parameters, second.parameters)

            reproduction_raw = create_trial_feedback(
                2, first, [anomaly(score=0.75)], 0.6
            )
            reproduction = store.prepare_feedback(first, reproduction_raw)
            self.assertEqual(reproduction["confirmation_status"], "CONFIRMED")
            state = store.record_completed_trial(first, reproduction)

            self.assertIsNone(state["pending_confirmation"])
            self.assertEqual(
                [item["mutation_id"] for item in state["confirmed_mutations"]], [1]
            )
            self.assertEqual(
                [item["mutation_id"] for item in state["interesting_mutations"]], [1]
            )
            next_decision = selector().decide(state, 366)
            self.assertEqual(next_decision.mode, "EXPLOIT")
            self.assertEqual(next_decision.parent_mutation_id, 1)

    def test_nonmatching_reproduction_rejects_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ExperimentStore(Path(directory), 1, {})
            root = make_mutation()
            candidate = store.prepare_feedback(
                root, create_trial_feedback(1, root, [anomaly()], 0.6)
            )
            state = store.record_completed_trial(root, candidate)
            replay, _ = selector().select_mutation(
                state=state, original_payload=BASE, source_bus="b_can",
                can_id=0x366, random_seed=366,
            )
            rejected = store.prepare_feedback(
                replay,
                create_trial_feedback(
                    2, replay, [anomaly("0x456", "PAYLOAD_CHANGE")], 0.6
                ),
            )
            self.assertEqual(rejected["confirmation_status"], "REJECTED")
            state = store.record_completed_trial(replay, rejected)

            self.assertIsNone(state["pending_confirmation"])
            self.assertEqual(state["interesting_mutations"], [])
            self.assertEqual(state["rejected_mutations"][0]["mutation_id"], 1)
            self.assertEqual(selector().decide(state, 366).mode, "EXPLORE")

    def test_default_half_overlap_confirms_matching_subset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ExperimentStore(Path(directory), 1, {})
            root = make_mutation()
            candidate = store.prepare_feedback(
                root,
                create_trial_feedback(
                    1, root,
                    [anomaly("0x123", "TIMING"), anomaly("0x456", "PAYLOAD_CHANGE")],
                    0.6,
                ),
            )
            state = store.record_completed_trial(root, candidate)
            replay, _ = selector().select_mutation(
                state=state, original_payload=BASE, source_bus="b_can",
                can_id=0x366, random_seed=366,
            )
            confirmed = store.prepare_feedback(
                replay,
                create_trial_feedback(
                    2, replay, [anomaly("0x123", "TIMING")], 0.6
                ),
            )
            self.assertEqual(confirmed["confirmation_status"], "CONFIRMED")
            self.assertEqual(confirmed["confirmation"]["overlap_ratio"], 0.5)

    def test_different_payload_signal_does_not_confirm_the_candidate(self) -> None:
        def payload_anomaly(signal: str):
            return {
                "target_bus": "I_CAN",
                "target_id": "0x123",
                "type": "PAYLOAD_CHANGE",
                "score": 0.9,
                "evidence": {
                    "stable_signal_changes": [{"signal": signal}],
                    "stable_undefined_bit_changes": [],
                    "length_change_frames": 0,
                },
            }

        with tempfile.TemporaryDirectory() as directory:
            store = ExperimentStore(Path(directory), 1, {})
            root = make_mutation()
            candidate = store.prepare_feedback(
                root,
                create_trial_feedback(1, root, [payload_anomaly("Signal_A")], 0.6),
            )
            state = store.record_completed_trial(root, candidate)
            replay, _ = selector().select_mutation(
                state=state, original_payload=BASE, source_bus="b_can",
                can_id=0x366, random_seed=366,
            )
            checked = store.prepare_feedback(
                replay,
                create_trial_feedback(2, replay, [payload_anomaly("Signal_B")], 0.6),
            )

        self.assertEqual(checked["confirmation_status"], "REJECTED")
        self.assertEqual(checked["confirmation"]["overlap_ratio"], 0.0)

    def test_required_reproductions_keeps_pending_until_count_reached(self) -> None:
        config = {"minimum_overlap_ratio": 0.5, "required_reproductions": 2}
        with tempfile.TemporaryDirectory() as directory:
            store = ExperimentStore(Path(directory), 1, {})
            root = make_mutation()
            candidate = store.prepare_feedback(
                root, create_trial_feedback(1, root, [anomaly()], 0.6), config
            )
            state = store.record_completed_trial(root, candidate)
            replay1, _ = selector().select_mutation(
                state=state, original_payload=BASE, source_bus="b_can",
                can_id=0x366, random_seed=366,
            )
            checked1 = store.prepare_feedback(
                replay1, create_trial_feedback(2, replay1, [anomaly()], 0.6), config
            )
            self.assertEqual(checked1["confirmation_status"], "REPRODUCED")
            state = store.record_completed_trial(replay1, checked1)
            self.assertEqual(state["pending_confirmation"]["successful_reproductions"], 1)

            replay2, _ = selector().select_mutation(
                state=state, original_payload=BASE, source_bus="b_can",
                can_id=0x366, random_seed=366,
            )
            checked2 = store.prepare_feedback(
                replay2, create_trial_feedback(3, replay2, [anomaly()], 0.6), config
            )
            self.assertEqual(checked2["confirmation_status"], "CONFIRMED")
            state = store.record_completed_trial(replay2, checked2)
            self.assertEqual(state["interesting_mutations"][0]["mutation_id"], 1)

    def test_v1_interesting_entries_are_migrated_as_unconfirmed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ExperimentStore(Path(directory), 1, {})
            old = store.empty_feedback_state()
            old["schema_version"] = 1
            old["interesting_mutations"] = [{
                "mutation_id": 7,
                "score": 1.0,
                "mutation": make_mutation(7).to_dict(),
            }]
            old["last_feedback"] = {"interesting": True}
            store.feedback_path.write_text(json.dumps(old), encoding="utf-8")

            migrated = store.load_feedback_state()

            self.assertEqual(migrated["schema_version"], 2)
            self.assertEqual(migrated["interesting_mutations"], [])
            self.assertEqual(
                migrated["legacy_unconfirmed_mutations"][0]["mutation_id"], 7
            )
            self.assertFalse(migrated["last_feedback"]["interesting"])

    def test_prepared_candidate_reconciles_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ExperimentStore(Path(directory), 1, {})
            root = make_mutation()
            prepared = store.prepare_feedback(
                root, create_trial_feedback(1, root, [anomaly()], 0.6)
            )
            trial = store.create_trial(1)
            store.write_json(trial / "metadata.json", {
                "status": "analyzed", "trial_id": 1,
            })
            store.write_json(trial / "mutation.json", root.to_dict())
            store.write_json(trial / "feedback.json", prepared)

            self.assertEqual(store.reconcile_analyzed_trials(), [1])
            self.assertEqual(store.reconcile_analyzed_trials(), [])
            state = store.load_feedback_state()

            self.assertEqual(state["total_trials"], 1)
            self.assertEqual(state["pending_confirmation"]["mutation_id"], 1)
            self.assertEqual(state["interesting_mutations"], [])

    def test_clean_reference_catalog_accumulates_once_per_completed_trial(self) -> None:
        update = {
            "schema_version": 1,
            "buses": {
                "I_CAN": {
                    "control_exposure_seconds": 15.0,
                    "frames": {
                        "STD:0x123": {
                            "can_id": "0x123",
                            "is_extended_id": False,
                            "frame_count": 4,
                            "dlc_counts": {"8": 4},
                        }
                    },
                }
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            store = ExperimentStore(Path(directory), 1, {})
            root = make_mutation()
            feedback = store.prepare_feedback(
                root, create_trial_feedback(1, root, [], 0.6)
            )
            first = store.record_completed_trial(root, feedback, update)
            second = store.record_completed_trial(root, feedback, update)

        self.assertEqual(first["reference_catalog"], second["reference_catalog"])
        catalog = second["reference_catalog"]
        self.assertEqual(catalog["contributing_trial_ids"], [1])
        self.assertEqual(
            catalog["buses"]["I_CAN"]["control_exposure_seconds"], 15.0
        )
        self.assertEqual(
            catalog["buses"]["I_CAN"]["frames"]["STD:0x123"]["frame_count"], 4
        )

    def test_captured_metadata_with_complete_feedback_is_recovered(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ExperimentStore(Path(directory), 1, {})
            root = make_mutation()
            prepared = store.prepare_feedback(
                root, create_trial_feedback(1, root, [anomaly()], 0.6)
            )
            trial = store.create_trial(1)
            store.write_json(trial / "metadata.json", {
                "status": "captured", "trial_id": 1,
            })
            store.write_json(trial / "mutation.json", root.to_dict())
            store.write_json(trial / "anomalies.json", {
                "schema_version": 2,
                "reference_update": {"schema_version": 1, "buses": {}},
            })
            store.write_json(trial / "feedback.json", prepared)

            self.assertEqual(store.reconcile_analyzed_trials(), [1])
            state = store.load_feedback_state()
            metadata = json.loads((trial / "metadata.json").read_text())

        self.assertEqual(metadata["status"], "completed")
        self.assertEqual(state["pending_confirmation"]["mutation_id"], 1)


if __name__ == "__main__":
    unittest.main()
