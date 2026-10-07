from __future__ import annotations

import unittest
from unittest.mock import patch

from clock_sync import (
    ALIGNMENT_METHOD,
    ClockSyncError,
    align_timestamp_ns,
    build_clock_alignment,
    guarded_phase_bounds,
    validate_clock_sample,
)
from ssh_manager import CommandResult, SSHManager


class ClockSampleTests(unittest.TestCase):
    def test_clock_sample_preserves_existing_fields_and_adds_uncertainty(self) -> None:
        manager = SSHManager({"host": "unused"})

        def fake_run(command, **kwargs):
            del kwargs
            if command[0] == "date":
                return CommandResult("1150000000\n", "", 0)
            return CommandResult("Reference ID : test\n", "", 0)

        manager.run = fake_run  # type: ignore[method-assign]
        with patch("ssh_manager.time.time_ns", side_effect=[1_000_000_000, 1_200_000_000]):
            sample = manager.clock_sample()

        self.assertEqual(sample["offset_ms"], 50.0)
        self.assertEqual(sample["round_trip_ms"], 200.0)
        self.assertEqual(sample["sampled_at_control_ns"], 1_100_000_000)
        self.assertEqual(sample["uncertainty_ms"], 100.0)
        self.assertTrue(sample["chrony_available"])
        self.assertIn("Reference ID", sample["chrony_tracking"])


class ClockAlignmentTests(unittest.TestCase):
    OFFSETS = {
        "b_can": {"offset_ms": 57.586752, "round_trip_ms": 76.831832},
        "p_can": {"offset_ms": 52.152482, "round_trip_ms": 78.539705},
        "i_can": {"offset_ms": 43.039932, "round_trip_ms": 70.954694},
    }

    def test_trial_one_relative_corrections_and_guards(self) -> None:
        alignment = build_clock_alignment(
            self.OFFSETS,
            "B_CAN",
            {"boundary_guard_ms": 10.0, "max_relative_uncertainty_ms": 100.0},
        )
        self.assertEqual(alignment["method"], ALIGNMENT_METHOD)
        self.assertEqual(alignment["reference_bus"], "b_can")
        b_can = alignment["per_bus"]["b_can"]
        p_can = alignment["per_bus"]["p_can"]
        i_can = alignment["per_bus"]["i_can"]
        self.assertEqual(b_can["correction_ns"], 0)
        self.assertEqual(b_can["relative_uncertainty_ms"], 0.0)
        self.assertAlmostEqual(p_can["correction_ms"], 5.434270, places=6)
        self.assertAlmostEqual(i_can["correction_ms"], 14.546820, places=6)
        self.assertAlmostEqual(p_can["relative_uncertainty_ms"], 77.6857685)
        self.assertAlmostEqual(i_can["relative_uncertainty_ms"], 73.893263)
        self.assertAlmostEqual(p_can["effective_guard_ms"], 87.6857685)

    def test_alignment_moves_receiver_timestamp_into_source_clock(self) -> None:
        alignment = build_clock_alignment(
            {
                "b_can": {"offset_ms": 100.0, "round_trip_ms": 2.0},
                "p_can": {"offset_ms": -100.0, "round_trip_ms": 2.0},
            },
            "b_can",
        )
        # Same real instant: P records 2.95 s and B records 3.15 s.
        self.assertEqual(
            align_timestamp_ns(2_950_000_000, alignment["per_bus"]["p_can"]),
            3_150_000_000,
        )
        self.assertEqual(
            align_timestamp_ns(3_150_000_000, alignment["per_bus"]["b_can"]),
            3_150_000_000,
        )

    def test_guarded_bounds_exclude_uncertain_edges(self) -> None:
        alignment = build_clock_alignment(
            {
                "b_can": {"offset_ms": 0.0, "round_trip_ms": 4.0},
                "p_can": {"offset_ms": 0.0, "round_trip_ms": 6.0},
            },
            "b_can",
            {"boundary_guard_ms": 5.0},
        )
        # P uncertainty is 2 ms + 3 ms, plus the configured 5 ms guard.
        self.assertEqual(
            guarded_phase_bounds(
                1_000_000_000,
                2_000_000_000,
                alignment["per_bus"]["p_can"],
            ),
            (1_010_000_000, 1_990_000_000),
        )

    def test_legacy_sample_without_new_metadata_is_supported(self) -> None:
        sample = validate_clock_sample({"offset_ms": 1, "round_trip_ms": 8})
        self.assertEqual(sample["uncertainty_ms"], 4.0)
        self.assertNotIn("sampled_at_control_ns", sample)

    def test_invalid_or_excessively_uncertain_samples_fail_closed(self) -> None:
        with self.assertRaisesRegex(ClockSyncError, "finite"):
            validate_clock_sample({"offset_ms": float("nan"), "round_trip_ms": 1})
        with self.assertRaisesRegex(ClockSyncError, "round trip"):
            build_clock_alignment(
                {"b_can": {"offset_ms": 0, "round_trip_ms": 251}},
                "b_can",
                {"max_round_trip_ms": 250},
            )
        with self.assertRaisesRegex(ClockSyncError, "relative clock uncertainty"):
            build_clock_alignment(
                {
                    "b_can": {"offset_ms": 0, "round_trip_ms": 80},
                    "p_can": {"offset_ms": 0, "round_trip_ms": 80},
                },
                "b_can",
                {"max_relative_uncertainty_ms": 79},
            )
        with self.assertRaisesRegex(ClockSyncError, "absolute clock offset"):
            build_clock_alignment(
                {"b_can": {"offset_ms": 501, "round_trip_ms": 1}},
                "b_can",
                {"max_absolute_offset_ms": 500},
            )

    def test_phase_too_short_for_guard_fails_closed(self) -> None:
        alignment = build_clock_alignment(
            {"b_can": {"offset_ms": 0, "round_trip_ms": 1}},
            "b_can",
            {"boundary_guard_ms": 500},
        )
        with self.assertRaisesRegex(ClockSyncError, "too short"):
            guarded_phase_bounds(
                1_000_000_000,
                2_000_000_000,
                alignment["per_bus"]["b_can"],
            )


if __name__ == "__main__":
    unittest.main()
