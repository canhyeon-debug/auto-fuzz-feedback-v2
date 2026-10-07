from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from trial_analysis import analyze_trial
from trial_models import MutationCase


BASE = bytes.fromhex("00000000200000F0")
DBC = Path(__file__).resolve().parent.parent / "A5.dbc"


def mutation() -> MutationCase:
    return MutationCase(
        mutation_id=1,
        source_bus="b_can",
        can_id=0x366,
        operator="BIT_FLIP",
        original_payload=BASE,
        mutated_payload=bytes.fromhex("00001000200000F0"),
        random_seed=366,
    )


PHASES = {
    "baseline_start": 1_000_000_000,
    "baseline_end": 11_000_000_000,
    "normal_start": 11_000_000_000,
    "normal_end": 16_000_000_000,
    "mutation_start": 20_000_000_000,
    "mutation_end": 21_000_000_000,
    "recovery_start": 21_000_000_000,
    "recovery_end": 31_000_000_000,
}


def record(stamp: int, bus: str, can_id: int, payload: bytes) -> str:
    return json.dumps({
        "record_type": "can_rx",
        "wall_time_ns": stamp,
        "bus": bus,
        "arbitration_id": can_id,
        "is_extended_id": can_id > 0x7FF,
        "data_hex": payload.hex().upper(),
        "is_error_frame": False,
        "is_remote_frame": False,
    }) + "\n"


class AnalysisV2Tests(unittest.TestCase):
    def analyse(self, lines: list[str], **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "i_can.jsonl"
            path.write_text("".join(lines), encoding="utf-8")
            return analyze_trial(
                rx_paths={"i_can": path},
                phase_times_ns=kwargs.pop("phase_times_ns", PHASES),
                mutation=mutation(),
                thresholds=kwargs.pop("thresholds", {
                    "minimum_control_frames": 3,
                    "minimum_mutation_frames": 3,
                    "minimum_expected_frames": 3,
                    "minimum_timing_intervals": 3,
                    "new_message_minimum_frames": 3,
                    "new_message_minimum_reference_seconds": 60,
                    "payload_change_ratio": 0.2,
                }),
                **kwargs,
            )

    @staticmethod
    def airbag_payload(counter: int) -> bytes:
        # Airbag_01: byte 0 CRC, byte 1 low nibble BZ, byte 7 bits 1..7
        # SC_Masterzeit.  Semantic status fields remain unchanged.
        payload = bytearray(8)
        payload[0] = (counter * 17) & 0xFF
        payload[1] = counter & 0x0F
        payload[7] = (counter << 1) & 0xFE
        return bytes(payload)

    def test_normal_control_suppresses_dynamic_raw_payload_novelty(self) -> None:
        lines = []
        for index in range(5):
            lines.append(record(
                15_100_000_000 + index * 150_000_000,
                "i_can", 0x40, self.airbag_payload(index),
            ))
            lines.append(record(
                20_100_000_000 + index * 150_000_000,
                "i_can", 0x40, self.airbag_payload(index + 8),
            ))
        result = self.analyse(lines, dbc_path=DBC)

        payload_anomalies = [
            item for item in result["anomalies"]
            if item["target_id"] == "0x40" and item["type"] == "PAYLOAD_CHANGE"
        ]
        self.assertEqual(payload_anomalies, [])
        metric = next(item for item in result["metrics"] if item["can_id"] == "0x40")
        ignored = {item["signal"] for item in metric["payload_analysis"]["ignored_dynamic_fields"]}
        self.assertIn("Airbag_01_CRC", ignored)
        self.assertIn("Airbag_01_BZ", ignored)
        self.assertIn("SC_Masterzeit", ignored)
        self.assertEqual(metric["reference_phase"], "normal")
        self.assertEqual(
            metric["phase_diagnostics"]["baseline_to_normal"]["comparison"],
            "BASELINE_VS_NORMAL",
        )
        self.assertEqual(
            metric["phase_diagnostics"]["mutation_to_recovery"]["comparison"],
            "MUTATION_VS_RECOVERY",
        )
        self.assertTrue(
            metric["phase_diagnostics"]["mutation_to_recovery"]["diagnostic_only"]
        )
        self.assertIn("I_CAN", result["reference_update"]["buses"])

    def test_known_rare_id_is_not_new_message(self) -> None:
        lines = [
            record(20_100_000_000 + index * 10_000_000, "i_can", 0x123, b"\xAA")
            for index in range(3)
        ]
        catalog = {
            "buses": {
                "I_CAN": {
                    "control_exposure_seconds": 100,
                    "frames": {
                        "STD:0x123": {
                            "can_id": "0x123", "is_extended_id": False,
                            "frame_count": 3,
                        }
                    },
                }
            }
        }
        result = self.analyse(lines, reference_catalog=catalog)

        self.assertFalse(any(item["type"] == "NEW_MESSAGE" for item in result["anomalies"]))
        self.assertEqual(result["suppressed_findings"][0]["reason"], "SEEN_IN_PRIOR_CONTROL")

    def test_low_rate_difference_is_insufficient_not_frequency_anomaly(self) -> None:
        lines = [record(15_500_000_000, "i_can", 0x222, b"\x00")]
        result = self.analyse(lines)

        self.assertFalse(any(
            item["target_id"] == "0x222" and item["type"] in {"FREQUENCY_CHANGE", "MESSAGE_LOSS"}
            for item in result["anomalies"]
        ))
        finding = next(
            item for item in result["insufficient_evidence"]
            if item["target_id"] == "0x222" and item["metric"] == "FREQUENCY_CHANGE"
        )
        self.assertEqual(finding["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(finding["reason"], "expected_mutation_frames_below_minimum")

    def test_cross_bus_is_attribute_and_not_duplicate_type(self) -> None:
        lines = []
        for index in range(5):
            lines.append(record(15_100_000_000 + index * 150_000_000, "i_can", 0x321, b"\x00"))
            lines.append(record(20_100_000_000 + index * 150_000_000, "i_can", 0x321, b"\x02"))
        result = self.analyse(lines)

        self.assertNotIn("CROSS_BUS", {item["type"] for item in result["anomalies"]})
        payload = next(item for item in result["anomalies"] if item["type"] == "PAYLOAD_CHANGE")
        self.assertTrue(payload["cross_bus"])
        self.assertEqual(result["summary"]["cross_bus_anomaly_count"], len(result["anomalies"]))

    def test_clock_correction_and_uncertainty_guard_assign_frames(self) -> None:
        phases = {
            "baseline_start": 1_000_000_000,
            "baseline_end": 2_000_000_000,
            "normal_start": 2_000_000_000,
            "normal_end": 3_000_000_000,
            "mutation_start": 3_000_000_000,
            "mutation_end": 4_000_000_000,
            "recovery_start": 4_000_000_000,
            "recovery_end": 5_000_000_000,
        }
        # source - bus offset = -20 ms.  Guard = explicit 1 ms + 2/2 + 4/2 = 4 ms.
        # Raw 3.023 s aligns to 3.003 s and is excluded; 3.025 s aligns to 3.005 s.
        lines = [
            record(2_025_000_000, "i_can", 0x444, b"\x00"),
            record(3_023_000_000, "i_can", 0x444, b"\x00"),
            record(3_025_000_000, "i_can", 0x444, b"\x00"),
        ]
        result = self.analyse(
            lines,
            phase_times_ns=phases,
            clock_offsets={
                "b_can": {"offset_ms": 10, "round_trip_ms": 2},
                "i_can": {"offset_ms": 30, "round_trip_ms": 4},
            },
            source_bus="b_can",
            boundary_guard_ms=1,
            thresholds={
                "minimum_control_frames": 5,
                "minimum_expected_frames": 3,
                "new_message_minimum_reference_seconds": 60,
            },
        )

        alignment = result["time_alignment"]["I_CAN"]
        self.assertEqual(alignment["applied_correction_ms"], -20)
        self.assertEqual(alignment["boundary_guard_ms"], 4)
        metric = next(item for item in result["metrics"] if item["can_id"] == "0x444")
        self.assertEqual(metric["normal"]["message_count"], 1)
        self.assertEqual(metric["mutation"]["message_count"], 1)


if __name__ == "__main__":
    unittest.main()
