#!/usr/bin/env python3
"""Offline, previous-trial feedback runner for three isolated laptop/Pi pairs.

The B-CAN laptop is the control PC.  It prepares one immutable mutation package,
injects it through the B-CAN Pi, and later analyzes result bundles produced by
the P-CAN and I-CAN laptops.  Feedback is committed only after all three result
bundles (B TX, P RX, I RX) have been collected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping, Optional

from can_common import ConfigurationError, load_yaml_config, parse_can_data, parse_int
from clock_sync import (
    align_timestamp_ns,
    build_clock_alignment,
    guarded_phase_bounds,
)
from experiment_runner import (
    dbc_signal_metadata,
    load_capture_bounds,
    load_phase_times,
    next_experiment_id,
    ns_to_iso,
    parse_candump_payloads,
)
from experiment_store import ExperimentStore
from mutation_feedback import create_trial_feedback
from ssh_manager import SSHManager, remote_join
from strategy_selector import StrategyDecision, TrialStrategySelector
from trial_analysis import analyze_trial, validate_capture_log
from trial_models import MutationCase, utc_now


RX_BUSES = ("p_can", "i_can")
ALL_BUSES = ("b_can", *RX_BUSES)
PACKAGE_MEMBERS = {"trial_plan.json", "mutation.json"}


def normalize_bus(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_")
    aliases = {"b": "b_can", "p": "p_can", "i": "i_can"}
    normalized = aliases.get(normalized, normalized)
    if normalized not in ALL_BUSES:
        raise ConfigurationError("bus must be B_CAN, P_CAN, or I_CAN")
    return normalized


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _package_digest(plan: Mapping[str, Any], mutation: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in plan.items() if key != "package_digest"}
    return _digest_bytes(_canonical_bytes({"plan": unsigned, "mutation": mutation}))


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(
        value, ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n").encode("utf-8")


def _write_zip(path: Path, members: Mapping[str, bytes]) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Result bundles and trial packages are immutable evidence.  ``x`` refuses
    # to overwrite an existing package instead of silently replacing it.
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in members.items():
            archive.writestr(name, value)


def load_trial_package(path: Path) -> tuple[dict[str, Any], MutationCase]:
    with zipfile.ZipFile(path.expanduser().resolve(), "r") as archive:
        names = set(archive.namelist())
        if names != PACKAGE_MEMBERS:
            raise ValueError(
                f"Invalid trial package members: expected={sorted(PACKAGE_MEMBERS)}, "
                f"actual={sorted(names)}"
            )
        plan = json.loads(archive.read("trial_plan.json"))
        mutation_data = json.loads(archive.read("mutation.json"))
    expected = str(plan.get("package_digest", ""))
    actual = _package_digest(plan, mutation_data)
    if not expected or expected != actual:
        raise ValueError("Trial package digest mismatch")
    mutation = MutationCase.from_dict(mutation_data)
    if mutation.mutation_id != int(plan["mutation_id"]):
        raise ValueError("Trial package mutation_id mismatch")
    if mutation.source_bus != "b_can":
        raise ValueError("Distributed trial injection source must be B_CAN")
    return plan, mutation


def _resolve_config_path(value: Any, config_path: Optional[Path]) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute() and config_path is not None:
        path = config_path.parent / path
    return path.resolve()


def _pending_trials(store: ExperimentStore) -> list[int]:
    pending = []
    for metadata_path in sorted(store.path.glob("trial_*/metadata.json")):
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if metadata.get("status") not in {"completed", "failed"}:
            pending.append(int(metadata.get("trial_id", -1)))
    return pending


def prepare_trial_package(
    *,
    config: Mapping[str, Any],
    config_path: Optional[Path],
    experiment_id: int,
    target_id: int,
    random_seed: int,
    mutation_profile: Optional[str],
    undefined_max_bits: int,
    base_payload: Optional[bytes],
    output: Optional[Path],
) -> Path:
    if target_id != 0x366 and mutation_profile is not None:
        raise ConfigurationError("targeted mutation profiles are only valid for CAN ID 0x366")
    root = _resolve_config_path(config.get("experiments_root", "experiments"), config_path)
    snapshot = {
        "mode": "distributed_offline",
        "target_id": f"0x{target_id:X}",
        "source_bus": "B_CAN",
        "random_seed": random_seed,
        "mutation_profile": mutation_profile,
        "undefined_max_bits": undefined_max_bits,
        "runner_config": dict(config),
    }
    store = ExperimentStore(root, experiment_id, snapshot)
    store.reconcile_analyzed_trials(config.get("feedback", {}))
    pending = _pending_trials(store)
    if pending:
        raise RuntimeError(
            "Previous distributed trial is not completed; analyze or mark it failed first: "
            + ", ".join(map(str, pending))
        )

    target_cfg = config.get("target", {})
    original = base_payload
    if original is None:
        reference = target_cfg.get("reference_payload")
        if reference is None:
            raise ConfigurationError("target.reference_payload or --base-payload is required")
        original = parse_can_data(reference)
    if len(original) != 8:
        raise ConfigurationError("0x366 distributed baseline payload must be exactly 8 bytes")

    state = store.load_feedback_state()
    state = {**state, "next_mutation_id": store.next_mutation_id()}
    selector = TrialStrategySelector(config.get("feedback", {}))
    dbc_value = config.get("dbc", "../A5.dbc")
    dbc_path = _resolve_config_path(dbc_value, config_path) if dbc_value else None
    mutation, decision = selector.select_mutation(
        state=state,
        original_payload=original,
        source_bus="b_can",
        can_id=target_id,
        random_seed=random_seed,
        mutation_profile=mutation_profile,
        dbc_path=dbc_path,
        undefined_max_bits=undefined_max_bits,
    )
    signal = dbc_signal_metadata(mutation, dbc_path)
    if signal is not None:
        mutation = replace(mutation, signal=signal)

    trial_id = store.next_trial_id()
    trial_dir = store.create_trial(trial_id)
    trial_cfg = config.get("trial", {})
    distributed_cfg = config.get("distributed", {})
    timing = {
        "receiver_lead_seconds": float(distributed_cfg.get("receiver_lead_seconds", 30.0)),
        "receiver_tail_seconds": float(distributed_cfg.get("receiver_tail_seconds", 5.0)),
        "baseline_seconds": float(trial_cfg.get("baseline_seconds", 10.0)),
        "normal_seconds": float(trial_cfg.get("normal_seconds", 5.0)),
        "mutation_seconds": float(trial_cfg.get("mutation_seconds", 5.0)),
        "post_seconds": float(trial_cfg.get("post_seconds", 10.0)),
        "runner_timeout_seconds": float(trial_cfg.get("runner_timeout_seconds", 120.0)),
    }
    if any(value < 0 for value in timing.values()):
        raise ConfigurationError("distributed trial timing values cannot be negative")
    if timing["receiver_lead_seconds"] <= 0 or timing["receiver_tail_seconds"] <= 0:
        raise ConfigurationError("receiver lead/tail seconds must be greater than zero")
    if any(timing[name] <= 0 for name in (
        "baseline_seconds", "normal_seconds", "mutation_seconds", "post_seconds",
    )):
        raise ConfigurationError("all campaign phase durations must be greater than zero")
    if timing["normal_seconds"] < timing["mutation_seconds"]:
        raise ConfigurationError(
            "normal_seconds must be >= mutation_seconds for a duration-matched control"
        )

    time_sync = dict(config.get("time_sync", {}))
    sample_count = int(time_sync.get("samples", 3))
    warning_threshold = float(time_sync.get("warning_threshold_ms", 50.0))
    if sample_count < 1 or warning_threshold < 0:
        raise ConfigurationError("time_sync samples must be >= 1 and warning threshold >= 0")
    # Validate all hard-limit/guard values while preparing the signed package.
    build_clock_alignment(
        {"b_can": {"offset_ms": 0.0, "round_trip_ms": 0.0}},
        "b_can",
        time_sync,
    )
    if dbc_path is not None and not dbc_path.is_file():
        raise ConfigurationError(f"DBC file does not exist: {dbc_path}")
    dbc_reference = {
        "enabled": dbc_path is not None,
        "name": dbc_path.name if dbc_path is not None else None,
        "sha256": _digest_bytes(dbc_path.read_bytes()) if dbc_path is not None else None,
    }

    plan: dict[str, Any] = {
        "schema_version": 2,
        "execution_mode": "distributed_offline_previous_trial_feedback",
        "experiment_id": experiment_id,
        "trial_id": trial_id,
        "mutation_id": mutation.mutation_id,
        "source_bus": "B_CAN",
        "receiver_buses": ["P_CAN", "I_CAN"],
        "target_id": f"0x{target_id:X}",
        "channel": str(target_cfg.get("channel", "can0")),
        "sender_config": str(config.get("sender_config", "sender_trial.yaml")),
        "probe_live_payload": bool(target_cfg.get("probe_live_payload", True)),
        "probe_samples": int(target_cfg.get("probe_samples", 3)),
        "probe_timeout_seconds": float(target_cfg.get("probe_timeout_seconds", 6.0)),
        "timing": timing,
        "clock_warning_threshold_ms": warning_threshold,
        "time_sync": time_sync,
        "clock_reference_assumption": "control_laptops_share_synchronized_utc",
        "anomaly_thresholds": dict(config.get("anomaly_thresholds", {})),
        "feedback_policy": dict(config.get("feedback", {})),
        "dbc_reference": dbc_reference,
        "prepared_at": utc_now(),
        "strategy": decision.__dict__,
    }
    mutation_data = mutation.to_dict()
    plan["package_digest"] = _package_digest(plan, mutation_data)
    metadata = {
        "schema_version": 1,
        "status": "prepared_offline",
        "execution_mode": plan["execution_mode"],
        "experiment_id": experiment_id,
        "trial_id": trial_id,
        "target_id": plan["target_id"],
        "source_bus": "B_CAN",
        "mutation_id": mutation.mutation_id,
        "random_seed": random_seed,
        "feedback_snapshot_total_trials": int(state.get("total_trials", 0)),
        "start_time": utc_now(),
        "strategy": decision.__dict__,
        "required_results": ["B_CAN_TX", "P_CAN_RX", "I_CAN_RX"],
        "package_digest": plan["package_digest"],
    }
    store.write_json(trial_dir / "mutation.json", mutation_data)
    store.write_json(trial_dir / "trial_plan.json", plan)
    store.write_json(trial_dir / "metadata.json", metadata)

    package_path = output
    if package_path is None:
        package_path = store.path / "outbox" / (
            f"experiment_{experiment_id:04d}_trial_{trial_id:04d}.zip"
        )
    _write_zip(package_path, {
        "trial_plan.json": _json_bytes(plan),
        "mutation.json": _json_bytes(mutation_data),
    })
    print(f"[PREPARED] Experiment {experiment_id}, Trial {trial_id}")
    print(f"[MUTATION] {mutation.mutation_uid} / {mutation.operator} / {mutation.mutated_payload.hex().upper()}")
    print(f"[PACKAGE]  {package_path.resolve()}")
    print("[FEEDBACK] Completed previous trials only; current trial feedback is not used.")
    return package_path.resolve()


def _node_settings(config: Mapping[str, Any], requested_bus: str) -> tuple[dict[str, Any], dict[str, Any]]:
    node = dict(config.get("node", {}))
    configured_bus = normalize_bus(str(node.get("bus", requested_bus)))
    if configured_bus != requested_bus:
        raise ConfigurationError(
            f"node.bus={configured_bus} does not match requested bus={requested_bus}"
        )
    ssh = node.get("ssh")
    if not isinstance(ssh, Mapping):
        raise ConfigurationError("node.ssh mapping is required")
    return node, dict(ssh)


def _wait_remote(manager: SSHManager, process: Any, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not manager.process_alive(process):
            return
        time.sleep(0.25)
    manager.stop_process(process)
    raise TimeoutError(f"Remote capture exceeded timeout ({timeout:g}s)")


def _print_clock_warning(bus: str, clock: Mapping[str, Any], threshold_ms: float) -> None:
    offset = float(clock.get("offset_ms", 0.0))
    if abs(offset) > threshold_ms:
        print(
            f"[WARN] {bus.upper()} Pi clock offset={offset:.3f} ms "
            f"> {threshold_ms:g} ms"
        )
    if not clock.get("chrony_available", False):
        print(f"[WARN] {bus.upper()} Pi chrony status is unavailable")
    elif "not synchronised" in str(clock.get("chrony_tracking", "")).lower():
        print(f"[WARN] {bus.upper()} Pi chrony reports an unsynchronised clock")


def _plan_time_sync(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Read the signed clock policy, retaining old-package compatibility."""

    configured = plan.get("time_sync")
    if isinstance(configured, Mapping):
        return dict(configured)
    return {
        "warning_threshold_ms": float(
            plan.get("clock_warning_threshold_ms", 50.0)
        ),
    }


def _validate_local_clock(
    plan: Mapping[str, Any], bus: str, clock: Mapping[str, Any],
) -> None:
    # A single-node alignment validates offset, RTT and all option types.  The
    # cross-laptop relative uncertainty is validated only after all bundles are
    # reunited on the B-CAN Control PC.
    build_clock_alignment({bus: clock}, bus, _plan_time_sync(plan))


def _sample_node_clock(manager: SSHManager, plan: Mapping[str, Any]) -> dict[str, Any]:
    policy = _plan_time_sync(plan)
    sample_count = max(1, int(policy.get("samples", 1)))
    samples = [manager.clock_sample() for _ in range(sample_count)]
    best = min(samples, key=lambda item: float(item.get("round_trip_ms", float("inf"))))
    return {**best, "samples": samples}


def _result_zip(
    *,
    output: Path,
    plan: Mapping[str, Any],
    role: str,
    bus: str,
    data_name: str,
    data: bytes,
    clock: Mapping[str, Any],
    stdout: bytes = b"",
) -> Path:
    manifest = {
        "schema_version": 1,
        "experiment_id": int(plan["experiment_id"]),
        "trial_id": int(plan["trial_id"]),
        "mutation_id": int(plan["mutation_id"]),
        "package_digest": str(plan["package_digest"]),
        "role": role,
        "bus": bus.upper(),
        "data_file": data_name,
        "data_sha256": _digest_bytes(data),
        "clock_sample": dict(clock),
        "created_at": utc_now(),
    }
    members = {"result_manifest.json": _json_bytes(manifest), data_name: data}
    if stdout:
        members["remote.stdout.log"] = stdout
    _write_zip(output, members)
    return output.resolve()


def receive_trial(
    *, package: Path, config: Mapping[str, Any], bus: str, output: Optional[Path],
    manager_factory=SSHManager,
) -> Path:
    if bus not in RX_BUSES:
        raise ConfigurationError("receive supports only P_CAN or I_CAN")
    plan, _ = load_trial_package(package)
    node, ssh = _node_settings(config, bus)
    manager = manager_factory(ssh)
    timing = plan["timing"]
    duration = sum(float(timing[name]) for name in (
        "receiver_lead_seconds", "baseline_seconds", "normal_seconds",
        "mutation_seconds", "post_seconds", "receiver_tail_seconds",
    ))
    project = str(node.get("project_dir", "/home/pi/auto-fuzz-26-1/pi_can_lab"))
    python = str(node.get("python", remote_join(project, ".venv/bin/python")))
    remote_root = str(node.get("remote_root", "/tmp/auto_fuzz_distributed"))
    remote_dir = remote_join(
        remote_root, f"experiment_{int(plan['experiment_id']):04d}",
        f"trial_{int(plan['trial_id']):04d}", bus,
    )
    remote_log = remote_join(remote_dir, f"{bus}.jsonl")
    remote_stdout = remote_join(remote_dir, "capture.stdout.log")
    receiver_config = str(node.get("receiver_config", f"receiver_{bus[0]}_can.yaml"))
    command = [
        python, remote_join(project, "can_receiver.py"),
        "--config", remote_join(project, receiver_config),
        "--bus-name", bus,
        "--output", remote_log,
        "--output-policy", "fail",
        "--experiment-id", str(plan["experiment_id"]),
        "--duration", f"{duration:g}",
        "--print-mode", "none", "--no-report",
    ]
    local_dir = Path(node.get("results_dir", "distributed_results")).expanduser().resolve()
    local_dir.mkdir(parents=True, exist_ok=True)
    raw_path = local_dir / f"experiment_{int(plan['experiment_id']):04d}_trial_{int(plan['trial_id']):04d}_{bus}.jsonl"
    stdout_path = raw_path.with_suffix(".stdout.log")
    try:
        clock = _sample_node_clock(manager, plan)
        _validate_local_clock(plan, bus, clock)
        _print_clock_warning(
            bus, clock,
            float(_plan_time_sync(plan).get("warning_threshold_ms", 50.0)),
        )
        manager.ensure_directory(remote_dir)
        process = manager.start_process(command, remote_stdout)
        print(f"[CAPTURE] {bus.upper()} started for {duration:g}s")
        print("[ACTION]  Start B-CAN inject command now if both receiver laptops are ready.")
        _wait_remote(manager, process, duration + 30.0)
        manager.download(remote_log, raw_path)
        manager.download(remote_stdout, stdout_path)
        validate_capture_log(raw_path, int(plan["experiment_id"]))
    finally:
        manager.close()
    output_path = output or local_dir / (
        f"experiment_{int(plan['experiment_id']):04d}_trial_{int(plan['trial_id']):04d}_{bus}_result.zip"
    )
    result = _result_zip(
        output=output_path, plan=plan, role="rx", bus=bus,
        data_name=f"{bus}.jsonl", data=raw_path.read_bytes(), clock=clock,
        stdout=stdout_path.read_bytes(),
    )
    print(f"[RESULT] {result}")
    return result


def _probe_live_payload(manager: SSHManager, plan: Mapping[str, Any]) -> bytes:
    can_id = parse_int(plan["target_id"], "target ID")
    samples = max(1, int(plan.get("probe_samples", 3)))
    timeout = float(plan.get("probe_timeout_seconds", 6.0))
    mask = "1FFFFFFF" if can_id > 0x7FF else "7FF"
    result = manager.run([
        "timeout", f"{timeout:g}", "candump", "-L", "-n", str(samples),
        f"{plan.get('channel', 'can0')},{can_id:X}:{mask}",
    ], timeout=timeout + 2.0, check=False)
    payloads = parse_candump_payloads(result.stdout, can_id)
    if not payloads:
        raise RuntimeError(f"No 0x{can_id:X} baseline payload captured on B_CAN")
    counts = {payload: payloads.count(payload) for payload in set(payloads)}
    return max(counts, key=counts.get)


def _sender_command(
    *, plan: Mapping[str, Any], mutation: MutationCase, node: Mapping[str, Any], remote_tx: str,
) -> list[str]:
    project = str(node.get("project_dir", "/home/pi/auto-fuzz-26-1/pi_can_lab"))
    python = str(node.get("python", remote_join(project, ".venv/bin/python")))
    timing = plan["timing"]
    command = [
        python, remote_join(project, "can_sender.py"),
        "--config", remote_join(project, str(plan["sender_config"])),
        "--bus-name", "b_can", "--id", plan["target_id"],
        "--data", mutation.original_payload.hex(),
        "--experiment-id", str(plan["experiment_id"]),
        "--output", remote_tx, "--output-policy", "fail", "--count", "1",
        "--mutation-data", mutation.mutated_payload.hex(),
        "--mutation-id", str(mutation.mutation_id),
        "--mutation-uid", mutation.mutation_uid,
        "--mutation-operator", mutation.operator,
        "--mutation-metadata-json", json.dumps(
            mutation.parameters, ensure_ascii=True, separators=(",", ":")
        ),
        "--generation-reason", mutation.generation_reason,
        "--random-seed", str(mutation.random_seed),
        "--baseline-duration", str(float(timing["baseline_seconds"])),
        "--normal-duration", str(float(timing["normal_seconds"])),
        "--mutation-duration", str(float(timing["mutation_seconds"])),
        "--recovery-duration", str(float(timing["post_seconds"])),
        "--execute",
    ]
    if mutation.parent_mutation_id is not None:
        command.extend(["--parent-mutation-id", str(mutation.parent_mutation_id)])
    return command


def inject_trial(
    *, package: Path, config: Mapping[str, Any], output: Optional[Path], execute: bool,
    manager_factory=SSHManager,
) -> Optional[Path]:
    plan, mutation = load_trial_package(package)
    node, ssh = _node_settings(config, "b_can")
    if not execute:
        print("[SAFE] Preview only; no SSH connection or CAN transmission was started.")
        print(f"[TRIAL] Experiment {plan['experiment_id']}, Trial {plan['trial_id']}")
        print(f"[TX]    0x{mutation.can_id:X}#{mutation.mutated_payload.hex().upper()}")
        print("[SAFE] Add --execute only after P-CAN and I-CAN captures are running.")
        return None
    manager = manager_factory(ssh)
    remote_root = str(node.get("remote_root", "/tmp/auto_fuzz_distributed"))
    remote_dir = remote_join(
        remote_root, f"experiment_{int(plan['experiment_id']):04d}",
        f"trial_{int(plan['trial_id']):04d}", "b_can",
    )
    remote_tx = remote_join(remote_dir, "tx.jsonl")
    local_dir = Path(node.get("results_dir", "distributed_results")).expanduser().resolve()
    local_dir.mkdir(parents=True, exist_ok=True)
    tx_path = local_dir / f"experiment_{int(plan['experiment_id']):04d}_trial_{int(plan['trial_id']):04d}_tx.jsonl"
    stdout_path = tx_path.with_suffix(".stdout.log")
    stderr_path = tx_path.with_suffix(".stderr.log")
    try:
        clock = _sample_node_clock(manager, plan)
        _validate_local_clock(plan, "b_can", clock)
        _print_clock_warning(
            "b_can", clock,
            float(_plan_time_sync(plan).get("warning_threshold_ms", 50.0)),
        )
        manager.ensure_directory(remote_dir)
        if bool(plan.get("probe_live_payload", True)):
            observed = _probe_live_payload(manager, plan)
            if observed != mutation.original_payload:
                raise RuntimeError(
                    "Live B-CAN baseline differs from prepared mutation baseline: "
                    f"live={observed.hex().upper()} prepared={mutation.original_payload.hex().upper()}"
                )
        command = _sender_command(
            plan=plan, mutation=mutation, node=node, remote_tx=remote_tx
        )
        timeout = float(plan["timing"]["runner_timeout_seconds"])
        result = manager.run(command, timeout=timeout)
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")
        manager.download(remote_tx, tx_path)
        load_phase_times(tx_path, require_complete_campaign=True)
    finally:
        manager.close()
    output_path = output or local_dir / (
        f"experiment_{int(plan['experiment_id']):04d}_trial_{int(plan['trial_id']):04d}_b_can_tx_result.zip"
    )
    result_path = _result_zip(
        output=output_path, plan=plan, role="tx", bus="b_can",
        data_name="tx.jsonl", data=tx_path.read_bytes(), clock=clock,
        stdout=stdout_path.read_bytes(),
    )
    print(f"[TX COMPLETE] {mutation.mutation_uid}")
    print(f"[RESULT]      {result_path}")
    return result_path


def load_result_bundle(path: Path) -> tuple[dict[str, Any], bytes]:
    with zipfile.ZipFile(path.expanduser().resolve(), "r") as archive:
        names = set(archive.namelist())
        if "result_manifest.json" not in names:
            raise ValueError(f"{path}: result_manifest.json is missing")
        manifest = json.loads(archive.read("result_manifest.json"))
        data_name = str(manifest.get("data_file", ""))
        if not data_name or data_name not in names or Path(data_name).name != data_name:
            raise ValueError(f"{path}: invalid data_file")
        data = archive.read(data_name)
    if _digest_bytes(data) != manifest.get("data_sha256"):
        raise ValueError(f"{path}: result data digest mismatch")
    return manifest, data


def _write_immutable(path: Path, data: bytes) -> None:
    if path.exists():
        if path.read_bytes() != data:
            raise FileExistsError(f"Refusing to overwrite different raw result: {path}")
        return
    path.write_bytes(data)


def analyze_distributed_trial(
    *, config: Mapping[str, Any], config_path: Optional[Path], package: Path,
    tx_result: Path, p_result: Path, i_result: Path,
) -> dict[str, Any]:
    plan, mutation = load_trial_package(package)
    supplied = [load_result_bundle(path) for path in (tx_result, p_result, i_result)]
    by_key: dict[tuple[str, str], tuple[dict[str, Any], bytes]] = {}
    for manifest, data in supplied:
        if str(manifest.get("package_digest")) != str(plan["package_digest"]):
            raise ValueError("Result belongs to a different trial package")
        for field in ("experiment_id", "trial_id", "mutation_id"):
            if int(manifest[field]) != int(plan[field]):
                raise ValueError(f"Result {field} mismatch")
        key = (str(manifest["role"]), normalize_bus(str(manifest["bus"])))
        if key in by_key:
            raise ValueError(f"Duplicate result role/bus: {key}")
        by_key[key] = (manifest, data)
    required = {("tx", "b_can"), ("rx", "p_can"), ("rx", "i_can")}
    if set(by_key) != required:
        raise ValueError(f"Required results are {sorted(required)}; received {sorted(by_key)}")

    root = _resolve_config_path(config.get("experiments_root", "experiments"), config_path)
    store = ExperimentStore(root, int(plan["experiment_id"]), {
        "mode": "distributed_offline", "target_id": plan["target_id"],
        "source_bus": "B_CAN",
    })
    trial_dir = store.path / f"trial_{int(plan['trial_id']):04d}"
    trial_dir.mkdir(parents=True, exist_ok=True)
    existing_mutation = trial_dir / "mutation.json"
    mutation_bytes = _json_bytes(mutation.to_dict())
    _write_immutable(existing_mutation, mutation_bytes)
    _write_immutable(trial_dir / "trial_plan.json", _json_bytes(plan))
    tx_path = trial_dir / "tx.jsonl"
    p_path = trial_dir / "p_can.jsonl"
    i_path = trial_dir / "i_can.jsonl"
    _write_immutable(tx_path, by_key[("tx", "b_can")][1])
    _write_immutable(p_path, by_key[("rx", "p_can")][1])
    _write_immutable(i_path, by_key[("rx", "i_can")][1])

    feedback_policy = plan.get("feedback_policy")
    if not isinstance(feedback_policy, Mapping):
        feedback_policy = config.get("feedback", {})
    metadata_path = trial_dir / "metadata.json"
    feedback_path = trial_dir / "feedback.json"
    anomalies_path = trial_dir / "anomalies.json"
    if metadata_path.is_file():
        existing_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        existing_status = str(existing_metadata.get("status", ""))
        if existing_status == "completed":
            if not feedback_path.is_file() or not anomalies_path.is_file():
                raise ValueError("Completed distributed trial is missing derived artifacts")
            feedback = json.loads(feedback_path.read_text(encoding="utf-8"))
            print(
                f"[ALREADY COMPLETED] Experiment {plan['experiment_id']}, "
                f"Trial {plan['trial_id']}"
            )
            return feedback
        if feedback_path.is_file() and anomalies_path.is_file():
            store.reconcile_analyzed_trials(feedback_policy)
            recovered_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if recovered_metadata.get("status") == "completed":
                feedback = json.loads(feedback_path.read_text(encoding="utf-8"))
                print(
                    f"[RECOVERED] Experiment {plan['experiment_id']}, "
                    f"Trial {plan['trial_id']}"
                )
                return feedback

    phases = load_phase_times(tx_path, require_complete_campaign=True)
    clocks = {
        key[1]: value[0].get("clock_sample") for key, value in by_key.items()
    }
    clock_policy = _plan_time_sync(plan)
    clock_alignment = build_clock_alignment(clocks, "b_can", clock_policy)
    for bus, bus_alignment in clock_alignment["per_bus"].items():
        for phase in ("baseline", "normal", "mutation", "recovery"):
            phase_key = "recovery" if phase == "recovery" else phase
            guarded_phase_bounds(
                int(phases[f"{phase_key}_start"]),
                int(phases[f"{phase_key}_end"]),
                bus_alignment,
            )
    capture_quality = {}
    for bus, path in (("p_can", p_path), ("i_can", i_path)):
        quality = validate_capture_log(path, int(plan["experiment_id"]))
        raw_start_ns, raw_end_ns = load_capture_bounds(path)
        bus_alignment = clock_alignment["per_bus"][bus]
        start_ns = align_timestamp_ns(raw_start_ns, bus_alignment)
        end_ns = align_timestamp_ns(raw_end_ns, bus_alignment)
        baseline_bounds = guarded_phase_bounds(
            int(phases["baseline_start"]), int(phases["baseline_end"]), bus_alignment,
        )
        recovery_bounds = guarded_phase_bounds(
            int(phases["recovery_start"]), int(phases["recovery_end"]), bus_alignment,
        )
        if start_ns > baseline_bounds[0] or end_ns < recovery_bounds[1]:
            raise ValueError(
                f"{bus} capture does not cover guarded campaign windows: "
                f"aligned_capture={start_ns}..{end_ns}"
            )
        capture_quality[bus] = {
            **quality,
            "raw_capture_start_ns": raw_start_ns,
            "raw_capture_end_ns": raw_end_ns,
            "aligned_capture_start_ns": start_ns,
            "aligned_capture_end_ns": end_ns,
        }

    state = store.load_feedback_state()
    dbc_reference = plan.get("dbc_reference")
    if int(plan.get("schema_version", 1)) >= 2 and not isinstance(
        dbc_reference, Mapping
    ):
        raise ValueError("Schema-v2 trial package is missing dbc_reference")
    if isinstance(dbc_reference, Mapping):
        if bool(dbc_reference.get("enabled", False)):
            dbc_value = config.get("dbc", "../A5.dbc")
            if not dbc_value:
                raise ConfigurationError("Signed trial requires a DBC, but config disables it")
            dbc_path = _resolve_config_path(dbc_value, config_path)
            if not dbc_path.is_file():
                raise ConfigurationError(f"DBC file does not exist: {dbc_path}")
            actual_dbc_digest = _digest_bytes(dbc_path.read_bytes())
            if actual_dbc_digest != str(dbc_reference.get("sha256")):
                raise ValueError(
                    "DBC digest mismatch: distributed analysis must use the DBC "
                    "that was signed into the trial package"
                )
        else:
            dbc_path = None
    else:
        # Schema-v1 package compatibility.  Such packages predate DBC pinning.
        dbc_value = config.get("dbc", "../A5.dbc")
        dbc_path = _resolve_config_path(dbc_value, config_path) if dbc_value else None
    anomaly_thresholds = plan.get("anomaly_thresholds")
    if not isinstance(anomaly_thresholds, Mapping):
        anomaly_thresholds = config.get("anomaly_thresholds", {})
    analysis = analyze_trial(
        rx_paths={"p_can": p_path, "i_can": i_path},
        phase_times_ns=phases,
        mutation=mutation,
        thresholds=anomaly_thresholds,
        dbc_path=dbc_path,
        reference_catalog=state.get("reference_catalog"),
        clock_offsets=clocks,
        source_bus="b_can",
        boundary_guard_ms=float(clock_policy.get("boundary_guard_ms", 0.0)),
    )
    anomalies_doc = {
        "schema_version": 1, "trial_id": int(plan["trial_id"]),
        "mutation_id": mutation.mutation_id, **analysis,
    }
    store.write_json(anomalies_path, anomalies_doc)
    threshold = float(feedback_policy.get("interesting_score_threshold", 0.6))
    raw_feedback = create_trial_feedback(
        int(plan["trial_id"]), mutation, analysis["anomalies"], threshold
    )
    feedback = store.prepare_feedback(
        mutation, raw_feedback, feedback_policy,
    )
    store.write_json(feedback_path, feedback)
    metadata = {
        "schema_version": 1,
        "status": "analyzed",
        "execution_mode": plan["execution_mode"],
        "experiment_id": int(plan["experiment_id"]),
        "trial_id": int(plan["trial_id"]),
        "target_id": plan["target_id"],
        "source_bus": "B_CAN",
        "mutation_id": mutation.mutation_id,
        "start_time": plan["prepared_at"],
        "end_time": utc_now(),
        "phase_times_ns": phases,
        "baseline_start": ns_to_iso(phases.get("baseline_start")),
        "baseline_end": ns_to_iso(phases.get("baseline_end")),
        "normal_start": ns_to_iso(phases.get("normal_start")),
        "normal_end": ns_to_iso(phases.get("normal_end")),
        "mutation_start": ns_to_iso(phases.get("mutation_start")),
        "mutation_end": ns_to_iso(phases.get("mutation_end")),
        "post_start": ns_to_iso(phases.get("recovery_start")),
        "post_end": ns_to_iso(phases.get("recovery_end")),
        "logs": {"tx": "tx.jsonl", "p_can": "p_can.jsonl", "i_can": "i_can.jsonl"},
        "capture_quality": capture_quality,
        "clock_samples": clocks,
        "clock_alignment": clock_alignment,
        "clock_reference_assumption": plan.get(
            "clock_reference_assumption",
            "control_laptops_share_synchronized_utc",
        ),
        "confirmation_status": feedback.get("confirmation_status"),
        "required_results": ["B_CAN_TX", "P_CAN_RX", "I_CAN_RX"],
        "package_digest": plan["package_digest"],
        "dbc_reference": dbc_reference,
    }
    store.write_json(metadata_path, metadata)
    store.record_completed_trial(
        mutation, feedback, analysis.get("reference_update"),
    )
    metadata["status"] = "completed"
    store.write_json(metadata_path, metadata)
    print(f"[COMPLETED] Experiment {plan['experiment_id']}, Trial {plan['trial_id']}")
    print(f"[ANOMALY]   count={analysis['summary']['anomaly_count']} max={analysis['summary']['maximum_score']:.2f}")
    print(
        "[FEEDBACK]  "
        f"status={feedback.get('confirmation_status', 'UNKNOWN')} "
        f"exploit_ready={'YES' if feedback.get('eligible_for_exploitation') else 'NO'}"
    )
    print("[NEXT]      Run prepare again; pending candidates are reproduced before exploitation.")
    return feedback


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Distributed B-TX + P/I-RX previous-trial feedback runner"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare", help="create one immutable next-trial package on B Control PC")
    prepare.add_argument("--config", default="distributed_runner.yaml")
    prepare.add_argument("--experiment-id", type=int)
    prepare.add_argument("--target-id", default="0x366")
    prepare.add_argument("--base-payload")
    prepare.add_argument("--random-seed", type=int, default=366)
    prepare.add_argument("--mutation-profile")
    prepare.add_argument("--undefined-max-bits", type=int, default=2)
    prepare.add_argument("--output")

    receive = sub.add_parser("receive", help="capture P_CAN or I_CAN through this laptop's Pi")
    receive.add_argument("--config", default="distributed_node.yaml")
    receive.add_argument("--package", required=True)
    receive.add_argument("--bus", required=True, choices=("P_CAN", "I_CAN", "p_can", "i_can"))
    receive.add_argument("--output")

    inject = sub.add_parser("inject", help="inject the prepared mutation through B_CAN Pi")
    inject.add_argument("--config", default="distributed_node.yaml")
    inject.add_argument("--package", required=True)
    inject.add_argument("--output")
    inject.add_argument("--execute", action="store_true")

    analyze = sub.add_parser("analyze", help="merge B TX + P/I RX and commit feedback")
    analyze.add_argument("--config", default="distributed_runner.yaml")
    analyze.add_argument("--package", required=True)
    analyze.add_argument("--tx-result", required=True)
    analyze.add_argument("--p-result", required=True)
    analyze.add_argument("--i-result", required=True)
    return parser


def run(args: argparse.Namespace) -> int:
    config, config_path = load_yaml_config(args.config)
    if args.command == "prepare":
        root = _resolve_config_path(config.get("experiments_root", "experiments"), config_path)
        experiment_id = args.experiment_id or next_experiment_id(root)
        prepare_trial_package(
            config=config, config_path=config_path, experiment_id=experiment_id,
            target_id=parse_int(args.target_id, "target ID"), random_seed=args.random_seed,
            mutation_profile=args.mutation_profile,
            undefined_max_bits=args.undefined_max_bits,
            base_payload=parse_can_data(args.base_payload) if args.base_payload else None,
            output=Path(args.output) if args.output else None,
        )
    elif args.command == "receive":
        receive_trial(
            package=Path(args.package), config=config, bus=normalize_bus(args.bus),
            output=Path(args.output) if args.output else None,
        )
    elif args.command == "inject":
        inject_trial(
            package=Path(args.package), config=config,
            output=Path(args.output) if args.output else None, execute=args.execute,
        )
    elif args.command == "analyze":
        analyze_distributed_trial(
            config=config, config_path=config_path, package=Path(args.package),
            tx_result=Path(args.tx_result), p_result=Path(args.p_result),
            i_result=Path(args.i_result),
        )
    return 0


def main() -> int:
    try:
        return run(build_parser().parse_args())
    except Exception as exc:
        print(f"[ERROR] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
