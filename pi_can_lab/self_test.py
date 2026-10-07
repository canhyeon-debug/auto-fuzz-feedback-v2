#!/usr/bin/env python3
"""Offline DBC encode/decode and python-can virtual bus smoke test."""

from __future__ import annotations

import argparse
from pathlib import Path

from can_common import (
    load_dbc,
    open_can_bus,
    parse_can_data,
    require_module,
    shutdown_bus,
    signal_defaults,
)


def dbc_round_trip(database, frame_id: int, signal_name: str) -> None:
    message = database.get_message_by_frame_id(frame_id)
    values = signal_defaults(message)
    values[signal_name] = 1
    payload = bytes(message.encode(values, scaling=True, padding=False, strict=True))
    decoded = message.decode(payload, decode_choices=False, scaling=True)
    assert decoded[signal_name] == 1
    assert len(payload) == message.length
    print(f"[OK] DBC {message.name} 0x{frame_id:X}: {signal_name}=1 -> {payload.hex().upper()}")


def virtual_bus_round_trip() -> None:
    can = require_module("can", "python-can")
    tx = open_can_bus("virtual", "pi-can-lab-self-test", receive_own_messages=False)
    rx = open_can_bus("virtual", "pi-can-lab-self-test", receive_own_messages=False)
    try:
        expected = parse_can_data("01 23 45 67 89 AB CD EF")
        tx.send(can.Message(arbitration_id=0x123, data=expected, is_extended_id=False))
        received = rx.recv(timeout=1.0)
        assert received is not None
        assert received.arbitration_id == 0x123
        assert bytes(received.data) == expected
        print("[OK] python-can virtual TX/RX")
    finally:
        shutdown_bus(tx)
        shutdown_bus(rx)


def main() -> int:
    default_dbc = Path(__file__).resolve().parent.parent / "A5.dbc"
    parser = argparse.ArgumentParser(description="Pi CAN Lab 설치/DBC self-test")
    parser.add_argument("--dbc", default=str(default_dbc), help="테스트할 DBC")
    args = parser.parse_args()

    database = load_dbc(Path(args.dbc).expanduser().resolve())
    dbc_round_trip(database, 0x65A, "BCM1_Warnblink_Taster")
    dbc_round_trip(database, 0x366, "BM_Warnblinken")
    virtual_bus_round_trip()
    print("[PASS] 모든 self-test 통과")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
