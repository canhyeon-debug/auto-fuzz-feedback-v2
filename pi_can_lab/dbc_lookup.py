#!/usr/bin/env python3
"""Small CLI for inspecting messages and signals in a DBC file."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Iterable, List

from can_common import ConfigurationError, load_dbc, parse_int


def text_of_comment(comment: Any) -> str:
    if isinstance(comment, dict):
        return " | ".join(str(value) for value in comment.values())
    return str(comment or "")


def print_message(message: Any, include_signals: bool = True) -> None:
    kind = "EXT" if message.is_extended_frame else "STD"
    cycle = f"{message.cycle_time} ms" if message.cycle_time is not None else "DBC 미지정"
    senders = ", ".join(message.senders) if message.senders else "미지정"
    print(
        f"\n0x{message.frame_id:X} ({message.frame_id})  {message.name}  "
        f"DLC={message.length} {kind} cycle={cycle} sender={senders}"
    )
    comment = text_of_comment(message.comment).strip().replace("\n", " ")
    if comment:
        print(f"  설명: {comment}")
    if not include_signals:
        return
    for signal in message.signals:
        endian = "LE" if signal.byte_order == "little_endian" else "BE"
        signed = "signed" if signal.is_signed else "unsigned"
        limits = f"[{signal.minimum}|{signal.maximum}]"
        print(
            f"  - {signal.name}: start={signal.start}, length={signal.length}, "
            f"{endian}, {signed}, scale={signal.scale}, offset={signal.offset}, range={limits}"
        )


def matches(message: Any, term: str) -> bool:
    lowered = term.casefold()
    if lowered in message.name.casefold() or lowered in text_of_comment(message.comment).casefold():
        return True
    for signal in message.signals:
        if lowered in signal.name.casefold() or lowered in text_of_comment(signal.comment).casefold():
            return True
    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DBC 메시지/신호 검색 도구")
    parser.add_argument("--dbc", required=True, help="DBC 파일 경로")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--id", dest="frame_id", help="CAN ID (예: 0x366)")
    group.add_argument("--message", help="정확한 DBC 메시지 이름")
    group.add_argument("--search", help="메시지/신호/설명에서 검색할 문자열")
    parser.add_argument("--limit", type=int, default=100, help="검색 결과 메시지 최대 개수")
    return parser


def run(args: argparse.Namespace) -> int:
    database = load_dbc(Path(args.dbc).expanduser().resolve())
    print(
        f"DBC: {args.dbc}\nmessages={len(database.messages)}, "
        f"signals={sum(len(message.signals) for message in database.messages)}"
    )

    messages: List[Any]
    if args.frame_id:
        frame_id = parse_int(args.frame_id, "CAN ID")
        try:
            messages = [database.get_message_by_frame_id(frame_id)]
        except KeyError as exc:
            raise ConfigurationError(f"DBC에 CAN ID 0x{frame_id:X}가 없습니다.") from exc
    elif args.message:
        try:
            messages = [database.get_message_by_name(args.message)]
        except KeyError as exc:
            raise ConfigurationError(f"DBC에 메시지 '{args.message}'가 없습니다.") from exc
    elif args.search:
        messages = [message for message in database.messages if matches(message, args.search)]
    else:
        print("--id, --message 또는 --search를 추가하면 상세 내용을 볼 수 있습니다.")
        return 0

    if not messages:
        print("검색 결과가 없습니다.")
        return 1
    for message in messages[: max(1, args.limit)]:
        print_message(message)
    if len(messages) > args.limit:
        print(f"\n... {len(messages) - args.limit}개 메시지는 생략했습니다. --limit을 늘리세요.")
    return 0


def main() -> int:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(errors='replace')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(errors='replace')
    try:
        return run(build_parser().parse_args())
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
