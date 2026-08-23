"""Generate a derived read-only P2-11 Area rename status review."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
from pathlib import Path

import orjson

from deebot_client.diagnostics.goat_map_area_rename_restore import (
    build_area_rename_status_review,
)
from deebot_client.diagnostics.goat_map_delta import validate_delta_output_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--original-summary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    """Build the derived report without modifying either source."""
    args = _parser().parse_args()
    validate_delta_output_path(args.output, args.artifact)
    report = build_area_rename_status_review(
        args.artifact,
        args.original_summary,
    )
    args.output.write_bytes(orjson.dumps(report, option=orjson.OPT_INDENT_2) + b"\n")
    print(f"Read-only P2-11 status review: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
