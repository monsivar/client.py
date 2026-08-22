"""Compare two verified Phase 2 artifacts without map interpretation."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import orjson

from deebot_client.diagnostics.goat_map_delta import (
    compare_phase2_artifacts,
    validate_delta_output_path,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only structural comparison of two GOAT Phase 2 artifacts. "
            "No framing, geometry, or map decoding is performed."
        )
    )
    parser.add_argument("--before-artifact", type=Path, required=True)
    parser.add_argument("--after-artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    """Verify both artifacts, write a metadata-only delta, and print counts."""
    args = _parser().parse_args()
    validate_delta_output_path(
        args.output,
        args.before_artifact,
        args.after_artifact,
    )
    report = compare_phase2_artifacts(
        args.before_artifact,
        args.after_artifact,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(orjson.dumps(report, option=orjson.OPT_INDENT_2) + b"\n")
    print(f"Read-only delta report: {args.output.resolve()}")
    print(
        "Delta: "
        f"groups={report['group_count']} "
        f"changed_groups={report['changed_group_count']}"
    )
    print("Semantic map decoding: disabled")
    return 0


if __name__ == "__main__":
    sys.exit(main())
