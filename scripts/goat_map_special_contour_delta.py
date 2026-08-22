"""Compare zone-present and post-delete SpecialContour readbacks."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import orjson

from deebot_client.diagnostics.goat_map_delta import (
    compare_special_contour_present_to_absent,
    compare_special_contour_readbacks,
    validate_delta_output_path,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only SpecialContour inverse-operation byte delta. "
            "No payload semantics are assigned."
        )
    )
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument(
        "--absent-artifact",
        type=Path,
        help="Optional passive zone-absent artifact for cross-artifact comparison",
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    """Verify one artifact and compare its readback windows."""
    args = _parser().parse_args()
    artifacts = (
        (args.artifact, args.absent_artifact)
        if args.absent_artifact is not None
        else (args.artifact,)
    )
    validate_delta_output_path(args.output, *artifacts)
    report = (
        compare_special_contour_present_to_absent(
            args.artifact,
            args.absent_artifact,
        )
        if args.absent_artifact is not None
        else compare_special_contour_readbacks(args.artifact)
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(orjson.dumps(report, option=orjson.OPT_INDENT_2) + b"\n")
    print(f"Read-only SpecialContour delta: {args.output.resolve()}")
    print(
        "Delta: "
        f"status={report['comparison_status']} "
        f"result={report['comparison_result']} "
        f"groups={report['group_count']} "
        f"changed_groups={report['changed_group_count']} "
        f"missing={report['missing_roles']}"
    )
    print("SpecialContour parsing: disabled")
    return 0


if __name__ == "__main__":
    sys.exit(main())
