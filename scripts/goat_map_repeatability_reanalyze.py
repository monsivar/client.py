"""Regenerate corrected timing analysis from an immutable P2-08 artifact."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import orjson

from deebot_client.diagnostics.goat_map_delta import validate_delta_output_path
from deebot_client.diagnostics.goat_map_repeatability import (
    build_corrected_repeatability_report,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Reanalyze one verified repeatability artifact with integer-microsecond "
            "timing and explicitly supersede its earlier derived summary."
        )
    )
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--superseded-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    """Write a corrected metadata-only report outside the immutable artifact."""
    args = _parser().parse_args()
    validate_delta_output_path(args.output, args.artifact)
    if args.output.resolve() == args.superseded_report.resolve():
        raise ValueError("Corrected output must not overwrite the superseded report")
    report = build_corrected_repeatability_report(
        args.artifact,
        args.superseded_report,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(orjson.dumps(report, option=orjson.OPT_INDENT_2) + b"\n")
    statuses = report["corrected_hypothesis_statuses"]
    print(f"Corrected repeatability report: {args.output.resolve()}")
    print(
        "Provenance: "
        f"capture={report['artifact_reference']['capture_id']} "
        f"analysis={report['analysis_version']} "
        f"supersedes={report['superseded_report']['filename']}"
    )
    print(
        "Hypotheses: " + " ".join(f"{key}={value}" for key, value in statuses.items())
    )
    print("Artifact modification: false")
    return 0


if __name__ == "__main__":
    sys.exit(main())
