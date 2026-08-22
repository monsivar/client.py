"""Build a read-only exact-signature offset-34+ structural report."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import orjson

from deebot_client.diagnostics.goat_map_body_structure import (
    BodyStructureResearchError,
    analyze_body_structure_corpus,
)
from deebot_client.diagnostics.goat_map_delta import validate_delta_output_path

_DEFAULT_PHASE_PREFIXES = tuple(f"p2-{number:02d}" for number in range(1, 9))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify Phase 2 artifacts and analyze opaque offset-34+ remainders "
            "separately for every exact bytes-17..33 signature."
        )
    )
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument(
        "--phase-prefix",
        action="append",
        default=[],
        help="Artifact phase prefix; defaults to p2-01 through p2-08.",
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    """Write metadata-only analysis outside every immutable artifact."""
    args = _parser().parse_args()
    prefixes = tuple(args.phase_prefix) or _DEFAULT_PHASE_PREFIXES
    artifact_dirs = _discover_artifacts(args.artifact_root, prefixes)
    validate_delta_output_path(args.output, *artifact_dirs)
    report = analyze_body_structure_corpus(artifact_dirs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(orjson.dumps(report, option=orjson.OPT_INDENT_2) + b"\n")
    corpus = report["corpus"]
    priority = report["priority_order"][0]
    print(f"Read-only body-structure report: {args.output.resolve()}")
    print(
        "Corpus: "
        f"captures={corpus['capture_count']} samples={corpus['sample_count']} "
        f"signatures={corpus['exact_signature_count']} "
        f"excluded={corpus['excluded_sample_count']}"
    )
    print(
        "First priority: "
        f"signature={priority['signature_id']} reason={priority['reason']} "
        f"identical_samples={priority['max_identical_cross_capture_sample_count']}"
    )
    print("Body parser/decoder: disabled")
    return 0


def _discover_artifacts(root: Path, prefixes: tuple[str, ...]) -> tuple[Path, ...]:
    if not root.is_dir():
        message = f"Artifact root is not a directory: {root}"
        raise BodyStructureResearchError(message)
    artifact_dirs = tuple(
        sorted(
            path
            for path in root.iterdir()
            if path.is_dir()
            and path.name.startswith(prefixes)
            and (path / "manifest.json").is_file()
        )
    )
    if not artifact_dirs:
        raise BodyStructureResearchError("No matching Phase 2 artifacts were found")
    return artifact_dirs


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BodyStructureResearchError as err:
        print(f"Body-structure analysis failed: {err}", file=sys.stderr)
        sys.exit(2)
