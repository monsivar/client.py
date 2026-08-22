"""Build a read-only offset-17+ structural corpus report."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import orjson

from deebot_client.diagnostics.goat_map_delta import validate_delta_output_path
from deebot_client.diagnostics.goat_map_inner_structure import (
    InnerStructureResearchError,
    analyze_inner_structure_corpus,
)

_DEFAULT_PHASE_PREFIXES = tuple(f"p2-{number:02d}" for number in range(1, 9))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify existing Phase 2 artifacts and analyze opaque bytes at "
            "offsets 17 through 63 without parsing their content."
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
    report = analyze_inner_structure_corpus(artifact_dirs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(orjson.dumps(report, option=orjson.OPT_INDENT_2) + b"\n")
    corpus = report["corpus"]
    offset_17 = report["offset_17_assessment"]
    print(f"Read-only inner-structure report: {args.output.resolve()}")
    print(
        "Corpus: "
        f"captures={corpus['capture_count']} samples={corpus['sample_count']} "
        f"excluded={corpus['excluded_sample_count']}"
    )
    print(
        "Offset 17: "
        f"stability={offset_17['column']['stability']} "
        f"raw_values={len(offset_17['column']['values'])}"
    )
    print("Structural-header extension/parser/decoder: disabled")
    return 0


def _discover_artifacts(root: Path, prefixes: tuple[str, ...]) -> tuple[Path, ...]:
    if not root.is_dir():
        message = f"Artifact root is not a directory: {root}"
        raise InnerStructureResearchError(message)
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
        raise InnerStructureResearchError("No matching Phase 2 artifacts were found")
    return artifact_dirs


if __name__ == "__main__":
    try:
        sys.exit(main())
    except InnerStructureResearchError as err:
        print(f"Inner-structure analysis failed: {err}", file=sys.stderr)
        sys.exit(2)
