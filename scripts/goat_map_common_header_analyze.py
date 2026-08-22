"""Build a read-only onMI/onArI common-header report."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import orjson

from deebot_client.diagnostics.goat_map_common_header import (
    CommonHeaderResearchError,
    analyze_cross_family_common_header_corpus,
)
from deebot_client.diagnostics.goat_map_delta import validate_delta_output_path

_DEFAULT_PHASE_PREFIXES = tuple(f"p2-{number:02d}" for number in range(1, 9))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify existing Phase 2 artifacts and compare the proven onMI forms "
            "with complete grouped onArI derived streams without parsing them."
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
    report = analyze_cross_family_common_header_corpus(artifact_dirs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(orjson.dumps(report, option=orjson.OPT_INDENT_2) + b"\n")
    corpus = report["corpus"]
    common = report["longest_common_prefix"]["entire_corpus"]
    structure = report["first_post_infoSize_structure_change"]
    print(f"Read-only common-header report: {args.output.resolve()}")
    print(
        "Corpus: "
        f"captures={corpus['capture_count']} samples={corpus['sample_count']} "
        f"excluded={corpus['excluded_sample_count']}"
    )
    print(f"Longest common prefix: {common['byte_length']} bytes ({common['hex']})")
    print(
        "Post-infoSize structure: "
        f"status={structure['status']} "
        f"first_variable_offset={structure['first_variable_offset']}"
    )
    print("Parser/decoder: disabled")
    return 0


def _discover_artifacts(root: Path, prefixes: tuple[str, ...]) -> tuple[Path, ...]:
    if not root.is_dir():
        raise CommonHeaderResearchError("Artifact root is not a directory")
    artifact_dirs = tuple(
        path
        for path in sorted(root.iterdir())
        if path.is_dir()
        and (path / "manifest.json").is_file()
        and any(path.name.startswith(prefix) for prefix in prefixes)
    )
    if not artifact_dirs:
        raise CommonHeaderResearchError("No matching Phase 2 artifacts were found")
    return artifact_dirs


if __name__ == "__main__":
    sys.exit(main())
