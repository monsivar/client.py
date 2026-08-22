"""Build a read-only grouped onArI framing-research report."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import orjson

from deebot_client.diagnostics.goat_map_delta import validate_delta_output_path
from deebot_client.diagnostics.goat_map_on_ari_framing import (
    OnAriFramingResearchError,
    analyze_on_ari_grouped_framing_corpus,
)

_DEFAULT_PHASE_PREFIXES = tuple(f"p2-{number:02d}" for number in range(1, 9))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify existing Phase 2 artifacts and analyze complete opaque onArI "
            "segment sets without parsing their derived bytes."
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
    report = analyze_on_ari_grouped_framing_corpus(artifact_dirs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(orjson.dumps(report, option=orjson.OPT_INDENT_2) + b"\n")
    corpus = report["corpus"]
    info_size = next(
        item
        for item in report["field_candidates"]["relations"]
        if item["relation"] == "equals-envelope-infoSize"
    )
    print(f"Read-only grouped onArI framing report: {args.output.resolve()}")
    print(
        "Corpus: "
        f"captures={corpus['capture_count']} "
        f"complete_groups={corpus['complete_group_count']} "
        f"excluded={corpus['excluded_group_count']}"
    )
    print(f"Envelope infoSize relation: {info_size['status']}")
    print("Framing parser/codec execution: disabled")
    return 0


def _discover_artifacts(root: Path, prefixes: tuple[str, ...]) -> tuple[Path, ...]:
    if not root.is_dir():
        raise OnAriFramingResearchError("Artifact root is not a directory")
    artifact_dirs = tuple(
        path
        for path in sorted(root.iterdir())
        if path.is_dir()
        and (path / "manifest.json").is_file()
        and any(path.name.startswith(prefix) for prefix in prefixes)
    )
    if not artifact_dirs:
        raise OnAriFramingResearchError("No matching Phase 2 artifacts were found")
    return artifact_dirs


if __name__ == "__main__":
    sys.exit(main())
