"""Build a read-only onArI burst/framing report from Phase 2 artifacts."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import orjson

from deebot_client.diagnostics.goat_map_delta import validate_delta_output_path
from deebot_client.diagnostics.goat_map_on_ari_analysis import (
    OnAriAnalysisError,
    analyze_on_ari_corpus,
)

_DEFAULT_PHASE_PREFIXES = tuple(f"p2-{number:02d}" for number in range(1, 9))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify existing Phase 2 artifacts and analyze opaque onArI burst, "
            "Base64, envelope, and framing structure without reconstruction."
        )
    )
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument(
        "--phase-prefix",
        action="append",
        default=[],
        help="Artifact phase prefix; defaults to p2-01 through p2-08.",
    )
    parser.add_argument(
        "--burst-threshold-microseconds",
        type=int,
        default=250_000,
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    """Write metadata-only analysis outside every immutable artifact."""
    args = _parser().parse_args()
    prefixes = tuple(args.phase_prefix) or _DEFAULT_PHASE_PREFIXES
    artifact_dirs = _discover_artifacts(args.artifact_root, prefixes)
    validate_delta_output_path(args.output, *artifact_dirs)
    report = analyze_on_ari_corpus(
        artifact_dirs,
        burst_threshold_microseconds=args.burst_threshold_microseconds,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(orjson.dumps(report, option=orjson.OPT_INDENT_2) + b"\n")
    corpus = report["corpus"]
    base64 = report["strict_base64_assessment"]
    print(f"Read-only onArI report: {args.output.resolve()}")
    print(
        "Corpus: "
        f"captures={corpus['capture_count']} "
        f"onArI={corpus['on_ari_occurrence_count']} "
        f"bursts={corpus['burst_count']} "
        f"multi={corpus['multi_message_burst_count']}"
    )
    print(
        "Strict Base64: "
        f"valid={base64['valid_count']} invalid={base64['invalid_count']}"
    )
    print("Chunk reconstruction/map decoding: disabled")
    return 0


def _discover_artifacts(root: Path, prefixes: tuple[str, ...]) -> tuple[Path, ...]:
    if not root.is_dir():
        raise OnAriAnalysisError("Artifact root is not a directory")
    artifact_dirs = tuple(
        path
        for path in sorted(root.iterdir())
        if path.is_dir()
        and (path / "manifest.json").is_file()
        and any(path.name.startswith(prefix) for prefix in prefixes)
    )
    if not artifact_dirs:
        raise OnAriAnalysisError("No matching Phase 2 artifacts were found")
    return artifact_dirs


if __name__ == "__main__":
    sys.exit(main())
