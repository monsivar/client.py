"""Build a read-only cross-capture inventory for GOAT Phase 2 artifacts."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import orjson

from deebot_client.diagnostics.goat_map_delta import validate_delta_output_path
from deebot_client.diagnostics.goat_map_inventory import (
    CorpusInventoryError,
    analyze_phase2_corpus,
    inventory_csv,
)

_DEFAULT_PHASE_PREFIXES = tuple(f"p2-{number:02d}" for number in range(1, 8))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify and inventory existing GOAT Phase 2 artifacts without device "
            "calls, artifact modification, payload parsing, or semantic map decoding."
        )
    )
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument(
        "--phase-prefix",
        action="append",
        default=[],
        help="Artifact phase prefix to include; defaults to p2-01 through p2-07.",
    )
    parser.add_argument(
        "--summary-root",
        type=Path,
        default=Path.cwd(),
        help="Directory containing sanitized Phase 2 summary JSON files.",
    )
    parser.add_argument(
        "--summary-glob",
        default="goat-map-p2-*-summary.json",
        help="Glob used only for sanitized window timing metadata.",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inventory-csv", type=Path, required=True)
    return parser


def main() -> int:
    """Write metadata-only JSON analysis and CSV inventory outside artifacts."""
    args = _parser().parse_args()
    prefixes = tuple(args.phase_prefix) or _DEFAULT_PHASE_PREFIXES
    artifact_dirs = _discover_artifacts(args.artifact_root, prefixes)
    summary_paths = tuple(sorted(args.summary_root.glob(args.summary_glob)))
    validate_delta_output_path(args.output, *artifact_dirs)
    validate_delta_output_path(args.inventory_csv, *artifact_dirs)
    if args.output.resolve() == args.inventory_csv.resolve():
        raise ValueError("JSON and CSV outputs must be different files")

    report = analyze_phase2_corpus(
        artifact_dirs,
        summary_paths=summary_paths,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.inventory_csv.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(orjson.dumps(report, option=orjson.OPT_INDENT_2) + b"\n")
    args.inventory_csv.write_text(inventory_csv(report), encoding="utf-8", newline="")

    assessment = report["analysis"]["corpus_assessment"]
    print(f"Read-only corpus report: {args.output.resolve()}")
    print(f"Metadata inventory CSV: {args.inventory_csv.resolve()}")
    print(
        "Corpus: "
        f"captures={report['corpus']['capture_count']} "
        f"records={report['corpus']['record_count']} "
        f"inventory_rows={report['corpus']['inventory_row_count']}"
    )
    print(
        "Repeatability capture needed: "
        f"{assessment['non_editing_repeatability_capture_needed']}"
    )
    print("Payload/map decoding: disabled")
    return 0


def _discover_artifacts(root: Path, prefixes: tuple[str, ...]) -> tuple[Path, ...]:
    if not root.is_dir():
        raise CorpusInventoryError("Artifact root is not a directory")
    artifact_dirs = tuple(
        path
        for path in sorted(root.iterdir())
        if path.is_dir()
        and (path / "manifest.json").is_file()
        and any(path.name.startswith(prefix) for prefix in prefixes)
    )
    if not artifact_dirs:
        raise CorpusInventoryError("No matching Phase 2 artifacts were found")
    return artifact_dirs


if __name__ == "__main__":
    sys.exit(main())
