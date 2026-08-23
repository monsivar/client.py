"""Generate a sanitized read-only A/B/C differential for controlled Area edits."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any

import orjson

from deebot_client.diagnostics.goat_map_delta import validate_delta_output_path
from deebot_client.diagnostics.goat_map_three_state import (
    ThreeStateAnalysisError,
    analyze_controlled_area_three_state,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compare immutable P2-09c original/post-Divide bytes with the clean "
            "P2-10d post-Merge readback. No payload decoding beyond the proven "
            "strict Base64 representation layer is performed."
        )
    )
    parser.add_argument("--split-artifact", type=Path, required=True)
    parser.add_argument("--merge-artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    """Verify both artifacts and publish only derived metadata outside them."""
    args = _parser().parse_args()
    validate_delta_output_path(
        args.output,
        args.split_artifact,
        args.merge_artifact,
    )
    report = analyze_controlled_area_three_state(
        args.split_artifact,
        args.merge_artifact,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(orjson.dumps(report, option=orjson.OPT_INDENT_2) + b"\n")

    area = report["getAreaSet_type_ar"]["original_representation"]
    on_ari = report["grouped_onArI"]["full_derived_stream"]
    similarity = report["grouped_onArI"]["similarity_assessment"]
    print(f"Read-only three-state report: {args.output.resolve()}")
    print(
        "AreaSet ar: "
        f"classification={area['whole_value_classification']} "
        f"lengths={_lengths(area)}"
    )
    print(
        "Grouped onArI: "
        f"classification={on_ari['whole_value_classification']} "
        f"lengths={_lengths(on_ari)} "
        f"post-merge-closer-to={similarity['post_merge_C_is_closer_to']}"
    )
    print("Semantic parser/geometry interpretation: disabled")
    return 0


def _lengths(report: dict[str, Any]) -> str:
    states = report["states"]
    return "/".join(str(states[name]["length"]) for name in ("A", "B", "C"))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ThreeStateAnalysisError as err:
        print(f"Three-state analysis failed: {err}", file=sys.stderr)
        sys.exit(2)
