"""Compare proven onMI.info representation bytes without map interpretation."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any

import orjson

from deebot_client.diagnostics.goat_map_framing_research import (
    analyze_onmi_framing_pair,
)

_DEFAULT_FIXTURE = Path("tests/fixtures/goat_map/onmi_info_representations.json")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only framing-candidate analysis after strict Base64. "
            "No framing parser or map decoding is performed."
        )
    )
    parser.add_argument("--fixture", type=Path, default=_DEFAULT_FIXTURE)
    return parser


def _load_fixture(path: Path) -> list[dict[str, Any]]:
    parsed = orjson.loads(path.read_bytes())
    if not isinstance(parsed, list) or len(parsed) != 2:
        raise ValueError("Framing fixture must contain exactly two representations")
    if any(
        not isinstance(item, dict) or not isinstance(item.get("original"), str)
        for item in parsed
    ):
        raise ValueError("Framing fixture representations must contain original text")
    return parsed


def main() -> int:
    """Print non-semantic framing candidates for the golden pair."""
    args = _parser().parse_args()
    fixtures = _load_fixture(args.fixture)
    result = analyze_onmi_framing_pair(
        fixtures[0]["original"],
        fixtures[1]["original"],
        first_info_size=fixtures[0].get("info_size"),
        second_info_size=fixtures[1].get("info_size"),
    )
    print(orjson.dumps(result, option=orjson.OPT_INDENT_2).decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
