"""Inspect opaque onMI.info representations without modifying the artifact."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import orjson

from deebot_client.diagnostics.goat_map_blob_inspection import (
    inspect_onmi_info_artifact,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only structural inspection of captured onMI.info blobs. "
            "No map decoding or artifact writes are performed."
        )
    )
    parser.add_argument("--artifact-dir", required=True, type=Path)
    return parser


def main() -> int:
    """Print sanitized representation metrics for one local artifact."""
    args = _parser().parse_args()
    result = inspect_onmi_info_artifact(args.artifact_dir)
    print(orjson.dumps(result, option=orjson.OPT_INDENT_2).decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
