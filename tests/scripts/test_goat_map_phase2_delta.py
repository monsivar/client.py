from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from deebot_client.diagnostics.goat_map_delta import validate_delta_output_path

if TYPE_CHECKING:
    from pathlib import Path


def test_delta_output_must_not_modify_either_input_artifact(tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"

    with pytest.raises(ValueError, match="outside all input artifacts"):
        validate_delta_output_path(before / "delta.json", before, after)
    with pytest.raises(ValueError, match="outside all input artifacts"):
        validate_delta_output_path(after / "manifest.json", before, after)

    validate_delta_output_path(tmp_path / "delta.json", before, after)
