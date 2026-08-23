from __future__ import annotations

from typing import Any

import pytest

from deebot_client.diagnostics import goat_map_area_same_name
from deebot_client.diagnostics.goat_map_area_noop_save import AreaNoOpSaveReference
from deebot_client.diagnostics.goat_map_area_same_name import (
    _same_name_statuses,
    classify_same_name_area_delta,
    evaluate_area_same_name_preconditions,
)
from deebot_client.diagnostics.goat_map_area_split import (
    AreaSplitCaptureConfig,
    AreaSplitEvidenceObserver,
    _operation_label_value,
)


def _area_state(digest: str, *, status: str = "stable") -> dict[str, Any]:
    return {
        "status": status,
        "infoSize": 286,
        "representation": {"length": 124, "sha256": digest},
        "strict_base64_derived": {
            "status": "strict-base64-round-trip-proven",
            "length": 91,
            "sha256": digest,
        },
    }


def test_same_name_config_requires_five_byte_values_and_reopen() -> None:
    with pytest.raises(ValueError, match="post-save reopen"):
        AreaSplitCaptureConfig(
            operation="same-name-resubmission",
            reference_artifact_dir="p2-12c",
            expected_reference_capture_id="a" * 32,
            old_name_utf8_byte_length=5,
            new_name_utf8_byte_length=5,
        )
    with pytest.raises(ValueError, match="two five-byte names"):
        AreaSplitCaptureConfig(
            operation="same-name-resubmission",
            reference_artifact_dir="p2-12c",
            expected_reference_capture_id="a" * 32,
            old_name_utf8_byte_length=5,
            new_name_utf8_byte_length=4,
            post_split_reopen=True,
        )

    config = AreaSplitCaptureConfig(
        operation="same-name-resubmission",
        reference_artifact_dir="p2-12c",
        expected_reference_capture_id="a" * 32,
        old_name_utf8_byte_length=5,
        new_name_utf8_byte_length=5,
        post_split_reopen=True,
    )
    assert _operation_label_value(config, "pre-split-app-init-1") == (
        "pre-same-name-app-init-1"
    )
    assert _operation_label_value(config, "split-save") == "same-name-save"
    assert _operation_label_value(config, "post-split-reopen") == (
        "post-same-name-reopen"
    )


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        ("a", "a", "same-value-resubmission-no-structural-change"),
        ("a", "b", "same-value-resubmission-associated-structural-change"),
    ],
)
def test_same_name_area_delta_classification(
    before: str,
    after: str,
    expected: str,
) -> None:
    result = classify_same_name_area_delta(
        _area_state(before),
        _area_state(after),
    )
    assert result["classification"] == expected
    assert result["semantic_mapping"] is False


def test_same_name_area_delta_requires_stable_post_state() -> None:
    result = classify_same_name_area_delta(
        _area_state("a"),
        _area_state("b", status="missing-or-unstable-post-window"),
    )
    assert result["classification"] == "not-comparable"


def test_same_name_gate_is_separate_from_noop_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        goat_map_area_same_name,
        "evaluate_area_noop_save_preconditions",
        lambda *_args, **_kwargs: {
            "status": "passed",
            "result": "precondition-passed",
            "checks": {},
            "failures": [],
            "split_edit_gate_open": False,
            "noop_save_edit_gate_open": True,
            "reference": {"state": "old"},
        },
    )
    result = evaluate_area_same_name_preconditions(
        {"status": "passed", "checks": {}, "failures": []},
        AreaSplitEvidenceObserver(lambda: "init"),
        init_1_window="init-1",
        init_2_window="init-2",
        reference=AreaNoOpSaveReference("c" * 32, "p2-12c", state={}),
        capture_records=(),
    )

    assert result["same_name_resubmission_edit_gate_open"] is True
    assert result["noop_save_edit_gate_open"] is False
    assert result["reference"]["state"].endswith("before-same-name")


def test_role_coverage_is_not_an_input_to_same_name_area_delta_status() -> None:
    experiment, delta = _same_name_statuses(
        execution_completed=True,
        area_comparable=True,
    )
    assert experiment == "completed-action"
    assert delta == "controlled-structural-evidence"
