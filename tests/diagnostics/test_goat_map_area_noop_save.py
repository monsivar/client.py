from __future__ import annotations

from typing import Any

import pytest

from deebot_client.diagnostics import goat_map_area_noop_save
from deebot_client.diagnostics.goat_map_area_noop_save import (
    AreaNoOpSaveReference,
    _noop_save_statuses,
    classify_noop_save_area_delta,
    evaluate_area_noop_save_preconditions,
)
from deebot_client.diagnostics.goat_map_area_split import (
    AreaSplitCaptureConfig,
    AreaSplitEvidenceObserver,
    AreaSplitState,
    AreaSplitStateMachine,
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


def test_noop_save_config_requires_reference_and_reopen() -> None:
    with pytest.raises(ValueError, match="immutable reference"):
        AreaSplitCaptureConfig(operation="noop-save", post_split_reopen=True)
    with pytest.raises(ValueError, match="post-save reopen"):
        AreaSplitCaptureConfig(
            operation="noop-save",
            reference_artifact_dir="p2-12c",
            expected_reference_capture_id="a" * 32,
        )

    config = AreaSplitCaptureConfig(
        operation="noop-save",
        reference_artifact_dir="p2-12c",
        expected_reference_capture_id="a" * 32,
        post_split_reopen=True,
    )
    assert _operation_label_value(config, "pre-split-app-init-1") == (
        "pre-noop-save-app-init-1"
    )
    assert _operation_label_value(config, "split-edit") == "no-op-edit"
    assert _operation_label_value(config, "split-save") == "no-op-save"
    assert _operation_label_value(config, "post-split-reopen") == (
        "post-noop-save-reopen"
    )


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        ("a", "a", "no-op-save-no-structural-change"),
        ("a", "b", "no-op-save-associated-structural-change"),
    ],
)
def test_noop_save_area_delta_classification(
    before: str,
    after: str,
    expected: str,
) -> None:
    result = classify_noop_save_area_delta(
        _area_state(before),
        _area_state(after),
    )
    assert result["classification"] == expected
    assert result["semantic_mapping"] is False


def test_noop_save_area_delta_requires_stable_post_state() -> None:
    result = classify_noop_save_area_delta(
        _area_state("a"),
        _area_state("b", status="missing-or-unstable-post-window"),
    )
    assert result["classification"] == "not-comparable"


def test_role_coverage_is_not_an_input_to_noop_area_delta_status() -> None:
    experiment, delta = _noop_save_statuses(
        execution_completed=True,
        area_comparable=True,
    )
    assert experiment == "completed-action"
    assert delta == "controlled-structural-evidence"


def test_noop_save_gate_uses_p2_12c_reference_and_preserves_base_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshots = {
        "init-1": {"special_contour": []},
        "init-2": {"special_contour": []},
    }
    monkeypatch.setattr(
        goat_map_area_noop_save,
        "_observer_snapshot",
        lambda _evidence, windows: snapshots[windows[0]],
    )
    monkeypatch.setattr(
        goat_map_area_noop_save,
        "_capture_special_snapshot",
        lambda _records, _windows: [{"sha256": "a"}],
    )
    monkeypatch.setattr(
        goat_map_area_noop_save,
        "_restore_snapshot_checks",
        lambda _first, _second, _reference: {
            "AreaSet_ar": {"status": "passed", "reason": None}
        },
    )
    reference = AreaNoOpSaveReference("c" * 32, "p2-12c", state={})
    observer = AreaSplitEvidenceObserver(lambda: "init-1")
    passed = evaluate_area_noop_save_preconditions(
        {"status": "passed", "checks": {}, "failures": []},
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        reference=reference,
        capture_records=(),
    )
    failed = evaluate_area_noop_save_preconditions(
        {
            "status": "inconclusive",
            "checks": {},
            "failures": [{"check": "controlled-source-isolation", "reason": "x"}],
        },
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        reference=reference,
        capture_records=(),
    )

    assert passed["noop_save_edit_gate_open"] is True
    assert passed["split_edit_gate_open"] is False
    assert passed["reference"]["capture_id"] == "c" * 32
    assert failed["noop_save_edit_gate_open"] is False
    assert failed["status"] == "inconclusive"


def test_operator_can_abort_from_edit_before_save() -> None:
    machine = AreaSplitStateMachine()
    for state in (
        AreaSplitState.PRE_SPLIT_BASELINE,
        AreaSplitState.PRE_SPLIT_APP_INIT_1,
        AreaSplitState.PRE_SPLIT_APP_INIT_QUIET,
        AreaSplitState.PRE_SPLIT_APP_INIT_2,
        AreaSplitState.PRECONDITION_EVALUATION,
    ):
        machine.transition(state)
    machine.transition(AreaSplitState.SPLIT_EDIT, precondition_status="passed")
    machine.transition(AreaSplitState.INCONCLUSIVE)

    assert machine.state is AreaSplitState.INCONCLUSIVE
    assert all(item["to"] != "split-save" for item in machine.history)
