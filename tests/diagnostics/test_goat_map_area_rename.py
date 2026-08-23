from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import orjson
import pytest

from deebot_client.diagnostics.goat_map_area_merge import _observer_snapshot
from deebot_client.diagnostics.goat_map_area_rename import (
    AreaRenameReference,
    _rename_result_class,
    add_area_rename_analysis,
    evaluate_area_rename_preconditions,
)
from deebot_client.diagnostics.goat_map_area_split import (
    AreaSplitCaptureConfig,
    AreaSplitEvidenceObserver,
    _operation_label_value,
    evaluate_area_split_preconditions,
)
from deebot_client.diagnostics.goat_map_refresh import MowerState

_GOLDEN_ONMI = (
    Path(__file__).parents[1]
    / "fixtures"
    / "goat_map"
    / "onmi_info_representations.json"
)
_PREFIX = bytes.fromhex("5d00000400")
_INVARIANT = bytes.fromhex("002d96c042005e")
_SIGNATURE = bytes.fromhex("c8c9b157b2874a80dcc06c3923718e503b")


def _topic(command: str, direction: str) -> str:
    if direction == "event":
        return f"iot/atr/{command}/device/class/resource/j"
    marker = "q" if direction == "request" else "p"
    return f"iot/p2p/{command}/a/b/c/d/e/f/{marker}/id/j"


def _payload(data: dict[str, Any]) -> bytes:
    return orjson.dumps({"body": {"data": data}})


def _populate(
    observer: AreaSplitEvidenceObserver,
    *,
    at: datetime,
    batid: str,
    area_ar: str = "stable-c-area",
) -> None:
    fixture = next(
        item
        for item in orjson.loads(_GOLDEN_ONMI.read_bytes())
        if item["label"] == "immediate-876"
    )
    observer.observe_mqtt(_topic("getMI", "request"), b"{}", observed_at=at)
    observer.observe_mqtt(
        _topic("onMI", "event"),
        _payload(
            {
                "mid": "1",
                "infoSize": fixture["info_size"],
                "info": fixture["original"],
            }
        ),
        observed_at=at + timedelta(milliseconds=10),
    )
    for kind, value in (("ar", area_ar), ("vw", "stable-vw")):
        observer.observe_mqtt(
            _topic("getAreaSet", "response"),
            _payload(
                {
                    "mid": "1",
                    "aid": "0",
                    "type": kind,
                    "infoSize": len(value),
                    "subsets": value,
                }
            ),
            observed_at=at + timedelta(milliseconds=20),
        )
    info_size = 6933
    framed = (
        _PREFIX
        + info_size.to_bytes(4, "little")
        + _INVARIANT
        + b"\x14"
        + _SIGNATURE
        + b"\x33" * 700
    )
    third = len(framed) // 3
    chunks = (framed[:third], framed[third : third * 2], framed[third * 2 :])
    for index, chunk in enumerate(chunks):
        observer.observe_mqtt(
            _topic("onArI", "event"),
            _payload(
                {
                    "batid": batid,
                    "serial": "3",
                    "index": str(index),
                    "infoSize": info_size,
                    "mid": "1",
                    "type": 0,
                    "using": 1,
                    "info": base64.b64encode(chunk).decode("ascii"),
                }
            ),
            observed_at=at + timedelta(milliseconds=30 + index),
        )


def _special_record(window: str) -> dict[str, Any]:
    return {
        "window": window,
        "command": "getSpecialContour",
        "direction": "response",
        "opaque_segments": [
            {
                "source_path": "$.header.fwVer",
                "representations": {
                    "original": {"byte_length": 7, "sha256": "a" * 64}
                },
            }
        ],
    }


def _reference_snapshot(
    observer: AreaSplitEvidenceObserver,
    window: str,
) -> dict[str, Any]:
    snapshot = _observer_snapshot(observer, (window,))
    snapshot["special_contour"] = [
        {
            "command": "getSpecialContour",
            "direction": "response",
            "source_path": "$.header.fwVer",
            "byte_length": 7,
            "sha256": "a" * 64,
        }
    ]
    return snapshot


def test_rename_config_requires_reference_lengths_and_reopen() -> None:
    with pytest.raises(ValueError, match="immutable reference"):
        AreaSplitCaptureConfig(operation="rename")
    with pytest.raises(ValueError, match="Divide write reference"):
        AreaSplitCaptureConfig(
            operation="rename",
            reference_artifact_dir="c-state",
            expected_reference_capture_id="a" * 32,
        )
    with pytest.raises(ValueError, match="UTF-8 name lengths"):
        AreaSplitCaptureConfig(
            operation="rename",
            reference_artifact_dir="c-state",
            expected_reference_capture_id="a" * 32,
            divide_reference_artifact_dir="divide",
            expected_divide_reference_capture_id="b" * 32,
        )
    with pytest.raises(ValueError, match="post-save reopen"):
        AreaSplitCaptureConfig(
            operation="rename",
            reference_artifact_dir="c-state",
            expected_reference_capture_id="a" * 32,
            divide_reference_artifact_dir="divide",
            expected_divide_reference_capture_id="b" * 32,
            old_name_utf8_byte_length=5,
            new_name_utf8_byte_length=5,
        )


def test_rename_gate_requires_two_exact_c_state_readbacks() -> None:
    window = ["init-1"]
    observer = AreaSplitEvidenceObserver(lambda: window[0])
    started = datetime(2026, 8, 23, 12, tzinfo=UTC)
    _populate(observer, at=started, batid="first")
    reference = _reference_snapshot(observer, "init-1")
    window[0] = "init-2"
    _populate(observer, at=started + timedelta(minutes=1), batid="second")
    base = evaluate_area_split_preconditions(
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        allowed_app_windows=("init-1", "init-2"),
    )

    result = evaluate_area_rename_preconditions(
        base,
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        reference=AreaRenameReference("c" * 32, "p2-10d", reference),
        capture_records=(_special_record("init-1"), _special_record("init-2")),
    )

    assert result["status"] == "passed"
    assert result["split_edit_gate_open"] is False
    assert result["rename_edit_gate_open"] is True
    assert all(
        item["status"] == "passed"
        for item in result["checks"]["p2_10d_c_state"].values()
    )


def test_rename_gate_aborts_when_current_c_state_differs() -> None:
    window = ["init-1"]
    observer = AreaSplitEvidenceObserver(lambda: window[0])
    started = datetime(2026, 8, 23, 12, tzinfo=UTC)
    _populate(observer, at=started, batid="first")
    reference = _reference_snapshot(observer, "init-1")
    window[0] = "init-2"
    _populate(
        observer,
        at=started + timedelta(minutes=1),
        batid="second",
        area_ar="different-area",
    )
    base = evaluate_area_split_preconditions(
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        allowed_app_windows=("init-1", "init-2"),
    )

    result = evaluate_area_rename_preconditions(
        base,
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        reference=AreaRenameReference("c" * 32, "p2-10d", reference),
        capture_records=(_special_record("init-1"), _special_record("init-2")),
    )

    assert result["status"] == "inconclusive"
    assert result["rename_edit_gate_open"] is False
    assert "p2-10d-c-state-AreaSet_ar" in {
        item["check"] for item in result["failures"]
    }


@pytest.mark.parametrize(
    ("area", "on_ari", "expected"),
    [
        ("unchanged", "occurrence-count-changed", "byte-identical-static-families"),
        (
            "value-changed",
            "unchanged",
            "rename-associated-AreaSet-only-structural-change",
        ),
        (
            "unchanged",
            "value-changed",
            "rename-associated-onArI-only-structural-change",
        ),
        (
            "value-changed",
            "value-changed",
            "rename-associated-metadata-edit-associated-structural-change",
        ),
        ("before-only", "unchanged", "not-comparable"),
    ],
)
def test_rename_result_classification_is_non_semantic(
    area: str,
    on_ari: str,
    expected: str,
) -> None:
    assert _rename_result_class(area, on_ari) == expected


def test_rename_post_state_combines_save_and_passive_windows(tmp_path: Path) -> None:
    window = ["before"]
    observer = AreaSplitEvidenceObserver(lambda: window[0])
    started = datetime(2026, 8, 23, 12, tzinfo=UTC)
    _populate(observer, at=started, batid="before")
    window[0] = "rename-save"
    _populate(observer, at=started + timedelta(minutes=1), batid="primary")
    window[0] = "reopen"
    _populate(observer, at=started + timedelta(minutes=2), batid="reopen")
    records = (
        _special_record("before"),
        _special_record("rename-save"),
        _special_record("reopen"),
    )
    report: dict[str, Any] = {
        "controlled_area_rename": {
            "experiment_status": "complete",
            "delta_status": "controlled-structural-evidence",
            "windows": {
                "rename_edit": "rename-edit",
                "rename_save": "rename-save",
            },
            "write_attribution": {
                "status": "unattributed",
                "authoritative_command": None,
            },
            "comparison": {
                "getAreaSet": {
                    "groups": [
                        {
                            "key": {"mid": "1", "aid": "0", "type": "ar"},
                            "status": "unchanged",
                        }
                    ]
                },
                "grouped_onArI": {
                    "groups": [
                        {
                            "key": {"mid": "1", "type": "0", "serial": 3},
                            "status": "occurrence-count-changed",
                        }
                    ]
                },
            },
        }
    }

    add_area_rename_analysis(
        report,
        observer,
        before_window="before",
        primary_post_windows=("rename-save", "post-readback"),
        reopen_window="reopen",
        capture_records=records,
        divide_reference_artifact=tmp_path / "unused",
    )

    analysis = report["controlled_area_rename"]["rename_analysis"]
    assert analysis["post_state_stability"]["status"] == "passed"
    assert analysis["post_state_stability"]["primary_windows"] == [
        "rename-save",
        "post-readback",
    ]
    assert analysis["result_classification"] == "byte-identical-static-families"
    assert analysis["interpretation"]["name_bytes_located_in_structure"] is False
    assert analysis["interpretation"][
        "general_save_or_edit_generation_remains_alternative"
    ] is True


def test_rename_window_labels_do_not_change_internal_state_machine() -> None:
    config = AreaSplitCaptureConfig(
        operation="rename",
        reference_artifact_dir="c-state",
        expected_reference_capture_id="a" * 32,
        divide_reference_artifact_dir="divide",
        expected_divide_reference_capture_id="b" * 32,
        old_name_utf8_byte_length=5,
        new_name_utf8_byte_length=5,
        post_split_reopen=True,
    )

    assert _operation_label_value(config, "pre-split-app-init-1") == (
        "pre-rename-app-init-1"
    )
    assert _operation_label_value(config, "split-save") == "rename-save"
    assert _operation_label_value(config, "post-split-reopen") == (
        "post-rename-reopen"
    )
    assert config.mower_state is MowerState.PAUSED
