from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any

import orjson
import pytest

from deebot_client.diagnostics.goat_map_area_merge import _observer_snapshot
from deebot_client.diagnostics.goat_map_area_rename_restore import (
    AreaRenameRestoreReference,
    _restore_statuses,
    _role_comparison_review,
    _three_state_area_analysis,
    evaluate_area_rename_restore_preconditions,
)
from deebot_client.diagnostics.goat_map_area_split import (
    AreaSplitCaptureConfig,
    AreaSplitEvidenceObserver,
    _operation_label_value,
    evaluate_area_split_preconditions,
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
) -> None:
    info_size = 6933
    on_mi = (
        _PREFIX
        + (1756).to_bytes(4, "little")
        + _INVARIANT
        + b"\x11"
        + b"\x22" * 17
        + b"\x44" * 20
    )
    observer.observe_mqtt(_topic("getMI", "request"), b"{}", observed_at=at)
    observer.observe_mqtt(
        _topic("onMI", "event"),
        _payload(
            {
                "mid": "1",
                "infoSize": 1756,
                "info": base64.b64encode(on_mi).decode("ascii"),
            }
        ),
        observed_at=at + timedelta(milliseconds=10),
    )
    for kind, value in (("ar", "stable-b-area"), ("vw", "stable-vw")):
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
                "source_path": "$.body.data.info",
                "representations": {
                    "original": {"byte_length": 4, "sha256": "a" * 64}
                },
            }
        ],
    }


def _snapshot(
    observer: AreaSplitEvidenceObserver,
    window: str,
) -> dict[str, Any]:
    result = _observer_snapshot(observer, (window,))
    result["special_contour"] = [
        {
            "command": "getSpecialContour",
            "direction": "response",
            "source_path": "$.body.data.info",
            "byte_length": 4,
            "sha256": "a" * 64,
        }
    ]
    return result


def _area_state(digest: str, *, status: str = "stable") -> dict[str, Any]:
    return {
        "status": status,
        "infoSize": 1,
        "representation": {"length": 4, "sha256": digest},
        "strict_base64_derived": {
            "status": "strict-base64-round-trip-proven",
            "length": 1,
            "sha256": digest,
        },
    }


def test_restore_config_requires_exact_five_byte_names() -> None:
    with pytest.raises(ValueError, match="two five-byte names"):
        AreaSplitCaptureConfig(
            operation="rename",
            reference_artifact_dir="p2-11",
            expected_reference_capture_id="a" * 32,
            divide_reference_artifact_dir="p2-09c",
            expected_divide_reference_capture_id="b" * 32,
            post_split_reopen=True,
            rename_restore=True,
            old_name_utf8_byte_length=5,
            new_name_utf8_byte_length=4,
        )

    config = AreaSplitCaptureConfig(
        operation="rename",
        reference_artifact_dir="p2-11",
        expected_reference_capture_id="a" * 32,
        divide_reference_artifact_dir="p2-09c",
        expected_divide_reference_capture_id="b" * 32,
        post_split_reopen=True,
        rename_restore=True,
        old_name_utf8_byte_length=5,
        new_name_utf8_byte_length=5,
    )
    assert _operation_label_value(config, "pre-split-app-init-1") == (
        "pre-restore-app-init-1"
    )
    assert _operation_label_value(config, "split-save") == "restore-save"
    assert _operation_label_value(config, "post-split-reopen") == (
        "post-restore-reopen"
    )


def test_restore_gate_requires_two_exact_p2_11_b_state_readbacks() -> None:
    window = ["init-1"]
    observer = AreaSplitEvidenceObserver(lambda: window[0])
    started = datetime(2026, 8, 23, 12, tzinfo=UTC)
    _populate(observer, at=started, batid="first")
    reference = _snapshot(observer, "init-1")
    window[0] = "init-2"
    _populate(observer, at=started + timedelta(minutes=1), batid="second")
    base = evaluate_area_split_preconditions(
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        allowed_app_windows=("init-1", "init-2"),
    )

    result = evaluate_area_rename_restore_preconditions(
        base,
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        reference=AreaRenameRestoreReference(
            "c" * 32,
            "p2-11",
            a_state=reference,
            b_state=reference,
        ),
        capture_records=(_special_record("init-1"), _special_record("init-2")),
    )

    assert result["status"] == "passed"
    assert result["rename_restore_edit_gate_open"] is True
    assert result["rename_edit_gate_open"] is False
    assert result["split_edit_gate_open"] is False


def test_restore_gate_aborts_when_second_readback_differs() -> None:
    window = ["init-1"]
    observer = AreaSplitEvidenceObserver(lambda: window[0])
    started = datetime(2026, 8, 23, 12, tzinfo=UTC)
    _populate(observer, at=started, batid="first")
    reference = _snapshot(observer, "init-1")
    window[0] = "init-2"
    _populate(observer, at=started + timedelta(minutes=1), batid="second")
    observer.observe_mqtt(
        _topic("getAreaSet", "response"),
        _payload(
            {
                "mid": "1",
                "aid": "0",
                "type": "ar",
                "infoSize": 9,
                "subsets": "different",
            }
        ),
        observed_at=started + timedelta(minutes=1, milliseconds=50),
    )
    base = evaluate_area_split_preconditions(
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        allowed_app_windows=("init-1", "init-2"),
    )

    result = evaluate_area_rename_restore_preconditions(
        base,
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        reference=AreaRenameRestoreReference(
            "c" * 32,
            "p2-11",
            a_state=reference,
            b_state=reference,
        ),
        capture_records=(_special_record("init-1"), _special_record("init-2")),
    )

    assert result["status"] == "inconclusive"
    assert result["rename_restore_edit_gate_open"] is False
    assert "p2-11-b-state-AreaSet_ar" in {
        item["check"] for item in result["failures"]
    }


@pytest.mark.parametrize(
    ("a", "b", "c", "expected"),
    [
        ("a", "b", "a", "byte-restored"),
        ("a", "b", "b", "persistent-rename-state"),
        ("a", "b", "c", "stable-third-encoding"),
    ],
)
def test_area_ar_three_state_classification(
    a: str,
    b: str,
    c: str,
    expected: str,
) -> None:
    result = _three_state_area_analysis(
        _area_state(a),
        _area_state(b),
        _area_state(c),
    )
    assert result["classification"] == expected
    assert result["comparison_layers"] == [
        "original-representation-bytes",
        "strict-base64-derived-bytes",
        "length",
        "sha256",
        "infoSize",
    ]


def test_area_ar_three_state_requires_comparable_post_restore_value() -> None:
    result = _three_state_area_analysis(
        _area_state("a"),
        _area_state("b"),
        _area_state("c", status="missing-or-unstable-post-window"),
    )
    assert result["classification"] == "not-comparable"


def test_missing_role_overlap_is_incomplete_not_contradictory() -> None:
    before = {
        "area_set": [],
        "on_mi": [
            {
                "association": "request-associated",
                "original_length": 876,
                "original_sha256": "a",
                "info_size": 1756,
            }
        ],
        "on_ari": [],
        "special_contour": [],
    }
    primary = {
        "area_set": [],
        "on_mi": [
            {
                "association": "cadence-associated",
                "original_length": 52,
                "original_sha256": "b",
                "info_size": 25,
            }
        ],
        "on_ari": [],
        "special_contour": [],
    }
    reopen = before

    review = _role_comparison_review(before, primary, reopen)

    assert review["status"] == "role-comparison-incomplete"
    assert review["reason"] == "missing-role-overlap-not-conflicting-bytes"
    assert review["contradictory_comparable_bytes"] is False
    assert "request_associated_onMI" in review["missing_primary_reopen_overlap"]


def test_incomplete_role_coverage_does_not_invalidate_area_delta() -> None:
    experiment, delta = _restore_statuses(
        execution_completed=True,
        area_comparable=True,
        role_complete=False,
    )
    assert experiment == "completed-action"
    assert delta == "controlled-partial-structural-evidence"
