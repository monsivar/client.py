from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import orjson
import pytest

from deebot_client.diagnostics.goat_map_area_merge import (
    AreaMergeReference,
    _group_metadata,
    _observer_snapshot,
    _target_assessment,
    classify_area_merge_recovery,
    evaluate_area_merge_preconditions,
)
from deebot_client.diagnostics.goat_map_area_split import (
    AreaSplitCaptureConfig,
    AreaSplitEvidenceObserver,
    evaluate_area_split_preconditions,
)
from deebot_client.diagnostics.goat_map_refresh import MowerState
from deebot_client.diagnostics.goat_map_segment_grouping import (
    OpaqueSegmentInput,
    assemble_opaque_segment_set,
)

_GOLDEN_ONMI = (
    Path(__file__).parents[1]
    / "fixtures"
    / "goat_map"
    / "onmi_info_representations.json"
)
_PREFIX = bytes.fromhex("5d00000400")
_INVARIANT = bytes.fromhex("002d96c042005e")
_SIGNATURE = bytes.fromhex("b4fc81d4375de7a0f636f001dc016fe0ca")
_P2_09C_SPLIT_SIGNATURE = bytes.fromhex("c8c9b157b2874a80dcc06c3923718e503b")


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
    body_byte: int = 0x33,
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
    for kind, value in (("ar", "split-ar"), ("vw", "stable-vw")):
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
    info_size = 7002
    framed = (
        _PREFIX
        + info_size.to_bytes(4, "little")
        + _INVARIANT
        + b"\x14"
        + _SIGNATURE
        + bytes([body_byte]) * 700
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


def test_merge_config_is_paused_and_requires_reference() -> None:
    with pytest.raises(ValueError, match="immutable reference"):
        AreaSplitCaptureConfig(operation="merge")
    AreaSplitCaptureConfig(
        operation="merge",
        mower_state=MowerState.PAUSED,
        reference_artifact_dir="reference",
        expected_reference_capture_id="a" * 32,
    )
    with pytest.raises(ValueError, match="pre-merge artifact"):
        AreaSplitCaptureConfig(
            operation="merge",
            reference_artifact_dir="reference",
            expected_reference_capture_id="a" * 32,
            post_merge_recovery=True,
        )
    AreaSplitCaptureConfig(
        operation="merge",
        reference_artifact_dir="reference",
        expected_reference_capture_id="a" * 32,
        post_merge_recovery=True,
        pre_merge_artifact_dir="pre-merge",
        expected_pre_merge_capture_id="b" * 32,
    )


def test_merge_gate_requires_stable_p2_09c_split_state() -> None:
    window = ["init-1"]
    observer = AreaSplitEvidenceObserver(lambda: window[0])
    started = datetime(2026, 8, 23, 8, tzinfo=UTC)
    _populate(observer, at=started, batid="first")
    window[0] = "init-2"
    _populate(observer, at=started + timedelta(minutes=1), batid="second")
    base = evaluate_area_split_preconditions(
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        allowed_app_windows=("init-1", "init-2"),
    )
    reference = AreaMergeReference(
        capture_id="2" * 32,
        phase="p2-09c",
        original_pre_split=_observer_snapshot(observer, ("init-1",)),
        split_post=_observer_snapshot(observer, ("init-2",)),
    )

    result = evaluate_area_merge_preconditions(
        base,
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        reference=reference,
    )

    assert result["status"] == "passed"
    assert result["split_edit_gate_open"] is False
    assert result["merge_edit_gate_open"] is True
    assert result["checks"]["serial_3_type_0_repeatability"]["status"] == "passed"


def test_merge_gate_rejects_nonrepeatable_serial_three_state() -> None:
    window = ["init-1"]
    observer = AreaSplitEvidenceObserver(lambda: window[0])
    started = datetime(2026, 8, 23, 8, tzinfo=UTC)
    _populate(observer, at=started, batid="first", body_byte=0x33)
    reference_snapshot = _observer_snapshot(observer, ("init-1",))
    window[0] = "init-2"
    _populate(
        observer,
        at=started + timedelta(minutes=1),
        batid="second",
        body_byte=0x44,
    )
    base = evaluate_area_split_preconditions(
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        allowed_app_windows=("init-1", "init-2"),
    )
    reference = AreaMergeReference(
        capture_id="2" * 32,
        phase="p2-09c",
        original_pre_split=reference_snapshot,
        split_post=reference_snapshot,
    )

    result = evaluate_area_merge_preconditions(
        base,
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        reference=reference,
    )

    assert result["status"] == "inconclusive"
    assert result["merge_edit_gate_open"] is False
    assert "repeatable-serial-3-type-0-split-state" in {
        item["check"] for item in result["failures"]
    }


def test_restoration_target_distinguishes_exact_from_stable_third_encoding() -> None:
    expected = {
        "mid": "1",
        "aid": "0",
        "type": "ar",
        "info_size": 291,
        "subsets_length": 124,
        "subsets_sha256": "a" * 64,
    }
    exact = _target_assessment(
        [{**expected, "window": "post-1"}],
        expected,
        key_fields=("mid", "aid", "type"),
        value_fields=("info_size", "subsets_length", "subsets_sha256"),
    )
    alternative = _target_assessment(
        [
            {**expected, "subsets_sha256": "b" * 64, "window": "post-1"},
            {**expected, "subsets_sha256": "b" * 64, "window": "post-2"},
        ],
        expected,
        key_fields=("mid", "aid", "type"),
        value_fields=("info_size", "subsets_length", "subsets_sha256"),
    )

    assert exact["status"] == "exact-match-observed"
    assert alternative["status"] == "different-or-missing"
    assert alternative["post_state_stable_across_windows"] is True


def test_unknown_p2_09c_signature_uses_same_region_policy_as_live_observer() -> None:
    info_size = 7002
    framed = (
        _PREFIX
        + info_size.to_bytes(4, "little")
        + _INVARIANT
        + b"\x14"
        + _P2_09C_SPLIT_SIGNATURE
        + b"\x55" * 700
    )
    third = len(framed) // 3
    chunks = (framed[:third], framed[third : third * 2], framed[third * 2 :])
    segment_set = assemble_opaque_segment_set(
        tuple(
            OpaqueSegmentInput(
                batid="same-set",
                serial=3,
                index=index,
                info_size=info_size,
                mid="1",
                type=0,
                using=1,
                representation=base64.b64encode(chunk).decode("ascii"),
            )
            for index, chunk in enumerate(chunks)
        )
    )

    metadata = _group_metadata(
        SimpleNamespace(segment_set=segment_set, windows=("reference",))
    )

    assert metadata["context_signature_hex"] == _P2_09C_SPLIT_SIGNATURE.hex()
    assert metadata["opaque_common_body_region_length"] is None
    assert metadata["opaque_common_body_region_sha256"] is None
    assert metadata["opaque_after_701_length"] is None
    assert metadata["opaque_after_701_sha256"] is None


def test_recovery_source_isolation_failure_cannot_be_controlled_evidence() -> None:
    result = classify_area_merge_recovery(
        post_merge_stability_status="passed",
        recovery_precondition_status="inconclusive",
        exact_restoration=False,
        area_state_stable=True,
        on_ari_state_stable=True,
    )

    assert result == {
        "experiment_status": "recovery-readback-inconclusive",
        "delta_status": "inconclusive",
        "restoration_status": "stable-third-encoding",
    }
