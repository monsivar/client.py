from __future__ import annotations

import base64
from hashlib import sha256
from typing import TYPE_CHECKING

import orjson
import pytest

from deebot_client.diagnostics.goat_map_capture import GoatMapCaptureWriter
from deebot_client.diagnostics.goat_map_delta import (
    ArtifactDeltaError,
    byte_diff,
    compare_phase2_artifacts,
    compare_special_contour_present_to_absent,
    compare_special_contour_readbacks,
)
from deebot_client.diagnostics.goat_map_refresh import MowerState

if TYPE_CHECKING:
    from pathlib import Path


def _artifact(
    artifact_dir: Path,
    *,
    phase: str,
    decoded_info: bytes,
    info_size: int | None = None,
) -> None:
    writer = GoatMapCaptureWriter(
        artifact_dir,
        phase=phase,
        mower_state=MowerState.MOWING,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq", "jmq": "none", "appping": "ngiot"},
    )
    writer.record_mqtt(
        "iot/atr/onMI/device/class/resource/j",
        orjson.dumps(
            {
                "body": {
                    "data": {
                        "mid": "1",
                        "aid": "2",
                        "type": "ar",
                        "infoSize": len(decoded_info)
                        if info_size is None
                        else info_size,
                        "info": base64.b64encode(decoded_info).decode(),
                    }
                }
            }
        ),
    )
    writer.finalize()


def _file_digests(artifact_dir: Path) -> dict[str, str]:
    return {
        path.relative_to(artifact_dir).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in artifact_dir.rglob("*")
        if path.is_file()
    }


def test_byte_diff_reports_start_aligned_offsets_and_length_change() -> None:
    assert byte_diff(b"abcXYZ", b"abcQXYZ!") == {
        "first_differing_offset": 3,
        "last_differing_offset": 7,
        "different_byte_count": 5,
        "common_prefix_bytes": 3,
        "common_suffix_bytes": 0,
        "length_change": 2,
    }
    assert byte_diff(b"same", b"same") == {
        "first_differing_offset": None,
        "last_differing_offset": None,
        "different_byte_count": 0,
        "common_prefix_bytes": 4,
        "common_suffix_bytes": 4,
        "length_change": 0,
    }


def test_delta_is_read_only_and_reports_original_and_base64_derived_bytes(
    tmp_path: Path,
) -> None:
    before_dir = tmp_path / "before"
    after_dir = tmp_path / "after"
    _artifact(
        before_dir,
        phase="p2-05-before",
        decoded_info=b"HEAD-aaa-TAIL",
        info_size=25,
    )
    _artifact(
        after_dir,
        phase="p2-05-after",
        decoded_info=b"HEAD-bbb-TAIL",
        info_size=1756,
    )
    snapshots = {
        "before": _file_digests(before_dir),
        "after": _file_digests(after_dir),
    }

    report = compare_phase2_artifacts(before_dir, after_dir)

    assert snapshots == {
        "before": _file_digests(before_dir),
        "after": _file_digests(after_dir),
    }
    group = next(
        item
        for item in report["groups"]
        if item["command"] == "onMI"
        and item["map_ids"] == ["1"]
        and item["source_path"] == "$.body.data.info"
    )
    assert group["status"] == "changed"
    assert group["original_kind"] == "json-string-utf8-value"
    assert len(group["before_variants"]) == len(group["after_variants"]) == 1
    comparison = group["comparisons"][0]
    assert comparison["pairing"] == "unique-equal-byte-length"
    assert comparison["decoded_representation"] == {
        "encoding": "strict-canonical-base64",
        "before": {
            "sha256": sha256(b"HEAD-aaa-TAIL").hexdigest(),
            "byte_length": 13,
        },
        "after": {
            "sha256": sha256(b"HEAD-bbb-TAIL").hexdigest(),
            "byte_length": 13,
        },
        "byte_diff": {
            "first_differing_offset": 5,
            "last_differing_offset": 7,
            "different_byte_count": 3,
            "common_prefix_bytes": 5,
            "common_suffix_bytes": 5,
            "length_change": 0,
        },
        "semantic_interpretation": False,
    }
    assert {
        item["source_path"] for item in report["selected_field_comparison"]
    }.issuperset(
        {
            "$.body.data.mid",
            "$.body.data.aid",
            "$.body.data.type",
            "$.body.data.infoSize",
        }
    )
    info_size = next(
        item
        for item in report["selected_field_comparison"]
        if item["source_path"] == "$.body.data.infoSize"
    )
    assert info_size["status"] == "value-changed"
    assert info_size["before_values"] == [{"value": 25, "occurrence_count": 1}]
    assert info_size["after_values"] == [{"value": 1756, "occurrence_count": 1}]
    serialized = orjson.dumps(report).decode()
    assert "polygon" not in serialized
    assert "coordinate" not in serialized
    assert "zone-data" not in serialized


def test_delta_rejects_tampered_blob_before_comparison(tmp_path: Path) -> None:
    before_dir = tmp_path / "before"
    after_dir = tmp_path / "after"
    _artifact(before_dir, phase="p2-05-before", decoded_info=b"before")
    _artifact(after_dir, phase="p2-05-after", decoded_info=b"after")
    blob = next((before_dir / "blobs").glob("*.bin"))
    blob.write_bytes(b"tampered")

    with pytest.raises(ArtifactDeltaError, match=r"length|SHA-256"):
        compare_phase2_artifacts(before_dir, after_dir)


def test_delta_does_not_guess_pairs_when_multiple_variants_are_ambiguous(
    tmp_path: Path,
) -> None:
    before_dir = tmp_path / "before"
    after_dir = tmp_path / "after"
    before_writer = GoatMapCaptureWriter(
        before_dir,
        phase="before",
        mower_state=MowerState.MOWING,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq"},
    )
    after_writer = GoatMapCaptureWriter(
        after_dir,
        phase="after",
        mower_state=MowerState.MOWING,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq"},
    )
    for value in (b"AAAA", b"BBBB"):
        before_writer.record_mqtt(
            "iot/atr/onArI/device/class/resource/j",
            orjson.dumps({"body": {"data": {"mid": "1", "info": value.decode()}}}),
        )
    for value in (b"CCCC", b"DDDD"):
        after_writer.record_mqtt(
            "iot/atr/onArI/device/class/resource/j",
            orjson.dumps({"body": {"data": {"mid": "1", "info": value.decode()}}}),
        )
    before_writer.finalize()
    after_writer.finalize()

    report = compare_phase2_artifacts(before_dir, after_dir)

    group = next(
        item for item in report["groups"] if item["source_path"] == "$.body.data.info"
    )
    assert group["comparisons"] == []
    assert len(group["unpaired_before_sha256"]) == 2
    assert len(group["unpaired_after_sha256"]) == 2


def test_special_contour_delta_compares_present_and_post_delete_readbacks(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "p2-06"
    phase = "p2-06-controlled-special-contour-delete"
    writer = GoatMapCaptureWriter(
        artifact_dir,
        phase=phase,
        mower_state=MowerState.PAUSED,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq", "appping": "none"},
        capture_commands={"getSpecialContour", "onSpecialContour", "setSpecialContour"},
    )
    writer.set_context(f"{phase}:zone-present-readback", MowerState.PAUSED)
    writer.record_mqtt(
        "iot/p2p/getSpecialContour/a/b/c/d/e/f/p/id/j",
        orjson.dumps(
            {
                "body": {
                    "data": {
                        "mid": "1",
                        "info": base64.b64encode(b"FRAME-present-END").decode(),
                    }
                }
            }
        ),
    )
    writer.set_context(f"{phase}:post-delete-readback", MowerState.PAUSED)
    writer.record_mqtt(
        "iot/p2p/getSpecialContour/a/b/c/d/e/f/p/id/j",
        orjson.dumps(
            {
                "body": {
                    "data": {
                        "mid": "1",
                        "info": base64.b64encode(b"FRAME-deleted-END").decode(),
                    }
                }
            }
        ),
    )
    writer.finalize()

    report = compare_special_contour_readbacks(artifact_dir)

    group = next(
        item for item in report["groups"] if item["source_path"] == "$.body.data.info"
    )
    comparison = group["comparisons"][0]
    assert report["analysis_kind"] == ("opaque-special-contour-inverse-operation-delta")
    assert report["comparison_status"] == "complete"
    assert report["comparison_result"] == "comparable"
    assert report["missing_roles"] == []
    assert report["selection"]["before_window"].endswith(":zone-present-readback")
    assert comparison["decoded_representation"]["byte_diff"] == {
        "first_differing_offset": 6,
        "last_differing_offset": 12,
        "different_byte_count": 7,
        "common_prefix_bytes": 6,
        "common_suffix_bytes": 4,
        "length_change": 0,
    }


def test_special_contour_delta_is_incomplete_when_post_delete_window_is_empty(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "p2-06-incomplete"
    phase = "p2-06-controlled-special-contour-delete"
    writer = GoatMapCaptureWriter(
        artifact_dir,
        phase=phase,
        mower_state=MowerState.PAUSED,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq", "appping": "none"},
        capture_commands={"getSpecialContour", "onSpecialContour"},
    )
    writer.set_context(f"{phase}:zone-present-readback", MowerState.PAUSED)
    writer.record_mqtt(
        "iot/atr/onSpecialContour/device/class/resource/j",
        orjson.dumps({"body": {"data": {"info": "opaque-present"}}}),
    )
    writer.finalize()

    report = compare_special_contour_readbacks(artifact_dir)

    assert report["comparison_status"] == "incomplete"
    assert report["comparison_result"] == "not_comparable"
    assert report["missing_roles"] == ["after"]
    assert report["side_record_counts"] == {"before": 1, "after": 0}
    assert report["changed_group_count"] is None
    assert report["proven_byte_delta_group_count"] == 0
    assert report["groups"] == []
    assert report["presence_absence_observations"]
    assert all(
        observation["observation"] == "before-only"
        and observation["byte_delta_proven"] is False
        for observation in report["presence_absence_observations"]
    )


def test_one_sided_group_is_presence_observation_not_proven_delta(
    tmp_path: Path,
) -> None:
    before_dir = tmp_path / "before-with-extra"
    after_dir = tmp_path / "after-without-extra"
    before_writer = GoatMapCaptureWriter(
        before_dir,
        phase="before",
        mower_state=MowerState.MOWING,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq"},
    )
    after_writer = GoatMapCaptureWriter(
        after_dir,
        phase="after",
        mower_state=MowerState.MOWING,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq"},
    )
    common = orjson.dumps({"body": {"data": {"mid": "1", "info": "same"}}})
    before_writer.record_mqtt("iot/atr/onMI/device/class/resource/j", common)
    before_writer.record_mqtt(
        "iot/atr/onArI/device/class/resource/j",
        orjson.dumps({"body": {"data": {"mid": "1", "info": "extra"}}}),
    )
    after_writer.record_mqtt("iot/atr/onMI/device/class/resource/j", common)
    after_writer.record_mqtt(
        "iot/atr/onAreaSet/device/class/resource/j",
        orjson.dumps({"body": {"data": {"mid": "1", "type": 0}}}),
    )
    before_writer.finalize()
    after_writer.finalize()

    report = compare_phase2_artifacts(before_dir, after_dir)

    assert report["comparison_status"] == "complete"
    assert report["changed_group_count"] == 0
    assert report["proven_byte_delta_group_count"] == 0
    assert all(group["status"] == "unchanged" for group in report["groups"])
    extra = next(
        observation
        for observation in report["presence_absence_observations"]
        if observation["command"] == "onArI"
        and observation["source_path"] == "$.body.data.info"
    )
    assert extra["observation"] == "before-only"
    assert extra["byte_delta_proven"] is False
    selected_statuses = {
        (item["command"], item["source_path"]): item["status"]
        for item in report["selected_field_comparison"]
    }
    assert selected_statuses[("onMI", "$.body.data.mid")] == "identical"
    assert selected_statuses[("onArI", "$.body.data.mid")] == "before-only"
    assert selected_statuses[("onAreaSet", "$.body.data.type")] == "after-only"


def test_special_contour_present_to_absent_compares_distinct_artifacts(
    tmp_path: Path,
) -> None:
    present_dir = tmp_path / "present"
    absent_dir = tmp_path / "absent"
    present_phase = "p2-06-delete"
    absent_phase = "p2-07-zone-absent"
    present_writer = GoatMapCaptureWriter(
        present_dir,
        phase=present_phase,
        mower_state=MowerState.PAUSED,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq"},
        capture_commands={"getSpecialContour", "onSpecialContour"},
    )
    absent_writer = GoatMapCaptureWriter(
        absent_dir,
        phase=absent_phase,
        mower_state=MowerState.PAUSED,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq"},
        capture_commands={"getSpecialContour", "onSpecialContour"},
    )
    present_writer.set_context(
        f"{present_phase}:zone-present-readback",
        MowerState.PAUSED,
    )
    absent_writer.set_context(
        f"{absent_phase}:zone-absent-readback",
        MowerState.PAUSED,
    )
    present_writer.record_mqtt(
        "iot/atr/onSpecialContour/device/class/resource/j",
        orjson.dumps({"body": {"data": {"info": "present-value"}}}),
    )
    absent_writer.record_mqtt(
        "iot/atr/onSpecialContour/device/class/resource/j",
        orjson.dumps({"body": {"data": {"info": "absent-value"}}}),
    )
    present_writer.finalize()
    absent_writer.finalize()

    report = compare_special_contour_present_to_absent(present_dir, absent_dir)

    assert report["analysis_kind"] == "opaque-special-contour-present-absent-delta"
    assert report["comparison_status"] == "complete"
    assert report["selection"]["before_window"].endswith(":zone-present-readback")
    assert report["selection"]["after_window"].endswith(":zone-absent-readback")
    group = next(
        group
        for group in report["groups"]
        if group["source_path"] == "$.body.data.info"
    )
    assert group["status"] == "changed"
    assert report["proven_byte_delta_group_count"] == 1


def test_p2_07_selected_fields_separate_occurrence_count_from_value_change(
    tmp_path: Path,
) -> None:
    present_dir = tmp_path / "p2-06-present"
    absent_dir = tmp_path / "p2-07-absent"
    present_phase = "p2-06-delete"
    absent_phase = "p2-07-zone-absent"
    present_writer = GoatMapCaptureWriter(
        present_dir,
        phase=present_phase,
        mower_state=MowerState.PAUSED,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq"},
        capture_commands={"getSpecialContour"},
    )
    absent_writer = GoatMapCaptureWriter(
        absent_dir,
        phase=absent_phase,
        mower_state=MowerState.PAUSED,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq"},
        capture_commands={"getSpecialContour"},
    )
    present_writer.set_context(
        f"{present_phase}:zone-present-readback",
        MowerState.PAUSED,
    )
    absent_writer.set_context(
        f"{absent_phase}:zone-absent-readback",
        MowerState.PAUSED,
    )
    payload = orjson.dumps({"body": {"data": {"mid": "1", "type": 0}}})
    topic = "iot/p2p/getSpecialContour/a/b/c/d/e/f/q/id/j"
    for _ in range(2):
        present_writer.record_mqtt(topic, payload)
    for _ in range(3):
        absent_writer.record_mqtt(topic, payload)
    present_writer.finalize()
    absent_writer.finalize()

    report = compare_special_contour_present_to_absent(present_dir, absent_dir)

    selected = {
        item["source_path"]: item
        for item in report["selected_field_comparison"]
        if item["source_path"] in {"$.body.data.mid", "$.body.data.type"}
    }
    assert set(selected) == {"$.body.data.mid", "$.body.data.type"}
    assert selected["$.body.data.mid"] == {
        "command": "getSpecialContour",
        "direction": "request",
        "map_ids": ["1"],
        "source_path": "$.body.data.mid",
        "status": "occurrence-count-changed",
        "before_values": [{"value": "1", "occurrence_count": 2}],
        "after_values": [{"value": "1", "occurrence_count": 3}],
    }
    assert selected["$.body.data.type"]["status"] == "occurrence-count-changed"
    assert selected["$.body.data.type"]["before_values"] == [
        {"value": 0, "occurrence_count": 2}
    ]
    assert selected["$.body.data.type"]["after_values"] == [
        {"value": 0, "occurrence_count": 3}
    ]
