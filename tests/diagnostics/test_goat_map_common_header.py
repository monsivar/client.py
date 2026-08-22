from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import TYPE_CHECKING

import orjson

from deebot_client.diagnostics.goat_map_capture import GoatMapCaptureWriter
from deebot_client.diagnostics.goat_map_common_header import (
    Association,
    CommonHeaderSample,
    MessageFamily,
    analyze_common_header_samples,
    analyze_cross_family_common_header_corpus,
)
from deebot_client.diagnostics.goat_map_refresh import MowerState

if TYPE_CHECKING:
    from pathlib import Path

_INVARIANT = bytes.fromhex("002d96c042005e")


def _derived(
    *,
    info_size: int,
    family_byte: int,
    association_byte: int,
    body_length: int,
) -> bytes:
    body = bytes(
        (index * 29 + association_byte) % 251 + 1 for index in range(body_length)
    )
    return (
        bytes.fromhex("5d00000400")
        + info_size.to_bytes(4, "little")
        + _INVARIANT
        + bytes([family_byte, association_byte])
        + body
    )


def _sample(
    *,
    capture: str,
    phase: str,
    family: MessageFamily,
    association: Association,
    info_size: int,
    family_byte: int,
    association_byte: int,
    body_length: int,
) -> CommonHeaderSample:
    derived = _derived(
        info_size=info_size,
        family_byte=family_byte,
        association_byte=association_byte,
        body_length=body_length,
    )
    return CommonHeaderSample(
        capture_id=capture,
        phase=phase,
        timestamp="2026-08-22T12:00:00+00:00",
        message_family=family,
        association=association,
        info_size=info_size,
        derived_bytes=derived,
        derived_sha256=sha256(derived).hexdigest(),
    )


def _samples() -> tuple[CommonHeaderSample, ...]:
    return (
        _sample(
            capture="1" * 32,
            phase="capture-a",
            family="onMI",
            association="cadence-associated",
            info_size=25,
            family_byte=0x11,
            association_byte=0x21,
            body_length=80,
        ),
        _sample(
            capture="2" * 32,
            phase="capture-b",
            family="onMI",
            association="request-associated",
            info_size=1756,
            family_byte=0x11,
            association_byte=0x22,
            body_length=90,
        ),
        _sample(
            capture="3" * 32,
            phase="capture-c",
            family="onArI",
            association="cadence-associated",
            info_size=1303,
            family_byte=0x14,
            association_byte=0x31,
            body_length=100,
        ),
        _sample(
            capture="4" * 32,
            phase="capture-d",
            family="onArI",
            association="request-associated",
            info_size=6316,
            family_byte=0x14,
            association_byte=0x32,
            body_length=110,
        ),
    )


def _file_digests(artifact_dir: Path) -> dict[str, str]:
    return {
        path.relative_to(artifact_dir).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in artifact_dir.rglob("*")
        if path.is_file()
    }


def test_common_header_analysis_is_deterministic_and_contains_no_full_values() -> None:
    samples = _samples()

    first = analyze_common_header_samples(samples)
    second = analyze_common_header_samples(tuple(reversed(samples)))

    assert first == second
    assert first["parser_implemented"] is False
    assert first["decoder_implemented"] is False
    serialized = orjson.dumps(first)
    for sample in samples:
        assert sample.derived_bytes not in serialized
        assert sample.derived_bytes.hex().encode() not in serialized


def test_cross_family_prefix_columns_and_info_size_widths() -> None:
    report = analyze_common_header_samples(_samples())

    common = report["longest_common_prefix"]
    assert common["entire_corpus"] == {"byte_length": 5, "hex": "5d00000400"}
    assert [item["byte_length"] for item in common["by_message_family"]] == [5, 5]
    columns = report["byte_column_inventory"]
    assert all(columns[offset]["stability"] == "constant" for offset in range(7, 16))
    assert columns[16]["stability"] == "variable"

    hypotheses = report["field_candidates"]["infoSize_width_hypotheses"]
    assert hypotheses["uint16_little"]["status"] == "supported"
    assert hypotheses["uint32_little"]["status"] == "supported"
    assert hypotheses["width_discrimination"]["status"] == "candidate"
    assert hypotheses["width_discrimination"]["selected_width"] is None
    unknown = report["field_candidates"]["unknown_after_uint16_infoSize"]
    assert unknown["status"] == "candidate"
    assert unknown["offset"] == 7
    assert unknown["width"] == 2


def test_next_structure_is_supported_invariant_then_family_relation() -> None:
    report = analyze_common_header_samples(_samples())

    invariant = report["field_candidates"]["shared_invariant_after_infoSize"]
    assert invariant["status"] == "supported"
    assert invariant["offset"] == 9
    assert invariant["width"] == 7
    assert invariant["value_hex"] == "002d96c042005e"
    family = report["field_candidates"]["message_family_relation"]
    field = next(item for item in family["fields"] if item["offset"] == 16)
    assert field["status"] == "supported"
    assert field["values_by_metadata"] == [
        {"metadata_value": "onArI", "byte_value": 20, "hex": "14"},
        {"metadata_value": "onMI", "byte_value": 17, "hex": "11"},
    ]
    structure = report["first_post_infoSize_structure_change"]
    assert structure["status"] == "supported"
    assert structure["first_variable_offset"] == 16
    assert structure["parser_boundary_adoption"] is False
    assert (
        report["field_candidates"]["derived_total_length_relation"]["status"]
        == "rejected"
    )


def test_message_family_candidate_reports_counterexample() -> None:
    samples = (*_samples(),)
    conflicting = _sample(
        capture="5" * 32,
        phase="capture-e",
        family="onArI",
        association="request-associated",
        info_size=6400,
        family_byte=0x15,
        association_byte=0x33,
        body_length=120,
    )

    report = analyze_common_header_samples((*samples, conflicting))

    family = report["field_candidates"]["message_family_relation"]
    field = next(item for item in family["fields"] if item["offset"] == 16)
    assert field["status"] == "rejected"
    assert len(field["counterexamples"]) == 1
    assert field["counterexamples"][0]["capture_id"] == "5" * 32


def test_field_candidate_output_has_no_semantic_content_names() -> None:
    report = analyze_common_header_samples(_samples())
    serialized = orjson.dumps(report["field_candidates"]).lower()
    for forbidden in (b"polygon", b"coordinate", b"geometry", b"zone", b"area"):
        assert forbidden not in serialized


def test_cross_family_artifact_analysis_is_read_only(tmp_path: Path) -> None:
    artifact = tmp_path / "capture-a"
    writer = GoatMapCaptureWriter(
        artifact,
        phase="capture-a",
        mower_state=MowerState.MOWING,
        device_class="fixture-class",
        factors={"mqtt": "normal-mq"},
        capture_id_factory=lambda: "a" * 32,
    )
    start = datetime(2026, 8, 22, 12, tzinfo=UTC)
    on_mi = _derived(
        info_size=25,
        family_byte=0x11,
        association_byte=0x21,
        body_length=20,
    )
    assert len(on_mi) == 38
    writer.record_mqtt(
        "iot/atr/onMI/device/class/resource/j",
        orjson.dumps(
            {
                "body": {
                    "data": {
                        "mid": "1",
                        "info": base64.b64encode(on_mi).decode(),
                        "infoSize": 25,
                    }
                }
            }
        ),
        observed_at=start,
    )
    on_ari = _derived(
        info_size=1303,
        family_byte=0x14,
        association_byte=0x31,
        body_length=100,
    )
    writer.record_mqtt(
        "iot/atr/onArI/device/class/resource/j",
        orjson.dumps(
            {
                "body": {
                    "data": {
                        "mid": "1",
                        "batid": "batch-a",
                        "serial": "1",
                        "index": "0",
                        "using": 1,
                        "type": "-1",
                        "info": base64.b64encode(on_ari).decode(),
                        "infoSize": 1303,
                    }
                }
            }
        ),
        observed_at=start + timedelta(milliseconds=1),
    )
    writer.finalize()
    before = _file_digests(artifact)

    report = analyze_cross_family_common_header_corpus((artifact,))

    assert before == _file_digests(artifact)
    assert report["corpus"]["sample_count"] == 2
    assert report["corpus"]["excluded_sample_count"] == 0
