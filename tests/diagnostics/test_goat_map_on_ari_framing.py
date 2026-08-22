from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import TYPE_CHECKING

import orjson

from deebot_client.diagnostics.goat_map_capture import GoatMapCaptureWriter
from deebot_client.diagnostics.goat_map_on_ari_framing import (
    GroupedOnAriObservation,
    analyze_grouped_on_ari_framing,
    analyze_on_ari_grouped_framing_corpus,
)
from deebot_client.diagnostics.goat_map_refresh import MowerState
from deebot_client.diagnostics.goat_map_segment_grouping import (
    OpaqueSegmentInput,
    assemble_opaque_segment_set,
)

if TYPE_CHECKING:
    from pathlib import Path


def _framed_bytes(info_size: int, body_length: int, seed: int) -> bytes:
    body = bytes((index * 37 + seed) % 251 + 1 for index in range(body_length))
    return b"\x5d\x00\x00\x04\x00" + info_size.to_bytes(4, "little") + b"\x00" + body


def _observation(
    *,
    capture_id: str,
    phase: str,
    batid: str,
    info_size: int,
    raw: bytes,
    serial: int = 2,
    role: str = "request-associated",
    control_transport: str = "legacy",
) -> GroupedOnAriObservation:
    split = len(raw) // 2
    parts = [raw] if serial == 1 else [raw[:split], raw[split:]]
    segment_set = assemble_opaque_segment_set(
        [
            OpaqueSegmentInput(
                batid=batid,
                serial=serial,
                index=index,
                info_size=info_size,
                mid="1",
                type="0" if serial == 2 else "-1",
                using=1,
                representation=base64.b64encode(part).decode(),
            )
            for index, part in enumerate(parts)
        ]
    )
    return GroupedOnAriObservation(
        capture_id=capture_id,
        phase=phase,
        mower_state="mowing",
        windows=(f"{phase}:controlled-window",),
        first_timestamp="2026-08-22T12:00:00+00:00",
        event_transports=("normal-mq",),
        associated_control_transports=(control_transport,),
        associated_control_delta_microseconds=(100_000,),
        roles=(role,),
        segment_set=segment_set,
    )


def _file_digests(artifact_dir: Path) -> dict[str, str]:
    return {
        path.relative_to(artifact_dir).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in artifact_dir.rglob("*")
        if path.is_file()
    }


def test_grouped_framing_analysis_is_deterministic_and_metadata_only() -> None:
    first_raw = _framed_bytes(120, 100, 7) + b"\x00\x00"
    second_raw = _framed_bytes(140, 121, 13) + b"\x00"
    observations = (
        _observation(
            capture_id="1" * 32,
            phase="capture-a",
            batid="batch-a",
            info_size=120,
            raw=first_raw,
        ),
        _observation(
            capture_id="2" * 32,
            phase="capture-b",
            batid="batch-b",
            info_size=140,
            raw=second_raw,
            control_transport="ngiot",
        ),
    )

    first_report = analyze_grouped_on_ari_framing(observations)
    second_report = analyze_grouped_on_ari_framing(tuple(reversed(observations)))

    assert first_report == second_report
    assert first_report["framing_parser_implemented"] is False
    assert first_report["codec_or_decompression_attempted"] is False
    serialized = orjson.dumps(first_report)
    for observation in observations:
        for segment in observation.segment_set.segments:
            assert segment.original_representation.encode() not in serialized
        assert (
            observation.segment_set.derived_concatenation.hex().encode()
            not in serialized
        )

    short = _observation(
        capture_id="3" * 32,
        phase="capture-short",
        batid="batch-short",
        info_size=1,
        raw=b"\x01\x02\x03\x04\x05\x06",
        serial=1,
        role="unclassified",
    )
    short_report = analyze_grouped_on_ari_framing((short,))
    short_serialized = orjson.dumps(short_report)
    assert (
        short.segment_set.derived_concatenation.hex().encode() not in short_serialized
    )


def test_field_candidate_detects_supported_unaligned_little_endian_relation() -> None:
    observations = (
        _observation(
            capture_id="1" * 32,
            phase="capture-a",
            batid="batch-a",
            info_size=120,
            raw=_framed_bytes(120, 100, 3),
        ),
        _observation(
            capture_id="2" * 32,
            phase="capture-b",
            batid="batch-b",
            info_size=140,
            raw=_framed_bytes(140, 130, 5),
        ),
    )

    report = analyze_grouped_on_ari_framing(observations)

    relation = next(
        item
        for item in report["field_candidates"]["relations"]
        if item["relation"] == "equals-envelope-infoSize"
    )
    assert relation["status"] == "supported"
    field = next(
        item
        for item in relation["fields"]
        if item["offset"] == 5 and item["width"] == 4 and item["byte_order"] == "little"
    )
    assert field["status"] == "supported"
    assert field["counterexamples"] == []
    assert {item["observed_value"] for item in field["supporting_examples"]} == {
        120,
        140,
    }


def test_field_candidate_reports_counterexample_as_rejected() -> None:
    observations = (
        _observation(
            capture_id="1" * 32,
            phase="capture-a",
            batid="batch-a",
            info_size=120,
            raw=_framed_bytes(120, 100, 3),
        ),
        _observation(
            capture_id="2" * 32,
            phase="capture-b",
            batid="batch-b",
            info_size=140,
            raw=_framed_bytes(140, 110, 5),
        ),
        _observation(
            capture_id="3" * 32,
            phase="capture-c",
            batid="batch-c",
            info_size=160,
            raw=_framed_bytes(999, 120, 7),
        ),
    )

    report = analyze_grouped_on_ari_framing(observations)

    relation = next(
        item
        for item in report["field_candidates"]["relations"]
        if item["relation"] == "equals-envelope-infoSize"
    )
    field = next(
        item
        for item in relation["fields"]
        if item["offset"] == 5 and item["width"] == 4 and item["byte_order"] == "little"
    )
    assert field["status"] == "rejected"
    assert len(field["supporting_examples"]) == 2
    assert len(field["counterexamples"]) == 1


def test_different_lengths_report_structural_diff_without_interpretation() -> None:
    observations = (
        _observation(
            capture_id="1" * 32,
            phase="capture-a",
            batid="batch-a",
            info_size=120,
            raw=_framed_bytes(120, 100, 11),
        ),
        _observation(
            capture_id="2" * 32,
            phase="capture-b",
            batid="batch-b",
            info_size=140,
            raw=_framed_bytes(140, 130, 17),
        ),
    )

    report = analyze_grouped_on_ari_framing(observations)

    comparison = report["cross_group_structure"]["pairwise_comparisons"][0]
    assert "same-envelope-shape-different-derived-length" in comparison["relations"]
    assert comparison["left_length"] != comparison["right_length"]
    assert comparison["common_prefix_bytes"] == 5
    assert comparison["first_differing_offset"] == 5


def test_field_candidate_output_uses_only_structural_names() -> None:
    report = analyze_grouped_on_ari_framing(
        (
            _observation(
                capture_id="1" * 32,
                phase="capture-a",
                batid="batch-a",
                info_size=120,
                raw=_framed_bytes(120, 100, 19),
            ),
            _observation(
                capture_id="2" * 32,
                phase="capture-b",
                batid="batch-b",
                info_size=140,
                raw=_framed_bytes(140, 130, 23),
            ),
        )
    )

    serialized = orjson.dumps(report["field_candidates"]).lower()
    for forbidden in (b"polygon", b"coordinate", b"geometry", b"zone", b"area"):
        assert forbidden not in serialized


def test_artifact_corpus_analysis_is_read_only(tmp_path: Path) -> None:
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
    writer.record_mqtt(
        "iot/atr/onMI/device/class/resource/j",
        orjson.dumps(
            {
                "body": {
                    "data": {
                        "mid": "1",
                        "info": base64.b64encode(b"M" * 38).decode(),
                    }
                }
            }
        ),
        observed_at=start,
    )
    raw = _framed_bytes(1303, 100, 31)
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
                        "info": base64.b64encode(raw).decode(),
                        "infoSize": 1303,
                    }
                }
            }
        ),
        observed_at=start + timedelta(milliseconds=1),
    )
    writer.finalize()
    before = _file_digests(artifact)

    report = analyze_on_ari_grouped_framing_corpus((artifact,))

    assert before == _file_digests(artifact)
    assert report["corpus"]["capture_count"] == 1
    assert report["corpus"]["complete_group_count"] == 1
    assert report["corpus"]["excluded_group_count"] == 0
