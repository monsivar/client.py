from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import orjson

from deebot_client.diagnostics.goat_map_capture import GoatMapCaptureWriter
from deebot_client.diagnostics.goat_map_on_ari_analysis import analyze_on_ari_corpus
from deebot_client.diagnostics.goat_map_refresh import MowerState

if TYPE_CHECKING:
    from pathlib import Path


def _writer(path: Path, *, phase: str, capture_id: str) -> GoatMapCaptureWriter:
    return GoatMapCaptureWriter(
        path,
        phase=phase,
        mower_state=MowerState.MOWING,
        device_class="fixture-class",
        factors={"mqtt": "normal-mq"},
        capture_id_factory=lambda: capture_id,
    )


def _base64(decoded_length: int, byte: bytes) -> str:
    return base64.b64encode(byte * decoded_length).decode()


def _record_on_mi(
    writer: GoatMapCaptureWriter,
    info: str,
    observed_at: datetime,
) -> None:
    writer.record_mqtt(
        "iot/atr/onMI/device/class/resource/j",
        orjson.dumps({"body": {"data": {"mid": "1", "info": info}}}),
        observed_at=observed_at,
    )


def _record_on_ari(
    writer: GoatMapCaptureWriter,
    info: str,
    observed_at: datetime,
    *,
    batch: str,
    serial: str,
    index: str,
    info_size: int,
) -> None:
    writer.record_mqtt(
        "iot/atr/onArI/device/class/resource/j",
        orjson.dumps(
            {
                "body": {
                    "data": {
                        "mid": "1",
                        "batid": batch,
                        "serial": serial,
                        "index": index,
                        "using": 1,
                        "type": "0" if serial == "2" else "-1",
                        "info": info,
                        "infoSize": info_size,
                    }
                }
            }
        ),
        observed_at=observed_at,
    )


def test_on_ari_analysis_reports_bursts_base64_and_structural_patterns(
    tmp_path: Path,
) -> None:
    start = datetime(2026, 8, 22, 10, tzinfo=UTC)
    first_path = tmp_path / "p2-01"
    first = _writer(first_path, phase="p2-01", capture_id="1" * 32)
    first.set_context("p2-01:legacy-get-mi", MowerState.MOWING)
    _record_on_mi(first, _base64(657, b"M"), start)
    _record_on_ari(
        first,
        _base64(768, b"A"),
        start + timedelta(microseconds=100_000),
        batch="batch-a",
        serial="2",
        index="0",
        info_size=6400,
    )
    _record_on_ari(
        first,
        _base64(672, b"B"),
        start + timedelta(microseconds=101_000),
        batch="batch-a",
        serial="2",
        index="1",
        info_size=6400,
    )
    first.finalize()

    second_path = tmp_path / "p2-08"
    second = _writer(second_path, phase="p2-08", capture_id="8" * 32)
    second.set_context("p2-08:ngiot-get-mi", MowerState.MOWING)
    _record_on_mi(second, _base64(657, b"M"), start + timedelta(seconds=60))
    _record_on_ari(
        second,
        _base64(768, b"C"),
        start + timedelta(seconds=60, microseconds=100_000),
        batch="batch-b",
        serial="2",
        index="0",
        info_size=6316,
    )
    _record_on_ari(
        second,
        _base64(654, b"D"),
        start + timedelta(seconds=60, microseconds=101_000),
        batch="batch-b",
        serial="2",
        index="1",
        info_size=6316,
    )
    second.set_context("p2-08:cadence", MowerState.MOWING)
    _record_on_mi(second, _base64(38, b"S"), start + timedelta(seconds=120))
    _record_on_ari(
        second,
        _base64(597, b"E"),
        start + timedelta(seconds=120, microseconds=20_000),
        batch="batch-c",
        serial="1",
        index="0",
        info_size=1303,
    )
    second.finalize()

    report = analyze_on_ari_corpus((first_path, second_path))

    assert report["strict_base64_assessment"]["invalid_count"] == 0
    assert report["corpus"]["on_ari_occurrence_count"] == 5
    assert report["corpus"]["multi_message_burst_count"] == 2
    assert report["corpus"]["single_message_burst_count"] == 1
    multi = [item for item in report["bursts"] if item["message_count"] == 2]
    assert all(item["first_1024_decodes_to_768"] for item in multi)
    assert multi[0]["representation_lengths"] == [1024, 896]
    assert multi[1]["representation_lengths"] == [1024, 872]
    assert multi[1]["decoded_lengths"] == [768, 654]
    assert (
        multi[1]["infoSize_relationship"]["comparisons"][0]["equals_decoded_total"]
        is False
    )
    index_field = next(
        item
        for item in multi[1]["sequence_like_fields_by_name"]
        if item["field"] == "$.body.data.index"
    )
    assert index_field["status"] == "value-varies"
    assert index_field["values_by_ordinal"] == ["0", "1"]
    comparison = report["target_pattern_comparison"]
    assert comparison["same_envelope_structure_872_vs_896"] is True
    assert comparison["cadence_associated_bursts"][
        "representation_length_patterns"
    ] == [{"lengths": [796], "count": 1}]
    assert any(
        item["command"] == "onMI"
        and item["status"] == "strong-golden-fixture-candidate-after-manual-review"
        for item in report["fixture_assessment"]["strong_opaque_candidates"]
    )
    assert all(
        item["status"] == "structural-example-only-not-canonical"
        for item in report["fixture_assessment"]["on_ari_structural_examples"]
    )


def test_on_ari_analysis_explicitly_reports_invalid_base64(tmp_path: Path) -> None:
    artifact = tmp_path / "invalid"
    writer = _writer(artifact, phase="p2-invalid", capture_id="f" * 32)
    _record_on_ari(
        writer,
        "not-base64",
        datetime(2026, 8, 22, 10, tzinfo=UTC),
        batch="batch",
        serial="1",
        index="0",
        info_size=10,
    )
    writer.finalize()

    report = analyze_on_ari_corpus((artifact,))

    assert report["strict_base64_assessment"]["invalid_count"] == 1
    assert (
        report["strict_base64_assessment"]["corpus_result"]
        == "not-established-for-entire-corpus"
    )
    assert (
        report["bursts"][0]["structural_concatenation_candidate"]["performed"] is False
    )
