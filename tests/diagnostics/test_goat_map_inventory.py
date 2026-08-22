from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import TYPE_CHECKING

import orjson

from deebot_client.diagnostics.goat_map_capture import GoatMapCaptureWriter
from deebot_client.diagnostics.goat_map_inventory import (
    analyze_phase2_corpus,
    inventory_csv,
)
from deebot_client.diagnostics.goat_map_refresh import MowerState

if TYPE_CHECKING:
    from pathlib import Path

_GET_MI_REQUEST_TOPIC = (
    "iot/p2p/getMI/sender/class/resource/receiver/class/resource/q/req/j"
)
_AREA_RESPONSE_TOPIC = (
    "iot/p2p/getAreaSet/sender/class/resource/receiver/class/resource/p/req/j"
)


def _writer(path: Path, phase: str) -> GoatMapCaptureWriter:
    return GoatMapCaptureWriter(
        path,
        phase=phase,
        mower_state=MowerState.MOWING,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq", "jmq": "none", "appping": "ngiot"},
        capture_id_factory=lambda: sha256(phase.encode()).hexdigest()[:32],
    )


def _event_payload(
    command: str,
    info: str,
    *,
    area_type: str = "ar",
    aid: str = "0",
) -> bytes:
    key = "subsets" if command == "getAreaSet" else "info"
    return orjson.dumps(
        {
            "body": {
                "data": {
                    "mid": "1",
                    "aid": aid,
                    "type": area_type,
                    key: info,
                }
            }
        }
    )


def _record_event(
    writer: GoatMapCaptureWriter,
    command: str,
    info: str,
    observed_at: datetime,
) -> None:
    writer.record_mqtt(
        f"iot/atr/{command}/device/class/resource/j",
        _event_payload(command, info),
        observed_at=observed_at,
    )


def _record_area(
    writer: GoatMapCaptureWriter,
    subsets: str,
    area_type: str,
    observed_at: datetime,
) -> None:
    writer.record_mqtt(
        _AREA_RESPONSE_TOPIC,
        _event_payload("getAreaSet", subsets, area_type=area_type),
        observed_at=observed_at,
    )


def _build_corpus(tmp_path: Path) -> tuple[list[Path], list[Path], str, str]:
    long_info = base64.b64encode(b"L" * 657).decode()
    short_info = base64.b64encode(b"S" * 39).decode()
    ari_info = "opaque-ari-repeat"
    start = datetime(2026, 8, 22, 10, tzinfo=UTC)

    first = tmp_path / "p2-01"
    writer = _writer(first, "p2-01-paired")
    writer.set_context("p2-01-paired:legacy-get-mi-action", MowerState.MOWING)
    writer.record_mqtt(
        _GET_MI_REQUEST_TOPIC,
        orjson.dumps({"body": {"data": {"type": "0"}}}),
        observed_at=start,
    )
    _record_event(writer, "onMI", long_info, start + timedelta(milliseconds=100))
    _record_event(writer, "onArI", ari_info, start + timedelta(milliseconds=200))
    writer.set_context("p2-01-paired:tail", MowerState.MOWING)
    _record_event(writer, "onMI", short_info, start + timedelta(seconds=60))
    _record_event(writer, "onArI", ari_info, start + timedelta(seconds=60.1))
    _record_event(writer, "onMI", short_info, start + timedelta(seconds=120))
    _record_area(writer, "same-ar", "ar", start + timedelta(seconds=121))
    _record_area(writer, "first-vw", "vw", start + timedelta(seconds=122))
    writer.finalize()

    second = tmp_path / "p2-04"
    writer = _writer(second, "p2-04-app-open")
    app_start = start + timedelta(hours=1)
    writer.set_context(
        "p2-04-app-open:official-app-open-window",
        MowerState.MOWING,
    )
    writer.record_mqtt(
        _GET_MI_REQUEST_TOPIC,
        orjson.dumps({"body": {"data": {"type": "0"}}}),
        observed_at=app_start + timedelta(seconds=5),
    )
    _record_event(writer, "onMI", long_info, app_start + timedelta(seconds=5.1))
    _record_event(writer, "onArI", ari_info, app_start + timedelta(seconds=5.2))
    _record_event(writer, "onMI", short_info, app_start + timedelta(seconds=65))
    _record_area(writer, "same-ar", "ar", app_start + timedelta(seconds=66))
    _record_area(writer, "second-vw", "vw", app_start + timedelta(seconds=67))
    writer.finalize()

    summary = tmp_path / "summary.json"
    summary.write_bytes(
        orjson.dumps(
            {
                "records": [
                    {
                        "kind": "window",
                        "state": "started",
                        "phase": "p2-04-app-open:official-app-open-window",
                        "observed_at": app_start.isoformat(),
                    }
                ]
            }
        )
    )
    return [first, second], [summary], long_info, short_info


def _file_digests(paths: list[Path]) -> dict[str, str]:
    return {
        str(path): sha256(path.read_bytes()).hexdigest()
        for root in paths
        for path in root.rglob("*")
        if path.is_file()
    }


def test_inventory_is_read_only_and_correlates_get_mi_and_app_init(
    tmp_path: Path,
) -> None:
    artifacts, summaries, long_info, _ = _build_corpus(tmp_path)
    before = _file_digests(artifacts)

    report = analyze_phase2_corpus(artifacts, summary_paths=summaries)

    assert _file_digests(artifacts) == before
    assert report["corpus"]["capture_count"] == 2
    long_rows = [
        row
        for row in report["inventory"]
        if row["command"] == "onMI"
        and row["source_path"] == "$.body.data.info"
        and row["original_length"] == len(long_info)
    ]
    assert len(long_rows) == 2
    assert {row["decoded_length"] for row in long_rows} == {657}
    assert all(
        row["nearest_preceding_get_mi"]["delta_seconds"] == 0.1 for row in long_rows
    )
    app_row = next(row for row in long_rows if row["phase"] == "p2-04-app-open")
    assert app_row["context_labels"] == ["app-init-window"]
    assert app_row["seconds_from_window_start"] == 5.1
    assert (
        report["analysis"]["on_mi_info"]["form_876_get_mi_association"]["status"]
        == "consistent-in-corpus"
    )


def test_on_mi_reports_periodic_support_and_timing_counterexamples(
    tmp_path: Path,
) -> None:
    artifacts, summaries, _, _ = _build_corpus(tmp_path)
    report = analyze_phase2_corpus(artifacts, summary_paths=summaries)
    periodic = report["analysis"]["on_mi_info"]["form_52_periodicity"]
    assert periodic["status"] == "consistent-in-corpus"
    assert periodic["tight_get_mi_counterexamples"] == []
    assert periodic["intervals"][0]["interval_seconds"] == 60.0

    counter = tmp_path / "p2-counter"
    writer = _writer(counter, "p2-counter")
    start = datetime(2026, 8, 22, 13, tzinfo=UTC)
    writer.set_context("p2-counter:tail", MowerState.MOWING)
    _record_event(writer, "onMI", base64.b64encode(b"L" * 657).decode(), start)
    writer.record_mqtt(
        _GET_MI_REQUEST_TOPIC,
        orjson.dumps({"body": {"data": {"type": "0"}}}),
        observed_at=start + timedelta(seconds=1),
    )
    _record_event(
        writer,
        "onMI",
        base64.b64encode(b"S" * 39).decode(),
        start + timedelta(seconds=1.1),
    )
    writer.finalize()
    report = analyze_phase2_corpus([counter])
    on_mi = report["analysis"]["on_mi_info"]
    assert on_mi["form_876_get_mi_association"]["status"] == (
        "counterexamples-observed"
    )
    assert len(on_mi["form_876_get_mi_association"]["counterexamples"]) == 1
    assert on_mi["form_52_periodicity"]["tight_get_mi_counterexamples"]


def test_on_ari_groups_by_digest_and_preceding_on_mi_form(tmp_path: Path) -> None:
    artifacts, summaries, _, _ = _build_corpus(tmp_path)
    report = analyze_phase2_corpus(artifacts, summary_paths=summaries)
    on_ari = report["analysis"]["on_ari_info"]

    variant = next(
        item
        for item in on_ari["variants"]
        if item["original_sha256"] == sha256(b"opaque-ari-repeat").hexdigest()
    )
    assert variant["preceding_on_mi_forms"] == {"52-byte": 1, "876-byte": 2}
    app_observation = next(
        item for item in variant["observations"] if item["phase"] == "p2-04-app-open"
    )
    assert app_observation["seconds_from_app_init"] == 5.2
    assert app_observation["preceding_on_mi"]["delta_seconds"] == 0.1
    assert on_ari["causality_guard"].startswith("Legacy/N-GIoT")


def test_area_set_stability_separates_ar_vw_and_fixture_candidates(
    tmp_path: Path,
) -> None:
    artifacts, summaries, long_info, short_info = _build_corpus(tmp_path)
    report = analyze_phase2_corpus(artifacts, summary_paths=summaries)
    area = report["analysis"]["get_area_set_subsets"]

    assert area["types"] == {"ar": 2, "vw": 2, "other": {}}
    ar = next(item for item in area["stability"] if item["type"] == "ar")
    vw = next(item for item in area["stability"] if item["type"] == "vw")
    assert ar["stable_within_each_capture"] is True
    assert ar["stable_across_captures"] is True
    assert vw["stable_across_captures"] is False

    candidates = report["analysis"]["fixture_candidates"]
    digests = {item["original_sha256"] for item in candidates}
    assert sha256(long_info.encode()).hexdigest() in digests
    assert sha256(short_info.encode()).hexdigest() in digests
    assert all(
        item["repository_safe_assessment"] == "eligible-after-manual-review"
        for item in candidates
    )

    csv_text = inventory_csv(report)
    assert "nearest_get_mi_control_transport" in csv_text.splitlines()[0]
    assert "opaque-ari-repeat" not in csv_text
