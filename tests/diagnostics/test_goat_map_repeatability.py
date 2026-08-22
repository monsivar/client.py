from __future__ import annotations

import base64
from collections import Counter
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import TYPE_CHECKING

import orjson
import pytest

from deebot_client.diagnostics.goat_map_capture import GoatMapCaptureWriter
from deebot_client.diagnostics.goat_map_refresh import MowerState
from deebot_client.diagnostics.goat_map_repeatability import (
    RepeatabilityConfig,
    ShortOnMiCadenceObserver,
    analyze_repeatability_artifact,
    build_corrected_repeatability_report,
)

if TYPE_CHECKING:
    from pathlib import Path

_GET_MI_REQUEST_TOPIC = (
    "iot/p2p/getMI/sender/class/resource/receiver/class/resource/q/req/j"
)


def _writer(path: Path) -> GoatMapCaptureWriter:
    return GoatMapCaptureWriter(
        path,
        phase="p2-08-repeatability",
        mower_state=MowerState.MOWING,
        device_class="2i0fns",
        factors={
            "mqtt": "normal-mq",
            "jmq": "none",
            "appping": "ngiot",
            "get_mi_sequence": ["legacy", "ngiot"],
        },
        capture_id_factory=lambda: "8" * 32,
    )


def _payload(info: str) -> bytes:
    return orjson.dumps({"body": {"data": {"mid": "1", "info": info}}})


def _record_event(
    writer: GoatMapCaptureWriter,
    command: str,
    info: str,
    observed_at: datetime,
) -> None:
    writer.record_mqtt(
        f"iot/atr/{command}/device/class/resource/j",
        _payload(info),
        observed_at=observed_at,
    )


def _record_control(writer: GoatMapCaptureWriter, observed_at: datetime) -> None:
    writer.record_mqtt(
        _GET_MI_REQUEST_TOPIC,
        orjson.dumps({"body": {"data": {"type": "0"}}}),
        observed_at=observed_at,
    )


def _opaque_value(length: int, label: bytes) -> str:
    value = label
    assert len(value) <= length
    return (value + b"x" * (length - len(value))).decode()


def _repeatability_artifact(
    path: Path,
) -> tuple[str, datetime, dict[str, dict[str, int]]]:
    writer = _writer(path)
    start = datetime(2026, 8, 22, 10, tzinfo=UTC)
    short = base64.b64encode(b"S" * 38).decode()
    long = base64.b64encode(b"L" * 657).decode()
    ari_820 = _opaque_value(820, b"fixture-820")
    ari_1024 = _opaque_value(1024, b"fixture-1024")
    ari_896 = _opaque_value(896, b"fixture-896")

    writer.set_context("p2-08-repeatability:cadence-establishment", MowerState.MOWING)
    _record_event(writer, "onMI", short, start)
    _record_event(writer, "onMI", short, start + timedelta(seconds=60))

    writer.set_context("p2-08-repeatability:legacy-get-mi-action", MowerState.MOWING)
    _record_control(writer, start + timedelta(seconds=85))
    _record_event(writer, "onMI", long, start + timedelta(seconds=85.1))
    _record_event(writer, "onArI", ari_1024, start + timedelta(seconds=85.2))
    _record_event(writer, "onArI", ari_896, start + timedelta(seconds=85.3))

    writer.set_context(
        "p2-08-repeatability:cadence-observation-after-legacy",
        MowerState.MOWING,
    )
    _record_event(writer, "onMI", short, start + timedelta(seconds=120))
    _record_event(writer, "onArI", ari_820, start + timedelta(seconds=120.1))

    writer.set_context("p2-08-repeatability:ngiot-get-mi-action", MowerState.MOWING)
    _record_control(writer, start + timedelta(seconds=145))
    _record_event(writer, "onMI", long, start + timedelta(seconds=145.1))
    _record_event(writer, "onArI", ari_1024, start + timedelta(seconds=145.2))
    _record_event(writer, "onArI", ari_896, start + timedelta(seconds=145.3))

    writer.set_context(
        "p2-08-repeatability:cadence-observation-after-ngiot",
        MowerState.MOWING,
    )
    _record_event(writer, "onMI", short, start + timedelta(seconds=180))
    _record_event(writer, "onArI", ari_820, start + timedelta(seconds=180.1))
    writer.finalize()
    families = {
        sha256(ari_820.encode()).hexdigest(): {"length": 820, "on_mi_length": 52},
        sha256(ari_1024.encode()).hexdigest(): {
            "length": 1024,
            "on_mi_length": 876,
        },
        sha256(ari_896.encode()).hexdigest(): {
            "length": 896,
            "on_mi_length": 876,
        },
    }
    return short, start, families


def test_repeatability_config_requires_mowing_and_bounded_offset() -> None:
    RepeatabilityConfig(mower_state=MowerState.MOWING, control_offset_seconds=25)
    with pytest.raises(ValueError, match="active mowing"):
        RepeatabilityConfig(mower_state=MowerState.PAUSED)
    with pytest.raises(ValueError, match="Control offset"):
        RepeatabilityConfig(control_offset_seconds=19)


@pytest.mark.asyncio
async def test_cadence_observer_requires_two_equal_strict_base64_short_forms() -> None:
    observer = ShortOnMiCadenceObserver()
    start = datetime(2026, 8, 22, 10, tzinfo=UTC)
    short = base64.b64encode(b"S" * 38).decode()
    observer.observe(
        "iot/atr/onMI/device/class/resource/j",
        _payload(short),
        observed_at=start,
        monotonic_seconds=10,
    )
    observer.observe(
        "iot/atr/onMI/device/class/resource/j",
        _payload(short),
        observed_at=start + timedelta(seconds=60),
        monotonic_seconds=70,
    )

    cadence = await observer.wait_for_cadence(
        timeout_seconds=0.1,
        min_interval_seconds=45,
        max_interval_seconds=75,
    )
    assert cadence is not None
    assert cadence.interval_seconds == 60
    assert cadence.first.original_sha256 == cadence.second.original_sha256

    inconclusive = ShortOnMiCadenceObserver()
    inconclusive.observe(
        "iot/atr/onMI/device/class/resource/j",
        _payload("not-base64"),
        monotonic_seconds=1,
    )
    assert (
        await inconclusive.wait_for_cadence(
            timeout_seconds=0.01,
            min_interval_seconds=45,
            max_interval_seconds=75,
        )
        is None
    )


def test_repeatability_analysis_classifies_timing_and_supports_hypotheses(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "capture"
    _, start, families = _repeatability_artifact(artifact)

    report = analyze_repeatability_artifact(
        artifact,
        cadence_anchor_at=(start + timedelta(seconds=60)).isoformat(),
        # This fractional cadence reproduces the P2-08 boundary that formerly
        # differed by one microsecond after repeated timedelta addition.
        cadence_seconds=60.01633050000237,
        controlled_get_mi=[
            {
                "transport": "legacy",
                "started_at": (start + timedelta(seconds=85)).isoformat(),
            },
            {
                "transport": "ngiot",
                "started_at": (start + timedelta(seconds=145)).isoformat(),
            },
        ],
        expected_on_ari_families=families,
    )

    classifications = Counter(item["classification"] for item in report["observations"])
    assert classifications["control-associated"] == 6
    assert classifications["cadence-associated"] == 5
    assert classifications["ambiguous-overlap"] == 0
    assert report["hypotheses"]["H1"]["status"] == "supported-in-this-capture"
    assert report["hypotheses"]["H2"]["status"] == "supported-in-this-capture"
    assert report["hypotheses"]["H3"]["status"] == "supported-in-this-capture"
    assert report["hypotheses"]["H4"]["status"] == "supported-in-this-capture"
    assert all(
        result["role_proven"] is False for result in report["hypotheses"].values()
    )
    assert all(
        item["status"] == "eligible-after-manual-review"
        for item in report["fixture_candidates"]
    )


def test_repeatability_analysis_reports_counterexamples_without_proving_roles(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "counterexample"
    writer = _writer(artifact)
    start = datetime(2026, 8, 22, 10, tzinfo=UTC)
    short = base64.b64encode(b"S" * 38).decode()
    long = base64.b64encode(b"L" * 657).decode()
    ari_820 = _opaque_value(820, b"fixture-820")
    writer.set_context("p2-08-repeatability:cadence-establishment", MowerState.MOWING)
    _record_event(writer, "onMI", short, start)
    _record_event(writer, "onMI", short, start + timedelta(seconds=60))
    writer.set_context("p2-08-repeatability:legacy-get-mi-action", MowerState.MOWING)
    _record_control(writer, start + timedelta(seconds=85))
    _record_event(writer, "onMI", short, start + timedelta(seconds=85.1))
    _record_event(writer, "onMI", long, start + timedelta(seconds=120))
    _record_event(writer, "onArI", ari_820, start + timedelta(seconds=120.1))
    writer.finalize()
    families = {
        sha256(ari_820.encode()).hexdigest(): {"length": 820, "on_mi_length": 52}
    }

    report = analyze_repeatability_artifact(
        artifact,
        cadence_anchor_at=(start + timedelta(seconds=60)).isoformat(),
        cadence_seconds=60,
        expected_on_ari_families=families,
    )

    assert report["hypotheses"]["H1"]["status"] == "counterexample-observed"
    assert report["hypotheses"]["H2"]["status"] == "counterexample-observed"
    assert report["hypotheses"]["H3"]["status"] == "counterexample-observed"
    assert report["hypotheses"]["H4"]["status"] == "counterexample-observed"
    assert report["hypotheses"]["H4"]["counterexamples"]


def test_corrected_report_supersedes_prior_analysis_without_modifying_artifact(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "capture"
    _, start, _ = _repeatability_artifact(artifact)
    manifest_before = (artifact / "manifest.json").read_bytes()
    records_before = (artifact / "records.jsonl").read_bytes()
    manifest = orjson.loads(manifest_before)
    summary_path = tmp_path / "old-summary.json"
    summary_path.write_bytes(
        orjson.dumps(
            {
                "phase2_capture": manifest,
                "repeatability_run": {
                    "cadence_anchor_at": (start + timedelta(seconds=60)).isoformat(),
                    "cadence_seconds": 60.01633050000237,
                    "controls": [
                        {
                            "transport": "legacy",
                            "started_at": (start + timedelta(seconds=85)).isoformat(),
                        },
                        {
                            "transport": "ngiot",
                            "started_at": (start + timedelta(seconds=145)).isoformat(),
                        },
                    ],
                },
                "repeatability_analysis": {
                    "hypotheses": {
                        "H1": {"status": "supported-in-this-capture"},
                        "H2": {"status": "counterexample-observed"},
                        "H3": {"status": "counterexample-observed"},
                        "H4": {"status": "inconclusive"},
                    }
                },
            }
        )
    )

    corrected = build_corrected_repeatability_report(artifact, summary_path)

    assert corrected["analysis_version"] == "goat-repeatability-timing/v2"
    assert corrected["artifact_reference"]["capture_id"] == "8" * 32
    assert corrected["artifact_reference"]["artifact_modified"] is False
    assert corrected["superseded_report"]["status"] == "superseded"
    assert corrected["superseded_report"]["hypothesis_statuses"]["H2"] == (
        "counterexample-observed"
    )
    assert corrected["corrected_hypothesis_statuses"] == {
        "H1": "supported-in-this-capture",
        "H2": "supported-in-this-capture",
        "H3": "supported-in-this-capture",
        "H4": "inconclusive",
    }
    assert (artifact / "manifest.json").read_bytes() == manifest_before
    assert (artifact / "records.jsonl").read_bytes() == records_before
