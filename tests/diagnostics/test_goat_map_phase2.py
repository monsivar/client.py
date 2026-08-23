from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import orjson
import pytest

from deebot_client.diagnostics.goat_map_capture import (
    SPECIAL_CONTOUR_CAPTURE_COMMANDS,
    GoatMapCaptureWriter,
)
from deebot_client.diagnostics.goat_map_phase2 import (
    ControlledMapEditConfig,
    FrontendReloadAttributionConfig,
    PollerIsolationConfig,
    SpecialContourDeleteConfig,
    ZoneAbsentReadbackConfig,
    _SpecialContourTransitionObserver,
    summarize_controlled_map_edit_window,
    summarize_frontend_reload_window,
    summarize_poller_isolation_window,
    summarize_special_contour_delete,
    summarize_zone_absent_readback,
)
from deebot_client.diagnostics.goat_map_refresh import (
    MowerState,
    MqttTrafficRecorder,
    TrafficRecord,
)

if TYPE_CHECKING:
    from pathlib import Path


def _record(
    *,
    observed_at: datetime,
    phase: str,
    kind: str = "mqtt",
    command: str | None = None,
    direction: str | None = None,
    state: str | None = None,
    session: str | None = None,
) -> TrafficRecord:
    return TrafficRecord(
        observed_at=observed_at.isoformat(),
        kind=kind,  # type: ignore[arg-type]
        session=session or ("measurement" if kind == "window" else "mq"),
        phase=phase,
        mower_state=MowerState.MOWING.value,
        command=command,
        direction=direction,
        state=state,
    )


def test_frontend_reload_config_enforces_controlled_window() -> None:
    FrontendReloadAttributionConfig(
        mower_state=MowerState.MOWING,
        baseline_seconds=30,
        reload_window_seconds=90,
    )

    with pytest.raises(ValueError, match="active mowing"):
        FrontendReloadAttributionConfig(mower_state=MowerState.PAUSED)
    with pytest.raises(ValueError, match="baseline"):
        FrontendReloadAttributionConfig(baseline_seconds=29)
    with pytest.raises(ValueError, match="attribution window"):
        FrontendReloadAttributionConfig(reload_window_seconds=91)
    with pytest.raises(ValueError, match="Unsupported"):
        FrontendReloadAttributionConfig(trigger="unknown")


def test_poller_isolation_config_requires_paused_eight_minute_window() -> None:
    PollerIsolationConfig(mower_state=MowerState.PAUSED, quiet_seconds=480)

    with pytest.raises(ValueError, match="paused"):
        PollerIsolationConfig(mower_state=MowerState.MOWING)
    with pytest.raises(ValueError, match="480"):
        PollerIsolationConfig(quiet_seconds=479)


def test_controlled_map_edit_config_requires_paused_bounded_window() -> None:
    ControlledMapEditConfig(
        mower_state=MowerState.PAUSED,
        baseline_seconds=30,
        post_save_seconds=90,
    )

    with pytest.raises(ValueError, match="paused"):
        ControlledMapEditConfig(mower_state=MowerState.MOWING)
    with pytest.raises(ValueError, match="baseline"):
        ControlledMapEditConfig(baseline_seconds=9)
    with pytest.raises(ValueError, match="Post-save"):
        ControlledMapEditConfig(post_save_seconds=181)


def test_special_contour_delete_config_requires_paused_readback_windows() -> None:
    SpecialContourDeleteConfig(
        mower_state=MowerState.PAUSED,
        initial_readback_timeout=45,
        post_delete_seconds=120,
    )

    with pytest.raises(ValueError, match="paused"):
        SpecialContourDeleteConfig(mower_state=MowerState.MOWING)
    with pytest.raises(ValueError, match="readback"):
        SpecialContourDeleteConfig(initial_readback_timeout=10)
    with pytest.raises(ValueError, match="Post-delete"):
        SpecialContourDeleteConfig(post_delete_seconds=301)


def test_zone_absent_readback_config_requires_explicit_state_and_bounded_window() -> (
    None
):
    ZoneAbsentReadbackConfig(
        mower_state=MowerState.PAUSED,
        baseline_seconds=30,
        readback_seconds=120,
    )

    with pytest.raises(ValueError, match="explicit mower state"):
        ZoneAbsentReadbackConfig(mower_state=MowerState.UNKNOWN)
    with pytest.raises(ValueError, match="baseline"):
        ZoneAbsentReadbackConfig(baseline_seconds=9)
    with pytest.raises(ValueError, match="readback window"):
        ZoneAbsentReadbackConfig(readback_seconds=181)


def test_frontend_reload_summary_preserves_unattributed_full_pattern_timing() -> None:
    phase = "p2-03:frontend-reload-window"
    started_at = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    records = [
        _record(
            observed_at=started_at,
            phase=phase,
            kind="window",
            state="started",
        )
    ]
    for offset, command in enumerate(
        ("getInfo", "getPos", "getMapTrack", "getMI", "getAreaSet"),
        start=1,
    ):
        records.append(
            _record(
                observed_at=started_at + timedelta(seconds=offset),
                phase=phase,
                command=command,
                direction="request",
            )
        )
    records.append(
        _record(
            observed_at=started_at + timedelta(seconds=8),
            phase=phase,
            command="getAreaSet",
            direction="response",
        )
    )

    summary = summarize_frontend_reload_window(records, phase)

    assert summary["classification"] == "concurrent-external"
    assert summary["client_source"] == "unattributed"
    assert summary["pattern_result"] == "full-pattern-observed"
    assert summary["get_area_set_count"] == 2
    assert summary["get_area_set_request_count"] == 1
    assert summary["commands"]["getAreaSet"]["observations"] == [
        {
            "observed_at": (started_at + timedelta(seconds=5)).isoformat(),
            "offset_seconds": 5.0,
            "direction": "request",
        },
        {
            "observed_at": (started_at + timedelta(seconds=8)).isoformat(),
            "offset_seconds": 8.0,
            "direction": "response",
        },
    ]


def test_frontend_reload_summary_distinguishes_state_position_only() -> None:
    phase = "p2-03:frontend-reload-window"
    started_at = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    records = [
        _record(
            observed_at=started_at,
            phase=phase,
            kind="window",
            state="started",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=1),
            phase=phase,
            command="getInfo",
            direction="request",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=2),
            phase=phase,
            command="getPos",
            direction="request",
        ),
    ]

    summary = summarize_frontend_reload_window(records, phase)

    assert summary["pattern_result"] == "state-position-only"
    assert summary["commands"]["getMI"]["count"] == 0
    assert summary["commands"]["getAreaSet"]["count"] == 0


def test_frontend_reload_summary_identifies_absent_control_pattern() -> None:
    phase = "p2-03:frontend-reload-window"
    started_at = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    records = [
        _record(
            observed_at=started_at,
            phase=phase,
            kind="window",
            state="started",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=1),
            phase=phase,
            command="onPos",
            direction="event",
        ),
    ]

    summary = summarize_frontend_reload_window(records, phase)

    assert summary["pattern_result"] == "no-target-control-pattern"
    assert summary["client_source"] == "unattributed"


def test_official_app_open_summary_uses_distinct_unattributed_window() -> None:
    phase = "p2-04:official-app-open-window"
    started_at = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    records = [
        _record(
            observed_at=started_at,
            phase=phase,
            kind="window",
            state="started",
        )
    ]

    summary = summarize_frontend_reload_window(
        records,
        phase,
        trigger="official-app-open",
    )

    assert summary["classification"] == "concurrent-external"
    assert summary["client_source"] == "unattributed"
    assert summary["trigger"] == "official-app-open"
    assert summary["window_label"] == "official-app-open-window"
    assert summary["pattern_result"] == "no-target-control-pattern"


def test_poller_isolation_summary_verifies_request_free_window() -> None:
    phase = "p2-poller:quiet-observation"
    started_at = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)
    records = [
        _record(
            observed_at=started_at,
            phase=phase,
            kind="window",
            state="started",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=480),
            phase=phase,
            kind="window",
            state="ended",
        ),
    ]

    summary = summarize_poller_isolation_window(records, phase)

    assert summary["quiet_environment_status"] == "verified-for-retry"
    assert summary["external_request_count"] == 0
    assert summary["source_attribution"] == "unknown"
    assert summary["diagnostic_control_actions"] == []


def test_poller_isolation_summary_reports_unattributed_360_second_polling() -> None:
    phase = "p2-poller:quiet-observation"
    started_at = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)
    records = [
        _record(
            observed_at=started_at,
            phase=phase,
            kind="window",
            state="started",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=30),
            phase=phase,
            command="getBattery",
            direction="request",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=30.2),
            phase=phase,
            command="getBattery",
            direction="response",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=390),
            phase=phase,
            command="getBattery",
            direction="request",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=390.2),
            phase=phase,
            command="getBattery",
            direction="response",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=480),
            phase=phase,
            kind="window",
            state="ended",
        ),
    ]

    summary = summarize_poller_isolation_window(records, phase)

    assert summary["quiet_environment_status"] == "not-verified-for-retry"
    assert summary["source_attribution"] == "unknown"
    assert summary["external_request_count"] == 2
    assert summary["observation"] == (
        "periodic concurrent-external read-only polling, source unattributed"
    )
    battery = summary["commands"]["getBattery"]
    assert battery["request_intervals_seconds"] == [360.0]
    assert battery["periodicity"]["status"] == (
        "approximately-360-second-cadence-observed"
    )
    assert battery["request_observations"][0][
        "nearest_later_response_delta_seconds"
    ] == pytest.approx(0.2)


def test_zone_absent_summary_is_passive_and_preserves_network_timing() -> None:
    phase = "p2-07:zone-absent-readback"
    started_at = datetime(2026, 8, 22, 18, 0, tzinfo=UTC)
    records = [
        _record(
            observed_at=started_at,
            phase=phase,
            kind="window",
            state="started",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=1),
            phase=phase,
            command="getSpecialContour",
            direction="request",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=2),
            phase=phase,
            command="getSpecialContour",
            direction="response",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=3),
            phase=phase,
            command="onSpecialContour",
            direction="event",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=4),
            phase=phase,
            command="onMI",
            direction="event",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=120),
            phase=phase,
            kind="window",
            state="ended",
        ),
    ]

    summary = summarize_zone_absent_readback(records, phase)

    assert summary["classification"] == "zone-absent-readback"
    assert summary["external_trigger"] == "official-ecovacs-app-map-open"
    assert summary["network_timestamps_authoritative"] is True
    assert summary["diagnostic_control_actions"] == []
    assert summary["mower_states"] == ["mowing"]
    assert summary["special_contour_readback_count"] == 2
    assert (
        summary["first_special_contour_readback_at"]
        == (started_at + timedelta(seconds=2)).isoformat()
    )
    assert (
        summary["last_special_contour_readback_at"]
        == (started_at + timedelta(seconds=3)).isoformat()
    )
    assert summary["target_commands"]["onMI"]["event_count"] == 1
    assert summary["payload_decoding"] is False
    assert summary["semantic_field_mapping"] is False


def test_controlled_map_edit_summary_uses_exact_save_marker_and_all_commands() -> None:
    phase = "p2-05:controlled-map-edit"
    started_at = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    records = [
        _record(
            observed_at=started_at,
            phase=phase,
            kind="marker",
            state="edit-window-started",
            session="controlled-map-edit",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=12),
            phase=phase,
            command="setAreaSet",
            direction="request",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=13),
            phase=phase,
            kind="marker",
            state="save-confirmed",
            session="controlled-map-edit",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=14),
            phase=phase,
            command="onMapState",
            direction="event",
        ),
        _record(
            observed_at=started_at + timedelta(seconds=103),
            phase=phase,
            kind="marker",
            state="edit-window-ended",
            session="controlled-map-edit",
        ),
    ]

    summary = summarize_controlled_map_edit_window(records, phase)

    assert summary["classification"] == "controlled-map-edit"
    assert (
        summary["save_confirmed_at"] == (started_at + timedelta(seconds=13)).isoformat()
    )
    assert summary["save_offset_seconds"] == 13
    assert summary["commands"]["setAreaSet"]["request_count"] == 1
    assert summary["commands"]["onMapState"]["event_count"] == 1
    assert (
        summary["commands"]["onMapState"]["observations"][0][
            "offset_from_save_confirm_seconds"
        ]
        == 1
    )
    assert summary["name_based_map_event_candidates"] == ["onMapState"]
    assert summary["diagnostic_control_actions"] == []


def test_special_contour_summary_uses_set_request_as_authoritative_boundary() -> None:
    base = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    zone_phase = "p2-06:zone-present-readback"
    delete_phase = "p2-06:controlled-special-contour-delete"
    post_phase = "p2-06:post-delete-readback"
    records = [
        _record(
            observed_at=base,
            phase=zone_phase,
            command="getSpecialContour",
            direction="response",
        ),
        _record(
            observed_at=base,
            phase=zone_phase,
            kind="marker",
            state="zone-present-readback-observed",
            session="controlled-special-contour-delete",
        ),
        _record(
            observed_at=base + timedelta(seconds=10),
            phase=delete_phase,
            kind="marker",
            state="delete-action-armed",
            session="controlled-special-contour-delete",
        ),
        _record(
            observed_at=base + timedelta(seconds=20),
            phase=delete_phase,
            command="setSpecialContour",
            direction="request",
        ),
        _record(
            observed_at=base + timedelta(seconds=21),
            phase=post_phase,
            command="onSpecialContour",
            direction="event",
        ),
        _record(
            observed_at=base + timedelta(seconds=22),
            phase=post_phase,
            command="getSpecialContour",
            direction="response",
        ),
        _record(
            observed_at=base + timedelta(seconds=26),
            phase=post_phase,
            kind="marker",
            state="manual-save-confirmed",
            session="controlled-special-contour-delete",
        ),
        _record(
            observed_at=base + timedelta(seconds=140),
            phase=post_phase,
            kind="marker",
            state="observation-ended",
            session="controlled-special-contour-delete",
        ),
    ]

    summary = summarize_special_contour_delete(
        records,
        zone_present_phase=zone_phase,
        delete_phase=delete_phase,
        post_delete_phase=post_phase,
    )

    assert summary["set_request_at"] == (base + timedelta(seconds=20)).isoformat()
    assert summary["manual_save_offset_from_set_request_seconds"] == 6
    assert summary["network_timestamps_authoritative"] is True
    assert summary["manual_marker_is_operator_context_only"] is True
    assert summary["zone_present_readback_count"] == 1
    assert summary["post_delete_readback_count"] == 1
    assert summary["reversible_readback_pair_observed"] is True


def test_special_contour_transition_places_followup_in_post_delete_window(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "transition"
    phase = "p2-06"
    delete_phase = f"{phase}:controlled-special-contour-delete"
    post_phase = f"{phase}:post-delete-readback"
    recorder = MqttTrafficRecorder(phase=delete_phase, mower_state=MowerState.PAUSED)
    writer = GoatMapCaptureWriter(
        artifact_dir,
        phase=phase,
        mower_state=MowerState.PAUSED,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq"},
        capture_commands=SPECIAL_CONTOUR_CAPTURE_COMMANDS,
    )
    writer.set_context(delete_phase, MowerState.PAUSED)
    transition = _SpecialContourTransitionObserver(
        recorder,
        writer,
        post_phase,
        lambda: MowerState.PAUSED,
    )
    payload = orjson.dumps({"body": {"data": {"mid": "1", "info": "opaque"}}})
    request_topic = "iot/p2p/setSpecialContour/a/b/c/d/e/f/q/id/j"
    response_topic = "iot/p2p/getSpecialContour/a/b/c/d/e/f/p/id/j"

    recorder.record_mqtt("mq", request_topic, payload)
    writer.record_mqtt(request_topic, payload)
    transition.on_message(None, None)  # type: ignore[arg-type]
    writer.record_mqtt(response_topic, payload)
    writer.finalize()

    records = [
        orjson.loads(line)
        for line in (artifact_dir / "records.jsonl").read_bytes().splitlines()
    ]
    assert records[0]["command"] == "setSpecialContour"
    assert records[0]["window"] == delete_phase
    assert records[1]["command"] == "getSpecialContour"
    assert records[1]["window"] == post_phase
    marker = next(
        record
        for record in recorder.records
        if record.kind == "marker" and record.state == "set-request-observed"
    )
    set_request = next(
        record
        for record in recorder.records
        if record.kind == "mqtt" and record.command == "setSpecialContour"
    )
    assert marker.observed_at == set_request.observed_at
