from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import orjson
import pytest

from deebot_client.diagnostics.goat_map_area_split import (
    AreaSplitCaptureConfig,
    AreaSplitEvidenceObserver,
    AreaSplitGateClosedError,
    AreaSplitState,
    AreaSplitStateMachine,
    attribute_area_split_save,
    compare_area_split_observations,
    evaluate_area_split_postconditions,
    evaluate_area_split_preconditions,
    summarize_area_split_map_commands,
)
from deebot_client.diagnostics.goat_map_refresh import (
    MowerState,
    TrafficRecord,
)

_GOLDEN_ONMI = (
    Path(__file__).parents[1]
    / "fixtures"
    / "goat_map"
    / "onmi_info_representations.json"
)
_PREFIX = bytes.fromhex("5d00000400")
_INVARIANT = bytes.fromhex("002d96c042005e")
_ONARI_SERIAL_2_SIGNATURE = bytes.fromhex("b4fc81d4375de7a0f636f001dc016fe0ca")


def _topic(command: str, *, direction: str) -> str:
    if direction == "event":
        return f"iot/atr/{command}/device/class/resource/j"
    marker = "q" if direction == "request" else "p"
    return f"iot/p2p/{command}/a/b/c/d/e/f/{marker}/id/j"


def _payload(data: dict[str, Any]) -> bytes:
    return orjson.dumps({"body": {"data": data}})


def _onmi_fixture(label: str = "immediate-876") -> dict[str, Any]:
    fixtures = orjson.loads(_GOLDEN_ONMI.read_bytes())
    return next(item for item in fixtures if item["label"] == label)


def _framed_onari(*, info_size: int, body_byte: int) -> bytes:
    return (
        _PREFIX
        + info_size.to_bytes(4, "little")
        + _INVARIANT
        + b"\x14"
        + _ONARI_SERIAL_2_SIGNATURE
        + bytes([body_byte]) * 700
    )


def _populate_stable_window(
    observer: AreaSplitEvidenceObserver,
    *,
    observed_at: datetime,
    batid: str,
    onari_body_byte: int,
    subsets: str = "opaque-area-set",
    mid: str = "1",
    onmi_label: str = "immediate-876",
    include_onari: bool = True,
    onari_serial: int = 2,
    cardinality_as_strings: bool = False,
) -> None:
    fixture = _onmi_fixture(onmi_label)
    observer.observe_mqtt(
        _topic("getMI", direction="request"),
        b"{}",
        observed_at=observed_at,
    )
    observer.observe_mqtt(
        _topic("onMI", direction="event"),
        _payload(
            {
                "mid": mid,
                "infoSize": fixture["info_size"],
                "info": fixture["original"],
            }
        ),
        observed_at=observed_at + timedelta(milliseconds=100),
    )
    observer.observe_mqtt(
        _topic("getAreaSet", direction="response"),
        _payload(
            {
                "mid": mid,
                "aid": "7",
                "type": "ar",
                "infoSize": len(subsets),
                "subsets": subsets,
            }
        ),
        observed_at=observed_at + timedelta(milliseconds=200),
    )
    if not include_onari:
        return
    info_size = 6316
    framed = _framed_onari(info_size=info_size, body_byte=onari_body_byte)
    chunk_size = len(framed) // onari_serial
    segments = tuple(
        framed[index * chunk_size : (index + 1) * chunk_size]
        if index < onari_serial - 1
        else framed[index * chunk_size :]
        for index in range(onari_serial)
    )
    for index, segment in enumerate(segments):
        observer.observe_mqtt(
            _topic("onArI", direction="event"),
            _payload(
                {
                    "batid": batid,
                    "serial": str(onari_serial)
                    if cardinality_as_strings
                    else onari_serial,
                    "index": str(index) if cardinality_as_strings else index,
                    "infoSize": info_size,
                    "mid": mid,
                    "type": 0,
                    "using": 1,
                    "info": base64.b64encode(segment).decode("ascii"),
                }
            ),
            observed_at=observed_at + timedelta(milliseconds=300 + index * 10),
        )


def _record(
    *,
    observed_at: datetime,
    phase: str,
    command: str,
    direction: str = "request",
    mower_state: MowerState = MowerState.PAUSED,
) -> TrafficRecord:
    return TrafficRecord(
        observed_at=observed_at.isoformat(),
        kind="mqtt",
        session="mq",
        phase=phase,
        mower_state=mower_state.value,
        transport="mq",
        topic=f"iot/p2p/{command}/<redacted>",
        command=command,
        direction=direction,
    )


def test_area_split_config_requires_paused_and_bounded_windows() -> None:
    AreaSplitCaptureConfig(mower_state=MowerState.PAUSED)

    with pytest.raises(ValueError, match="paused"):
        AreaSplitCaptureConfig(mower_state=MowerState.MOWING)
    with pytest.raises(ValueError, match="baseline"):
        AreaSplitCaptureConfig(baseline_seconds=29)
    with pytest.raises(ValueError, match="App-init"):
        AreaSplitCaptureConfig(app_init_seconds=29)
    with pytest.raises(ValueError, match="Post-split"):
        AreaSplitCaptureConfig(post_split_seconds=119)


def test_state_machine_never_opens_edit_gate_without_explicit_pass() -> None:
    machine = AreaSplitStateMachine()
    for state in (
        AreaSplitState.PRE_SPLIT_BASELINE,
        AreaSplitState.PRE_SPLIT_APP_INIT_1,
        AreaSplitState.PRE_SPLIT_APP_INIT_QUIET,
        AreaSplitState.PRE_SPLIT_APP_INIT_2,
        AreaSplitState.PRECONDITION_EVALUATION,
    ):
        machine.transition(state)

    with pytest.raises(AreaSplitGateClosedError, match="explicitly passed"):
        machine.transition(
            AreaSplitState.SPLIT_EDIT, precondition_status="inconclusive"
        )

    machine.transition(AreaSplitState.SPLIT_EDIT, precondition_status="passed")
    assert machine.state is AreaSplitState.SPLIT_EDIT


def test_precondition_passes_with_stable_map_and_different_onari_bytes() -> None:
    window = ["init-1"]
    observer = AreaSplitEvidenceObserver(lambda: window[0])
    started = datetime(2026, 8, 22, 12, tzinfo=UTC)
    _populate_stable_window(
        observer,
        observed_at=started,
        batid="set-one",
        onari_body_byte=0x11,
    )
    window[0] = "init-2"
    _populate_stable_window(
        observer,
        observed_at=started + timedelta(minutes=1),
        batid="set-two",
        onari_body_byte=0x22,
    )

    result = evaluate_area_split_preconditions(
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        allowed_app_windows=("init-1", "init-2"),
    )

    assert result["status"] == "passed"
    assert result["split_edit_gate_open"] is True
    assert result["checks"]["complete_grouped_onArI"]["byte_identity_required"] is False


def test_p2_09_canonical_string_serial_three_opens_precondition_gate() -> None:
    window = ["init-1"]
    observer = AreaSplitEvidenceObserver(lambda: window[0])
    started = datetime(2026, 8, 22, 12, tzinfo=UTC)
    for name, batid, offset in (
        ("init-1", "p2-09-string-set-one", 0),
        ("init-2", "p2-09-string-set-two", 60),
    ):
        window[0] = name
        _populate_stable_window(
            observer,
            observed_at=started + timedelta(seconds=offset),
            batid=batid,
            onari_body_byte=0x33,
            onari_serial=3,
            cardinality_as_strings=True,
        )

    result = evaluate_area_split_preconditions(
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        allowed_app_windows=("init-1", "init-2"),
    )

    assert result["status"] == "passed"
    assert result["split_edit_gate_open"] is True
    grouped = observer.complete_on_ari_sets(("init-1", "init-2"))
    assert grouped["incomplete"] == []
    assert [item["serial"] for item in grouped["complete"]] == [3, 3]
    assert all(item["segment_count"] == 3 for item in grouped["complete"])


def test_precondition_fails_for_changed_area_set_and_external_quiet_request() -> None:
    window = ["init-1"]
    observer = AreaSplitEvidenceObserver(lambda: window[0])
    started = datetime(2026, 8, 22, 12, tzinfo=UTC)
    _populate_stable_window(
        observer,
        observed_at=started,
        batid="set-one",
        onari_body_byte=0x11,
    )
    window[0] = "init-2"
    _populate_stable_window(
        observer,
        observed_at=started + timedelta(minutes=1),
        batid="set-two",
        onari_body_byte=0x22,
        subsets="changed-area-set",
    )
    external = _record(
        observed_at=started + timedelta(seconds=50),
        phase="pre-split-app-init-quiet",
        command="getMI",
    )

    result = evaluate_area_split_preconditions(
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        recorder_records=(external,),
        allowed_app_windows=("init-1", "init-2"),
    )

    assert result["status"] == "inconclusive"
    assert result["split_edit_gate_open"] is False
    failed_checks = {item["check"] for item in result["failures"]}
    assert failed_checks == {"stable-getAreaSet", "controlled-source-isolation"}
    unexpected = result["checks"]["controlled_source_isolation"]["unexpected_sequences"]
    assert unexpected[0]["classification"] == "concurrent-external"


@pytest.mark.parametrize(
    ("changed_arguments", "expected_check"),
    [
        ({"mid": "2"}, "same-static-map-mid"),
        ({"onmi_label": "periodic-52"}, "comparable-onMI"),
        ({"include_onari": False}, "complete-grouped-onArI"),
    ],
)
def test_each_required_static_gate_failure_keeps_edit_closed(
    changed_arguments: dict[str, Any],
    expected_check: str,
) -> None:
    window = ["init-1"]
    observer = AreaSplitEvidenceObserver(lambda: window[0])
    started = datetime(2026, 8, 22, 12, tzinfo=UTC)
    _populate_stable_window(
        observer,
        observed_at=started,
        batid="set-one",
        onari_body_byte=0x11,
    )
    window[0] = "init-2"
    _populate_stable_window(
        observer,
        observed_at=started + timedelta(minutes=1),
        batid="set-two",
        onari_body_byte=0x22,
        **changed_arguments,
    )

    result = evaluate_area_split_preconditions(
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        allowed_app_windows=("init-1", "init-2"),
    )

    assert result["status"] == "inconclusive"
    assert result["split_edit_gate_open"] is False
    assert expected_check in {item["check"] for item in result["failures"]}


def test_app_originated_controls_inside_marked_init_windows_are_allowed() -> None:
    window = ["init-1"]
    observer = AreaSplitEvidenceObserver(lambda: window[0])
    started = datetime(2026, 8, 22, 12, tzinfo=UTC)
    _populate_stable_window(
        observer,
        observed_at=started,
        batid="set-one",
        onari_body_byte=0x11,
    )
    window[0] = "init-2"
    _populate_stable_window(
        observer,
        observed_at=started + timedelta(minutes=1),
        batid="set-two",
        onari_body_byte=0x22,
    )
    controls = tuple(
        _record(
            observed_at=started + timedelta(seconds=offset),
            phase="init-1" if offset < 60 else "init-2",
            command=command,
        )
        for offset, command in (
            (1, "appping"),
            (2, "getMI"),
            (3, "getAreaSet"),
            (61, "appping"),
            (62, "getMI"),
            (63, "getAreaSet"),
        )
    )

    result = evaluate_area_split_preconditions(
        observer,
        init_1_window="init-1",
        init_2_window="init-2",
        recorder_records=controls,
        allowed_app_windows=("init-1", "init-2"),
    )

    assert result["status"] == "passed"
    assert result["checks"]["controlled_source_isolation"]["status"] == "passed"


def test_save_attribution_ignores_reads_and_discovers_unknown_write() -> None:
    started = datetime(2026, 8, 22, 12, tzinfo=UTC)
    records = (
        _record(observed_at=started, phase="edit", command="getMapTrack"),
        _record(
            observed_at=started + timedelta(milliseconds=50),
            phase="edit",
            command="divideWorkingArea",
        ),
    )

    result = attribute_area_split_save(records, edit_windows=("edit",))

    assert result["status"] == "attributed"
    assert result["authoritative_command"] == "divideWorkingArea"
    assert result["authoritative_network_timestamp"] == records[1].observed_at
    assert result["candidates"][0]["opaque_payload_allowlisted"] is False


def test_multiple_distinct_save_write_commands_are_ambiguous() -> None:
    started = datetime(2026, 8, 22, 12, tzinfo=UTC)
    records = (
        _record(observed_at=started, phase="save", command="setAreaSet"),
        _record(
            observed_at=started + timedelta(milliseconds=10),
            phase="save",
            command="saveMapPartition",
        ),
    )

    result = attribute_area_split_save(records, edit_windows=("save",))

    assert result["status"] == "ambiguous"
    assert result["authoritative_network_timestamp"] is None
    assert result["distinct_candidate_commands"] == ["saveMapPartition", "setAreaSet"]


def test_missing_write_is_unattributed_without_affecting_delta_postconditions() -> None:
    window = ["post-split"]
    observer = AreaSplitEvidenceObserver(lambda: window[0])
    _populate_stable_window(
        observer,
        observed_at=datetime(2026, 8, 22, 12, tzinfo=UTC),
        batid="post-set",
        onari_body_byte=0x33,
    )

    attribution = attribute_area_split_save((), edit_windows=("split-save",))
    postcondition = evaluate_area_split_postconditions(
        observer,
        after_windows=("post-split",),
        recorder_records=(),
    )

    assert attribution["status"] == "unattributed"
    assert attribution["authoritative_network_timestamp"] is None
    assert postcondition["status"] == "passed"
    assert "save_network_attribution" not in postcondition["checks"]


def test_observation_statuses_do_not_treat_presence_as_byte_delta() -> None:
    result = compare_area_split_observations(
        [
            {"key": "same", "digest": "a"},
            {"key": "count", "digest": "b"},
            {"key": "count", "digest": "b"},
            {"key": "changed", "digest": "c"},
            {"key": "before", "digest": "d"},
        ],
        [
            {"key": "same", "digest": "a"},
            {"key": "count", "digest": "b"},
            {"key": "changed", "digest": "e"},
            {"key": "after", "digest": "f"},
        ],
        key_fields=("key",),
        value_fields=("digest",),
    )
    statuses = {item["key"]["key"]: item for item in result["groups"]}

    assert statuses["same"]["status"] == "unchanged"
    assert statuses["count"]["status"] == "occurrence-count-changed"
    assert statuses["changed"]["status"] == "value-changed"
    assert statuses["before"]["status"] == "before-only"
    assert statuses["after"]["status"] == "after-only"
    assert all(item["byte_delta_proven"] is False for item in statuses.values())


def test_unknown_map_write_is_kept_as_sanitized_command_timing_only() -> None:
    record = _record(
        observed_at=datetime(2026, 8, 22, 12, tzinfo=UTC),
        phase="split-save",
        command="setFutureMapShape",
    )

    inventory = summarize_area_split_map_commands(
        (record,),
        windows={"split-save"},
    )

    assert inventory == [
        {
            "command": "setFutureMapShape",
            "direction": "request",
            "count": 1,
            "first_at": record.observed_at,
            "last_at": record.observed_at,
            "windows": ["split-save"],
            "classification": "sanitized-command-timing-only",
        }
    ]
