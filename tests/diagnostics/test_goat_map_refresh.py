from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, MagicMock, patch

from aiomqtt import Message
import orjson
import pytest

from deebot_client.diagnostics.goat_map_refresh import (
    AppPresenceMqttClient,
    ControlTransport,
    EndpointSource,
    ExperimentConfig,
    GoatMapDiagnosticExperiment,
    GoatMapScenario,
    JmqMode,
    LegacyGetMiCommand,
    MowerState,
    MqttTrafficRecorder,
    NgiotControlClient,
    ScenarioFeatures,
    build_app_presence_identity,
    build_ngiot_payload,
    create_diagnostic_mqtt_clients,
    extract_ngiot_services,
    resolve_ngiot_endpoints,
    sanitize_capture,
)
from deebot_client.models import ApiDeviceInfo, Credentials
from deebot_client.mqtt_client import MqttClient, MqttConfiguration, SubscriberInfo

if TYPE_CHECKING:
    from collections.abc import Callable

    from aiohttp import ClientSession

    from deebot_client.authentication import Authenticator
    from deebot_client.models import DeviceInfo


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        (
            GoatMapScenario.MQ_ONLY,
            ScenarioFeatures(
                JmqMode.NONE, ControlTransport.NONE, ControlTransport.NONE
            ),
        ),
        (
            GoatMapScenario.MQ_AND_JMQ,
            ScenarioFeatures(
                JmqMode.APP_PRESENCE,
                ControlTransport.NONE,
                ControlTransport.NONE,
            ),
        ),
        (
            GoatMapScenario.MQ_JMQ_APPPING,
            ScenarioFeatures(
                JmqMode.APP_PRESENCE,
                ControlTransport.NGIOT,
                ControlTransport.NONE,
            ),
        ),
        (
            GoatMapScenario.MQ_JMQ_APPPING_NGIOT_GET_MI,
            ScenarioFeatures(
                JmqMode.APP_PRESENCE,
                ControlTransport.NGIOT,
                ControlTransport.NGIOT,
            ),
        ),
    ],
)
def test_scenario_features(
    scenario: GoatMapScenario, expected: ScenarioFeatures
) -> None:
    assert ScenarioFeatures.for_scenario(scenario) == expected


def test_experiment_config_keeps_factors_independent() -> None:
    config = ExperimentConfig(
        phase="legacy-after-jmq",
        mower_state=MowerState.MOWING,
        jmq=JmqMode.APP_PRESENCE,
        appping=ControlTransport.NONE,
        get_mi=ControlTransport.LEGACY,
    )

    assert config.get_mi == ControlTransport.LEGACY
    assert config.appping == ControlTransport.NONE


def _device(*, with_services: bool = True) -> ApiDeviceInfo:
    device = ApiDeviceInfo(
        {
            "class": "2i0fns",
            "company": "eco-ng",
            "did": "device",
            "name": "goat",
            "resource": "resource",
        }
    )
    if with_services:
        device["service"] = {
            "jmq": "jmq-advertised.example.net",
            "mqs": "mqs-advertised.example.net",
        }
    return device


def test_extract_ngiot_services_preserves_raw_device_fields() -> None:
    raw = _device()

    services = extract_ngiot_services(raw)

    assert services.jmq == "jmq-advertised.example.net"
    assert services.mqs == "mqs-advertised.example.net"
    assert raw["service"]["jmq"] == services.jmq


def test_resolve_ngiot_endpoints_prefers_advertised_services() -> None:
    endpoints = resolve_ngiot_endpoints(_device(), "NO")

    assert endpoints.jmq.host == "jmq-advertised.example.net"
    assert endpoints.jmq.source == EndpointSource.DEVICE_SERVICE
    assert endpoints.mqs.host == "mqs-advertised.example.net"
    assert endpoints.mqs.source == EndpointSource.DEVICE_SERVICE
    assert endpoints.sst.host == "api-base.dc-eu.ww.ecouser.net"
    assert endpoints.sst.source == EndpointSource.REGIONAL_FALLBACK


def test_resolve_ngiot_endpoints_has_explicit_regional_fallbacks() -> None:
    endpoints = resolve_ngiot_endpoints(_device(with_services=False), "NO")

    assert endpoints.jmq.host == "jmq-ngiot-eu.dc.robotww.ecouser.net"
    assert endpoints.mqs.host == "api-ngiot.dc-eu.ww.ecouser.net"
    assert endpoints.jmq.source == EndpointSource.REGIONAL_FALLBACK
    assert endpoints.mqs.source == EndpointSource.REGIONAL_FALLBACK


@pytest.mark.parametrize(
    "value",
    [
        "https://jmq-ngiot-eu.dc.ww.ecouser.net",
        "user@jmq-ngiot-eu.dc.ww.ecouser.net",
        "jmq-ngiot-eu.dc.ww.ecouser.net:443",
        "jmq-ngiot-eu.dc.ww.ecouser.net/path",
        "",
        123,
    ],
)
def test_extract_ngiot_services_rejects_non_host_values(value: Any) -> None:
    with pytest.raises((TypeError, ValueError), match=r"service host|only a hostname"):
        extract_ngiot_services({"service": {"jmq": value}})


def test_sanitize_capture_retains_protocol_fields_and_masks_secrets() -> None:
    capture = {
        "token": "top-secret",
        "si": "request-id",
        "reqid": "inner-request-id",
        "body": {
            "data": {
                "mid": "42",
                "mapId": "43",
                "type": "0",
                "info": "opaque-map-payload",
                "nested": {"password": "secret"},
            }
        },
    }

    sanitized = sanitize_capture(capture)

    assert sanitized["token"] == "<redacted:str:len=10>"  # noqa: S105
    assert sanitized["si"] == "<redacted:str:len=10>"
    assert sanitized["reqid"] == "<redacted:str:len=16>"
    data = sanitized["body"]["data"]
    assert data["mid"] == "42"
    assert data["mapId"] == "43"
    assert data["type"] == "0"
    assert data["info"] == "<redacted:str:len=18>"
    assert data["nested"]["password"] == "<redacted:str:len=6>"  # noqa: S105


def test_recorder_reports_context_frequency_and_mid_correlation() -> None:
    recorder = MqttTrafficRecorder(phase="baseline", mower_state=MowerState.MOWING)
    start = datetime(2026, 8, 22, tzinfo=UTC)
    config = MagicMock(hostname="mq-eu.ecouser.net", port=443)
    jmq_config = MagicMock(hostname="jmq.example.net", port=443)
    topic = "iot/atr/onPos/device-id/2i0fns/resource/j"

    recorder.record_window("started")
    recorder.record_session("mq", config, "connected", observed_at=start)
    recorder.record_mqtt(
        "mq",
        topic,
        b'{"body":{"data":{"mid":"7","x":1}}}',
        observed_at=start + timedelta(seconds=1),
    )
    recorder.record_mqtt(
        "mq",
        topic,
        b'{"body":{"data":{"mid":"7","x":2}}}',
        observed_at=start + timedelta(seconds=1.5),
    )
    recorder.set_context("after-jmq", MowerState.MOWING)
    recorder.record_session(
        "jmq-app-presence",
        jmq_config,
        "connected",
        observed_at=start + timedelta(seconds=2),
    )
    recorder.record_mqtt(
        "mq",
        "iot/atr/onMI/device-id/2i0fns/resource/j",
        b'{"body":{"data":{"mid":"7","info":"opaque"}}}',
        observed_at=start + timedelta(seconds=3),
    )
    recorder.record_control(
        ControlTransport.LEGACY,
        "getMI",
        {"resp": {"body": {"data": {"mid": "7", "info": "opaque"}}}},
    )

    report = recorder.report()

    assert report["sessions"]["mq"]["commands"] == {"onMI": 1, "onPos": 2}
    assert report["sessions"]["mq"]["on_pos"] == {
        "count": 2,
        "hz": 2.0,
        "interval_ms_median": 500.0,
    }
    assert report["records"][0]["phase"] == "baseline"
    assert report["records"][0]["mower_state"] == "mowing"
    assert len(report["mid_correlation"]["7"]) == 4
    assert "device-id" not in str(report)
    comparison = report["normal_mq_around_jmq_connect"]
    assert comparison["before"]["message_count"] == 2
    assert comparison["after"]["commands"] == {"onMI": 1}
    assert report["interpretation"]["active_mowing_windows"] == ["baseline"]


def test_recorder_separates_map_ids_from_other_numeric_ids() -> None:
    recorder = MqttTrafficRecorder(phase="returning", mower_state=MowerState.RETURNING)
    start = datetime(2026, 8, 22, tzinfo=UTC)

    recorder.record_mqtt(
        "mq",
        "iot/atr/onFwBuryPoint-bd_task-return-normal-start/device/class/resource/j",
        orjson.dumps(
            {
                "body": {
                    "data": {
                        "mid": 221558440,
                        "mapId": "221558440",
                        "taskId": 221558440,
                        "deviceId": 999999,
                        "count": 12,
                    }
                }
            }
        ),
        observed_at=start,
    )
    recorder.record_mqtt(
        "mq",
        "iot/atr/onPos/device/class/resource/j",
        orjson.dumps(
            {
                "body": {
                    "data": {
                        "mid": "0",
                        "mapId": 1,
                        "taskId": 221558440,
                        "count": 13,
                    }
                }
            }
        ),
        observed_at=start + timedelta(seconds=1),
    )

    report = recorder.report()
    bury_point, position = report["records"]

    assert bury_point["map_ids"] == ()
    assert bury_point["other_numeric_ids"] == (
        {"field": "mid", "value": "221558440"},
        {"field": "mapId", "value": "221558440"},
        {"field": "taskId", "value": "221558440"},
    )
    assert position["map_ids"] == ("0", "1")
    assert position["other_numeric_ids"] == ({"field": "taskId", "value": "221558440"},)
    assert sorted(report["mid_correlation"]) == ["0", "1"]
    assert "221558440" not in report["mid_correlation"]
    observations = report["other_numeric_id_observations"]["221558440"]
    assert {item["command"] for item in observations} == {
        "onFwBuryPoint-bd_task-return-normal-start",
        "onPos",
    }
    assert {item["field"] for item in observations} == {"mapId", "mid", "taskId"}
    assert report["sessions"]["mq"]["map_ids"] == ["0", "1"]
    assert report["sessions"]["mq"]["other_numeric_ids"] == [
        {"field": "mapId", "value": "221558440"},
        {"field": "mid", "value": "221558440"},
        {"field": "taskId", "value": "221558440"},
    ]
    assert "999999" not in str(report)


def test_presence_renewal_summary_records_checkpoints_and_stream_gaps() -> None:
    recorder = MqttTrafficRecorder(phase="renewal", mower_state=MowerState.MOWING)
    start = datetime(2026, 8, 22, 10, tzinfo=UTC)
    pos_topic = "iot/atr/onPos/device-id/2i0fns/resource/j"
    track_topic = "iot/atr/onMapTrack/device-id/2i0fns/resource/j"
    appping_topic = (
        "iot/p2p/appping/sender/class/resource/receiver/class/resource/q/req/j"
    )

    recorder.record_presence_marker(
        "first-appping-issued", ControlTransport.NGIOT, observed_at=start
    )
    recorder.record_mqtt(
        "mq", appping_topic, b"{}", observed_at=start + timedelta(seconds=0.2)
    )
    for seconds in (1, 239.5, 240.5, 241, 550):
        recorder.record_mqtt(
            "mq", pos_topic, b"{}", observed_at=start + timedelta(seconds=seconds)
        )
    for seconds in (2, 239, 241, 551):
        recorder.record_mqtt(
            "mq", track_topic, b"{}", observed_at=start + timedelta(seconds=seconds)
        )
    recorder.record_presence_marker(
        "renewal-appping-issued",
        ControlTransport.NGIOT,
        observed_at=start + timedelta(seconds=240),
    )
    recorder.record_mqtt(
        "mq", appping_topic, b"{}", observed_at=start + timedelta(seconds=240.2)
    )
    recorder.record_presence_marker(
        "observation-ended",
        ControlTransport.NGIOT,
        observed_at=start + timedelta(seconds=700),
    )

    summary = recorder.presence_renewal_summary()

    assert summary is not None
    assert summary["renewal_elapsed_seconds"] == 240
    assert summary["observed_from_first_ping_seconds"] == 700
    assert summary["live_stream_confirmed_before_renewal"] is True
    assert len(summary["observed_appping_request_timestamps"]) == 2
    renewal = summary["around_appping"][1]
    assert renewal["mqtt_request_observed_at"].endswith("10:04:00.200000+00:00")
    assert renewal["onPos"] == {
        "last_before": (start + timedelta(seconds=239.5)).isoformat(),
        "first_after": (start + timedelta(seconds=240.5)).isoformat(),
    }
    pos = summary["streams"]["onPos"]
    assert pos["interruptions"][-1]["duration_seconds"] == 309
    assert pos["tail_gap_seconds"] == 150


async def test_experiment_sends_two_apppings_on_renewal_schedule(
    authenticator: Authenticator,
    device_info: DeviceInfo,
) -> None:
    normal = MagicMock()
    normal.disconnect = AsyncMock()
    config = MagicMock(hostname="mq-eu.ecouser.net", port=443)

    async def subscribe(_: SubscriberInfo) -> Callable[[], None]:
        recorder.record_session("mq", config, "connected")
        return lambda: None

    normal.subscribe = AsyncMock(side_effect=subscribe)
    control = MagicMock()
    control.call = AsyncMock(return_value={"body": {"code": 0}})

    def clients(**kwargs: Any) -> tuple[MagicMock, None]:
        nonlocal recorder
        recorder = kwargs["recorder"]
        return normal, None

    recorder = MqttTrafficRecorder()
    experiment = GoatMapDiagnosticExperiment(
        authenticator=authenticator,
        device_info=device_info,
        device_id="app-device",
        country="NO",
        http_session=cast("ClientSession", MagicMock()),
    )

    with (
        patch(
            "deebot_client.diagnostics.goat_map_refresh.create_diagnostic_mqtt_clients",
            side_effect=clients,
        ),
        patch(
            "deebot_client.diagnostics.goat_map_refresh.NgiotControlClient",
            return_value=control,
        ),
    ):
        report = await experiment.run(
            ExperimentConfig(
                phase="presence-renewal",
                mower_state=MowerState.MOWING,
                jmq=JmqMode.NONE,
                appping=ControlTransport.NGIOT,
                get_mi=ControlTransport.NONE,
            ),
            baseline_seconds=0,
            appping_renew_after_seconds=0.01,
            presence_total_seconds=0.03,
        )

    assert control.call.await_count == 2
    assert [call.args for call in control.call.await_args_list] == [
        ("appping", {}),
        ("appping", {}),
    ]
    assert report["presence_renewal"]["renewal_elapsed_seconds"] >= 0.009
    markers = [record for record in report["records"] if record["kind"] == "marker"]
    assert [record["state"] for record in markers] == [
        "first-appping-issued",
        "renewal-appping-issued",
        "observation-ended",
    ]


async def test_recorder_waits_for_confirmed_connection() -> None:
    recorder = MqttTrafficRecorder()
    config = MagicMock(hostname="mq-eu.ecouser.net", port=443)

    with pytest.raises(TimeoutError):
        await recorder.wait_connected("mq", 0.001)

    recorder.record_session("mq", config, "connected")
    await recorder.wait_connected("mq", 0.001)


def test_mqtt_observer_is_passive(authenticator: Authenticator) -> None:
    recorder = MqttTrafficRecorder()
    client = MqttClient(
        MqttConfiguration(
            hostname="localhost",
            port=1883,
            ssl_context=None,
            device_id="app-device",
        ),
        authenticator,
        observer=recorder.observer("mq"),
    )

    client._handle_message(
        Message(
            "iot/atr/onMI/device/class/resource/j",
            b'{"body":{"data":{"mid":"8","info":"opaque"}}}',
            0,
            retain=False,
            mid=1,
            properties=None,
        )
    )

    assert client.last_message_received_at is not None
    assert recorder.records[0].command == "onMI"
    assert recorder.records[0].map_ids == ("8",)


def _credentials_with_realm() -> Credentials:
    payload = base64.urlsafe_b64encode(orjson.dumps({"r": "realm-7"})).rstrip(b"=")
    return Credentials(
        token=f"header.{payload.decode()}.signature",
        user_id="account-user",
    )


def test_build_app_presence_identity_matches_reference_shape() -> None:
    username, client_id = build_app_presence_identity(
        _device(), _credentials_with_realm()
    )

    assert client_id == "account-user@USER/realm-7"
    did, encoded = username.split("`", 1)
    feature, role = encoded.split("\n`")
    assert did == "device"
    assert orjson.loads(base64.b64decode(feature)) == {"fv": "1.0.0", "wv": "v2.1.0"}
    assert orjson.loads(base64.b64decode(role)) == {"app": "user", "st": 10}


def test_create_diagnostic_clients_uses_app_presence_as_main_jmq(
    authenticator: Authenticator,
) -> None:
    recorder = MqttTrafficRecorder()

    normal, jmq = create_diagnostic_mqtt_clients(
        device_id="app-device",
        country="NO",
        device_info=_device(),
        authenticator=authenticator,
        recorder=recorder,
        jmq_mode=JmqMode.APP_PRESENCE,
    )

    assert normal._config.hostname == "mq-eu.ecouser.net"
    assert isinstance(jmq, AppPresenceMqttClient)
    assert jmq._config.hostname == "jmq-advertised.example.net"
    endpoint = recorder.records[0]
    assert endpoint.endpoint_source == "device service"


def test_create_diagnostic_clients_marks_normal_credentials_as_control(
    authenticator: Authenticator,
) -> None:
    _, jmq = create_diagnostic_mqtt_clients(
        device_id="app-device",
        country="NO",
        device_info=_device(),
        authenticator=authenticator,
        recorder=MqttTrafficRecorder(),
        jmq_mode=JmqMode.NORMAL_CREDENTIALS_CONTROL,
    )

    assert isinstance(jmq, MqttClient)


def test_build_ngiot_payload_is_deterministic_with_explicit_metadata() -> None:
    payload = build_ngiot_payload(
        {"type": "0"},
        request_id="abcdef",
        timestamp_ms=1234,
        timezone_name="Europe/Oslo",
        timezone_minutes=120,
    )

    assert payload["body"] == {"data": {"type": "0"}}
    assert payload["header"]["reqid"] == "abcdef"
    assert payload["header"]["ts"] == "1234"
    assert payload["header"]["ver"] == "0.0.22"


def test_legacy_get_mi_uses_existing_command_envelope_without_decoding() -> None:
    command = LegacyGetMiCommand({"type": "0"})
    payload = cast("dict[str, Any]", command._get_payload())

    assert command.NAME == "getMI"
    assert payload["body"]["data"] == {"type": "0"}


def _response_context(value: Any) -> MagicMock:
    response = MagicMock()
    response.json = AsyncMock(return_value=value)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=response)
    context.__aexit__ = AsyncMock(return_value=None)
    return context


def _raw_response_context(value: bytes) -> MagicMock:
    response = MagicMock()
    response.read = AsyncMock(return_value=value)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=response)
    context.__aexit__ = AsyncMock(return_value=None)
    return context


async def test_ngiot_control_issues_sst_and_generates_request_id(
    authenticator: Authenticator,
) -> None:
    cast("Any", authenticator).authenticate = AsyncMock(
        return_value=_credentials_with_realm()
    )
    session = MagicMock()
    session.post.side_effect = [
        _response_context({"data": {"data": {"token": "short-lived-sst"}}}),
        _response_context({"code": 0, "data": {"mid": "7", "info": "opaque"}}),
    ]
    recorder = MqttTrafficRecorder(phase="ngiot-get-mi", mower_state=MowerState.MOWING)
    client = NgiotControlClient(
        cast("ClientSession", session),
        authenticator,
        _device(),
        "NO",
        recorder,
    )

    request_uuid = MagicMock(hex="generated-request-id")
    with patch(
        "deebot_client.diagnostics.goat_map_refresh.uuid4",
        return_value=request_uuid,
    ):
        result = await client.call("getMI", {"type": "0"})

    assert result["data"]["info"] == "opaque"
    sst_call, control_call = session.post.call_args_list
    assert sst_call.args[0] == (
        "https://api-base.dc-eu.ww.ecouser.net/api/new-perm/token/sst/issue"
    )
    assert sst_call.kwargs["json"]["exp"] == 600
    assert sst_call.kwargs["json"]["acl"][0]["policy"][0]["perms"] == ["Control"]
    assert control_call.args[0] == (
        "https://mqs-advertised.example.net/api/iot/endpoint/control"
    )
    assert control_call.kwargs["params"] == {
        "si": "generated-request-id",
        "ct": "q",
        "eid": "device",
        "et": "2i0fns",
        "er": "resource",
        "apn": "getMI",
        "fmt": "j",
    }
    headers = control_call.kwargs["headers"]
    assert headers["x-eco-request-id"] == "generated-request-id"
    assert headers["authorization"] == "Bearer short-lived-sst"

    report = recorder.report()
    assert "generated-request-id" not in str(report)
    assert "short-lived-sst" not in str(report)
    endpoints = [r for r in report["records"] if r["kind"] == "endpoint"]
    assert endpoints[0]["broker"] == "mqs-advertised.example.net:443"
    assert endpoints[0]["endpoint_source"] == "device service"
    control = next(r for r in report["records"] if r["kind"] == "control")
    assert control["transport"] == "ngiot"
    assert control["mower_state"] == "mowing"
    assert control["sanitized_response"]["data"]["mid"] == "7"


async def test_ngiot_control_forwards_wire_response_and_registers_secrets(
    authenticator: Authenticator,
) -> None:
    cast("Any", authenticator).authenticate = AsyncMock(
        return_value=_credentials_with_realm()
    )
    raw = b'{"code":0,"data":{"mid":"7","info":"opaque"}}\r\n'
    session = MagicMock()
    session.post.side_effect = [
        _response_context({"data": {"data": {"token": "short-lived-sst"}}}),
        _raw_response_context(raw),
    ]
    capture_response = MagicMock()
    register_secret = MagicMock()
    client = NgiotControlClient(
        cast("ClientSession", session),
        authenticator,
        _device(),
        "NO",
        MqttTrafficRecorder(),
        capture_response=capture_response,
        register_secret=register_secret,
    )

    with patch(
        "deebot_client.diagnostics.goat_map_refresh.uuid4",
        return_value=MagicMock(hex="generated-request-id"),
    ):
        result = await client.call("getMI", {})

    assert result["data"]["info"] == "opaque"
    capture_response.assert_called_once_with(ControlTransport.NGIOT, "getMI", raw)
    assert [item.args[0] for item in register_secret.call_args_list] == [
        "short-lived-sst",
        "generated-request-id",
    ]


async def test_ngiot_control_capture_accepts_empty_appping_response(
    authenticator: Authenticator,
) -> None:
    cast("Any", authenticator).authenticate = AsyncMock(
        return_value=_credentials_with_realm()
    )
    session = MagicMock()
    session.post.side_effect = [
        _response_context({"data": {"data": {"token": "short-lived-sst"}}}),
        _raw_response_context(b"\r\n"),
    ]
    capture_response = MagicMock()
    register_secret = MagicMock()
    client = NgiotControlClient(
        cast("ClientSession", session),
        authenticator,
        _device(),
        "NO",
        MqttTrafficRecorder(),
        capture_response=capture_response,
        register_secret=register_secret,
    )

    with patch(
        "deebot_client.diagnostics.goat_map_refresh.uuid4",
        return_value=MagicMock(hex="generated-request-id"),
    ):
        result = await client.call("appping", {})

    assert result == {}
    capture_response.assert_not_called()
    assert [item.args[0] for item in register_secret.call_args_list] == [
        "short-lived-sst",
        "generated-request-id",
    ]


async def test_ngiot_control_reuses_sst_but_not_request_ids(
    authenticator: Authenticator,
) -> None:
    cast("Any", authenticator).authenticate = AsyncMock(
        return_value=_credentials_with_realm()
    )
    session = MagicMock()
    session.post.side_effect = [
        _response_context({"data": {"data": {"token": "short-lived-sst"}}}),
        _response_context({"code": 0}),
        _response_context({"code": 0}),
    ]
    client = NgiotControlClient(
        cast("ClientSession", session),
        authenticator,
        _device(),
        "NO",
        MqttTrafficRecorder(),
    )
    request_ids = [MagicMock(hex="request-one"), MagicMock(hex="request-two")]

    with patch(
        "deebot_client.diagnostics.goat_map_refresh.uuid4",
        side_effect=request_ids,
    ):
        await client.call("getMI", {})
        await client.call("appping", {})

    assert session.post.call_count == 3
    first_control = session.post.call_args_list[1].kwargs
    second_control = session.post.call_args_list[2].kwargs
    assert first_control["params"]["si"] == "request-one"
    assert second_control["params"]["si"] == "request-two"
    assert first_control["headers"]["x-eco-request-id"] == "request-one"
    assert second_control["headers"]["x-eco-request-id"] == "request-two"
