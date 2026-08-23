from __future__ import annotations

from hashlib import sha256
import re
from typing import TYPE_CHECKING, Any

from aiomqtt import Message
import orjson
import pytest

from deebot_client.diagnostics.goat_map_capture import (
    CONTROLLED_MAP_EDIT_CAPTURE_COMMANDS,
    SPECIAL_CONTOUR_CAPTURE_COMMANDS,
    CaptureArtifactError,
    CaptureLimits,
    CaptureSecurityError,
    CaptureSizeLimitError,
    GoatMapCaptureObserver,
    GoatMapCaptureWriter,
)
from deebot_client.diagnostics.goat_map_refresh import ControlTransport, MowerState
from deebot_client.mqtt_client import MqttConfiguration

if TYPE_CHECKING:
    from pathlib import Path


def _writer(
    artifact_dir: Path,
    *,
    forbidden_values: tuple[str, ...] = (),
    limits: CaptureLimits | None = None,
) -> GoatMapCaptureWriter:
    return GoatMapCaptureWriter(
        artifact_dir,
        phase="p2-01-getmi-paired-mowing",
        mower_state=MowerState.MOWING,
        device_class="2i0fns",
        factors={"jmq": "none", "appping": "ngiot"},
        forbidden_values=forbidden_values,
        limits=limits,
    )


def _records(artifact_dir: Path) -> list[dict[str, Any]]:
    return [
        orjson.loads(line)
        for line in (artifact_dir / "records.jsonl").read_bytes().splitlines()
    ]


def test_capture_id_is_random_and_anonymous(tmp_path: Path) -> None:
    first = _writer(tmp_path / "first")
    second = _writer(tmp_path / "second")

    assert first.capture_id != second.capture_id
    assert re.fullmatch(r"[0-9a-f]{32}", first.capture_id)
    assert "2i0fns" not in first.capture_id


def test_opaque_original_round_trips_byte_identically_and_deduplicates(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "capture"
    writer = _writer(artifact_dir)
    opaque = b"AA=BB+/=="
    raw = b' {"body":{"data":{"mid":"1","info":"AA\\u003dBB+/=="}},"ret":"ok"}\r\n'

    writer.record_mqtt("iot/atr/onMI/device/class/resource/j", raw)
    writer.record_mqtt("iot/atr/onArI/device/class/resource/j", raw)
    manifest = writer.finalize()

    digest = sha256(opaque).hexdigest()
    assert (artifact_dir / "blobs" / f"{digest}.bin").read_bytes() == opaque
    assert manifest["record_count"] == 2
    assert manifest["unique_blob_count"] == 1
    assert manifest["total_blob_bytes"] == len(opaque)
    assert manifest["capture_id"] == writer.capture_id
    assert manifest["factors"] == {"appping": "ngiot", "jmq": "none"}
    records = _records(artifact_dir)
    for record in records:
        segment = record["opaque_segments"][0]
        representations = segment["representations"]
        assert representations["original"] == {
            "kind": "json-string-utf8-value",
            "content_type": "application/octet-stream",
            "blob": f"blobs/{digest}.bin",
            "sha256": digest,
            "byte_length": len(opaque),
        }
        assert representations["decoded"] is None
        assert record["source_representation"] == "mqtt-payload-json-bytes"
    serialized = (artifact_dir / "records.jsonl").read_text()
    assert "device/class/resource" not in serialized
    assert "AA\\u003dBB" not in serialized


def test_capture_size_limit_is_fail_closed(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "too-large"
    writer = _writer(
        artifact_dir,
        limits=CaptureLimits(max_blob_bytes=32, max_total_bytes=256),
    )
    raw = orjson.dumps({"body": {"data": {"info": "x" * 64}}})

    with pytest.raises(CaptureSizeLimitError, match="per-blob"):
        writer.record_mqtt("iot/atr/onMI/device/class/resource/j", raw)
    with pytest.raises(CaptureArtifactError, match="fail-closed"):
        writer.finalize()
    assert not artifact_dir.exists()


def test_capture_total_size_limit_counts_only_unique_blobs(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "too-large-total"
    writer = _writer(
        artifact_dir,
        limits=CaptureLimits(max_blob_bytes=128, max_total_bytes=150),
    )
    first = orjson.dumps({"body": {"data": {"info": "a" * 80}}})
    second = orjson.dumps({"body": {"data": {"info": "b" * 80}}})

    writer.record_mqtt("iot/atr/onMI/device/class/resource/j", first)
    writer.record_mqtt("iot/atr/onArI/device/class/resource/j", first)
    with pytest.raises(CaptureSizeLimitError, match="total blob"):
        writer.record_mqtt("iot/atr/onArI/device/class/resource/j", second)
    with pytest.raises(CaptureArtifactError, match="fail-closed"):
        writer.finalize()
    assert not artifact_dir.exists()


@pytest.mark.parametrize(
    "raw",
    [
        orjson.dumps({"body": {"data": {"info": "secret-canary-value"}}}),
        b'{"body":{"data":{"info":"secret\\u002dcanary-value"}}}',
        orjson.dumps({"body": {"data": {"token": "not-written"}}}),
        orjson.dumps({"body": {"data": {"id": "0123456789abcdef0123456789abcdef"}}}),
    ],
)
def test_secret_canary_rejects_entire_artifact(tmp_path: Path, raw: bytes) -> None:
    artifact_dir = tmp_path / "secret"
    writer = _writer(
        artifact_dir,
        forbidden_values=("secret-canary-value",),
    )

    with pytest.raises(CaptureSecurityError):
        writer.record_mqtt("iot/atr/onMI/device/class/resource/j", raw)
    with pytest.raises(CaptureArtifactError, match="fail-closed"):
        writer.finalize()
    assert not artifact_dir.exists()


def test_header_request_id_is_redacted_without_rejecting_map_payload(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "request-id-redacted"
    writer = _writer(artifact_dir)
    request_id = "mqtt-protocol-request-id"
    opaque = b"opaque-static-map"
    raw = orjson.dumps(
        {
            "header": {"reqid": request_id, "ts": "123"},
            "body": {"data": {"mid": "1", "info": opaque.decode()}},
        }
    )

    writer.record_mqtt("iot/atr/onMI/device/class/resource/j", raw)
    writer.finalize()

    record = _records(artifact_dir)[0]
    assert record["sanitized_envelope"]["header"]["reqid"].startswith("<redacted:")
    digest = sha256(opaque).hexdigest()
    assert (artifact_dir / "blobs" / f"{digest}.bin").read_bytes() == opaque
    assert request_id.encode() not in (artifact_dir / "records.jsonl").read_bytes()
    assert all(
        request_id.encode() not in path.read_bytes()
        for path in artifact_dir.rglob("*.bin")
    )


def test_request_id_outside_header_rejects_entire_artifact(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "request-id-outside-header"
    writer = _writer(artifact_dir)
    raw = orjson.dumps({"body": {"data": {"reqid": "unexpected", "info": "opaque"}}})

    with pytest.raises(CaptureSecurityError, match="reqid"):
        writer.record_mqtt("iot/atr/onMI/device/class/resource/j", raw)
    with pytest.raises(CaptureArtifactError, match="fail-closed"):
        writer.finalize()
    assert not artifact_dir.exists()


def test_non_static_map_command_is_not_captured_or_scanned(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "capture"
    writer = _writer(artifact_dir, forbidden_values=("secret-canary-value",))

    writer.record_mqtt(
        "iot/atr/onBattery/device/class/resource/j",
        orjson.dumps({"token": "secret-canary-value"}),
    )
    manifest = writer.finalize()

    assert manifest["record_count"] == 0
    assert manifest["unique_blob_count"] == 0


def test_capture_supports_complete_static_map_command_family(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "static-family"
    writer = _writer(artifact_dir)
    payload = {"body": {"data": {"mid": "1", "info": "opaque"}}}

    writer.record_control(ControlTransport.LEGACY, "getMI", payload)
    for command in ("onMI", "onArI", "onAreaSet"):
        writer.record_mqtt(
            f"iot/atr/{command}/device/class/resource/j",
            orjson.dumps(payload),
        )
    writer.record_mqtt(
        "iot/p2p/getAreaSet/sender/class/resource/receiver/class/resource/p/req/j",
        orjson.dumps(payload),
    )
    writer.finalize()

    assert {record["command"] for record in _records(artifact_dir)} == {
        "getMI",
        "onMI",
        "onArI",
        "getAreaSet",
        "onAreaSet",
    }


def test_snapshot_records_is_detached_and_preserves_explicit_allowlist(
    tmp_path: Path,
) -> None:
    writer = _writer(tmp_path / "snapshot")
    writer.record_mqtt(
        "iot/atr/onMI/device/class/resource/j",
        orjson.dumps({"body": {"data": {"mid": "1", "info": "opaque"}}}),
    )

    snapshot = writer.snapshot_records()
    snapshot[0]["command"] = "mutated-in-test"

    assert writer.snapshot_records()[0]["command"] == "onMI"
    assert writer.captured_commands == frozenset(writer.finalize()["captured_commands"])


def test_controlled_edit_allowlist_adds_map_signals_without_capturing_other_data(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "controlled-edit"
    writer = GoatMapCaptureWriter(
        artifact_dir,
        phase="p2-05-edit",
        mower_state=MowerState.PAUSED,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq", "appping": "none"},
        capture_commands=CONTROLLED_MAP_EDIT_CAPTURE_COMMANDS,
    )
    payload = orjson.dumps({"body": {"data": {"mid": "1", "info": "opaque"}}})

    writer.record_mqtt("iot/atr/onMapState/device/class/resource/j", payload)
    writer.record_mqtt("iot/p2p/setAreaSet/a/b/c/d/e/f/q/id/j", payload)
    writer.record_mqtt("iot/atr/onBattery/device/class/resource/j", payload)
    manifest = writer.finalize()

    assert {record["command"] for record in _records(artifact_dir)} == {
        "onMapState",
        "setAreaSet",
    }
    assert manifest["captured_commands"] == sorted(CONTROLLED_MAP_EDIT_CAPTURE_COMMANDS)


def test_special_contour_family_is_byte_preserved_by_explicit_allowlist(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "special-contour"
    writer = GoatMapCaptureWriter(
        artifact_dir,
        phase="p2-06",
        mower_state=MowerState.PAUSED,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq", "appping": "none"},
        capture_commands=SPECIAL_CONTOUR_CAPTURE_COMMANDS,
    )
    request_id = "request-secret-value"
    payload = orjson.dumps(
        {
            "header": {"reqid": request_id},
            "body": {"data": {"mid": "1", "info": "opaque"}},
        }
    )

    writer.record_mqtt("iot/p2p/setSpecialContour/a/b/c/d/e/f/q/id/j", payload)
    writer.record_mqtt("iot/p2p/getSpecialContour/a/b/c/d/e/f/p/id/j", payload)
    writer.record_mqtt("iot/atr/onSpecialContour/device/class/resource/j", payload)
    manifest = writer.finalize()

    assert {record["command"] for record in _records(artifact_dir)} == {
        "setSpecialContour",
        "getSpecialContour",
        "onSpecialContour",
    }
    assert manifest["captured_commands"] == sorted(SPECIAL_CONTOUR_CAPTURE_COMMANDS)
    assert request_id.encode() not in (artifact_dir / "records.jsonl").read_bytes()


def test_special_contour_mssid_is_not_misclassified_as_wifi_ssid(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "special-contour-mssid"
    writer = GoatMapCaptureWriter(
        artifact_dir,
        phase="p2-06",
        mower_state=MowerState.PAUSED,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq", "appping": "none"},
        capture_commands=SPECIAL_CONTOUR_CAPTURE_COMMANDS,
    )
    payload = orjson.dumps(
        {"body": {"data": {"mid": "1", "mssid": "8", "info": "opaque"}}}
    )

    writer.record_mqtt("iot/p2p/setSpecialContour/a/b/c/d/e/f/q/id/j", payload)
    manifest = writer.finalize()

    assert manifest["record_count"] == 1
    record = _records(artifact_dir)[0]
    segment = next(
        item
        for item in record["opaque_segments"]
        if item["source_path"] == "$.body.data.mssid"
    )
    blob = segment["representations"]["original"]["blob"]
    assert (artifact_dir / blob).read_bytes() == b"8"


@pytest.mark.parametrize("field", ["ssid", "bssid", "essid"])
def test_actual_network_identifier_fields_remain_fail_closed(
    tmp_path: Path,
    field: str,
) -> None:
    artifact_dir = tmp_path / field
    writer = GoatMapCaptureWriter(
        artifact_dir,
        phase="p2-06",
        mower_state=MowerState.PAUSED,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq", "appping": "none"},
        capture_commands=SPECIAL_CONTOUR_CAPTURE_COMMANDS,
    )
    payload = orjson.dumps({"body": {"data": {field: "private-network"}}})

    with pytest.raises(CaptureSecurityError, match=field):
        writer.record_mqtt(
            "iot/p2p/setSpecialContour/a/b/c/d/e/f/q/id/j",
            payload,
        )
    with pytest.raises(CaptureArtifactError, match="fail-closed"):
        writer.finalize()
    assert not artifact_dir.exists()


def test_capture_observer_reports_only_first_fail_closed_error(tmp_path: Path) -> None:
    writer = GoatMapCaptureWriter(
        tmp_path / "observer-failure",
        phase="p2-06",
        mower_state=MowerState.PAUSED,
        device_class="2i0fns",
        factors={"mqtt": "normal-mq", "appping": "none"},
        capture_commands=SPECIAL_CONTOUR_CAPTURE_COMMANDS,
    )
    observer = GoatMapCaptureObserver(writer)
    config = MqttConfiguration(
        hostname="localhost",
        port=1883,
        ssl_context=None,
        device_id="anonymous-test-client",
    )
    message = Message(
        "iot/p2p/setSpecialContour/a/b/c/d/e/f/q/id/j",
        orjson.dumps({"body": {"data": {"ssid": "private-network"}}}),
        0,
        retain=False,
        mid=1,
        properties=None,
    )

    with pytest.raises(CaptureSecurityError, match="ssid"):
        observer.on_message(config, message)
    observer.on_message(config, message)

    with pytest.raises(CaptureArtifactError, match="fail-closed"):
        writer.finalize()
