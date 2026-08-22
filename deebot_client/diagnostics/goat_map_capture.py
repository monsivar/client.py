"""Fail-closed, opt-in artifact capture for GOAT static-map research."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import re
import shutil
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import orjson

from deebot_client.mqtt_client import MqttConfiguration, MqttObserver

from .goat_map_refresh import ControlTransport, MowerState, sanitize_capture

if TYPE_CHECKING:
    from pathlib import Path

    from aiomqtt import Message

STATIC_MAP_CAPTURE_COMMANDS = frozenset(
    {"getMI", "onMI", "onArI", "getAreaSet", "onAreaSet"}
)
CONTROLLED_MAP_EDIT_CAPTURE_COMMANDS = STATIC_MAP_CAPTURE_COMMANDS | frozenset(
    {
        "getMapState",
        "onMapState",
        "getMapTrack",
        "onMapTrack",
        "setAreaSet",
        "getSpecialContour",
        "onSpecialContour",
        "setSpecialContour",
    }
)
SPECIAL_CONTOUR_CAPTURE_COMMANDS = frozenset(
    {"getSpecialContour", "onSpecialContour", "setSpecialContour"}
)
_MAP_ID_KEYS = frozenset({"mid", "mapId", "mapID"})
_ENVELOPE_KEYS = frozenset({"body", "data", "header", "resp"})
_NON_OPAQUE_VALUE_KEYS = frozenset(
    {
        "code",
        "count",
        "fmt",
        "index",
        "mapId",
        "mapID",
        "mid",
        "msg",
        "pri",
        "reqid",
        "result",
        "ret",
        "serial",
        "tmz",
        "total",
        "totalCount",
        "type",
        "ts",
        "using",
        "ver",
    }
)
_ALLOWED_FACTOR_KEYS = frozenset({"appping", "get_mi_sequence", "jmq", "mqtt"})
_ALLOWED_FACTOR_VALUES = frozenset({"legacy", "ngiot", "none", "normal-mq"})
_SENSITIVE_KEY_PARTS = (
    "account",
    "auth",
    "credential",
    "deviceid",
    "email",
    "password",
    "reqid",
    "request_id",
    "requestid",
    "secret",
    "service_id",
    "token",
    "userid",
)
_SENSITIVE_EXACT_KEYS = frozenset(
    {
        "authorization",
        "bssid",
        "did",
        "eid",
        "er",
        "essid",
        "mac",
        "si",
        "ssid",
        "uid",
    }
)
_REDACTABLE_HEADER_KEYS = frozenset({"reqid", "request_id", "requestid"})
_REQUEST_ID_PATTERN = re.compile(
    r"^(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})$",
    re.IGNORECASE,
)
_CAPTURE_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_DEFAULT_MAX_BLOB_BYTES = 16 * 1024 * 1024
_DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_SCHEMA_VERSION = "goat-static-map-capture/v1"
_REDACTION_POLICY_VERSION = 1


class CaptureArtifactError(ValueError):
    """Base error for a Phase 2 artifact rejected before publication."""


class CaptureSecurityError(CaptureArtifactError):
    """A payload contained a secret or identity marker."""


class CaptureSizeLimitError(CaptureArtifactError):
    """A capture exceeded its configured local size limit."""


@dataclass(frozen=True, kw_only=True)
class CaptureLimits:
    """Byte limits enforced before an artifact can be finalized."""

    max_blob_bytes: int = _DEFAULT_MAX_BLOB_BYTES
    max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES

    def __post_init__(self) -> None:
        if self.max_blob_bytes <= 0 or self.max_total_bytes <= 0:
            raise ValueError("Capture size limits must be positive")
        if self.max_blob_bytes > self.max_total_bytes:
            raise ValueError("Per-blob limit cannot exceed total capture limit")


class GoatMapCaptureWriter:
    """Collect sanitized metadata and content-addressed opaque payload blobs."""

    def __init__(  # noqa: PLR0913
        self,
        artifact_dir: Path,
        *,
        phase: str,
        mower_state: MowerState,
        device_class: str,
        factors: Mapping[str, Any],
        forbidden_values: Iterable[str | bytes] = (),
        limits: CaptureLimits | None = None,
        capture_id_factory: Callable[[], str] | None = None,
        now: Callable[[], datetime] | None = None,
        capture_commands: Iterable[str] | None = None,
    ) -> None:
        capture_id = (capture_id_factory or _new_capture_id)()
        if not _CAPTURE_ID_PATTERN.fullmatch(capture_id):
            raise ValueError("Capture ID must be an anonymous 32-character hex value")
        self._artifact_dir = artifact_dir
        self._phase = phase
        self._initial_mower_state = mower_state
        self._mower_state = mower_state
        self._window = "initializing"
        self._limits = limits or CaptureLimits()
        self._capture_id = capture_id
        self._created_at = (now or _utc_now)().astimezone(UTC).isoformat()
        self._manifest_factors = _manifest_factors(factors)
        self._device_class = device_class
        self._capture_commands = frozenset(
            capture_commands or STATIC_MAP_CAPTURE_COMMANDS
        )
        if not self._capture_commands or any(
            not command or "/" in command for command in self._capture_commands
        ):
            raise ValueError("Capture commands must be non-empty topic-safe names")
        self._forbidden_values: set[bytes] = set()
        self._records: list[dict[str, Any]] = []
        self._blobs: dict[str, bytes] = {}
        self._total_blob_bytes = 0
        self._failed = False
        self._finalized = False
        for value in forbidden_values:
            self.register_forbidden_value(value)

    @property
    def capture_id(self) -> str:
        """Return the anonymous identifier generated for this artifact only."""
        return self._capture_id

    def set_context(self, window: str, mower_state: MowerState) -> None:
        """Update experiment context inherited by subsequent capture records."""
        self._ensure_writable()
        if not window:
            raise ValueError("Capture window must be non-empty")
        self._window = window
        self._mower_state = mower_state

    def register_forbidden_value(self, value: str | bytes) -> None:
        """Register a runtime secret or identity that must never reach disk."""
        self._ensure_writable()
        encoded = value.encode() if isinstance(value, str) else bytes(value)
        if encoded:
            self._forbidden_values.add(encoded)

    def record_mqtt(
        self,
        topic: str,
        payload: str | bytes | bytearray,
        *,
        observed_at: datetime | None = None,
    ) -> None:
        """Capture an allowlisted MQTT payload without retaining its full topic."""
        command, direction, topic_shape = _mqtt_topic_metadata(topic)
        if command not in self._capture_commands:
            return
        raw = payload.encode() if isinstance(payload, str) else bytes(payload)
        self._record(
            command=command,
            direction=direction,
            transport="normal-mq",
            topic_shape=topic_shape,
            raw=raw,
            representation_kind="mqtt-payload-json-bytes",
            observed_at=observed_at,
        )

    def record_control(
        self,
        transport: ControlTransport,
        command: str,
        payload: Mapping[str, Any] | list[Any] | bytes,
        *,
        response_body_bytes: bool = False,
        observed_at: datetime | None = None,
    ) -> None:
        """Capture an allowlisted control result with honest representation metadata."""
        if command not in self._capture_commands:
            return
        if isinstance(payload, bytes):
            raw = payload
            representation_kind = (
                "http-response-json-bytes"
                if response_body_bytes
                else "provided-json-bytes"
            )
        else:
            raw = orjson.dumps(payload, option=orjson.OPT_SORT_KEYS)
            representation_kind = "canonical-json-v1"
        self._record(
            command=command,
            direction="response",
            transport=transport.value,
            topic_shape=None,
            raw=raw,
            representation_kind=representation_kind,
            observed_at=observed_at,
        )

    def finalize(self) -> dict[str, Any]:
        """Atomically publish a complete artifact and return its public manifest."""
        self._ensure_writable()
        if self._artifact_dir.exists():
            message = f"Capture artifact already exists: {self._artifact_dir}"
            raise FileExistsError(message)
        manifest = {
            "schema_version": _SCHEMA_VERSION,
            "capture_id": self._capture_id,
            "created_at": self._created_at,
            "phase": self._phase,
            "mower_state": self._initial_mower_state.value,
            "final_mower_state": self._mower_state.value,
            "device_class": self._device_class,
            "factors": self._manifest_factors,
            "captured_commands": sorted(self._capture_commands),
            "redaction_policy_version": _REDACTION_POLICY_VERSION,
            "records_file": "records.jsonl",
            "blob_directory": "blobs",
            "record_count": len(self._records),
            "unique_blob_count": len(self._blobs),
            "total_blob_bytes": self._total_blob_bytes,
            "limits": {
                "max_blob_bytes": self._limits.max_blob_bytes,
                "max_total_bytes": self._limits.max_total_bytes,
            },
        }
        parent = self._artifact_dir.parent
        parent.mkdir(parents=True, exist_ok=True)
        temporary = parent / f".{self._artifact_dir.name}.{uuid4().hex}.tmp"
        temporary.mkdir()
        try:
            blobs_dir = temporary / "blobs"
            blobs_dir.mkdir()
            for digest, raw in self._blobs.items():
                (blobs_dir / f"{digest}.bin").write_bytes(raw)
            records = b"".join(orjson.dumps(record) + b"\n" for record in self._records)
            (temporary / "records.jsonl").write_bytes(records)
            (temporary / "manifest.json").write_bytes(
                orjson.dumps(manifest, option=orjson.OPT_INDENT_2) + b"\n"
            )
            temporary.replace(self._artifact_dir)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        self._finalized = True
        return manifest

    def _record(  # noqa: PLR0913
        self,
        *,
        command: str,
        direction: str,
        transport: str,
        topic_shape: str | None,
        raw: bytes,
        representation_kind: str,
        observed_at: datetime | None,
    ) -> None:
        self._ensure_writable()
        try:
            if len(raw) > self._limits.max_total_bytes:
                raise CaptureSizeLimitError(
                    "Input exceeds the total capture size limit"
                )
            parsed = orjson.loads(raw)
            if not isinstance(parsed, (dict, list)):
                raise CaptureSecurityError(
                    "Static-map payload must be a JSON object or list"
                )
            self._assert_no_secrets(parsed)
            opaque_values = _opaque_values(parsed)
            self._assert_segment_sizes(opaque_values)
        except CaptureArtifactError, orjson.JSONDecodeError:
            self._failed = True
            raise
        segments: list[dict[str, Any]] = []
        for source_path, original_kind, opaque in opaque_values:
            digest = sha256(opaque).hexdigest()
            if digest not in self._blobs:
                self._blobs[digest] = opaque
                self._total_blob_bytes += len(opaque)
            segments.append(
                {
                    "source_path": source_path,
                    "representations": {
                        "original": {
                            "kind": original_kind,
                            "content_type": "application/octet-stream",
                            "blob": f"blobs/{digest}.bin",
                            "sha256": digest,
                            "byte_length": len(opaque),
                        },
                        "decoded": None,
                    },
                }
            )
        self._records.append(
            {
                "sequence": len(self._records) + 1,
                "observed_at": (observed_at or _utc_now()).astimezone(UTC).isoformat(),
                "window": self._window,
                "mower_state": self._mower_state.value,
                "command": command,
                "direction": direction,
                "transport": transport,
                "topic_shape": topic_shape,
                "source_representation": representation_kind,
                "map_ids": _map_ids(parsed),
                "sanitized_envelope": sanitize_capture(parsed),
                "opaque_segments": segments,
            }
        )

    def _assert_no_secrets(self, parsed: Any) -> None:
        def visit(value: Any, *, parent_key: str = "") -> None:
            if isinstance(value, Mapping):
                for key, item in value.items():
                    key_text = str(key)
                    lowered = key_text.casefold()
                    if lowered in _REDACTABLE_HEADER_KEYS:
                        if parent_key.casefold() != "header":
                            message = f"Payload contains forbidden field: {key_text}"
                            raise CaptureSecurityError(message)
                        continue
                    if lowered in _SENSITIVE_EXACT_KEYS or any(
                        part in lowered for part in _SENSITIVE_KEY_PARTS
                    ):
                        message = f"Payload contains forbidden field: {key_text}"
                        raise CaptureSecurityError(message)
                    if (
                        lowered == "id"
                        and isinstance(item, str)
                        and _REQUEST_ID_PATTERN.fullmatch(item)
                    ):
                        raise CaptureSecurityError(
                            "Payload contains a request-shaped generic ID"
                        )
                    visit(item, parent_key=key_text)
            elif isinstance(value, list):
                for item in value:
                    visit(item, parent_key=parent_key)
            elif isinstance(value, (str, int)) and not isinstance(value, bool):
                encoded = str(value).encode()
                if any(forbidden in encoded for forbidden in self._forbidden_values):
                    raise CaptureSecurityError(
                        "Payload matched a registered secret canary"
                    )

        visit(parsed)

    def _assert_segment_sizes(
        self, opaque_values: list[tuple[str, str, bytes]]
    ) -> None:
        prospective = self._total_blob_bytes
        pending: set[str] = set()
        for _, _, raw in opaque_values:
            if len(raw) > self._limits.max_blob_bytes:
                raise CaptureSizeLimitError("Payload exceeds the per-blob size limit")
            digest = sha256(raw).hexdigest()
            if digest not in self._blobs and digest not in pending:
                prospective += len(raw)
                pending.add(digest)
        if prospective > self._limits.max_total_bytes:
            raise CaptureSizeLimitError("Capture exceeds the total blob size limit")

    def _ensure_writable(self) -> None:
        if self._failed:
            raise CaptureArtifactError("Capture writer is fail-closed after rejection")
        if self._finalized:
            raise CaptureArtifactError("Capture artifact has already been finalized")


class GoatMapCaptureObserver(MqttObserver):
    """MQTT observer that forwards only writer-allowlisted map payloads."""

    def __init__(self, writer: GoatMapCaptureWriter) -> None:
        self._writer = writer
        self._capture_failed = False

    def on_connected(self, _: MqttConfiguration) -> None:
        """Ignore broker lifecycle; Phase 1 records it separately."""

    def on_disconnected(self, _: MqttConfiguration) -> None:
        """Ignore broker lifecycle; Phase 1 records it separately."""

    def on_message(self, _: MqttConfiguration, message: Message) -> None:
        """Forward the raw MQTT payload without retaining the complete topic."""
        if self._capture_failed:
            return
        try:
            self._writer.record_mqtt(message.topic.value, message.payload)
        except CaptureArtifactError:
            self._capture_failed = True
            raise


class CombinedMqttObserver(MqttObserver):
    """Fan out passive MQTT observations to independent diagnostic sinks."""

    def __init__(self, *observers: MqttObserver) -> None:
        self._observers = observers

    def on_connected(self, config: MqttConfiguration) -> None:
        """Forward a broker connection."""
        for observer in self._observers:
            observer.on_connected(config)

    def on_disconnected(self, config: MqttConfiguration) -> None:
        """Forward a broker disconnect."""
        for observer in self._observers:
            observer.on_disconnected(config)

    def on_message(self, config: MqttConfiguration, message: Message) -> None:
        """Forward one immutable message to each observer."""
        for observer in self._observers:
            observer.on_message(config, message)


def _new_capture_id() -> str:
    return uuid4().hex


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


def _mqtt_topic_metadata(topic: str) -> tuple[str, str, str]:
    parts = topic.split("/")
    command = parts[2] if len(parts) > 2 else "<unknown>"
    if topic.startswith("iot/atr/"):
        direction = "event"
        shape = f"iot/atr/{command}/<device>/<class>/<resource>/<format>"
    elif topic.startswith("iot/p2p/"):
        direction = "request" if len(parts) > 9 and parts[9] == "q" else "response"
        shape = f"iot/p2p/{command}/<sender>/<receiver>/<direction>/<request>/<format>"
    else:
        direction = "unknown"
        shape = "/".join(parts[:3])
    return command, direction, shape


def _map_ids(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            if (
                key in _MAP_ID_KEYS
                and isinstance(item, (str, int))
                and not isinstance(item, bool)
            ):
                found.append(str(item))
            else:
                found.extend(_map_ids(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_map_ids(item))
    return list(dict.fromkeys(found))


def _manifest_factors(factors: Mapping[str, Any]) -> dict[str, Any]:
    unknown = set(factors) - _ALLOWED_FACTOR_KEYS
    if unknown:
        raise CaptureSecurityError("Manifest contains a non-allowlisted factor")
    encoded = orjson.dumps(dict(factors), option=orjson.OPT_SORT_KEYS)
    normalized: dict[str, Any] = orjson.loads(encoded)
    values = [
        item
        for value in normalized.values()
        for item in (value if isinstance(value, list) else [value])
    ]
    if any(
        not isinstance(value, str) or value not in _ALLOWED_FACTOR_VALUES
        for value in values
    ):
        raise CaptureSecurityError("Manifest contains a non-allowlisted factor value")
    return normalized


def _opaque_values(
    value: Any,
    *,
    path: str = "$",
) -> list[tuple[str, str, bytes]]:
    found: list[tuple[str, str, bytes]] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            item_path = f"{path}.{key_text}"
            if (
                key_text in _NON_OPAQUE_VALUE_KEYS
                or key_text.casefold() in _REDACTABLE_HEADER_KEYS
            ):
                continue
            if key_text in _ENVELOPE_KEYS:
                found.extend(_opaque_values(item, path=item_path))
            elif isinstance(item, str):
                found.append((item_path, "json-string-utf8-value", item.encode()))
            elif isinstance(item, (Mapping, list)):
                found.append(
                    (
                        item_path,
                        "canonical-json-v1",
                        orjson.dumps(item, option=orjson.OPT_SORT_KEYS),
                    )
                )
            elif item is not None:
                found.append((item_path, "canonical-json-v1", orjson.dumps(item)))
    elif isinstance(value, list):
        found.append((path, "canonical-json-v1", orjson.dumps(value)))
    return found
