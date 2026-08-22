"""Opt-in GOAT map refresh protocol diagnostics.

This module records protocol metadata and sanitized response shapes. It does not
decode mower map payloads and is not used by normal client initialization.
"""

from __future__ import annotations

import asyncio
import base64
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from itertools import pairwise
import secrets
import ssl
import statistics
import time
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlparse
from uuid import uuid4

from aiohttp import ClientTimeout
from aiomqtt import Client, ProtocolVersion
import orjson

from deebot_client.commands.json.common import JsonCommandWithMessageHandling
from deebot_client.event_bus import EventBus
from deebot_client.events import StateEvent
from deebot_client.message import HandlingResult
from deebot_client.messages import get_message
from deebot_client.models import State
from deebot_client.mqtt_client import (
    MqttClient,
    MqttConfiguration,
    MqttObserver,
    SubscriberInfo,
    create_mqtt_config,
)
from deebot_client.util.continents import get_continent

if TYPE_CHECKING:
    from aiohttp import ClientSession
    from aiomqtt import Message

    from deebot_client.authentication import Authenticator
    from deebot_client.command import Command
    from deebot_client.models import ApiDeviceInfo, Credentials, DeviceInfo

_INTERESTING_COMMANDS = frozenset(
    {"onPos", "onMI", "onArI", "onMapTrack", "onMapState", "onAreaSet"}
)
_MAP_ID_KEYS = frozenset({"mid", "mapId", "mapID"})
_MAP_ID_COMMANDS = _INTERESTING_COMMANDS | frozenset(
    {
        "getPos",
        "getMI",
        "getArI",
        "getMapTrack",
        "getMapState",
        "getAreaSet",
        "getSpecialContour",
    }
)
_NON_REPORTABLE_ID_KEY_PARTS = (
    "account",
    "auth",
    "client",
    "device",
    "request",
    "resource",
    "service",
    "ssid",
    "user",
)
_SAFE_VALUE_KEYS = frozenset(
    {
        "batid",
        "built",
        "code",
        "count",
        "fmt",
        "index",
        "mapId",
        "mapID",
        "mid",
        "msg",
        "pri",
        "result",
        "ret",
        "serial",
        "total",
        "totalCount",
        "type",
        "using",
        "ver",
    }
)
_SENSITIVE_KEY_PARTS = (
    "account",
    "auth",
    "credential",
    "email",
    "mac",
    "password",
    "reqid",
    "requestid",
    "secret",
    "service_id",
    "ssid",
    "token",
    "uid",
    "userid",
)
_MAX_CAPTURE_LIST_ITEMS = 10
_APP_PRESENCE_FEATURE_META = {"fv": "1.0.0", "wv": "v2.1.0"}
_APP_PRESENCE_ROLE_META = {"app": "user", "st": 10}
_HTTP_TIMEOUT = ClientTimeout(total=60)


class GoatMapScenario(StrEnum):
    """Convenience presets layered on the independent experiment factors."""

    MQ_ONLY = "A"
    MQ_AND_JMQ = "B"
    MQ_JMQ_APPPING = "C"
    MQ_JMQ_APPPING_NGIOT_GET_MI = "D"


class JmqMode(StrEnum):
    """JMQ behavior for a diagnostic run."""

    NONE = "none"
    APP_PRESENCE = "app-presence"
    NORMAL_CREDENTIALS_CONTROL = "normal-credentials-control"


class ControlTransport(StrEnum):
    """Transport used for a diagnostic control command."""

    NONE = "none"
    LEGACY = "legacy"
    NGIOT = "ngiot"


class MowerState(StrEnum):
    """Mower state declared or observed during a measurement window."""

    DOCKED = "docked"
    IDLE = "idle"
    MOWING = "mowing"
    PAUSED = "paused"
    RETURNING = "returning"
    UNKNOWN = "unknown"


class EndpointSource(StrEnum):
    """How an endpoint was selected."""

    DEVICE_SERVICE = "device service"
    REGIONAL_FALLBACK = "fallback"


@dataclass(frozen=True)
class ScenarioFeatures:
    """Independent factors selected by a convenience scenario."""

    jmq: JmqMode
    appping: ControlTransport
    get_mi: ControlTransport

    @classmethod
    def for_scenario(cls, scenario: GoatMapScenario) -> ScenarioFeatures:
        """Return reference-path presets without constraining custom runs."""
        return {
            GoatMapScenario.MQ_ONLY: cls(
                JmqMode.NONE, ControlTransport.NONE, ControlTransport.NONE
            ),
            GoatMapScenario.MQ_AND_JMQ: cls(
                JmqMode.APP_PRESENCE,
                ControlTransport.NONE,
                ControlTransport.NONE,
            ),
            GoatMapScenario.MQ_JMQ_APPPING: cls(
                JmqMode.APP_PRESENCE,
                ControlTransport.NGIOT,
                ControlTransport.NONE,
            ),
            GoatMapScenario.MQ_JMQ_APPPING_NGIOT_GET_MI: cls(
                JmqMode.APP_PRESENCE,
                ControlTransport.NGIOT,
                ControlTransport.NGIOT,
            ),
        }[scenario]


@dataclass(frozen=True, kw_only=True)
class ExperimentConfig:
    """Orthogonal settings for one reproducible diagnostic run."""

    phase: str
    mower_state: MowerState
    jmq: JmqMode = JmqMode.NONE
    appping: ControlTransport = ControlTransport.NONE
    get_mi: ControlTransport = ControlTransport.NONE

    @classmethod
    def for_scenario(
        cls,
        scenario: GoatMapScenario,
        *,
        mower_state: MowerState,
        phase: str | None = None,
    ) -> ExperimentConfig:
        """Create a config from a named preset."""
        features = ScenarioFeatures.for_scenario(scenario)
        return cls(
            phase=phase or f"scenario-{scenario.value}",
            mower_state=mower_state,
            jmq=features.jmq,
            appping=features.appping,
            get_mi=features.get_mi,
        )


@dataclass(frozen=True)
class NgiotServices:
    """N-GIoT service hosts retained in raw device information."""

    jmq: str | None
    mqs: str | None


@dataclass(frozen=True)
class EndpointSelection:
    """A sanitized endpoint choice and its provenance."""

    host: str
    source: EndpointSource


@dataclass(frozen=True)
class NgiotEndpoints:
    """Selected JMQ, control, and SST endpoints."""

    jmq: EndpointSelection
    mqs: EndpointSelection
    sst: EndpointSelection


def _service_host(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError("N-GIoT service host must be a non-empty string")
    parsed = urlparse(f"//{value}")
    try:
        port = parsed.port
    except ValueError as ex:
        raise ValueError("N-GIoT service value must contain only a hostname") from ex
    if (
        parsed.hostname != value
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
    ):
        raise ValueError("N-GIoT service value must contain only a hostname")
    return value


def extract_ngiot_services(device_info: Mapping[str, Any]) -> NgiotServices:
    """Extract unmodified ``service.jmq`` and ``service.mqs`` hostnames."""
    service = device_info.get("service")
    if service is None:
        return NgiotServices(jmq=None, mqs=None)
    if not isinstance(service, Mapping):
        raise TypeError("Device service information must be an object")
    return NgiotServices(
        jmq=_service_host(service.get("jmq")),
        mqs=_service_host(service.get("mqs")),
    )


def resolve_ngiot_endpoints(
    device_info: Mapping[str, Any], country: str
) -> NgiotEndpoints:
    """Prefer advertised device endpoints and retain explicit regional fallbacks."""
    services = extract_ngiot_services(device_info)
    continent = get_continent(country.upper())
    return NgiotEndpoints(
        jmq=EndpointSelection(
            services.jmq or f"jmq-ngiot-{continent}.dc.robotww.ecouser.net",
            EndpointSource.DEVICE_SERVICE
            if services.jmq
            else EndpointSource.REGIONAL_FALLBACK,
        ),
        mqs=EndpointSelection(
            services.mqs or f"api-ngiot.dc-{continent}.ww.ecouser.net",
            EndpointSource.DEVICE_SERVICE
            if services.mqs
            else EndpointSource.REGIONAL_FALLBACK,
        ),
        sst=EndpointSelection(
            f"api-base.dc-{continent}.ww.ecouser.net",
            EndpointSource.REGIONAL_FALLBACK,
        ),
    )


def sanitize_capture(value: Any, *, key: str = "") -> Any:
    """Return bounded capture data without credentials or opaque blob contents."""
    lowered_key = key.casefold().replace("_", "")
    if lowered_key == "si" or any(
        part.replace("_", "") in lowered_key for part in _SENSITIVE_KEY_PARTS
    ):
        return _redacted_scalar(value)
    if isinstance(value, Mapping):
        return {
            str(item_key): sanitize_capture(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        items = [
            sanitize_capture(item, key=key) for item in value[:_MAX_CAPTURE_LIST_ITEMS]
        ]
        if len(value) > _MAX_CAPTURE_LIST_ITEMS:
            items.append(f"<truncated:{len(value) - _MAX_CAPTURE_LIST_ITEMS}>")
        return items
    if key in _SAFE_VALUE_KEYS and isinstance(
        value, (str, int, float, bool, type(None))
    ):
        return value
    if isinstance(value, bool) or value is None:
        return value
    return _redacted_scalar(value)


def _redacted_scalar(value: Any) -> str:
    length = len(value) if isinstance(value, (str, bytes, bytearray, list, dict)) else 0
    suffix = f":len={length}" if length else ""
    return f"<redacted:{type(value).__name__}{suffix}>"


def _topic_details(topic: str) -> tuple[str, str]:
    parts = topic.split("/")
    command = parts[2] if len(parts) > 2 else "<unknown>"
    if topic.startswith("iot/atr/"):
        return command, "event"
    if topic.startswith("iot/p2p/") and len(parts) > 10:
        return command, "request" if parts[9] == "q" else "response"
    return command, "unknown"


def _json_payload(payload: str | bytes | bytearray) -> Any:
    try:
        return orjson.loads(payload)
    except orjson.JSONDecodeError, TypeError:
        return None


@dataclass(frozen=True, order=True)
class NumericId:
    """A non-map numeric identifier retained without surrounding payload data."""

    field: str
    value: str


def _looks_like_id_field(key: str) -> bool:
    if key in _MAP_ID_KEYS:
        return True
    lowered = key.lower()
    if any(part in lowered for part in _NON_REPORTABLE_ID_KEY_PARTS):
        return False
    return (
        key == "id"
        or key.endswith(("Id", "ID", "_id"))
        or lowered in {"batid", "firmwareid", "fwid", "taskid"}
    )


def _identifier_values(value: Any) -> list[NumericId]:
    found: list[NumericId] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            if (
                isinstance(key, str)
                and _looks_like_id_field(key)
                and isinstance(item, (str, int))
                and not isinstance(item, bool)
            ):
                found.append(NumericId(key, str(item)))
            else:
                found.extend(_identifier_values(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_identifier_values(item))
    return list(dict.fromkeys(found))


def _classified_ids(
    command: str, value: Any
) -> tuple[tuple[str, ...], tuple[NumericId, ...]]:
    candidates = _identifier_values(value)
    map_ids: list[str] = []
    other_numeric_ids: list[NumericId] = []
    for candidate in candidates:
        if command in _MAP_ID_COMMANDS and candidate.field in _MAP_ID_KEYS:
            map_ids.append(candidate.value)
        elif candidate.value.isdecimal():
            other_numeric_ids.append(candidate)
    return (
        tuple(dict.fromkeys(map_ids)),
        tuple(dict.fromkeys(other_numeric_ids)),
    )


@dataclass(frozen=True)
class TrafficRecord:
    """One sanitized diagnostic event with experiment context."""

    observed_at: str
    kind: Literal["window", "endpoint", "state", "session", "mqtt", "control", "marker"]
    session: str
    phase: str
    mower_state: str
    state: str | None = None
    broker: str | None = None
    endpoint_source: str | None = None
    transport: str | None = None
    topic: str | None = None
    command: str | None = None
    direction: str | None = None
    map_ids: tuple[str, ...] = ()
    other_numeric_ids: tuple[NumericId, ...] = ()
    sanitized_response: Any = None


class MqttTrafficRecorder:
    """Collect broker/session metadata and sanitized GOAT traffic statistics."""

    def __init__(
        self,
        *,
        phase: str = "unassigned",
        mower_state: MowerState = MowerState.UNKNOWN,
    ) -> None:
        self._records: list[TrafficRecord] = []
        self._connected: dict[str, asyncio.Event] = {}
        self._phase = phase
        self._mower_state = mower_state

    @property
    def records(self) -> tuple[TrafficRecord, ...]:
        """Return immutable view of recorded events."""
        return tuple(self._records)

    def observer(self, session: str) -> MqttObserver:
        """Create an observer bound to a human-readable session label."""
        return _RecorderObserver(self, session)

    async def wait_connected(self, session: str, timeout_seconds: float) -> None:
        """Wait until the named session has completed its MQTT handshake."""
        event = self._connected.setdefault(session, asyncio.Event())
        await asyncio.wait_for(event.wait(), timeout=timeout_seconds)

    def set_context(self, phase: str, mower_state: MowerState) -> None:
        """Set context inherited by subsequent records."""
        if not phase:
            raise ValueError("Diagnostic phase must be non-empty")
        self._phase = phase
        self._mower_state = mower_state

    def record_window(self, state: Literal["started", "ended"]) -> None:
        """Mark a measurement window boundary."""
        self._append("window", "measurement", state=state)

    def record_mower_state(self, mower_state: MowerState, source: str) -> None:
        """Record and apply a mower-state update."""
        self._mower_state = mower_state
        self._append("state", source, state=mower_state.value)

    def record_endpoint(self, service: str, selection: EndpointSelection) -> None:
        """Record a non-secret endpoint and whether device-info or fallback won."""
        self._append(
            "endpoint",
            service,
            broker=f"{selection.host}:443",
            endpoint_source=selection.source.value,
        )

    def record_session(
        self,
        session: str,
        config: MqttConfiguration,
        state: Literal["connected", "disconnected"],
        *,
        observed_at: datetime | None = None,
    ) -> None:
        """Record broker lifecycle without client IDs or credentials."""
        self._append(
            "session",
            session,
            state=state,
            broker=f"{config.hostname}:{config.port}",
            observed_at=observed_at,
        )
        if state == "connected":
            self._connected.setdefault(session, asyncio.Event()).set()

    def record_mqtt(
        self,
        session: str,
        topic: str,
        payload: str | bytes | bytearray,
        *,
        observed_at: datetime | None = None,
    ) -> None:
        """Record topic metadata; never retain the complete topic or payload."""
        command, direction = _topic_details(topic)
        decoded = _json_payload(payload)
        map_ids, other_numeric_ids = _classified_ids(command, decoded)
        self._append(
            "mqtt",
            session,
            transport=session,
            topic=_sanitize_topic(topic),
            command=command,
            direction=direction,
            map_ids=map_ids,
            other_numeric_ids=other_numeric_ids,
            observed_at=observed_at,
        )

    def record_control(
        self,
        transport: ControlTransport,
        command: str,
        response: Any,
        *,
        observed_at: datetime | None = None,
    ) -> None:
        """Record a raw-but-sanitized HTTP/control response."""
        map_ids, other_numeric_ids = _classified_ids(command, response)
        self._append(
            "control",
            transport.value,
            transport=transport.value,
            command=command,
            map_ids=map_ids,
            other_numeric_ids=other_numeric_ids,
            sanitized_response=sanitize_capture(response),
            observed_at=observed_at,
        )

    def record_presence_marker(
        self,
        state: Literal[
            "first-appping-issued", "renewal-appping-issued", "observation-ended"
        ],
        transport: ControlTransport,
        *,
        observed_at: datetime | None = None,
    ) -> None:
        """Mark renewal scheduling without retaining request IDs or credentials."""
        self._append(
            "marker",
            "presence-renewal",
            state=state,
            transport=transport.value,
            command="appping" if state != "observation-ended" else None,
            observed_at=observed_at,
        )

    def record_map_edit_marker(
        self,
        state: Literal["edit-window-started", "save-confirmed", "edit-window-ended"],
        *,
        observed_at: datetime | None = None,
    ) -> None:
        """Mark operator-controlled map-edit timing without payload data."""
        self._append(
            "marker",
            "controlled-map-edit",
            state=state,
            observed_at=observed_at,
        )

    def record_special_contour_marker(
        self,
        state: Literal[
            "zone-present-readback-observed",
            "delete-action-armed",
            "set-request-observed",
            "manual-save-confirmed",
            "observation-ended",
        ],
        *,
        observed_at: datetime | None = None,
    ) -> None:
        """Mark SpecialContour control context while retaining network timing."""
        self._append(
            "marker",
            "controlled-special-contour-delete",
            state=state,
            observed_at=observed_at,
        )

    def _append(
        self,
        kind: Literal[
            "window", "endpoint", "state", "session", "mqtt", "control", "marker"
        ],
        session: str,
        *,
        observed_at: datetime | None = None,
        **values: Any,
    ) -> None:
        self._records.append(
            TrafficRecord(
                observed_at=_timestamp(observed_at),
                kind=kind,
                session=session,
                phase=self._phase,
                mower_state=self._mower_state.value,
                **values,
            )
        )

    def report(self) -> dict[str, Any]:
        """Build a serializable report with rates and map-ID correlation."""
        mqtt_records = [record for record in self._records if record.kind == "mqtt"]
        sessions = sorted(
            {
                record.session
                for record in self._records
                if record.kind in {"session", "mqtt"}
            }
        )
        windows = [record for record in self._records if record.kind == "window"]
        return {
            "records": [asdict(record) for record in self._records],
            "sessions": {
                session: self._session_summary(session, mqtt_records)
                for session in sessions
            },
            "measurement_windows": [asdict(record) for record in windows],
            "phases": self._phase_summaries(mqtt_records),
            "mid_correlation": self._mid_correlation(),
            "other_numeric_id_observations": self._other_numeric_id_observations(),
            "normal_mq_around_jmq_connect": self._around_jmq_connect(mqtt_records),
            "interpretation": {
                "active_mowing_windows": sorted(
                    {
                        record.phase
                        for record in windows
                        if record.state == "started"
                        and record.mower_state == MowerState.MOWING.value
                    }
                ),
                "map_absence_outside_active_mowing_is_not_negative_evidence": True,
            },
        }

    def presence_renewal_summary(self) -> dict[str, Any] | None:
        """Summarize ping timing and stream gaps for an opt-in renewal run."""
        markers = [
            record
            for record in self._records
            if record.kind == "marker" and record.session == "presence-renewal"
        ]
        first_marker = next(
            (record for record in markers if record.state == "first-appping-issued"),
            None,
        )
        renewal_marker = next(
            (record for record in markers if record.state == "renewal-appping-issued"),
            None,
        )
        end_marker = next(
            (record for record in markers if record.state == "observation-ended"),
            None,
        )
        if first_marker is None or renewal_marker is None or end_marker is None:
            return None

        first_at = datetime.fromisoformat(first_marker.observed_at)
        renewal_at = datetime.fromisoformat(renewal_marker.observed_at)
        ended_at = datetime.fromisoformat(end_marker.observed_at)
        mqtt_requests = [
            record
            for record in self._records
            if record.kind == "mqtt"
            and record.command == "appping"
            and record.direction == "request"
            and first_marker.observed_at <= record.observed_at <= end_marker.observed_at
        ]
        streams = {
            "onPos": self._presence_stream_summary(
                "onPos", first_at, renewal_at, ended_at, gap_threshold_seconds=5
            ),
            "onMapTrack": self._presence_stream_summary(
                "onMapTrack",
                first_at,
                renewal_at,
                ended_at,
                gap_threshold_seconds=10,
            ),
        }
        return {
            "first_appping_issued_at": first_marker.observed_at,
            "renewal_appping_issued_at": renewal_marker.observed_at,
            "observation_ended_at": end_marker.observed_at,
            "renewal_elapsed_seconds": (renewal_at - first_at).total_seconds(),
            "observed_from_first_ping_seconds": (ended_at - first_at).total_seconds(),
            "observed_appping_request_timestamps": [
                record.observed_at for record in mqtt_requests
            ],
            "live_stream_confirmed_before_renewal": all(
                summary["first_at"] is not None
                and datetime.fromisoformat(summary["first_at"]) < renewal_at
                for summary in streams.values()
            ),
            "around_appping": [
                self._presence_checkpoint(
                    "first", first_marker.observed_at, mqtt_requests
                ),
                self._presence_checkpoint(
                    "renewal", renewal_marker.observed_at, mqtt_requests
                ),
            ],
            "streams": streams,
        }

    def _presence_stream_summary(
        self,
        command: str,
        first_at: datetime,
        renewal_at: datetime,
        ended_at: datetime,
        *,
        gap_threshold_seconds: float,
    ) -> dict[str, Any]:
        selected = sorted(
            (
                record
                for record in self._records
                if record.kind == "mqtt"
                and record.session == "mq"
                and record.command == command
                and first_at <= datetime.fromisoformat(record.observed_at) <= ended_at
            ),
            key=lambda record: record.observed_at,
        )
        timestamps = [datetime.fromisoformat(record.observed_at) for record in selected]
        interruptions = [
            {
                "last_before": previous.isoformat(),
                "first_after": current.isoformat(),
                "duration_seconds": (current - previous).total_seconds(),
            }
            for previous, current in pairwise(timestamps)
            if (current - previous).total_seconds() >= gap_threshold_seconds
        ]
        first_event = timestamps[0] if timestamps else None
        last_event = timestamps[-1] if timestamps else None
        return {
            "count": len(timestamps),
            "first_at": first_event.isoformat() if first_event else None,
            "last_at": last_event.isoformat() if last_event else None,
            "initial_delay_seconds": (
                (first_event - first_at).total_seconds() if first_event else None
            ),
            "last_before_renewal_at": _last_at_or_before(timestamps, renewal_at),
            "first_after_renewal_at": _first_at_or_after(timestamps, renewal_at),
            "gap_threshold_seconds": gap_threshold_seconds,
            "interruptions": interruptions,
            "tail_gap_seconds": (
                (ended_at - last_event).total_seconds() if last_event else None
            ),
        }

    def _presence_checkpoint(
        self,
        label: str,
        issued_at: str,
        mqtt_requests: list[TrafficRecord],
    ) -> dict[str, Any]:
        issued = datetime.fromisoformat(issued_at)
        matching_request = next(
            (
                record
                for record in mqtt_requests
                if datetime.fromisoformat(record.observed_at) >= issued
            ),
            None,
        )
        result: dict[str, Any] = {
            "label": label,
            "issued_at": issued_at,
            "mqtt_request_observed_at": (
                matching_request.observed_at if matching_request else None
            ),
        }
        for command in ("onPos", "onMapTrack"):
            timestamps = sorted(
                datetime.fromisoformat(record.observed_at)
                for record in self._records
                if record.kind == "mqtt"
                and record.session == "mq"
                and record.command == command
            )
            result[command] = {
                "last_before": _last_at_or_before(timestamps, issued),
                "first_after": _first_at_or_after(timestamps, issued),
            }
        return result

    def _session_summary(
        self, session: str, records: list[TrafficRecord]
    ) -> dict[str, Any]:
        selected = [record for record in records if record.session == session]
        commands = Counter(record.command for record in selected if record.command)
        positions = [record for record in selected if record.command == "onPos"]
        lifecycle = [
            record
            for record in self._records
            if record.kind == "session" and record.session == session
        ]
        return {
            "connection_states": [record.state for record in lifecycle],
            "brokers": sorted(
                {record.broker for record in lifecycle if record.broker is not None}
            ),
            "message_count": len(selected),
            "commands": dict(sorted(commands.items())),
            "interesting_commands": {
                command: commands.get(command, 0)
                for command in sorted(_INTERESTING_COMMANDS)
            },
            "on_pos": _frequency_summary(positions),
            "map_ids": sorted(
                {map_id for record in selected for map_id in record.map_ids}
            ),
            "other_numeric_ids": _summarize_other_numeric_ids(selected),
        }

    def _phase_summaries(
        self, mqtt_records: list[TrafficRecord]
    ) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for phase in sorted({record.phase for record in self._records}):
            phase_records = [
                record for record in self._records if record.phase == phase
            ]
            phase_mqtt = [record for record in mqtt_records if record.phase == phase]
            commands = Counter(
                record.command for record in phase_mqtt if record.command is not None
            )
            positions = [record for record in phase_mqtt if record.command == "onPos"]
            result[phase] = {
                "mower_states": sorted(
                    {record.mower_state for record in phase_records}
                ),
                "mqtt_commands": dict(sorted(commands.items())),
                "interesting_commands": {
                    command: commands.get(command, 0)
                    for command in sorted(_INTERESTING_COMMANDS)
                },
                "on_pos": _frequency_summary(positions),
                "map_ids": sorted(
                    {map_id for record in phase_records for map_id in record.map_ids}
                ),
                "other_numeric_ids": _summarize_other_numeric_ids(phase_records),
                "controls": [
                    {
                        "transport": record.transport,
                        "command": record.command,
                        "map_ids": record.map_ids,
                        "other_numeric_ids": tuple(
                            asdict(identifier)
                            for identifier in record.other_numeric_ids
                        ),
                    }
                    for record in phase_records
                    if record.kind == "control"
                ],
            }
        return result

    def _mid_correlation(self) -> dict[str, list[dict[str, str]]]:
        result: dict[str, list[dict[str, str]]] = {}
        for record in self._records:
            for map_id in record.map_ids:
                result.setdefault(map_id, []).append(
                    {
                        "kind": record.kind,
                        "session": record.session,
                        "phase": record.phase,
                        "mower_state": record.mower_state,
                        "transport": record.transport or "",
                        "command": record.command or "",
                    }
                )
        return dict(sorted(result.items()))

    def _other_numeric_id_observations(
        self,
    ) -> dict[str, list[dict[str, str]]]:
        result: dict[str, list[dict[str, str]]] = {}
        for record in self._records:
            for identifier in record.other_numeric_ids:
                result.setdefault(identifier.value, []).append(
                    {
                        "field": identifier.field,
                        "kind": record.kind,
                        "session": record.session,
                        "phase": record.phase,
                        "mower_state": record.mower_state,
                        "transport": record.transport or "",
                        "command": record.command or "",
                    }
                )
        return dict(sorted(result.items()))

    def _around_jmq_connect(
        self, mqtt_records: list[TrafficRecord]
    ) -> dict[str, Any] | None:
        marker = next(
            (
                record
                for record in self._records
                if record.kind == "session"
                and record.session.startswith("jmq")
                and record.state == "connected"
            ),
            None,
        )
        if marker is None:
            return None
        before = [
            record
            for record in mqtt_records
            if record.session == "mq" and record.observed_at < marker.observed_at
        ]
        after = [
            record
            for record in mqtt_records
            if record.session == "mq" and record.observed_at >= marker.observed_at
        ]
        return {
            "jmq_connected_at": marker.observed_at,
            "jmq_session": marker.session,
            "before": _period_summary(before),
            "after": _period_summary(after),
        }


class _RecorderObserver:
    def __init__(self, recorder: MqttTrafficRecorder, session: str) -> None:
        self._recorder = recorder
        self._session = session

    def on_connected(self, config: MqttConfiguration) -> None:
        self._recorder.record_session(self._session, config, "connected")

    def on_disconnected(self, config: MqttConfiguration) -> None:
        self._recorder.record_session(self._session, config, "disconnected")

    def on_message(self, _: MqttConfiguration, message: Message) -> None:
        self._recorder.record_mqtt(self._session, message.topic.value, message.payload)


def _timestamp(value: datetime | None) -> str:
    return (value or datetime.now(tz=UTC)).astimezone(UTC).isoformat()


def _sanitize_topic(topic: str) -> str:
    parts = topic.split("/")
    if len(parts) < 3:
        return topic
    if parts[1] == "atr":
        return "/".join([*parts[:3], "<device>", "<class>", "<resource>", *parts[6:]])
    if parts[1] == "p2p" and len(parts) > 11:
        return "/".join(
            [*parts[:3], "<sender>", "<receiver>", parts[9], "<request>", parts[-1]]
        )
    return "/".join(parts[:3])


def _summarize_other_numeric_ids(
    records: list[TrafficRecord],
) -> list[dict[str, str]]:
    identifiers = {
        identifier for record in records for identifier in record.other_numeric_ids
    }
    return [
        {"field": identifier.field, "value": identifier.value}
        for identifier in sorted(identifiers)
    ]


def _frequency_summary(records: list[TrafficRecord]) -> dict[str, Any]:
    timestamps = [datetime.fromisoformat(record.observed_at) for record in records]
    if len(timestamps) < 2:
        return {"count": len(timestamps), "hz": None, "interval_ms_median": None}
    intervals = [
        (current - previous).total_seconds()
        for previous, current in pairwise(timestamps)
    ]
    duration = (timestamps[-1] - timestamps[0]).total_seconds()
    return {
        "count": len(timestamps),
        "hz": (len(timestamps) - 1) / duration if duration > 0 else None,
        "interval_ms_median": statistics.median(intervals) * 1000,
    }


def _last_at_or_before(timestamps: list[datetime], checkpoint: datetime) -> str | None:
    selected = [timestamp for timestamp in timestamps if timestamp <= checkpoint]
    return selected[-1].isoformat() if selected else None


def _first_at_or_after(timestamps: list[datetime], checkpoint: datetime) -> str | None:
    return next(
        (timestamp.isoformat() for timestamp in timestamps if timestamp >= checkpoint),
        None,
    )


def _period_summary(records: list[TrafficRecord]) -> dict[str, Any]:
    commands = Counter(record.command for record in records if record.command)
    return {
        "message_count": len(records),
        "commands": dict(sorted(commands.items())),
        "on_pos": _frequency_summary(
            [record for record in records if record.command == "onPos"]
        ),
    }


def build_ngiot_payload(
    data: Mapping[str, Any],
    *,
    request_id: str | None = None,
    timestamp_ms: int | None = None,
    timezone_name: str = "UTC",
    timezone_minutes: int = 0,
) -> dict[str, Any]:
    """Build the observed N-GIoT request envelope without interpreting data."""
    return {
        "body": {"data": dict(data)},
        "header": {
            "channel": "Android",
            "m": "request",
            "pri": 2,
            "reqid": request_id or secrets.token_urlsafe(6)[:6],
            "ts": str(timestamp_ms or round(time.time() * 1000)),
            "tzc": timezone_name,
            "tzm": timezone_minutes,
            "ver": "0.0.22",
        },
    }


def _base64_json(value: Mapping[str, Any]) -> str:
    return base64.b64encode(orjson.dumps(value)).decode()


def _jwt_claim(token: str, claim: str) -> str | None:
    """Read a routing claim without logging or validating the credential."""
    try:
        payload = token.split(".", 2)[1]
        payload += "=" * (-len(payload) % 4)
        decoded = orjson.loads(base64.urlsafe_b64decode(payload))
    except IndexError, ValueError, orjson.JSONDecodeError:
        return None
    value = decoded.get(claim) if isinstance(decoded, Mapping) else None
    return str(value) if value is not None else None


def build_app_presence_identity(
    device_info: Mapping[str, Any], credentials: Credentials
) -> tuple[str, str]:
    """Build the reference app-presence username and client ID."""
    realm = _jwt_claim(credentials.token, "r")
    if not realm:
        raise ValueError("Could not determine N-GIoT realm from account token")
    username = (
        f"{device_info['did']}`{_base64_json(_APP_PRESENCE_FEATURE_META)}"
        f"\n`{_base64_json(_APP_PRESENCE_ROLE_META)}"
    )
    return username, f"{credentials.user_id}@USER/{realm}"


class AppPresenceMqttClient:
    """Short-lived, opt-in JMQ session matching the reference app identity."""

    def __init__(
        self,
        config: MqttConfiguration,
        authenticator: Authenticator,
        device_info: ApiDeviceInfo,
        recorder: MqttTrafficRecorder,
    ) -> None:
        self._config = config
        self._authenticator = authenticator
        self._device_info = device_info
        self._recorder = recorder
        self._task: asyncio.Task[None] | None = None

    async def connect(self) -> None:
        """Open the app-presence session without changing normal MQTT."""
        if self._task is not None and not self._task.done():
            return
        credentials = await self._authenticator.authenticate()
        username, client_id = build_app_presence_identity(
            self._device_info, credentials
        )

        async def listen() -> None:
            connected = False
            try:
                async with Client(
                    hostname=self._config.hostname,
                    port=self._config.port,
                    username=username,
                    password=credentials.token,
                    identifier=client_id,
                    protocol=ProtocolVersion.V311,
                    tls_context=self._config.ssl_context,
                ) as client:
                    connected = True
                    self._recorder.record_session(
                        "jmq-app-presence", self._config, "connected"
                    )
                    async for message in client.messages:
                        self._recorder.record_mqtt(
                            "jmq-app-presence",
                            message.topic.value,
                            message.payload,
                        )
            finally:
                if connected:
                    self._recorder.record_session(
                        "jmq-app-presence", self._config, "disconnected"
                    )

        self._task = asyncio.create_task(listen())

    async def disconnect(self) -> None:
        """Close the app-presence session."""
        if self._task is not None and self._task.cancel():
            with suppress(asyncio.CancelledError):
                await self._task
        self._task = None

    async def wait_connected(self, timeout_seconds: float) -> None:
        """Wait for CONNACK and surface an early connection task failure."""
        if self._task is None:
            raise RuntimeError("App-presence session has not been started")
        connected = asyncio.create_task(
            self._recorder.wait_connected("jmq-app-presence", timeout_seconds)
        )
        done, _ = await asyncio.wait(
            {connected, self._task}, return_when=asyncio.FIRST_COMPLETED
        )
        if self._task in done:
            connected.cancel()
            with suppress(asyncio.CancelledError):
                await connected
            await self._task
            raise RuntimeError("App-presence session ended before CONNACK")
        await connected


DiagnosticJmqClient = AppPresenceMqttClient | MqttClient


def create_diagnostic_mqtt_clients(  # noqa: PLR0913
    *,
    device_id: str,
    country: str,
    device_info: ApiDeviceInfo,
    authenticator: Authenticator,
    recorder: MqttTrafficRecorder,
    jmq_mode: JmqMode,
) -> tuple[MqttClient, DiagnosticJmqClient | None]:
    """Create normal MQ and an independently selected opt-in JMQ probe."""
    normal = MqttClient(
        create_mqtt_config(device_id=device_id, country=country),
        authenticator,
        observer=recorder.observer("mq"),
    )
    if jmq_mode == JmqMode.NONE:
        return normal, None

    endpoints = resolve_ngiot_endpoints(device_info, country)
    recorder.record_endpoint("jmq", endpoints.jmq)
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    config = create_mqtt_config(
        device_id=device_id,
        country=country,
        override_mqtt_url=f"mqtts://{endpoints.jmq.host}:443",
        ssl_context=ssl_context,
    )
    if jmq_mode == JmqMode.APP_PRESENCE:
        return normal, AppPresenceMqttClient(
            config, authenticator, device_info, recorder
        )

    return normal, MqttClient(
        config,
        authenticator,
        observer=recorder.observer("jmq-normal-credentials-control"),
    )


@dataclass(frozen=True)
class _SstToken:
    token: str
    expires_at: float


class NgiotControlClient:
    """Minimal N-GIoT control probe with legitimate short-lived SST auth."""

    def __init__(  # noqa: PLR0913
        self,
        session: ClientSession,
        authenticator: Authenticator,
        device_info: ApiDeviceInfo,
        country: str,
        recorder: MqttTrafficRecorder,
        capture_response: Callable[[ControlTransport, str, bytes], None] | None = None,
        register_secret: Callable[[str], None] | None = None,
    ) -> None:
        self._session = session
        self._authenticator = authenticator
        self._device_info = device_info
        self._recorder = recorder
        self._capture_response = capture_response
        self._register_secret = register_secret
        self._endpoints = resolve_ngiot_endpoints(device_info, country)
        self._sst: _SstToken | None = None
        recorder.record_endpoint("mqs-control", self._endpoints.mqs)
        recorder.record_endpoint("sst-issue", self._endpoints.sst)

    async def call(self, command: str, data: Mapping[str, Any]) -> dict[str, Any]:
        """Send a research control request and retain only its sanitized response."""
        sst = await self._sst_token()
        request_id = uuid4().hex
        if self._register_secret is not None:
            self._register_secret(request_id)
        api = self._device_info
        url = f"https://{self._endpoints.mqs.host}/api/iot/endpoint/control"
        params = {
            "si": request_id,
            "ct": "q",
            "eid": api["did"],
            "et": api["class"],
            "er": api["resource"],
            "apn": command,
            "fmt": "j",
        }
        headers = {
            "authorization": f"Bearer {sst.token}",
            "x-eco-request-id": request_id,
            "content-type": "application/octet-stream",
            "user-agent": "okhttp/4.9.1",
        }
        async with self._session.post(
            url,
            params=params,
            json=build_ngiot_payload(data),
            headers=headers,
            timeout=_HTTP_TIMEOUT,
        ) as response:
            response.raise_for_status()
            if self._capture_response is None:
                decoded = await response.json(content_type=None)
            else:
                raw_response = await response.read()
                if raw_response.strip():
                    decoded = orjson.loads(raw_response)
                    self._capture_response(
                        ControlTransport.NGIOT, command, raw_response
                    )
                else:
                    decoded = None
        result: dict[str, Any] = decoded if isinstance(decoded, dict) else {}
        self._recorder.record_control(ControlTransport.NGIOT, command, decoded)
        return result

    async def _sst_token(self) -> _SstToken:
        if self._sst is not None and self._sst.expires_at > time.time():
            return self._sst
        credentials = await self._authenticator.authenticate()
        api = self._device_info
        body = {
            "acl": [
                {
                    "policy": [
                        {
                            "obj": [f"Endpoint:{api['class']}:{api['did']}"],
                            "perms": ["Control"],
                        }
                    ],
                    "svc": "dim",
                }
            ],
            "exp": 600,
            "sub": credentials.user_id,
        }
        headers = {
            "authorization": f"Bearer {credentials.token}",
            "content-type": "application/json",
            "user-agent": "okhttp/4.9.1",
        }
        url = f"https://{self._endpoints.sst.host}/api/new-perm/token/sst/issue"
        async with self._session.post(
            url, json=body, headers=headers, timeout=_HTTP_TIMEOUT
        ) as response:
            response.raise_for_status()
            result = await response.json(content_type=None)
        try:
            token = str(result["data"]["data"]["token"])
        except (KeyError, TypeError) as ex:
            raise ValueError("SST issue response did not contain a token") from ex
        self._sst = _SstToken(token=token, expires_at=time.time() + 540)
        if self._register_secret is not None:
            self._register_secret(token)
        return self._sst


class _RawLegacyCommand(JsonCommandWithMessageHandling):
    """Research-only legacy command that preserves the raw response."""

    NAME = "diagnosticRawLegacy"

    @classmethod
    def _handle_body(cls, _: EventBus, __: dict[str, Any]) -> HandlingResult:
        return HandlingResult.success()


class LegacyAppPingCommand(_RawLegacyCommand):
    """Experimental legacy ``appping`` control."""

    NAME = "appping"

    def __init__(self) -> None:
        super().__init__({})


class LegacyGetMiCommand(_RawLegacyCommand):
    """Legacy ``getMI`` control that leaves its response opaque."""

    NAME = "getMI"

    def __init__(self, data: Mapping[str, Any]) -> None:
        super().__init__(dict(data))


StateProvider = Callable[[str, MowerState], MowerState | Awaitable[MowerState]]


class GoatMapDiagnosticExperiment:
    """Run isolated factor combinations without enabling production map support."""

    def __init__(
        self,
        *,
        authenticator: Authenticator,
        device_info: DeviceInfo,
        device_id: str,
        country: str,
        http_session: ClientSession | None = None,
    ) -> None:
        self._authenticator = authenticator
        self._device_info = device_info
        self._device_id = device_id
        self._country = country
        self._http_session = http_session

    async def run(  # noqa: C901, PLR0912, PLR0913, PLR0915
        self,
        config: ExperimentConfig,
        *,
        baseline_seconds: float = 30,
        observation_seconds: float = 30,
        appping_renew_after_seconds: float | None = None,
        presence_total_seconds: float | None = None,
        connect_timeout: float = 30,
        get_mi_data: Mapping[str, Any] | None = None,
        state_provider: StateProvider | None = None,
    ) -> dict[str, Any]:
        """Run a factor combination and return a sanitized in-memory report."""
        renewal_enabled = (
            appping_renew_after_seconds is not None
            or presence_total_seconds is not None
        )
        if renewal_enabled:
            if (
                appping_renew_after_seconds is None
                or presence_total_seconds is None
                or appping_renew_after_seconds <= 0
                or presence_total_seconds <= appping_renew_after_seconds
            ):
                raise ValueError(
                    "Presence renewal requires positive renewal and total durations, "
                    "with total greater than renewal"
                )
            if config.appping == ControlTransport.NONE:
                raise ValueError("Presence renewal requires an appping transport")
            if config.jmq != JmqMode.NONE or config.get_mi != ControlTransport.NONE:
                raise ValueError("Presence renewal must run without JMQ or getMI")
        recorder = MqttTrafficRecorder(
            phase=config.phase, mower_state=config.mower_state
        )
        normal, jmq = create_diagnostic_mqtt_clients(
            device_id=self._device_id,
            country=self._country,
            device_info=self._device_info.api,
            authenticator=self._authenticator,
            recorder=recorder,
            jmq_mode=config.jmq,
        )

        async def no_command(_: Command) -> dict[str, Any]:
            return {}

        event_bus = EventBus(no_command, self._device_info.static.capabilities)
        subscriptions: list[Callable[[], None]] = []
        control: NgiotControlClient | None = None

        async def on_state(event: StateEvent) -> None:
            recorder.record_mower_state(_diagnostic_state(event.state), "mqtt-state")

        subscriptions.append(event_bus.subscribe(StateEvent, on_state))

        def handle_known_message(name: str, payload: str | bytes | bytearray) -> None:
            """Update known state events without decoding unknown map payloads."""
            if message := get_message(name, self._device_info.static):
                message.handle(event_bus, payload)

        async def window(label: str, duration: float) -> None:
            current = (
                MowerState(recorder.records[-1].mower_state)
                if recorder.records
                else config.mower_state
            )
            if state_provider is not None:
                provided = state_provider(label, current)
                current = (
                    await provided if isinstance(provided, Awaitable) else provided
                )
            recorder.set_context(f"{config.phase}:{label}", current)
            recorder.record_window("started")
            await asyncio.sleep(duration)
            recorder.record_window("ended")

        async def ngiot() -> NgiotControlClient:
            nonlocal control
            if self._http_session is None:
                raise ValueError("N-GIoT controls require http_session")
            if control is None:
                control = NgiotControlClient(
                    self._http_session,
                    self._authenticator,
                    self._device_info.api,
                    self._country,
                    recorder,
                )
            return control

        async def legacy(command: _RawLegacyCommand) -> None:
            result = await command.execute(
                self._authenticator, self._device_info.api, event_bus
            )
            recorder.record_control(
                ControlTransport.LEGACY, command.NAME, result.raw_response
            )

        def action_context(label: str) -> None:
            current = (
                MowerState(recorder.records[-1].mower_state)
                if recorder.records
                else config.mower_state
            )
            recorder.set_context(f"{config.phase}:{label}", current)

        async def appping_action() -> None:
            if config.appping == ControlTransport.LEGACY:
                await legacy(LegacyAppPingCommand())
            elif config.appping == ControlTransport.NGIOT:
                await (await ngiot()).call("appping", {})

        async def sleep_until(deadline: float) -> None:
            await asyncio.sleep(max(0, deadline - asyncio.get_running_loop().time()))

        get_mi_args = {"type": "0"} if get_mi_data is None else get_mi_data
        try:
            subscriptions.append(
                await normal.subscribe(
                    SubscriberInfo(self._device_info, event_bus, handle_known_message)
                )
            )
            await recorder.wait_connected("mq", connect_timeout)
            await window("baseline", baseline_seconds)

            if isinstance(jmq, AppPresenceMqttClient):
                await jmq.connect()
                await jmq.wait_connected(connect_timeout)
                await window("after-jmq-app-presence", observation_seconds)
            elif isinstance(jmq, MqttClient):
                subscriptions.append(
                    await jmq.subscribe(
                        SubscriberInfo(
                            self._device_info, event_bus, handle_known_message
                        )
                    )
                )
                await recorder.wait_connected(
                    "jmq-normal-credentials-control", connect_timeout
                )
                await window("after-jmq-negative-control", observation_seconds)

            if renewal_enabled:
                renew_after = appping_renew_after_seconds
                total_duration = presence_total_seconds
                if renew_after is None or total_duration is None:
                    raise RuntimeError("Presence renewal timing validation failed")
                action_context("presence-renewal-observation")
                recorder.record_window("started")
                loop = asyncio.get_running_loop()
                first_started = loop.time()

                action_context("presence-renewal-first-appping-action")
                recorder.record_presence_marker("first-appping-issued", config.appping)
                await appping_action()

                action_context("presence-renewal-observation")
                await sleep_until(first_started + renew_after)

                action_context("presence-renewal-second-appping-action")
                recorder.record_presence_marker(
                    "renewal-appping-issued", config.appping
                )
                await appping_action()

                action_context("presence-renewal-observation")
                await sleep_until(first_started + total_duration)
                recorder.record_window("ended")
                recorder.record_presence_marker("observation-ended", config.appping)
            elif config.appping != ControlTransport.NONE:
                action_context(f"{config.appping.value}-appping-action")
                await appping_action()
                await window(
                    f"after-{config.appping.value}-appping", observation_seconds
                )

            if config.get_mi == ControlTransport.LEGACY:
                action_context("legacy-get-mi-action")
                await legacy(LegacyGetMiCommand(get_mi_args))
            elif config.get_mi == ControlTransport.NGIOT:
                action_context("ngiot-get-mi-action")
                await (await ngiot()).call("getMI", get_mi_args)
            if config.get_mi != ControlTransport.NONE:
                await window(f"after-{config.get_mi.value}-get-mi", observation_seconds)
        finally:
            for unsubscribe in subscriptions:
                unsubscribe()
            await normal.disconnect()
            if jmq is not None:
                await jmq.disconnect()
            await event_bus.teardown()

        report = recorder.report()
        report["experiment"] = {
            **asdict(config),
            "baseline_seconds": baseline_seconds,
            "observation_seconds": observation_seconds,
            "get_mi_payload_decoded": False,
        }
        if renewal_enabled:
            report["experiment"].update(
                {
                    "appping_renew_after_seconds": appping_renew_after_seconds,
                    "presence_total_seconds": presence_total_seconds,
                }
            )
            report["presence_renewal"] = recorder.presence_renewal_summary()
        return report


def _diagnostic_state(state: State) -> MowerState:
    return {
        State.DOCKED: MowerState.DOCKED,
        State.IDLE: MowerState.IDLE,
        State.CLEANING: MowerState.MOWING,
        State.PAUSED: MowerState.PAUSED,
        State.RETURNING: MowerState.RETURNING,
    }.get(state, MowerState.UNKNOWN)
