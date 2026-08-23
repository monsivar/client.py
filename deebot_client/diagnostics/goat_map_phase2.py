"""Controlled Phase 2 GOAT static-map capture orchestration."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from itertools import pairwise
from typing import TYPE_CHECKING, Any

from deebot_client.event_bus import EventBus
from deebot_client.events import StateEvent
from deebot_client.messages import get_message
from deebot_client.models import State
from deebot_client.mqtt_client import (
    MqttClient,
    MqttConfiguration,
    MqttObserver,
    SubscriberInfo,
    create_mqtt_config,
)

from .goat_map_capture import (
    CombinedMqttObserver,
    GoatMapCaptureObserver,
    GoatMapCaptureWriter,
)
from .goat_map_refresh import (
    ControlTransport,
    LegacyGetMiCommand,
    MowerState,
    MqttTrafficRecorder,
    NgiotControlClient,
)
from .goat_map_repeatability import (
    EstablishedCadence,
    RepeatabilityConfig,
    ShortFormObservation,
    ShortOnMiCadenceObserver,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, Sequence

    from aiohttp import ClientSession
    from aiomqtt import Message

    from deebot_client.authentication import Authenticator
    from deebot_client.command import Command
    from deebot_client.models import DeviceInfo


@dataclass(frozen=True, kw_only=True)
class Phase2CaptureConfig:
    """Timing and state metadata for the first controlled capture sequence."""

    phase: str = "p2-01-getmi-paired-mowing"
    mower_state: MowerState = MowerState.MOWING
    baseline_seconds: float = 30
    live_confirmation_timeout: float = 30
    post_get_mi_seconds: float = 45
    cooldown_seconds: float = 30
    tail_seconds: float = 30
    connect_timeout: float = 30

    def __post_init__(self) -> None:
        durations = (
            self.baseline_seconds,
            self.live_confirmation_timeout,
            self.post_get_mi_seconds,
            self.cooldown_seconds,
            self.tail_seconds,
            self.connect_timeout,
        )
        if any(duration < 0 for duration in durations):
            raise ValueError("Phase 2 capture durations cannot be negative")
        if self.connect_timeout == 0 or self.live_confirmation_timeout == 0:
            raise ValueError(
                "Connection and live-confirmation timeouts must be positive"
            )


@dataclass(frozen=True, kw_only=True)
class FrontendReloadAttributionConfig:
    """Timing and state metadata for a passive external-trigger observation."""

    phase: str = "p2-03-frontend-reload-attribution"
    mower_state: MowerState = MowerState.MOWING
    trigger: str = "frontend-reload"
    baseline_seconds: float = 45
    reload_window_seconds: float = 90
    connect_timeout: float = 30

    def __post_init__(self) -> None:
        if self.mower_state is not MowerState.MOWING:
            raise ValueError("Passive attribution requires active mowing")
        if self.trigger not in _ATTRIBUTION_TRIGGER_METADATA:
            raise ValueError("Unsupported passive attribution trigger")
        if not 30 <= self.baseline_seconds <= 60:
            raise ValueError(
                "Passive attribution baseline must be between 30 and 60 seconds"
            )
        if not 60 <= self.reload_window_seconds <= 90:
            raise ValueError(
                "Passive attribution window must be between 60 and 90 seconds"
            )
        if self.connect_timeout <= 0:
            raise ValueError("Connection timeout must be positive")


@dataclass(frozen=True, kw_only=True)
class PollerIsolationConfig:
    """Timing and state metadata for one passive external-poller check."""

    phase: str = "p2-12-poller-isolation"
    mower_state: MowerState = MowerState.PAUSED
    quiet_seconds: float = 480
    connect_timeout: float = 30

    def __post_init__(self) -> None:
        if self.mower_state is not MowerState.PAUSED:
            raise ValueError("Poller isolation requires a paused mower")
        if not 480 <= self.quiet_seconds <= 1800:
            raise ValueError("Poller isolation must run for 480 to 1800 seconds")
        if self.connect_timeout <= 0:
            raise ValueError("Connection timeout must be positive")


@dataclass(frozen=True, kw_only=True)
class ControlledMapEditConfig:
    """Timing and state metadata for one operator-controlled map edit."""

    phase: str = "p2-05-controlled-nogo-delta-edit"
    mower_state: MowerState = MowerState.PAUSED
    baseline_seconds: float = 30
    post_save_seconds: float = 90
    connect_timeout: float = 30

    def __post_init__(self) -> None:
        if self.mower_state is not MowerState.PAUSED:
            raise ValueError("Controlled map editing requires a paused mower")
        if not 10 <= self.baseline_seconds <= 60:
            raise ValueError("Map-edit baseline must be between 10 and 60 seconds")
        if not 30 <= self.post_save_seconds <= 180:
            raise ValueError("Post-save observation must be between 30 and 180 seconds")
        if self.connect_timeout <= 0:
            raise ValueError("Connection timeout must be positive")


@dataclass(frozen=True, kw_only=True)
class SpecialContourDeleteConfig:
    """Timing for one passive, inverse SpecialContour deletion control."""

    phase: str = "p2-06-controlled-special-contour-delete"
    mower_state: MowerState = MowerState.PAUSED
    baseline_seconds: float = 30
    initial_readback_timeout: float = 45
    post_delete_seconds: float = 120
    connect_timeout: float = 30

    def __post_init__(self) -> None:
        if self.mower_state is not MowerState.PAUSED:
            raise ValueError("SpecialContour deletion requires a paused mower")
        if not 10 <= self.baseline_seconds <= 60:
            raise ValueError(
                "SpecialContour baseline must be between 10 and 60 seconds"
            )
        if not 15 <= self.initial_readback_timeout <= 120:
            raise ValueError(
                "Initial readback timeout must be between 15 and 120 seconds"
            )
        if not 60 <= self.post_delete_seconds <= 300:
            raise ValueError(
                "Post-delete observation must be between 60 and 300 seconds"
            )
        if self.connect_timeout <= 0:
            raise ValueError("Connection timeout must be positive")


@dataclass(frozen=True, kw_only=True)
class ZoneAbsentReadbackConfig:
    """Timing and explicit mower state for a passive absent-state readback."""

    phase: str = "p2-07-zone-absent-readback"
    mower_state: MowerState = MowerState.PAUSED
    baseline_seconds: float = 30
    readback_seconds: float = 120
    connect_timeout: float = 30

    def __post_init__(self) -> None:
        if self.mower_state is MowerState.UNKNOWN:
            raise ValueError("Zone-absent readback requires an explicit mower state")
        if not 10 <= self.baseline_seconds <= 60:
            raise ValueError(
                "Zone-absent readback baseline must be between 10 and 60 seconds"
            )
        if not 60 <= self.readback_seconds <= 180:
            raise ValueError(
                "Zone-absent readback window must be between 60 and 180 seconds"
            )
        if self.connect_timeout <= 0:
            raise ValueError("Connection timeout must be positive")


class GoatMapPhase2CaptureExperiment:
    """Capture paired legacy/N-GIoT getMI without interpreting payloads."""

    def __init__(  # noqa: PLR0913
        self,
        *,
        authenticator: Authenticator,
        device_info: DeviceInfo,
        device_id: str,
        country: str,
        http_session: ClientSession,
        writer: GoatMapCaptureWriter,
    ) -> None:
        self._authenticator = authenticator
        self._device_info = device_info
        self._device_id = device_id
        self._country = country
        self._http_session = http_session
        self._writer = writer

    async def run(  # noqa: PLR0915
        self,
        config: Phase2CaptureConfig,
        *,
        get_mi_data: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run the approved p2-01 sequence and return Phase 1-style metadata."""
        recorder = MqttTrafficRecorder(
            phase=config.phase,
            mower_state=config.mower_state,
        )
        observer = CombinedMqttObserver(
            recorder.observer("mq"),
            GoatMapCaptureObserver(self._writer),
        )
        normal = MqttClient(
            create_mqtt_config(device_id=self._device_id, country=self._country),
            self._authenticator,
            observer=observer,
        )

        async def no_command(_: Command) -> dict[str, Any]:
            return {}

        event_bus = EventBus(no_command, self._device_info.static.capabilities)
        subscriptions: list[Callable[[], None]] = []

        async def on_state(event: StateEvent) -> None:
            state = _capture_state(event.state)
            recorder.record_mower_state(state, "mqtt-state")
            self._writer.set_context(current_window(), state)

        subscriptions.append(event_bus.subscribe(StateEvent, on_state))

        def handle_known_message(name: str, payload: str | bytes | bytearray) -> None:
            if message := get_message(name, self._device_info.static):
                message.handle(event_bus, payload)

        def current_state() -> MowerState:
            return (
                MowerState(recorder.records[-1].mower_state)
                if recorder.records
                else config.mower_state
            )

        def current_window() -> str:
            return recorder.records[-1].phase if recorder.records else config.phase

        def context(label: str) -> None:
            phase = f"{config.phase}:{label}"
            state = current_state()
            recorder.set_context(phase, state)
            self._writer.set_context(phase, state)

        async def window(label: str, duration: float) -> None:
            context(label)
            recorder.record_window("started")
            await asyncio.sleep(duration)
            recorder.record_window("ended")

        def capture_ngiot_response(
            transport: ControlTransport, command: str, raw: bytes
        ) -> None:
            self._writer.record_control(
                transport,
                command,
                raw,
                response_body_bytes=True,
            )

        ngiot = NgiotControlClient(
            self._http_session,
            self._authenticator,
            self._device_info.api,
            self._country,
            recorder,
            capture_response=capture_ngiot_response,
            register_secret=self._writer.register_forbidden_value,
        )
        get_mi_args = {"type": "0"} if get_mi_data is None else get_mi_data
        try:
            subscriptions.append(
                await normal.subscribe(
                    SubscriberInfo(self._device_info, event_bus, handle_known_message)
                )
            )
            await recorder.wait_connected("mq", config.connect_timeout)
            await window("baseline", config.baseline_seconds)

            context("ngiot-appping-action")
            records_before_appping = len(recorder.records)
            await ngiot.call("appping", {})
            await _wait_for_mqtt_command(
                recorder,
                "onPos",
                after_index=records_before_appping,
                timeout_seconds=config.live_confirmation_timeout,
            )

            context("legacy-get-mi-action")
            legacy_result = await LegacyGetMiCommand(get_mi_args).execute(
                self._authenticator,
                self._device_info.api,
                event_bus,
            )
            if not legacy_result.device_reached:
                raise RuntimeError("Legacy getMI did not return a capture response")
            self._writer.record_control(
                ControlTransport.LEGACY,
                "getMI",
                legacy_result.raw_response,
            )
            recorder.record_control(
                ControlTransport.LEGACY,
                "getMI",
                legacy_result.raw_response,
            )
            await window("after-legacy-get-mi", config.post_get_mi_seconds)
            await window("cooldown", config.cooldown_seconds)

            context("ngiot-get-mi-action")
            await ngiot.call("getMI", get_mi_args)
            await window("after-ngiot-get-mi", config.post_get_mi_seconds)
            await window("tail", config.tail_seconds)
        finally:
            for unsubscribe in subscriptions:
                unsubscribe()
            await normal.disconnect()
            await event_bus.teardown()

        report = recorder.report()
        report["experiment"] = {
            **asdict(config),
            "jmq": "none",
            "appping": "ngiot",
            "get_mi_sequence": ["legacy", "ngiot"],
            "get_mi_payload_decoded": False,
            "static_map_capture_commands": [
                "getMI",
                "onMI",
                "onArI",
                "getAreaSet",
                "onAreaSet",
            ],
        }
        return report


class GoatMapRepeatabilityExperiment:
    """Run one non-editing cadence/getMI timing experiment on normal MQ."""

    def __init__(  # noqa: PLR0913
        self,
        *,
        authenticator: Authenticator,
        device_info: DeviceInfo,
        device_id: str,
        country: str,
        http_session: ClientSession,
        writer: GoatMapCaptureWriter,
    ) -> None:
        self._authenticator = authenticator
        self._device_info = device_info
        self._device_id = device_id
        self._country = country
        self._http_session = http_session
        self._writer = writer

    async def run(  # noqa: C901, PLR0912, PLR0915
        self,
        config: RepeatabilityConfig,
    ) -> dict[str, Any]:
        """Observe cadence, schedule two controls, and retain only opaque captures."""
        recorder = MqttTrafficRecorder(
            phase=config.phase,
            mower_state=config.mower_state,
        )
        cadence_observer = ShortOnMiCadenceObserver()
        observer = CombinedMqttObserver(
            recorder.observer("mq"),
            GoatMapCaptureObserver(self._writer),
            cadence_observer,
        )
        normal = MqttClient(
            create_mqtt_config(device_id=self._device_id, country=self._country),
            self._authenticator,
            observer=observer,
        )

        async def no_command(_: Command) -> dict[str, Any]:
            return {}

        event_bus = EventBus(no_command, self._device_info.static.capabilities)
        subscriptions: list[Callable[[], None]] = []

        def current_state() -> MowerState:
            return (
                MowerState(recorder.records[-1].mower_state)
                if recorder.records
                else config.mower_state
            )

        def context(label: str) -> str:
            phase = f"{config.phase}:{label}"
            state = current_state()
            recorder.set_context(phase, state)
            self._writer.set_context(phase, state)
            return phase

        async def on_state(event: StateEvent) -> None:
            state = _capture_state(event.state)
            recorder.record_mower_state(state, "mqtt-state")
            self._writer.set_context(recorder.records[-1].phase, state)

        subscriptions.append(event_bus.subscribe(StateEvent, on_state))

        def handle_known_message(name: str, payload: str | bytes | bytearray) -> None:
            if message := get_message(name, self._device_info.static):
                message.handle(event_bus, payload)

        def capture_ngiot_response(
            transport: ControlTransport,
            command: str,
            raw: bytes,
        ) -> None:
            self._writer.record_control(
                transport,
                command,
                raw,
                response_body_bytes=True,
            )

        ngiot = NgiotControlClient(
            self._http_session,
            self._authenticator,
            self._device_info.api,
            self._country,
            recorder,
            capture_response=capture_ngiot_response,
            register_secret=self._writer.register_forbidden_value,
        )
        loop = asyncio.get_running_loop()
        status = "inconclusive"
        reason: str | None = None
        presence_started_monotonic: float | None = None
        appping_started_at: str | None = None
        presence_established_at: str | None = None
        cadence_anchor_at: str | None = None
        cadence_seconds: float | None = None
        controls: list[dict[str, Any]] = []
        cadence_observations: list[dict[str, Any]] = []
        try:
            subscriptions.append(
                await normal.subscribe(
                    SubscriberInfo(self._device_info, event_bus, handle_known_message)
                )
            )
            await recorder.wait_connected("mq", config.connect_timeout)

            context("baseline")
            recorder.record_window("started")
            await asyncio.sleep(config.baseline_seconds)
            recorder.record_window("ended")

            context("ngiot-appping-action")
            appping_started_at = datetime.now(UTC).isoformat()
            await ngiot.call("appping", {})
            presence_started_monotonic = loop.time()
            presence_established_at = datetime.now(UTC).isoformat()
            cadence_start_count = len(cadence_observer.observations)

            context("cadence-establishment")
            recorder.record_window("started")
            cadence = await cadence_observer.wait_for_cadence(
                after_count=cadence_start_count,
                timeout_seconds=config.cadence_timeout_seconds,
                min_interval_seconds=config.cadence_min_seconds,
                max_interval_seconds=config.cadence_max_seconds,
            )
            recorder.record_window("ended")
            if cadence is None:
                reason = "two-compatible-52-byte-observations-not-established"
            else:
                cadence_anchor_at = cadence.second.observed_at
                cadence_seconds = cadence.interval_seconds
                cadence_observations.extend(
                    _cadence_observation(item)
                    for item in (cadence.first, cadence.second)
                )
                expected_end = (
                    cadence.second.monotonic_seconds
                    + (2 * cadence.interval_seconds)
                    + config.final_event_grace_seconds
                )
                lease_deadline = (
                    presence_started_monotonic + config.presence_lease_budget_seconds
                )
                if expected_end > lease_deadline:
                    reason = "insufficient-single-presence-lease-budget"
                else:
                    await _sleep_until(
                        cadence.second.monotonic_seconds + config.control_offset_seconds
                    )
                    context("legacy-get-mi-action")
                    before_count = len(cadence_observer.observations)
                    legacy_started = datetime.now(UTC).isoformat()
                    legacy_result = await LegacyGetMiCommand({"type": "0"}).execute(
                        self._authenticator,
                        self._device_info.api,
                        event_bus,
                    )
                    if not legacy_result.device_reached:
                        reason = "legacy-get-mi-device-not-reached"
                    else:
                        self._writer.record_control(
                            ControlTransport.LEGACY,
                            "getMI",
                            legacy_result.raw_response,
                        )
                        recorder.record_control(
                            ControlTransport.LEGACY,
                            "getMI",
                            legacy_result.raw_response,
                        )
                        controls.append(
                            {"transport": "legacy", "started_at": legacy_started}
                        )
                        context("cadence-observation-after-legacy")
                        third = await cadence_observer.wait_for_next(
                            after_count=before_count,
                            digest=cadence.second.original_sha256,
                            timeout_seconds=(
                                cadence.interval_seconds
                                + config.cadence_boundary_tolerance_seconds
                            ),
                        )
                        if third is None:
                            reason = "no-52-byte-observation-after-legacy"
                        elif not _cadence_interval_is_valid(
                            cadence.second,
                            third,
                            cadence,
                            config,
                        ):
                            cadence_observations.append(_cadence_observation(third))
                            reason = "52-byte-cadence-not-sustained-after-legacy"
                        else:
                            cadence_observations.append(_cadence_observation(third))
                            await _sleep_until(
                                third.monotonic_seconds + config.control_offset_seconds
                            )
                            context("ngiot-get-mi-action")
                            before_count = len(cadence_observer.observations)
                            ngiot_started = datetime.now(UTC).isoformat()
                            await ngiot.call("getMI", {"type": "0"})
                            controls.append(
                                {"transport": "ngiot", "started_at": ngiot_started}
                            )
                            context("cadence-observation-after-ngiot")
                            fourth = await cadence_observer.wait_for_next(
                                after_count=before_count,
                                digest=third.original_sha256,
                                timeout_seconds=(
                                    cadence.interval_seconds
                                    + config.cadence_boundary_tolerance_seconds
                                ),
                            )
                            if fourth is None:
                                reason = "no-52-byte-observation-after-ngiot"
                            elif not _cadence_interval_is_valid(
                                third,
                                fourth,
                                cadence,
                                config,
                            ):
                                cadence_observations.append(
                                    _cadence_observation(fourth)
                                )
                                reason = "52-byte-cadence-not-sustained-after-ngiot"
                            else:
                                cadence_observations.append(
                                    _cadence_observation(fourth)
                                )
                                await asyncio.sleep(config.final_event_grace_seconds)
                                status = "complete"
        finally:
            for unsubscribe in subscriptions:
                unsubscribe()
            await normal.disconnect()
            await event_bus.teardown()

        report = recorder.report()
        report["experiment"] = {
            **asdict(config),
            "capture_mode": "repeatability",
            "mqtt": "normal-mq",
            "jmq": "none",
            "appping_count": 1,
            "get_mi_sequence": [item["transport"] for item in controls],
            "map_edit_actions": [],
            "official_app_required_closed": True,
            "payload_decoding": False,
            "representation_layer_use": "strict-base64-short-form-detection-only",
        }
        report["repeatability_run"] = {
            "status": status,
            "inconclusive_reason": reason,
            "presence_started": presence_started_monotonic is not None,
            "appping_started_at": appping_started_at,
            "presence_established_at": presence_established_at,
            "cadence_anchor_at": cadence_anchor_at,
            "cadence_seconds": cadence_seconds,
            "cadence_observations": cadence_observations,
            "controls": controls,
            "opaque_payload_interpretation": False,
        }
        return report


def _cadence_observation(observation: ShortFormObservation) -> dict[str, Any]:
    return {
        "timestamp": observation.observed_at,
        "representation_length": 52,
        "representation_sha256": observation.original_sha256,
    }


def _cadence_interval_is_valid(
    before: ShortFormObservation,
    after: ShortFormObservation,
    cadence: EstablishedCadence,
    config: RepeatabilityConfig,
) -> bool:
    observed = after.monotonic_seconds - before.monotonic_seconds
    return (
        config.cadence_min_seconds <= observed <= config.cadence_max_seconds
        and abs(observed - cadence.interval_seconds)
        <= config.cadence_boundary_tolerance_seconds
    )


async def _sleep_until(monotonic_deadline: float) -> None:
    delay = monotonic_deadline - asyncio.get_running_loop().time()
    if delay > 0:
        await asyncio.sleep(delay)


class GoatMapFrontendReloadAttributionExperiment:
    """Observe an external UI trigger without issuing control commands."""

    def __init__(
        self,
        *,
        authenticator: Authenticator,
        device_info: DeviceInfo,
        device_id: str,
        country: str,
        writer: GoatMapCaptureWriter,
    ) -> None:
        self._authenticator = authenticator
        self._device_info = device_info
        self._device_id = device_id
        self._country = country
        self._writer = writer

    async def run(
        self,
        config: FrontendReloadAttributionConfig,
        *,
        arm_reload: Callable[[], Awaitable[None]],
        announce_reload_window: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Run a passive baseline followed by a marked external-trigger window."""
        trigger = _ATTRIBUTION_TRIGGER_METADATA[config.trigger]
        recorder = MqttTrafficRecorder(
            phase=config.phase,
            mower_state=config.mower_state,
        )
        observer = CombinedMqttObserver(
            recorder.observer("mq"),
            GoatMapCaptureObserver(self._writer),
        )
        normal = MqttClient(
            create_mqtt_config(device_id=self._device_id, country=self._country),
            self._authenticator,
            observer=observer,
        )

        async def no_command(_: Command) -> dict[str, Any]:
            return {}

        event_bus = EventBus(no_command, self._device_info.static.capabilities)
        subscriptions: list[Callable[[], None]] = []

        def current_state() -> MowerState:
            return (
                MowerState(recorder.records[-1].mower_state)
                if recorder.records
                else config.mower_state
            )

        def context(label: str) -> str:
            phase = f"{config.phase}:{label}"
            state = current_state()
            recorder.set_context(phase, state)
            self._writer.set_context(phase, state)
            return phase

        async def on_state(event: StateEvent) -> None:
            state = _capture_state(event.state)
            recorder.record_mower_state(state, "mqtt-state")
            self._writer.set_context(recorder.records[-1].phase, state)

        subscriptions.append(event_bus.subscribe(StateEvent, on_state))

        def handle_known_message(name: str, payload: str | bytes | bytearray) -> None:
            if message := get_message(name, self._device_info.static):
                message.handle(event_bus, payload)

        reload_phase = f"{config.phase}:{trigger['window_label']}"
        try:
            subscriptions.append(
                await normal.subscribe(
                    SubscriberInfo(self._device_info, event_bus, handle_known_message)
                )
            )
            await recorder.wait_connected("mq", config.connect_timeout)

            context("baseline")
            recorder.record_window("started")
            await asyncio.sleep(config.baseline_seconds)
            recorder.record_window("ended")

            context(f"awaiting-{config.trigger}")
            await arm_reload()

            reload_phase = context(trigger["window_label"])
            recorder.record_window("started")
            reload_started_at = recorder.records[-1].observed_at
            if announce_reload_window is not None:
                announce_reload_window(reload_started_at)
            await asyncio.sleep(config.reload_window_seconds)
            recorder.record_window("ended")
        finally:
            for unsubscribe in subscriptions:
                unsubscribe()
            await normal.disconnect()
            await event_bus.teardown()

        report = recorder.report()
        report["experiment"] = {
            **asdict(config),
            "capture_mode": trigger["capture_mode"],
            "mqtt": "normal-mq",
            "jmq": "none",
            "diagnostic_control_actions": [],
            "payload_decoding": False,
            "reload_window": reload_phase,
        }
        report[trigger["report_key"]] = summarize_frontend_reload_window(
            recorder.records,
            reload_phase,
            trigger=config.trigger,
        )
        return report


class GoatMapPollerIsolationExperiment:
    """Observe normal MQ quietly without issuing any device-control call."""

    def __init__(
        self,
        *,
        authenticator: Authenticator,
        device_info: DeviceInfo,
        device_id: str,
        country: str,
        writer: GoatMapCaptureWriter,
    ) -> None:
        self._authenticator = authenticator
        self._device_info = device_info
        self._device_id = device_id
        self._country = country
        self._writer = writer

    async def run(self, config: PollerIsolationConfig) -> dict[str, Any]:
        """Run one uninterrupted passive quiet window on normal MQ."""
        recorder = MqttTrafficRecorder(
            phase=config.phase,
            mower_state=config.mower_state,
        )
        normal = MqttClient(
            create_mqtt_config(device_id=self._device_id, country=self._country),
            self._authenticator,
            observer=recorder.observer("mq"),
        )

        async def no_command(_: Command) -> dict[str, Any]:
            return {}

        event_bus = EventBus(no_command, self._device_info.static.capabilities)
        subscriptions: list[Callable[[], None]] = []

        async def on_state(event: StateEvent) -> None:
            state = _capture_state(event.state)
            recorder.record_mower_state(state, "mqtt-state")
            self._writer.set_context(recorder.records[-1].phase, state)

        subscriptions.append(event_bus.subscribe(StateEvent, on_state))

        def handle_known_message(name: str, payload: str | bytes | bytearray) -> None:
            if message := get_message(name, self._device_info.static):
                message.handle(event_bus, payload)

        quiet_phase = f"{config.phase}:quiet-observation"
        try:
            subscriptions.append(
                await normal.subscribe(
                    SubscriberInfo(self._device_info, event_bus, handle_known_message)
                )
            )
            await recorder.wait_connected("mq", config.connect_timeout)
            recorder.set_context(quiet_phase, config.mower_state)
            self._writer.set_context(quiet_phase, config.mower_state)
            recorder.record_window("started")
            await asyncio.sleep(config.quiet_seconds)
            recorder.record_window("ended")
        finally:
            for unsubscribe in subscriptions:
                unsubscribe()
            await normal.disconnect()
            await event_bus.teardown()

        report = recorder.report()
        report["experiment"] = {
            **asdict(config),
            "capture_mode": "poller-isolation",
            "mqtt": "normal-mq",
            "jmq": "none",
            "diagnostic_control_actions": [],
            "app_open_during_quiet_window": False,
            "payload_decoding": False,
            "quiet_window": quiet_phase,
        }
        report["poller_isolation"] = summarize_poller_isolation_window(
            recorder.records,
            quiet_phase,
        )
        return report


class GoatMapZoneAbsentReadbackExperiment:
    """Passively capture an app-triggered SpecialContour absent-state readback."""

    def __init__(
        self,
        *,
        authenticator: Authenticator,
        device_info: DeviceInfo,
        device_id: str,
        country: str,
        writer: GoatMapCaptureWriter,
    ) -> None:
        self._authenticator = authenticator
        self._device_info = device_info
        self._device_id = device_id
        self._country = country
        self._writer = writer

    async def run(
        self,
        config: ZoneAbsentReadbackConfig,
        *,
        arm_app_open: Callable[[], Awaitable[None]],
        announce_readback_window: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Observe normal MQ without issuing any diagnostic control command."""
        recorder = MqttTrafficRecorder(
            phase=config.phase,
            mower_state=config.mower_state,
        )
        observer = CombinedMqttObserver(
            recorder.observer("mq"),
            GoatMapCaptureObserver(self._writer),
        )
        normal = MqttClient(
            create_mqtt_config(device_id=self._device_id, country=self._country),
            self._authenticator,
            observer=observer,
        )

        async def no_command(_: Command) -> dict[str, Any]:
            return {}

        event_bus = EventBus(no_command, self._device_info.static.capabilities)
        subscriptions: list[Callable[[], None]] = []

        def current_state() -> MowerState:
            return (
                MowerState(recorder.records[-1].mower_state)
                if recorder.records
                else config.mower_state
            )

        def context(label: str) -> str:
            phase = f"{config.phase}:{label}"
            state = current_state()
            recorder.set_context(phase, state)
            self._writer.set_context(phase, state)
            return phase

        async def on_state(event: StateEvent) -> None:
            state = _capture_state(event.state)
            recorder.record_mower_state(state, "mqtt-state")
            self._writer.set_context(recorder.records[-1].phase, state)

        subscriptions.append(event_bus.subscribe(StateEvent, on_state))

        def handle_known_message(name: str, payload: str | bytes | bytearray) -> None:
            if message := get_message(name, self._device_info.static):
                message.handle(event_bus, payload)

        readback_phase = f"{config.phase}:zone-absent-readback"
        try:
            subscriptions.append(
                await normal.subscribe(
                    SubscriberInfo(self._device_info, event_bus, handle_known_message)
                )
            )
            await recorder.wait_connected("mq", config.connect_timeout)

            context("baseline")
            recorder.record_window("started")
            await asyncio.sleep(config.baseline_seconds)
            recorder.record_window("ended")

            context("awaiting-official-app-map-open")
            await arm_app_open()

            readback_phase = context("zone-absent-readback")
            recorder.record_window("started")
            readback_started_at = recorder.records[-1].observed_at
            if announce_readback_window is not None:
                announce_readback_window(readback_started_at)
            await asyncio.sleep(config.readback_seconds)
            recorder.record_window("ended")
        finally:
            for unsubscribe in subscriptions:
                unsubscribe()
            await normal.disconnect()
            await event_bus.teardown()

        report = recorder.report()
        report["experiment"] = {
            **asdict(config),
            "capture_mode": "zone-absent-readback",
            "external_trigger": "official-ecovacs-app-map-open",
            "mqtt": "normal-mq",
            "jmq": "none",
            "diagnostic_control_actions": [],
            "payload_decoding": False,
            "readback_window": readback_phase,
        }
        report["zone_absent_readback"] = summarize_zone_absent_readback(
            recorder.records,
            readback_phase,
        )
        return report


class GoatMapControlledMapEditExperiment:
    """Passively retain one marked official-app map-edit traffic window."""

    def __init__(
        self,
        *,
        authenticator: Authenticator,
        device_info: DeviceInfo,
        device_id: str,
        country: str,
        writer: GoatMapCaptureWriter,
    ) -> None:
        self._authenticator = authenticator
        self._device_info = device_info
        self._device_id = device_id
        self._country = country
        self._writer = writer

    async def run(
        self,
        config: ControlledMapEditConfig,
        *,
        arm_edit: Callable[[], Awaitable[None]],
        confirm_save: Callable[[], Awaitable[None]],
        announce_edit_window: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Observe baseline, edit/save marker, and a fixed post-save tail."""
        recorder = MqttTrafficRecorder(
            phase=config.phase,
            mower_state=config.mower_state,
        )
        observer = CombinedMqttObserver(
            recorder.observer("mq"),
            GoatMapCaptureObserver(self._writer),
        )
        normal = MqttClient(
            create_mqtt_config(device_id=self._device_id, country=self._country),
            self._authenticator,
            observer=observer,
        )

        async def no_command(_: Command) -> dict[str, Any]:
            return {}

        event_bus = EventBus(no_command, self._device_info.static.capabilities)
        subscriptions: list[Callable[[], None]] = []

        def current_state() -> MowerState:
            return (
                MowerState(recorder.records[-1].mower_state)
                if recorder.records
                else config.mower_state
            )

        def context(label: str) -> str:
            phase = f"{config.phase}:{label}"
            state = current_state()
            recorder.set_context(phase, state)
            self._writer.set_context(phase, state)
            return phase

        async def on_state(event: StateEvent) -> None:
            state = _capture_state(event.state)
            recorder.record_mower_state(state, "mqtt-state")
            self._writer.set_context(recorder.records[-1].phase, state)

        subscriptions.append(event_bus.subscribe(StateEvent, on_state))

        def handle_known_message(name: str, payload: str | bytes | bytearray) -> None:
            if message := get_message(name, self._device_info.static):
                message.handle(event_bus, payload)

        edit_phase = f"{config.phase}:controlled-map-edit"
        try:
            subscriptions.append(
                await normal.subscribe(
                    SubscriberInfo(self._device_info, event_bus, handle_known_message)
                )
            )
            await recorder.wait_connected("mq", config.connect_timeout)

            context("baseline")
            recorder.record_window("started")
            await asyncio.sleep(config.baseline_seconds)
            recorder.record_window("ended")

            context("awaiting-controlled-map-edit")
            await arm_edit()

            edit_phase = context("controlled-map-edit")
            recorder.record_window("started")
            recorder.record_map_edit_marker("edit-window-started")
            edit_started_at = recorder.records[-1].observed_at
            if announce_edit_window is not None:
                announce_edit_window(edit_started_at)

            await confirm_save()
            recorder.record_map_edit_marker("save-confirmed")
            await asyncio.sleep(config.post_save_seconds)
            recorder.record_map_edit_marker("edit-window-ended")
            recorder.record_window("ended")
        finally:
            for unsubscribe in subscriptions:
                unsubscribe()
            await normal.disconnect()
            await event_bus.teardown()

        report = recorder.report()
        report["experiment"] = {
            **asdict(config),
            "capture_mode": "controlled-map-edit",
            "mqtt": "normal-mq",
            "jmq": "none",
            "diagnostic_control_actions": [],
            "payload_decoding": False,
            "edit_window": edit_phase,
        }
        report["controlled_map_edit"] = summarize_controlled_map_edit_window(
            recorder.records,
            edit_phase,
        )
        return report


class _SpecialContourTransitionObserver(MqttObserver):
    """Move subsequent records at the first observed setSpecialContour request."""

    def __init__(
        self,
        recorder: MqttTrafficRecorder,
        writer: GoatMapCaptureWriter,
        post_delete_phase: str,
        current_state: Callable[[], MowerState],
    ) -> None:
        self._recorder = recorder
        self._writer = writer
        self._post_delete_phase = post_delete_phase
        self._current_state = current_state
        self._triggered = False

    def on_connected(self, _: MqttConfiguration) -> None:
        """Ignore connection lifecycle."""

    def on_disconnected(self, _: MqttConfiguration) -> None:
        """Ignore connection lifecycle."""

    def on_message(self, _: MqttConfiguration, __: Message) -> None:
        """Use the recorder's immediately preceding MQTT record as authority."""
        if self._triggered or not self._recorder.records:
            return
        record = self._recorder.records[-1]
        if not (
            record.kind == "mqtt"
            and record.command == "setSpecialContour"
            and record.direction == "request"
        ):
            return
        self._triggered = True
        observed_at = datetime.fromisoformat(record.observed_at)
        self._recorder.record_special_contour_marker(
            "set-request-observed",
            observed_at=observed_at,
        )
        self._recorder.record_window("ended")
        state = self._current_state()
        self._recorder.set_context(self._post_delete_phase, state)
        self._writer.set_context(self._post_delete_phase, state)
        self._recorder.record_window("started")


class GoatMapSpecialContourDeleteExperiment:
    """Capture a present readback and one inverse SpecialContour deletion."""

    def __init__(
        self,
        *,
        authenticator: Authenticator,
        device_info: DeviceInfo,
        device_id: str,
        country: str,
        writer: GoatMapCaptureWriter,
    ) -> None:
        self._authenticator = authenticator
        self._device_info = device_info
        self._device_id = device_id
        self._country = country
        self._writer = writer

    async def run(  # noqa: PLR0915
        self,
        config: SpecialContourDeleteConfig,
        *,
        arm_app_open: Callable[[], Awaitable[None]],
        confirm_delete_save: Callable[[], Awaitable[None]],
        announce_present_readback: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Run network-authoritative present/delete/readback windows."""
        recorder = MqttTrafficRecorder(
            phase=config.phase,
            mower_state=config.mower_state,
        )

        def current_state() -> MowerState:
            return (
                MowerState(recorder.records[-1].mower_state)
                if recorder.records
                else config.mower_state
            )

        post_delete_phase = f"{config.phase}:post-delete-readback"
        transition = _SpecialContourTransitionObserver(
            recorder,
            self._writer,
            post_delete_phase,
            current_state,
        )
        observer = CombinedMqttObserver(
            recorder.observer("mq"),
            GoatMapCaptureObserver(self._writer),
            transition,
        )
        normal = MqttClient(
            create_mqtt_config(device_id=self._device_id, country=self._country),
            self._authenticator,
            observer=observer,
        )

        async def no_command(_: Command) -> dict[str, Any]:
            return {}

        event_bus = EventBus(no_command, self._device_info.static.capabilities)
        subscriptions: list[Callable[[], None]] = []

        def context(label: str) -> str:
            phase = f"{config.phase}:{label}"
            state = current_state()
            recorder.set_context(phase, state)
            self._writer.set_context(phase, state)
            return phase

        async def on_state(event: StateEvent) -> None:
            state = _capture_state(event.state)
            recorder.record_mower_state(state, "mqtt-state")
            self._writer.set_context(recorder.records[-1].phase, state)

        subscriptions.append(event_bus.subscribe(StateEvent, on_state))

        def handle_known_message(name: str, payload: str | bytes | bytearray) -> None:
            if message := get_message(name, self._device_info.static):
                message.handle(event_bus, payload)

        zone_present_phase = f"{config.phase}:zone-present-readback"
        delete_phase = f"{config.phase}:controlled-special-contour-delete"
        try:
            subscriptions.append(
                await normal.subscribe(
                    SubscriberInfo(self._device_info, event_bus, handle_known_message)
                )
            )
            await recorder.wait_connected("mq", config.connect_timeout)

            context("baseline")
            recorder.record_window("started")
            await asyncio.sleep(config.baseline_seconds)
            recorder.record_window("ended")

            context("awaiting-app-open")
            await arm_app_open()

            zone_present_phase = context("zone-present-readback")
            recorder.record_window("started")
            readback_start_index = len(recorder.records)
            present_readback = await _wait_for_mqtt_record(
                recorder,
                command="getSpecialContour",
                direction="response",
                after_index=readback_start_index,
                timeout_seconds=config.initial_readback_timeout,
            )
            if present_readback is None:
                raise TimeoutError(
                    "No initial getSpecialContour response; do not delete the zone"
                )
            present_at = datetime.fromisoformat(present_readback.observed_at)
            recorder.record_special_contour_marker(
                "zone-present-readback-observed",
                observed_at=present_at,
            )
            recorder.record_window("ended")
            if announce_present_readback is not None:
                announce_present_readback(present_readback.observed_at)

            delete_phase = context("controlled-special-contour-delete")
            recorder.record_window("started")
            recorder.record_special_contour_marker("delete-action-armed")
            await confirm_delete_save()
            recorder.record_special_contour_marker("manual-save-confirmed")
            await asyncio.sleep(config.post_delete_seconds)
            recorder.record_special_contour_marker("observation-ended")
            recorder.record_window("ended")
        finally:
            for unsubscribe in subscriptions:
                unsubscribe()
            await normal.disconnect()
            await event_bus.teardown()

        report = recorder.report()
        report["experiment"] = {
            **asdict(config),
            "capture_mode": "controlled-special-contour-delete",
            "mqtt": "normal-mq",
            "jmq": "none",
            "diagnostic_control_actions": [],
            "payload_decoding": False,
            "zone_present_window": zone_present_phase,
            "delete_window": delete_phase,
            "post_delete_window": post_delete_phase,
        }
        report["controlled_special_contour_delete"] = summarize_special_contour_delete(
            recorder.records,
            zone_present_phase=zone_present_phase,
            delete_phase=delete_phase,
            post_delete_phase=post_delete_phase,
        )
        return report


_ATTRIBUTION_COMMAND_PATTERN = (
    "getInfo",
    "getPos",
    "getMapTrack",
    "getMI",
    "getAreaSet",
)
_ATTRIBUTION_TRIGGER_METADATA = {
    "frontend-reload": {
        "window_label": "frontend-reload-window",
        "capture_mode": "frontend-reload-attribution",
        "report_key": "frontend_reload_attribution",
        "note": "temporally correlated with Home Assistant frontend reload",
    },
    "official-app-open": {
        "window_label": "official-app-open-window",
        "capture_mode": "official-app-open-attribution",
        "report_key": "official_app_open_attribution",
        "note": "temporally correlated with operator-triggered official Ecovacs app open",
    },
}


def summarize_poller_isolation_window(
    records: Sequence[Any],
    quiet_phase: str,
) -> dict[str, Any]:
    """Summarize passive request/response timing without source attribution."""
    markers = [
        record
        for record in records
        if record.kind == "window" and record.phase == quiet_phase
    ]
    started = next((record for record in markers if record.state == "started"), None)
    ended = next(
        (record for record in reversed(markers) if record.state == "ended"),
        None,
    )
    if started is None or ended is None:
        raise ValueError("Poller-isolation window is missing timing markers")
    started_at = datetime.fromisoformat(started.observed_at)
    ended_at = datetime.fromisoformat(ended.observed_at)
    mqtt_records = [
        record
        for record in records
        if record.kind == "mqtt"
        and record.phase == quiet_phase
        and record.command is not None
        and record.direction in {"request", "response"}
    ]
    commands: dict[str, dict[str, Any]] = {}
    for command in sorted({str(record.command) for record in mqtt_records}):
        selected = [record for record in mqtt_records if record.command == command]
        requests = [record for record in selected if record.direction == "request"]
        responses = [record for record in selected if record.direction == "response"]
        request_times = [datetime.fromisoformat(record.observed_at) for record in requests]
        intervals = [
            (after - before).total_seconds()
            for before, after in pairwise(request_times)
        ]
        commands[command] = {
            "request_count": len(requests),
            "response_count": len(responses),
            "request_observations": [
                _poller_request_timing(record, responses, started_at) for record in requests
            ],
            "response_observations": [
                {
                    "observed_at": record.observed_at,
                    "offset_seconds": (
                        datetime.fromisoformat(record.observed_at) - started_at
                    ).total_seconds(),
                }
                for record in responses
            ],
            "request_intervals_seconds": intervals,
            "periodicity": _poller_periodicity(intervals, len(requests)),
        }
    external_requests = [
        {
            "command": record.command,
            "observed_at": record.observed_at,
            "offset_seconds": (
                datetime.fromisoformat(record.observed_at) - started_at
            ).total_seconds(),
            "classification": "concurrent-external",
        }
        for record in mqtt_records
        if record.direction == "request"
    ]
    verified = not external_requests
    periodic = any(
        command["periodicity"]["approximately_360_seconds"]
        for command in commands.values()
    )
    read_only_requests = all(
        str(item["command"]).casefold().startswith("get")
        for item in external_requests
    )
    if verified:
        observation = "no-concurrent-external-requests-observed"
    elif periodic and read_only_requests:
        observation = (
            "periodic concurrent-external read-only polling, source unattributed"
        )
    elif read_only_requests:
        observation = (
            "concurrent-external read-only polling observed, source unattributed"
        )
    else:
        observation = "concurrent-external request observed, source unattributed"
    return {
        "classification": "verified-for-retry" if verified else "external-polling-observed",
        "quiet_environment_status": (
            "verified-for-retry" if verified else "not-verified-for-retry"
        ),
        "source_attribution": "unknown",
        "observation": observation,
        "window_started_at": started.observed_at,
        "window_ended_at": ended.observed_at,
        "observed_seconds": (ended_at - started_at).total_seconds(),
        "diagnostic_control_actions": [],
        "external_request_count": len(external_requests),
        "external_requests": external_requests,
        "commands": commands,
        "network_timestamps_authoritative": True,
        "request_response_pairing": "nearest-later-same-command-timing-candidate",
        "client_identity_observed": False,
        "complete_topics_retained": False,
        "source_semantics": False,
    }


def _poller_request_timing(
    request: Any,
    responses: Sequence[Any],
    started_at: datetime,
) -> dict[str, Any]:
    request_at = datetime.fromisoformat(request.observed_at)
    response = next(
        (
            item
            for item in responses
            if datetime.fromisoformat(item.observed_at) >= request_at
        ),
        None,
    )
    response_at = (
        datetime.fromisoformat(response.observed_at) if response is not None else None
    )
    return {
        "observed_at": request.observed_at,
        "offset_seconds": (request_at - started_at).total_seconds(),
        "nearest_later_response_at": (
            response.observed_at if response is not None else None
        ),
        "nearest_later_response_delta_seconds": (
            (response_at - request_at).total_seconds()
            if response_at is not None
            else None
        ),
    }


def _poller_periodicity(
    intervals: Sequence[float],
    request_count: int,
) -> dict[str, Any]:
    if request_count == 0:
        return {"status": "not-observed", "approximately_360_seconds": False}
    if not intervals:
        return {
            "status": "single-observation-insufficient",
            "approximately_360_seconds": False,
        }
    approximately_360 = all(330 <= interval <= 390 for interval in intervals)
    return {
        "status": (
            "approximately-360-second-cadence-observed"
            if approximately_360
            else "intervals-observed-without-360-second-match"
        ),
        "approximately_360_seconds": approximately_360,
        "interval_count": len(intervals),
        "minimum_seconds": min(intervals),
        "maximum_seconds": max(intervals),
    }


def summarize_frontend_reload_window(
    records: Sequence[Any],
    reload_phase: str,
    *,
    trigger: str = "frontend-reload",
) -> dict[str, Any]:
    """Summarize command timing without attributing the initiating client."""
    try:
        trigger_metadata = _ATTRIBUTION_TRIGGER_METADATA[trigger]
    except KeyError as err:
        raise ValueError("Unsupported passive attribution trigger") from err
    window_start = next(
        (
            record
            for record in records
            if record.kind == "window"
            and record.phase == reload_phase
            and record.state == "started"
        ),
        None,
    )
    if window_start is None:
        raise ValueError("Frontend reload window has no start marker")
    started_at = datetime.fromisoformat(window_start.observed_at)
    mqtt_records = [
        record
        for record in records
        if record.kind == "mqtt" and record.phase == reload_phase
    ]
    command_observations: dict[str, dict[str, Any]] = {}
    for command in _ATTRIBUTION_COMMAND_PATTERN:
        selected = [record for record in mqtt_records if record.command == command]
        command_observations[command] = {
            "count": len(selected),
            "request_count": sum(record.direction == "request" for record in selected),
            "response_count": sum(
                record.direction == "response" for record in selected
            ),
            "event_count": sum(record.direction == "event" for record in selected),
            "observations": [
                {
                    "observed_at": record.observed_at,
                    "offset_seconds": (
                        datetime.fromisoformat(record.observed_at) - started_at
                    ).total_seconds(),
                    "direction": record.direction,
                }
                for record in selected
            ],
        }

    observed = {
        command
        for command, summary in command_observations.items()
        if summary["count"] > 0
    }
    if not observed:
        pattern_result = "no-target-control-pattern"
    elif observed == set(_ATTRIBUTION_COMMAND_PATTERN):
        pattern_result = "full-pattern-observed"
    elif {"getInfo", "getPos"}.issubset(observed) and not observed.intersection(
        {"getMapTrack", "getMI", "getAreaSet"}
    ):
        pattern_result = "state-position-only"
    else:
        pattern_result = "mixed-or-incomplete"

    return {
        "classification": "concurrent-external",
        "client_source": "unattributed",
        "trigger": trigger,
        "window_label": trigger_metadata["window_label"],
        "window_started_at": window_start.observed_at,
        "note": trigger_metadata["note"],
        "diagnostic_control_actions": [],
        "pattern": list(_ATTRIBUTION_COMMAND_PATTERN),
        "pattern_result": pattern_result,
        "commands": command_observations,
        "get_area_set_count": command_observations["getAreaSet"]["count"],
        "get_area_set_request_count": command_observations["getAreaSet"][
            "request_count"
        ],
    }


_ZONE_ABSENT_TARGET_COMMANDS = (
    "getSpecialContour",
    "onSpecialContour",
    "setSpecialContour",
    "getMI",
    "onMI",
    "onArI",
    "getAreaSet",
    "onAreaSet",
    "getMapState",
    "onMapState",
    "getMapTrack",
    "onMapTrack",
)


def summarize_zone_absent_readback(
    records: Sequence[Any],
    readback_phase: str,
) -> dict[str, Any]:
    """Summarize a passive app-triggered readback without parsing payload fields."""
    window_markers = [
        record
        for record in records
        if record.kind == "window" and record.phase == readback_phase
    ]
    window_start = next(
        (record for record in window_markers if record.state == "started"),
        None,
    )
    window_end = next(
        (record for record in reversed(window_markers) if record.state == "ended"),
        None,
    )
    if window_start is None or window_end is None:
        raise ValueError("Zone-absent readback window is missing timing markers")
    started_at = datetime.fromisoformat(window_start.observed_at)
    mqtt_records = [
        record
        for record in records
        if record.kind == "mqtt"
        and record.phase == readback_phase
        and record.command is not None
    ]
    commands: dict[str, dict[str, Any]] = {}
    for command in sorted({record.command for record in mqtt_records}):
        selected = [record for record in mqtt_records if record.command == command]
        commands[command] = {
            "count": len(selected),
            "request_count": sum(record.direction == "request" for record in selected),
            "response_count": sum(
                record.direction == "response" for record in selected
            ),
            "event_count": sum(record.direction == "event" for record in selected),
            "observations": [
                {
                    "observed_at": record.observed_at,
                    "offset_seconds": (
                        datetime.fromisoformat(record.observed_at) - started_at
                    ).total_seconds(),
                    "direction": record.direction,
                    "map_ids": list(record.map_ids),
                    "mower_state": record.mower_state,
                }
                for record in selected
            ],
        }
    special_readbacks = [
        record
        for record in mqtt_records
        if (record.command == "getSpecialContour" and record.direction == "response")
        or (record.command == "onSpecialContour" and record.direction == "event")
    ]
    states = list(
        dict.fromkeys(
            record.mower_state
            for record in records
            if record.phase == readback_phase and record.mower_state
        )
    )
    empty_summary = {
        "count": 0,
        "request_count": 0,
        "response_count": 0,
        "event_count": 0,
        "observations": [],
    }
    return {
        "classification": "zone-absent-readback",
        "external_trigger": "official-ecovacs-app-map-open",
        "window_label": "zone-absent-readback",
        "window_started_at": window_start.observed_at,
        "window_ended_at": window_end.observed_at,
        "network_timestamps_authoritative": True,
        "diagnostic_control_actions": [],
        "mower_states": states,
        "special_contour_readback_count": len(special_readbacks),
        "first_special_contour_readback_at": (
            special_readbacks[0].observed_at if special_readbacks else None
        ),
        "last_special_contour_readback_at": (
            special_readbacks[-1].observed_at if special_readbacks else None
        ),
        "commands": commands,
        "target_commands": {
            command: commands.get(command, empty_summary)
            for command in _ZONE_ABSENT_TARGET_COMMANDS
        },
        "payload_decoding": False,
        "semantic_field_mapping": False,
        "interpretation_guard": (
            "Observed command timing and opaque payload representations are retained; "
            "no SpecialContour field meaning is assigned."
        ),
    }


_MAP_EDIT_TARGET_COMMANDS = (
    "getMI",
    "onMI",
    "onArI",
    "getAreaSet",
    "onAreaSet",
    "getMapState",
    "onMapState",
)


def summarize_controlled_map_edit_window(
    records: Sequence[Any],
    edit_phase: str,
) -> dict[str, Any]:
    """Summarize a marked edit without assigning meaning to payload fields."""
    markers = {
        record.state: record
        for record in records
        if record.kind == "marker"
        and record.session == "controlled-map-edit"
        and record.phase == edit_phase
    }
    required_markers = {
        "edit-window-started",
        "save-confirmed",
        "edit-window-ended",
    }
    if not required_markers.issubset(markers):
        raise ValueError("Controlled map-edit window is missing timing markers")
    started_at = datetime.fromisoformat(markers["edit-window-started"].observed_at)
    saved_at = datetime.fromisoformat(markers["save-confirmed"].observed_at)
    mqtt_records = [
        record
        for record in records
        if record.kind == "mqtt"
        and record.phase == edit_phase
        and record.command is not None
    ]
    commands: dict[str, dict[str, Any]] = {}
    for command in sorted({record.command for record in mqtt_records}):
        selected = [record for record in mqtt_records if record.command == command]
        commands[command] = {
            "count": len(selected),
            "request_count": sum(record.direction == "request" for record in selected),
            "response_count": sum(
                record.direction == "response" for record in selected
            ),
            "event_count": sum(record.direction == "event" for record in selected),
            "observations": [
                {
                    "observed_at": record.observed_at,
                    "direction": record.direction,
                    "offset_from_window_start_seconds": (
                        datetime.fromisoformat(record.observed_at) - started_at
                    ).total_seconds(),
                    "offset_from_save_confirm_seconds": (
                        datetime.fromisoformat(record.observed_at) - saved_at
                    ).total_seconds(),
                    "map_ids": list(record.map_ids),
                }
                for record in selected
            ],
        }
    name_based_map_events = sorted(
        {
            record.command
            for record in mqtt_records
            if record.direction == "event"
            and (
                "map" in record.command.casefold()
                or "area" in record.command.casefold()
                or record.command in {"onMI", "onArI"}
            )
        }
    )
    return {
        "classification": "controlled-map-edit",
        "window_label": "controlled-map-edit",
        "window_started_at": markers["edit-window-started"].observed_at,
        "save_confirmed_at": markers["save-confirmed"].observed_at,
        "window_ended_at": markers["edit-window-ended"].observed_at,
        "save_offset_seconds": (saved_at - started_at).total_seconds(),
        "diagnostic_control_actions": [],
        "commands": commands,
        "target_commands": {
            command: commands.get(
                command,
                {
                    "count": 0,
                    "request_count": 0,
                    "response_count": 0,
                    "event_count": 0,
                    "observations": [],
                },
            )
            for command in _MAP_EDIT_TARGET_COMMANDS
        },
        "name_based_map_event_candidates": name_based_map_events,
        "interpretation_guard": (
            "Command names and timing are observed; payload fields remain opaque."
        ),
    }


def summarize_special_contour_delete(
    records: Sequence[Any],
    *,
    zone_present_phase: str,
    delete_phase: str,
    post_delete_phase: str,
) -> dict[str, Any]:
    """Summarize network-authoritative SpecialContour deletion timing."""
    markers = {
        record.state: record
        for record in records
        if record.kind == "marker"
        and record.session == "controlled-special-contour-delete"
    }
    required_markers = {
        "zone-present-readback-observed",
        "delete-action-armed",
        "manual-save-confirmed",
        "observation-ended",
    }
    if not required_markers.issubset(markers):
        raise ValueError("SpecialContour deletion is missing operator markers")
    delete_armed_at = datetime.fromisoformat(markers["delete-action-armed"].observed_at)
    special_records = [
        record
        for record in records
        if record.kind == "mqtt"
        and record.command
        in {"getSpecialContour", "onSpecialContour", "setSpecialContour"}
    ]
    set_request = next(
        (
            record
            for record in special_records
            if record.command == "setSpecialContour"
            and record.direction == "request"
            and datetime.fromisoformat(record.observed_at) >= delete_armed_at
        ),
        None,
    )
    set_at = (
        datetime.fromisoformat(set_request.observed_at)
        if set_request is not None
        else None
    )
    present_readbacks = [
        record
        for record in special_records
        if record.phase == zone_present_phase
        and record.command == "getSpecialContour"
        and record.direction == "response"
    ]
    post_delete_readbacks = [
        record
        for record in special_records
        if set_at is not None
        and record.command == "getSpecialContour"
        and record.direction == "response"
        and datetime.fromisoformat(record.observed_at) > set_at
    ]
    observations = [
        {
            "observed_at": record.observed_at,
            "phase": record.phase,
            "command": record.command,
            "direction": record.direction,
            "map_ids": list(record.map_ids),
            "offset_from_set_request_seconds": (
                (datetime.fromisoformat(record.observed_at) - set_at).total_seconds()
                if set_at is not None
                else None
            ),
        }
        for record in special_records
    ]
    manual_at = datetime.fromisoformat(markers["manual-save-confirmed"].observed_at)
    return {
        "classification": "controlled-special-contour-delete",
        "zone_present_window": zone_present_phase,
        "delete_window": delete_phase,
        "post_delete_window": post_delete_phase,
        "network_timestamps_authoritative": True,
        "manual_marker_is_operator_context_only": True,
        "zone_present_readback_at": markers[
            "zone-present-readback-observed"
        ].observed_at,
        "set_request_at": set_request.observed_at if set_request is not None else None,
        "manual_save_confirmed_at": markers["manual-save-confirmed"].observed_at,
        "manual_save_offset_from_set_request_seconds": (
            (manual_at - set_at).total_seconds() if set_at is not None else None
        ),
        "observation_ended_at": markers["observation-ended"].observed_at,
        "zone_present_readback_count": len(present_readbacks),
        "post_delete_readback_count": len(post_delete_readbacks),
        "reversible_readback_pair_observed": bool(
            present_readbacks and post_delete_readbacks
        ),
        "network_sequence": observations,
        "diagnostic_control_actions": [],
        "semantic_parsing": False,
        "interpretation_guard": (
            "The create/delete relationship applies to the controlled operation; "
            "opaque fields retain no assigned meaning."
        ),
    }


async def _wait_for_mqtt_record(
    recorder: MqttTrafficRecorder,
    *,
    command: str,
    direction: str,
    after_index: int,
    timeout_seconds: float,
) -> Any | None:
    try:
        async with asyncio.timeout(timeout_seconds):
            while True:
                if selected := next(
                    (
                        record
                        for record in recorder.records[after_index:]
                        if record.kind == "mqtt"
                        and record.command == command
                        and record.direction == direction
                    ),
                    None,
                ):
                    return selected
                await asyncio.sleep(0.1)
    except TimeoutError:
        return None


async def _wait_for_mqtt_command(
    recorder: MqttTrafficRecorder,
    command: str,
    *,
    after_index: int,
    timeout_seconds: float,
) -> None:
    async with asyncio.timeout(timeout_seconds):
        while True:
            if any(
                record.command == command for record in recorder.records[after_index:]
            ):
                return
            await asyncio.sleep(0.1)


def _capture_state(state: State) -> MowerState:
    return {
        State.DOCKED: MowerState.DOCKED,
        State.IDLE: MowerState.IDLE,
        State.CLEANING: MowerState.MOWING,
        State.PAUSED: MowerState.PAUSED,
        State.RETURNING: MowerState.RETURNING,
    }.get(state, MowerState.UNKNOWN)
