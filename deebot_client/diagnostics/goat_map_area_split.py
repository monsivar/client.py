"""Passive controlled Area split capture and metadata-only comparison."""

from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import orjson

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

from .goat_map_area_merge import (
    AreaMergeReference,
    add_area_merge_restoration_analysis,
    evaluate_area_merge_preconditions,
    load_area_merge_reference,
    load_pre_merge_reference,
)
from .goat_map_area_noop_save import (
    AreaNoOpSaveReference,
    evaluate_area_noop_save_preconditions,
    load_area_noop_save_reference,
)
from .goat_map_area_rename import (
    AreaRenameReference,
    add_area_rename_analysis,
    evaluate_area_rename_preconditions,
    load_area_rename_reference,
)
from .goat_map_area_rename_restore import (
    AreaRenameRestoreReference,
    evaluate_area_rename_restore_preconditions,
    load_area_rename_restore_reference,
)
from .goat_map_area_same_name import evaluate_area_same_name_preconditions
from .goat_map_capture import (
    CombinedMqttObserver,
    GoatMapCaptureObserver,
    GoatMapCaptureWriter,
)
from .goat_map_inner_structure_view import recognize_inner_structure
from .goat_map_refresh import MowerState, MqttTrafficRecorder, TrafficRecord
from .goat_map_representation import preserve_onmi_info_representation
from .goat_map_segment_grouping import (
    OpaqueSegmentInput,
    SegmentGroupingError,
    assemble_opaque_segment_set,
    normalize_segment_cardinality,
)
from .goat_map_structural_header import (
    StructuralHeaderError,
    recognize_structural_header,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from aiomqtt import Message

    from deebot_client.authentication import Authenticator
    from deebot_client.command import Command
    from deebot_client.models import DeviceInfo

type ComparisonStatus = Literal[
    "unchanged",
    "occurrence-count-changed",
    "value-changed",
    "before-only",
    "after-only",
]

_REQUEST_ASSOCIATION_SECONDS = 10.0
_OPAQUE_COMMON_BODY_LENGTH = 668
_MAP_WRITE_HINTS = (
    "area",
    "boundary",
    "contour",
    "divide",
    "map",
    "merge",
    "name",
    "rename",
    "save",
    "split",
    "zone",
)


class AreaSplitState(StrEnum):
    """Explicit states for one passive controlled split workflow."""

    PRE_SPLIT_BASELINE = "pre-split-baseline"
    PRE_SPLIT_APP_INIT_1 = "pre-split-app-init-1"
    PRE_SPLIT_APP_INIT_QUIET = "pre-split-app-init-quiet"
    PRE_SPLIT_APP_INIT_2 = "pre-split-app-init-2"
    PRECONDITION_EVALUATION = "precondition-evaluation"
    SPLIT_EDIT = "split-edit"
    SPLIT_SAVE = "split-save"
    POST_SPLIT_READBACK = "post-split-readback"
    POST_SPLIT_REOPEN = "post-split-reopen"
    INCONCLUSIVE = "inconclusive"
    COMPLETED = "completed"


class AreaSplitWorkflowError(ValueError):
    """The requested state transition violates the controlled workflow."""


class AreaSplitGateClosedError(AreaSplitWorkflowError):
    """The edit state was requested before the precondition gate passed."""


_ALLOWED_TRANSITIONS: dict[AreaSplitState | None, frozenset[AreaSplitState]] = {
    None: frozenset({AreaSplitState.PRE_SPLIT_BASELINE}),
    AreaSplitState.PRE_SPLIT_BASELINE: frozenset({AreaSplitState.PRE_SPLIT_APP_INIT_1}),
    AreaSplitState.PRE_SPLIT_APP_INIT_1: frozenset(
        {AreaSplitState.PRE_SPLIT_APP_INIT_QUIET}
    ),
    AreaSplitState.PRE_SPLIT_APP_INIT_QUIET: frozenset(
        {AreaSplitState.PRE_SPLIT_APP_INIT_2}
    ),
    AreaSplitState.PRE_SPLIT_APP_INIT_2: frozenset(
        {AreaSplitState.PRECONDITION_EVALUATION}
    ),
    AreaSplitState.PRECONDITION_EVALUATION: frozenset(
        {
            AreaSplitState.SPLIT_EDIT,
            AreaSplitState.INCONCLUSIVE,
            AreaSplitState.COMPLETED,
        }
    ),
    AreaSplitState.SPLIT_EDIT: frozenset(
        {AreaSplitState.SPLIT_SAVE, AreaSplitState.INCONCLUSIVE}
    ),
    AreaSplitState.SPLIT_SAVE: frozenset({AreaSplitState.POST_SPLIT_READBACK}),
    AreaSplitState.POST_SPLIT_READBACK: frozenset(
        {AreaSplitState.POST_SPLIT_REOPEN, AreaSplitState.COMPLETED}
    ),
    AreaSplitState.POST_SPLIT_REOPEN: frozenset({AreaSplitState.COMPLETED}),
    AreaSplitState.INCONCLUSIVE: frozenset(),
    AreaSplitState.COMPLETED: frozenset(),
}


@dataclass(frozen=True, kw_only=True)
class AreaSplitCaptureConfig:
    """Bounded timing and state settings for one passive Area split."""

    phase: str = "p2-09-controlled-area-split"
    mower_state: MowerState = MowerState.PAUSED
    baseline_seconds: float = 30
    app_init_seconds: float = 45
    between_init_quiet_seconds: float = 10
    post_split_seconds: float = 150
    post_split_reopen: bool = False
    post_reopen_seconds: float = 60
    connect_timeout: float = 30
    operation: Literal[
        "split", "merge", "rename", "noop-save", "same-name-resubmission"
    ] = "split"
    reference_artifact_dir: str | None = None
    expected_reference_capture_id: str | None = None
    divide_reference_artifact_dir: str | None = None
    expected_divide_reference_capture_id: str | None = None
    old_name_utf8_byte_length: int | None = None
    new_name_utf8_byte_length: int | None = None
    rename_restore: bool = False
    post_merge_recovery: bool = False
    pre_merge_artifact_dir: str | None = None
    expected_pre_merge_capture_id: str | None = None

    def __post_init__(self) -> None:  # noqa: C901, PLR0912
        operation_label = self.operation
        if self.mower_state is not MowerState.PAUSED:
            message = f"Controlled Area {operation_label} requires a paused mower"
            raise ValueError(message)
        if self.operation in {
            "merge",
            "rename",
            "noop-save",
            "same-name-resubmission",
        } and (
            not self.reference_artifact_dir or not self.expected_reference_capture_id
        ):
            message = (
                f"Controlled Area {self.operation} requires an immutable "
                "reference artifact"
            )
            raise ValueError(message)
        if self.operation == "rename" and (
            not self.divide_reference_artifact_dir
            or not self.expected_divide_reference_capture_id
        ):
            raise ValueError("Controlled Area rename requires the Divide write reference")
        if self.operation == "rename" and (
            self.old_name_utf8_byte_length is None
            or self.new_name_utf8_byte_length is None
            or self.old_name_utf8_byte_length <= 0
            or self.new_name_utf8_byte_length <= 0
        ):
            raise ValueError("Controlled Area rename requires positive UTF-8 name lengths")
        if self.operation == "rename" and not self.post_split_reopen:
            raise ValueError("Controlled Area rename requires a post-save reopen")
        if self.operation == "noop-save" and not self.post_split_reopen:
            raise ValueError("Controlled Area no-op Save requires a post-save reopen")
        if self.operation == "same-name-resubmission" and not self.post_split_reopen:
            raise ValueError("Same-name resubmission requires a post-save reopen")
        if self.operation == "same-name-resubmission" and (
            self.old_name_utf8_byte_length != 5
            or self.new_name_utf8_byte_length != 5
        ):
            raise ValueError("P2-13b same-name resubmission requires two five-byte names")
        if self.rename_restore and self.operation != "rename":
            raise ValueError("Area rename restore requires operation=rename")
        if self.rename_restore and (
            self.old_name_utf8_byte_length != 5
            or self.new_name_utf8_byte_length != 5
        ):
            raise ValueError("P2-12 rename restore requires two five-byte names")
        if self.post_merge_recovery and (
            self.operation != "merge"
            or not self.pre_merge_artifact_dir
            or not self.expected_pre_merge_capture_id
        ):
            raise ValueError(
                "Post-merge recovery requires an immutable pre-merge artifact"
            )
        if not 30 <= self.baseline_seconds <= 60:
            raise ValueError("Area split baseline must be between 30 and 60 seconds")
        if not 30 <= self.app_init_seconds <= 120:
            raise ValueError("App-init windows must be between 30 and 120 seconds")
        if not 5 <= self.between_init_quiet_seconds <= 60:
            raise ValueError("Between-init quiet time must be between 5 and 60 seconds")
        if not 120 <= self.post_split_seconds <= 180:
            raise ValueError("Post-split readback must be between 120 and 180 seconds")
        if not 30 <= self.post_reopen_seconds <= 120:
            raise ValueError("Post-split reopen must be between 30 and 120 seconds")
        if self.connect_timeout <= 0:
            raise ValueError("Connection timeout must be positive")


class AreaSplitStateMachine:
    """Pure transition guard; timing is metadata and never a parsing input."""

    def __init__(self, *, now: Callable[[], datetime] | None = None) -> None:
        self._state: AreaSplitState | None = None
        self._history: list[dict[str, str]] = []
        self._now = now or _utc_now

    @property
    def state(self) -> AreaSplitState | None:
        """Return the current workflow state."""
        return self._state

    @property
    def history(self) -> tuple[dict[str, str], ...]:
        """Return an immutable copy of state transitions."""
        return tuple(dict(item) for item in self._history)

    def transition(
        self,
        target: AreaSplitState,
        *,
        precondition_status: str | None = None,
    ) -> None:
        """Advance only through the documented graph and enforce the edit gate."""
        if target not in _ALLOWED_TRANSITIONS[self._state]:
            message = f"Invalid Area split transition: {self._state} -> {target}"
            raise AreaSplitWorkflowError(message)
        if target is AreaSplitState.SPLIT_EDIT and precondition_status != "passed":
            raise AreaSplitGateClosedError(
                "Split edit requires an explicitly passed precondition evaluation"
            )
        previous = self._state.value if self._state is not None else "initial"
        self._state = target
        self._history.append(
            {
                "from": previous,
                "to": target.value,
                "observed_at": self._now().astimezone(UTC).isoformat(),
            }
        )


@dataclass(frozen=True, slots=True)
class _OnMiEvidence:
    observed_at: str
    window: str
    association: str
    mid: str
    info_size: int | None
    original_length: int
    original_sha256: str
    derived_length: int
    derived_sha256: str
    context_signature_hex: str | None
    observed_context_class: str | None
    opaque_remainder_length: int | None
    opaque_remainder_sha256: str | None
    structural_error: str | None


@dataclass(frozen=True, slots=True)
class _AreaSetEvidence:
    observed_at: str
    window: str
    mid: str
    aid: str
    type: str
    info_size: int | None
    subsets_length: int
    subsets_sha256: str


@dataclass(frozen=True, slots=True)
class _OnAriSegmentEvidence:
    observed_at: str
    window: str
    segment: OpaqueSegmentInput


class AreaSplitEvidenceObserver(MqttObserver):
    """Keep only in-memory structural evidence needed by gate/comparison."""

    def __init__(
        self,
        current_window: Callable[[], str],
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._current_window = current_window
        self._now = now or _utc_now
        self._get_mi_requests: dict[str, list[datetime]] = defaultdict(list)
        self._on_mi: list[_OnMiEvidence] = []
        self._area_set: list[_AreaSetEvidence] = []
        self._on_ari: list[_OnAriSegmentEvidence] = []
        self._errors: list[dict[str, str]] = []

    def on_connected(self, _: MqttConfiguration) -> None:
        """Leave connection lifecycle to the independent recorder."""

    def on_disconnected(self, _: MqttConfiguration) -> None:
        """Leave connection lifecycle to the independent recorder."""

    def on_message(self, _: MqttConfiguration, message: Message) -> None:
        """Observe one payload without persisting it."""
        self.observe_mqtt(message.topic.value, message.payload)

    def observe_mqtt(
        self,
        topic: str,
        payload: str | bytes | bytearray,
        *,
        observed_at: datetime | None = None,
    ) -> None:
        """Pure-testable MQTT ingestion with bounded structural extraction."""
        command, direction = _topic_details(topic)
        window = self._current_window()
        timestamp = (observed_at or self._now()).astimezone(UTC)
        if command == "getMI" and direction == "request":
            self._get_mi_requests[window].append(timestamp)
            return
        if command not in {"onMI", "onArI", "getAreaSet"}:
            return
        try:
            parsed = orjson.loads(
                payload.encode() if isinstance(payload, str) else bytes(payload)
            )
            data = _payload_data(parsed)
            if command == "onMI":
                self._observe_on_mi(data, window, timestamp)
            elif command == "onArI":
                self._observe_on_ari(data, window, timestamp)
            elif direction == "response":
                self._observe_area_set(data, window, timestamp)
        except (KeyError, TypeError, ValueError, orjson.JSONDecodeError) as err:
            self._errors.append(
                {
                    "window": window,
                    "command": command,
                    "observed_at": timestamp.isoformat(),
                    "error": type(err).__name__,
                }
            )

    def on_mi(self, windows: Sequence[str]) -> list[dict[str, Any]]:
        """Return metadata-only onMI evidence for selected windows."""
        selected = set(windows)
        return [asdict(item) for item in self._on_mi if item.window in selected]

    def area_set(self, windows: Sequence[str]) -> list[dict[str, Any]]:
        """Return metadata-only getAreaSet evidence for selected windows."""
        selected = set(windows)
        return [asdict(item) for item in self._area_set if item.window in selected]

    def complete_on_ari_sets(self, windows: Sequence[str]) -> dict[str, Any]:
        """Assemble within each window and report incomplete identities safely."""
        selected = set(windows)
        complete: list[dict[str, Any]] = []
        incomplete: list[dict[str, Any]] = []
        for window in sorted(selected):
            grouped: dict[tuple[Any, ...], list[OpaqueSegmentInput]] = defaultdict(list)
            observed_at: dict[tuple[Any, ...], list[str]] = defaultdict(list)
            for item in self._on_ari:
                if item.window != window:
                    continue
                identity = _segment_identity_tuple(item.segment)
                grouped[identity].append(item.segment)
                observed_at[identity].append(item.observed_at)
            for identity, segments in grouped.items():
                identity_digest = _identity_digest(identity)
                try:
                    assembled = assemble_opaque_segment_set(tuple(segments))
                    complete.append(
                        _assembled_on_ari_report(
                            window,
                            identity_digest,
                            observed_at[identity],
                            assembled,
                        )
                    )
                except SegmentGroupingError as err:
                    incomplete.append(
                        {
                            "window": window,
                            "identity_sha256": identity_digest,
                            "observed_at": sorted(observed_at[identity]),
                            "error": type(err).__name__,
                        }
                    )
        return {
            "complete": sorted(
                complete,
                key=lambda item: (
                    item["window"],
                    item["observed_at"][0],
                    item["identity_sha256"],
                ),
            ),
            "incomplete": sorted(
                incomplete,
                key=lambda item: (item["window"], item["identity_sha256"]),
            ),
        }

    def errors(self, windows: Sequence[str]) -> list[dict[str, str]]:
        """Return parse/representation errors without payload data."""
        selected = set(windows)
        return [dict(item) for item in self._errors if item["window"] in selected]

    def _observe_on_mi(
        self,
        data: Mapping[str, Any],
        window: str,
        timestamp: datetime,
    ) -> None:
        info = _required_string(data, "info")
        mid = _required_scalar(data, "mid")
        info_size = _optional_int(data.get("infoSize"))
        preserved = preserve_onmi_info_representation(info)
        structural_error: str | None = None
        signature: str | None = None
        context_class: str | None = None
        remainder_length: int | None = None
        remainder_digest: str | None = None
        try:
            header = recognize_structural_header(
                preserved.decoded,
                envelope_info_size=info_size,
            )
            inner = recognize_inner_structure(header)
            signature = inner.context_signature_raw.hex()
            context_class = inner.observed_context_class
            remainder_length = len(inner.remainder)
            remainder_digest = sha256(inner.remainder).hexdigest()
        except (StructuralHeaderError, ValueError) as err:
            structural_error = type(err).__name__
        association = _on_mi_association(
            timestamp,
            self._get_mi_requests[window],
            original_length=len(info.encode("ascii")),
        )
        self._on_mi.append(
            _OnMiEvidence(
                observed_at=timestamp.isoformat(),
                window=window,
                association=association,
                mid=mid,
                info_size=info_size,
                original_length=len(info.encode("ascii")),
                original_sha256=preserved.original_sha256,
                derived_length=len(preserved.decoded),
                derived_sha256=preserved.decoded_sha256,
                context_signature_hex=signature,
                observed_context_class=context_class,
                opaque_remainder_length=remainder_length,
                opaque_remainder_sha256=remainder_digest,
                structural_error=structural_error,
            )
        )

    def _observe_area_set(
        self,
        data: Mapping[str, Any],
        window: str,
        timestamp: datetime,
    ) -> None:
        subsets = _required_string(data, "subsets")
        raw = subsets.encode("utf-8")
        self._area_set.append(
            _AreaSetEvidence(
                observed_at=timestamp.isoformat(),
                window=window,
                mid=_required_scalar(data, "mid"),
                aid=_required_scalar(data, "aid"),
                type=_required_scalar(data, "type"),
                info_size=_optional_int(data.get("infoSize")),
                subsets_length=len(raw),
                subsets_sha256=sha256(raw).hexdigest(),
            )
        )

    def _observe_on_ari(
        self,
        data: Mapping[str, Any],
        window: str,
        timestamp: datetime,
    ) -> None:
        segment = OpaqueSegmentInput(
            batid=_required_string(data, "batid"),
            serial=_required_int(data, "serial"),
            index=_required_int(data, "index", allow_zero=True),
            info_size=_required_envelope_value(data, "infoSize"),
            mid=_required_envelope_value(data, "mid"),
            type=_required_envelope_value(data, "type"),
            using=_required_envelope_value(data, "using"),
            representation=_required_string(data, "info"),
        )
        self._on_ari.append(
            _OnAriSegmentEvidence(
                observed_at=timestamp.isoformat(),
                window=window,
                segment=segment,
            )
        )


def evaluate_area_split_preconditions(  # noqa: PLR0913
    evidence: AreaSplitEvidenceObserver,
    *,
    init_1_window: str,
    init_2_window: str,
    recorder_records: Sequence[TrafficRecord] = (),
    allowed_app_windows: Sequence[str] = (),
    expected_mower_state: MowerState = MowerState.PAUSED,
) -> dict[str, Any]:
    """Evaluate the fail-closed split gate without requiring identical onArI."""
    windows = (init_1_window, init_2_window)
    on_mi_by_window = {window: evidence.on_mi((window,)) for window in windows}
    area_by_window = {window: evidence.area_set((window,)) for window in windows}
    on_ari_by_window = {
        window: evidence.complete_on_ari_sets((window,)) for window in windows
    }
    failures: list[dict[str, Any]] = []

    mids = {
        window: _static_mids(
            on_mi_by_window[window],
            area_by_window[window],
            on_ari_by_window[window]["complete"],
        )
        for window in windows
    }
    same_mid = (
        len(mids[init_1_window]) == 1 and mids[init_1_window] == mids[init_2_window]
    )
    if not same_mid:
        failures.append(
            {
                "check": "same-static-map-mid",
                "reason": "missing-ambiguous-or-different-mid",
            }
        )

    on_mi_check = _comparable_on_mi_check(
        on_mi_by_window[init_1_window],
        on_mi_by_window[init_2_window],
    )
    if on_mi_check["status"] != "passed":
        failures.append({"check": "comparable-onMI", "reason": on_mi_check["reason"]})

    area_check = _same_area_set_check(
        area_by_window[init_1_window],
        area_by_window[init_2_window],
    )
    if area_check["status"] != "passed":
        failures.append({"check": "stable-getAreaSet", "reason": area_check["reason"]})

    complete_counts = {
        window: len(on_ari_by_window[window]["complete"]) for window in windows
    }
    if any(count < 1 for count in complete_counts.values()):
        failures.append(
            {
                "check": "complete-grouped-onArI",
                "reason": "one-or-both-app-init-windows-have-no-complete-set",
            }
        )

    parse_errors = {window: evidence.errors((window,)) for window in windows}
    if any(parse_errors.values()):
        failures.append(
            {
                "check": "structural-evidence-errors",
                "reason": "known-static-family-payload-could-not-be-evaluated",
            }
        )

    unexpected_controls = _unexpected_control_sequences(
        recorder_records,
        allowed_app_windows=set(allowed_app_windows),
    )
    if unexpected_controls:
        failures.append(
            {
                "check": "controlled-source-isolation",
                "reason": "possible-concurrent-external-outside-app-window",
            }
        )

    observed_states = sorted(
        {
            record.mower_state
            for record in recorder_records
            if record.kind in {"window", "state", "mqtt"}
        }
    )
    state_matches = not observed_states or observed_states == [
        expected_mower_state.value
    ]
    if not state_matches:
        failures.append(
            {
                "check": "mower-state",
                "reason": "mower-state-transition-observed-before-edit",
            }
        )

    passed = not failures
    return {
        "status": "passed" if passed else "inconclusive",
        "result": "precondition-passed" if passed else "precondition-failed",
        "split_edit_gate_open": passed,
        "checks": {
            "same_static_map_mid": {
                "status": "passed" if same_mid else "failed",
                "values": mids,
            },
            "comparable_onMI": on_mi_check,
            "stable_getAreaSet": area_check,
            "complete_grouped_onArI": {
                "status": (
                    "passed"
                    if all(count >= 1 for count in complete_counts.values())
                    else "failed"
                ),
                "complete_set_counts": complete_counts,
                "incomplete_set_counts": {
                    window: len(on_ari_by_window[window]["incomplete"])
                    for window in windows
                },
                "byte_identity_required": False,
            },
            "structural_evidence_errors": parse_errors,
            "controlled_source_isolation": {
                "status": "passed" if not unexpected_controls else "failed",
                "unexpected_sequences": unexpected_controls,
                "classification": (
                    None if not unexpected_controls else "concurrent-external"
                ),
            },
            "mower_state": {
                "status": "passed" if state_matches else "failed",
                "expected": expected_mower_state.value,
                "observed": observed_states,
            },
        },
        "failures": failures,
    }


def attribute_area_split_save(
    records: Sequence[TrafficRecord],
    *,
    edit_windows: Sequence[str],
    opaque_allowlist: Sequence[str] = (),
) -> dict[str, Any]:
    """Attribute save conservatively from outbound map-write candidates."""
    selected_windows = set(edit_windows)
    candidates = [
        record
        for record in records
        if record.kind == "mqtt"
        and record.phase in selected_windows
        and record.direction == "request"
        and record.command is not None
        and _looks_like_map_write(record.command)
    ]
    candidates.sort(key=lambda item: item.observed_at)
    commands = sorted({record.command for record in candidates if record.command})
    allowlist = set(opaque_allowlist)
    observations = [
        {
            "observed_at": record.observed_at,
            "window": record.phase,
            "command": record.command,
            "topic_shape": record.topic,
            "opaque_payload_allowlisted": record.command in allowlist,
        }
        for record in candidates
    ]
    if not candidates:
        status = "unattributed"
        authoritative = None
    elif len(commands) == 1:
        status = "attributed"
        authoritative = observations[0]
    else:
        status = "ambiguous"
        authoritative = None
    return {
        "status": status,
        "authoritative_network_timestamp": (
            authoritative["observed_at"] if authoritative else None
        ),
        "authoritative_command": authoritative["command"] if authoritative else None,
        "distinct_candidate_commands": commands,
        "candidates": observations,
        "manual_marker_is_authoritative": False,
    }


def compare_area_split_evidence(
    evidence: AreaSplitEvidenceObserver,
    *,
    before_window: str,
    after_windows: Sequence[str],
    capture_records: Sequence[Mapping[str, Any]] = (),
    recorder_records: Sequence[TrafficRecord] = (),
) -> dict[str, Any]:
    """Compare structural metadata without inferring bytes for absent values."""
    before = (before_window,)
    after = tuple(after_windows)
    before_on_ari = evidence.complete_on_ari_sets(before)
    after_on_ari = evidence.complete_on_ari_sets(after)
    before_area = evidence.area_set(before)
    after_area = evidence.area_set(after)
    before_aids = sorted({item["aid"] for item in before_area})
    after_aids = sorted({item["aid"] for item in after_area})
    before_types = sorted({item["type"] for item in before_area})
    after_types = sorted({item["type"] for item in after_area})
    return {
        "comparison_kind": "metadata-and-digest-only",
        "presence_absence_is_byte_delta": False,
        "onMI": compare_area_split_observations(
            evidence.on_mi(before),
            evidence.on_mi(after),
            key_fields=("association",),
            value_fields=(
                "mid",
                "info_size",
                "original_length",
                "original_sha256",
                "derived_length",
                "derived_sha256",
                "context_signature_hex",
                "observed_context_class",
                "opaque_remainder_length",
                "opaque_remainder_sha256",
                "structural_error",
            ),
        ),
        "grouped_onArI": compare_area_split_observations(
            before_on_ari["complete"],
            after_on_ari["complete"],
            key_fields=("mid", "type", "using", "serial"),
            value_fields=(
                "info_size",
                "derived_length",
                "derived_sha256",
                "context_signature_hex",
                "observed_context_class",
                "opaque_remainder_length",
                "opaque_remainder_sha256",
                "opaque_common_body_region_length",
                "opaque_common_body_region_sha256",
                "opaque_after_701_length",
                "opaque_after_701_sha256",
                "structural_error",
            ),
        ),
        "getAreaSet": compare_area_split_observations(
            before_area,
            after_area,
            key_fields=("mid", "aid", "type"),
            value_fields=("info_size", "subsets_length", "subsets_sha256"),
        ),
        "area_key_inventory": {
            "before_aid": before_aids,
            "after_aid": after_aids,
            "new_aid": sorted(set(after_aids) - set(before_aids)),
            "missing_aid": sorted(set(before_aids) - set(after_aids)),
            "before_type": before_types,
            "after_type": after_types,
            "new_type": sorted(set(after_types) - set(before_types)),
            "missing_type": sorted(set(before_types) - set(after_types)),
        },
        "SpecialContour_control": _compare_capture_segments(
            capture_records,
            before_windows=set(before),
            after_windows=set(after),
            commands={"getSpecialContour", "onSpecialContour", "setSpecialContour"},
        ),
        "map_command_discovery": summarize_area_split_map_commands(
            recorder_records,
            windows={record.phase for record in recorder_records},
        ),
        "incomplete_grouped_onArI": {
            "before": before_on_ari["incomplete"],
            "after": after_on_ari["incomplete"],
        },
        "semantic_parser": False,
        "geometry_interpretation": False,
    }


def summarize_area_split_map_commands(
    records: Sequence[TrafficRecord],
    *,
    windows: set[str],
) -> list[dict[str, Any]]:
    """Inventory broad set*/on* command timing without payload retention."""
    selected = [
        record
        for record in records
        if record.kind == "mqtt"
        and record.phase in windows
        and record.command is not None
        and (record.command.startswith("set") or record.command.startswith("on"))
    ]
    grouped: dict[tuple[str, str | None], list[TrafficRecord]] = defaultdict(list)
    for record in selected:
        grouped[(record.command or "", record.direction)].append(record)
    return [
        {
            "command": command,
            "direction": direction,
            "count": len(items),
            "first_at": min(item.observed_at for item in items),
            "last_at": max(item.observed_at for item in items),
            "windows": sorted({item.phase for item in items}),
            "classification": "sanitized-command-timing-only",
        }
        for (command, direction), items in sorted(grouped.items())
    ]


class GoatMapAreaSplitExperiment:
    """Run one passive gated split workflow using the official app externally."""

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

    async def run(  # noqa: C901, PLR0912, PLR0913, PLR0915
        self,
        config: AreaSplitCaptureConfig,
        *,
        arm_app_init_1: Callable[[], Awaitable[None]],
        prepare_app_init_2: Callable[[], Awaitable[None]],
        arm_app_init_2: Callable[[], Awaitable[None]],
        arm_split_edit: Callable[[], Awaitable[None]],
        confirm_split_ready: Callable[[], Awaitable[bool | None]],
        confirm_save: Callable[[], Awaitable[None]],
        arm_post_reopen: Callable[[], Awaitable[None]] | None = None,
        announce_precondition: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Capture, gate, and compare without sending any control command."""
        if config.post_split_reopen and arm_post_reopen is None:
            raise ValueError("Post-split reopen requires an operator callback")
        merge_reference: AreaMergeReference | None = None
        rename_reference: AreaRenameReference | None = None
        rename_restore_reference: AreaRenameRestoreReference | None = None
        noop_save_reference: AreaNoOpSaveReference | None = None
        if config.operation == "merge":
            merge_reference = load_area_merge_reference(
                Path(config.reference_artifact_dir or ""),
                expected_capture_id=config.expected_reference_capture_id or "",
            )
            if config.post_merge_recovery:
                load_pre_merge_reference(
                    Path(config.pre_merge_artifact_dir or ""),
                    expected_capture_id=config.expected_pre_merge_capture_id or "",
                )
        elif config.operation == "rename":
            if config.rename_restore:
                rename_restore_reference = load_area_rename_restore_reference(
                    Path(config.reference_artifact_dir or ""),
                    expected_capture_id=config.expected_reference_capture_id or "",
                )
            else:
                rename_reference = load_area_rename_reference(
                    Path(config.reference_artifact_dir or ""),
                    expected_capture_id=config.expected_reference_capture_id or "",
                )
        elif config.operation in {"noop-save", "same-name-resubmission"}:
            noop_save_reference = load_area_noop_save_reference(
                Path(config.reference_artifact_dir or ""),
                expected_capture_id=config.expected_reference_capture_id or "",
            )
        recorder = MqttTrafficRecorder(
            phase=config.phase,
            mower_state=config.mower_state,
        )
        active_phase = config.phase
        evidence = AreaSplitEvidenceObserver(lambda: active_phase)
        observer = CombinedMqttObserver(
            recorder.observer("mq"),
            GoatMapCaptureObserver(self._writer),
            evidence,
        )
        normal = MqttClient(
            create_mqtt_config(device_id=self._device_id, country=self._country),
            self._authenticator,
            observer=observer,
        )
        machine = AreaSplitStateMachine()

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

        def transition(
            state: AreaSplitState,
            *,
            precondition_status: str | None = None,
        ) -> str:
            nonlocal active_phase
            machine.transition(state, precondition_status=precondition_status)
            active_phase = f"{config.phase}:{_operation_state_label(config, state)}"
            mower_state = current_state()
            recorder.set_context(active_phase, mower_state)
            self._writer.set_context(active_phase, mower_state)
            return active_phase

        async def fixed_window(
            state: AreaSplitState,
            duration: float,
            arm: Callable[[], Awaitable[None]] | None = None,
        ) -> str:
            phase = transition(state)
            recorder.record_window("started")
            if arm is not None:
                await arm()
            await asyncio.sleep(duration)
            recorder.record_window("ended")
            return phase

        async def on_state(event: StateEvent) -> None:
            state = _capture_state(event.state)
            recorder.record_mower_state(state, "mqtt-state")
            self._writer.set_context(active_phase, state)

        subscriptions.append(event_bus.subscribe(StateEvent, on_state))

        def handle_known_message(name: str, payload: str | bytes | bytearray) -> None:
            if message := get_message(name, self._device_info.static):
                message.handle(event_bus, payload)

        precondition: dict[str, Any] | None = None
        save_manual_at: str | None = None
        init_1_phase = f"{config.phase}:{_operation_state_label(config, AreaSplitState.PRE_SPLIT_APP_INIT_1)}"
        init_2_phase = f"{config.phase}:{_operation_state_label(config, AreaSplitState.PRE_SPLIT_APP_INIT_2)}"
        edit_phase = f"{config.phase}:{_operation_state_label(config, AreaSplitState.SPLIT_EDIT)}"
        save_phase = f"{config.phase}:{_operation_state_label(config, AreaSplitState.SPLIT_SAVE)}"
        post_phase = f"{config.phase}:{_operation_state_label(config, AreaSplitState.POST_SPLIT_READBACK)}"
        reopen_phase: str | None = None
        try:
            subscriptions.append(
                await normal.subscribe(
                    SubscriberInfo(self._device_info, event_bus, handle_known_message)
                )
            )
            await recorder.wait_connected("mq", config.connect_timeout)

            await fixed_window(
                AreaSplitState.PRE_SPLIT_BASELINE,
                config.baseline_seconds,
            )
            init_1_phase = await fixed_window(
                AreaSplitState.PRE_SPLIT_APP_INIT_1,
                config.app_init_seconds,
                arm_app_init_1,
            )

            await prepare_app_init_2()
            transition(AreaSplitState.PRE_SPLIT_APP_INIT_QUIET)
            recorder.record_window("started")
            await asyncio.sleep(config.between_init_quiet_seconds)
            recorder.record_window("ended")

            init_2_phase = await fixed_window(
                AreaSplitState.PRE_SPLIT_APP_INIT_2,
                config.app_init_seconds,
                arm_app_init_2,
            )
            evaluation_phase = transition(AreaSplitState.PRECONDITION_EVALUATION)
            recorder.record_window("started")
            precondition = evaluate_area_split_preconditions(
                evidence,
                init_1_window=init_1_phase,
                init_2_window=init_2_phase,
                recorder_records=recorder.records,
                allowed_app_windows=(init_1_phase, init_2_phase),
                expected_mower_state=config.mower_state,
            )
            if config.operation == "merge" and not config.post_merge_recovery:
                if merge_reference is None:
                    raise AreaSplitWorkflowError("Area merge reference was not loaded")
                precondition = evaluate_area_merge_preconditions(
                    precondition,
                    evidence,
                    init_1_window=init_1_phase,
                    init_2_window=init_2_phase,
                    reference=merge_reference,
                )
            elif config.operation == "rename":
                if config.rename_restore:
                    if rename_restore_reference is None:
                        raise AreaSplitWorkflowError(
                            "Area rename-restore reference was not loaded"
                        )
                    precondition = evaluate_area_rename_restore_preconditions(
                        precondition,
                        evidence,
                        init_1_window=init_1_phase,
                        init_2_window=init_2_phase,
                        reference=rename_restore_reference,
                        capture_records=self._writer.snapshot_records(),
                    )
                else:
                    if rename_reference is None:
                        raise AreaSplitWorkflowError(
                            "Area rename reference was not loaded"
                        )
                    precondition = evaluate_area_rename_preconditions(
                        precondition,
                        evidence,
                        init_1_window=init_1_phase,
                        init_2_window=init_2_phase,
                        reference=rename_reference,
                        capture_records=self._writer.snapshot_records(),
                    )
            elif config.operation == "noop-save":
                if noop_save_reference is None:
                    raise AreaSplitWorkflowError(
                        "Area no-op Save reference was not loaded"
                    )
                precondition = evaluate_area_noop_save_preconditions(
                    precondition,
                    evidence,
                    init_1_window=init_1_phase,
                    init_2_window=init_2_phase,
                    reference=noop_save_reference,
                    capture_records=self._writer.snapshot_records(),
                )
            elif config.operation == "same-name-resubmission":
                if noop_save_reference is None:
                    raise AreaSplitWorkflowError(
                        "Area same-name reference was not loaded"
                    )
                precondition = evaluate_area_same_name_preconditions(
                    precondition,
                    evidence,
                    init_1_window=init_1_phase,
                    init_2_window=init_2_phase,
                    reference=noop_save_reference,
                    capture_records=self._writer.snapshot_records(),
                )
            recorder.record_window("ended")
            if announce_precondition is not None:
                announce_precondition(precondition)
            if precondition["status"] != "passed":
                transition(AreaSplitState.INCONCLUSIVE)
                return _area_split_report(
                    recorder,
                    config,
                    machine,
                    precondition,
                    save_attribution=None,
                    comparison=None,
                    manual_save_confirmed_at=None,
                    windows={
                        "pre_split_app_init_1": init_1_phase,
                        "pre_split_app_init_2": init_2_phase,
                        "precondition_evaluation": evaluation_phase,
                    },
                )

            if config.post_merge_recovery:
                transition(AreaSplitState.COMPLETED)
                recovery_report = _area_split_report(
                    recorder,
                    config,
                    machine,
                    precondition,
                    save_attribution=None,
                    comparison=None,
                    manual_save_confirmed_at=None,
                    windows={
                        "post_merge_app_init_1": init_1_phase,
                        "post_merge_app_init_2": init_2_phase,
                        "precondition_evaluation": evaluation_phase,
                    },
                )
                controlled = recovery_report["controlled_area_merge"]
                controlled["experiment_status"] = "recovery-capture-complete"
                controlled["delta_status"] = "pending-read-only-recovery-analysis"
                controlled["post_merge_recovery"] = True
                controlled["write_attribution"] = {
                    "status": "unavailable-capture-finalization-failed",
                    "authoritative_network_timestamp": None,
                    "authoritative_command": None,
                }
                return recovery_report

            edit_phase = transition(
                AreaSplitState.SPLIT_EDIT,
                precondition_status=precondition["status"],
            )
            recorder.record_window("started")
            await arm_split_edit()
            operator_ready = await confirm_split_ready()
            recorder.record_window("ended")
            if operator_ready is False:
                transition(AreaSplitState.INCONCLUSIVE)
                aborted_report = _area_split_report(
                    recorder,
                    config,
                    machine,
                    precondition,
                    save_attribution=None,
                    comparison=None,
                    manual_save_confirmed_at=None,
                    windows={
                        "pre_split_app_init_1": init_1_phase,
                        "pre_split_app_init_2": init_2_phase,
                        "precondition_evaluation": evaluation_phase,
                        "split_edit": edit_phase,
                    },
                )
                controlled_key = (
                    "controlled_area_same_name_resubmission"
                    if config.operation == "same-name-resubmission"
                    else "controlled_area_noop_save"
                )
                controlled = aborted_report[controlled_key]
                controlled["experiment_status"] = "operator-aborted-before-save"
                controlled["delta_status"] = "not-comparable"
                controlled["operator_abort"] = {
                    "status": "operator-aborted-before-save",
                    "reason": (
                        "operator-did-not-confirm-same-name-only"
                        if config.operation == "same-name-resubmission"
                        else "operator-did-not-confirm-no-user-data-change"
                    ),
                    "save_window_opened": False,
                    "save_performed": False,
                }
                return aborted_report

            save_phase = transition(AreaSplitState.SPLIT_SAVE)
            recorder.record_window("started")
            await confirm_save()
            save_manual_at = _utc_now().isoformat()
            recorder.record_window("ended")

            post_phase = await fixed_window(
                AreaSplitState.POST_SPLIT_READBACK,
                config.post_split_seconds,
            )
            if config.post_split_reopen:
                if arm_post_reopen is None:
                    raise AreaSplitWorkflowError(
                        "Post-split reopen callback disappeared after validation"
                    )
                reopen_phase = await fixed_window(
                    AreaSplitState.POST_SPLIT_REOPEN,
                    config.post_reopen_seconds,
                    arm_post_reopen,
                )
            transition(AreaSplitState.COMPLETED)
        finally:
            for unsubscribe in subscriptions:
                unsubscribe()
            await normal.disconnect()
            await event_bus.teardown()

        if precondition is None:
            raise AreaSplitWorkflowError(
                "Precondition evaluation did not produce a result"
            )
        save_attribution = attribute_area_split_save(
            recorder.records,
            edit_windows=(edit_phase, save_phase),
            opaque_allowlist=tuple(self._writer.captured_commands),
        )
        after_windows = tuple(
            phase
            for phase in (save_phase, post_phase, reopen_phase)
            if phase is not None
        )
        comparison = compare_area_split_evidence(
            evidence,
            before_window=init_2_phase,
            after_windows=after_windows,
            capture_records=self._writer.snapshot_records(),
            recorder_records=recorder.records,
        )
        postcondition = evaluate_area_split_postconditions(
            evidence,
            after_windows=after_windows,
            recorder_records=recorder.records,
        )
        report = _area_split_report(
            recorder,
            config,
            machine,
            precondition,
            save_attribution=save_attribution,
            comparison=comparison,
            postcondition=postcondition,
            manual_save_confirmed_at=save_manual_at,
            windows={
                "pre_split_app_init_1": init_1_phase,
                "pre_split_app_init_2": init_2_phase,
                "split_edit": edit_phase,
                "split_save": save_phase,
                "post_split_readback": post_phase,
                "post_split_reopen": reopen_phase,
            },
        )
        if config.operation == "merge":
            if merge_reference is None:
                raise AreaSplitWorkflowError("Area merge reference was not loaded")
            add_area_merge_restoration_analysis(
                report,
                evidence,
                reference=merge_reference,
                post_merge_windows=after_windows,
                capture_records=self._writer.snapshot_records(),
            )
        elif config.operation == "rename" and not config.rename_restore:
            if reopen_phase is None:
                raise AreaSplitWorkflowError("Area rename post-save reopen is missing")
            add_area_rename_analysis(
                report,
                evidence,
                before_window=init_2_phase,
                primary_post_windows=(save_phase, post_phase),
                reopen_window=reopen_phase,
                capture_records=self._writer.snapshot_records(),
                divide_reference_artifact=Path(
                    config.divide_reference_artifact_dir or ""
                ),
                expected_divide_capture_id=(
                    config.expected_divide_reference_capture_id or ""
                ),
            )
        elif config.rename_restore:
            controlled = report["controlled_area_rename_restore"]
            controlled["experiment_status"] = "completed-action"
            controlled["delta_status"] = "pending-finalized-artifact-analysis"
            controlled["role_comparison"] = {
                "status": "pending-finalized-artifact-analysis"
            }
        elif config.operation == "noop-save":
            controlled = report["controlled_area_noop_save"]
            controlled["experiment_status"] = "completed-action"
            controlled["delta_status"] = "pending-finalized-artifact-analysis"
            controlled["role_comparison"] = {
                "status": "pending-finalized-artifact-analysis"
            }
        elif config.operation == "same-name-resubmission":
            controlled = report["controlled_area_same_name_resubmission"]
            controlled["experiment_status"] = "completed-action"
            controlled["delta_status"] = "pending-finalized-artifact-analysis"
            controlled["role_comparison"] = {
                "status": "pending-finalized-artifact-analysis"
            }
        return report


def evaluate_area_split_postconditions(
    evidence: AreaSplitEvidenceObserver,
    *,
    after_windows: Sequence[str],
    recorder_records: Sequence[TrafficRecord],
) -> dict[str, Any]:
    """Evaluate delta completeness independently of write attribution."""
    complete_on_ari = evidence.complete_on_ari_sets(after_windows)
    checks: dict[str, dict[str, Any]] = {
        "post_split_onMI": {
            "status": "passed" if evidence.on_mi(after_windows) else "failed",
            "count": len(evidence.on_mi(after_windows)),
        },
        "post_split_getAreaSet": {
            "status": "passed" if evidence.area_set(after_windows) else "failed",
            "count": len(evidence.area_set(after_windows)),
        },
        "post_split_complete_grouped_onArI": {
            "status": "passed" if complete_on_ari["complete"] else "failed",
            "complete_count": len(complete_on_ari["complete"]),
            "incomplete_count": len(complete_on_ari["incomplete"]),
        },
    }
    after_window_set = set(after_windows)
    state_transitions = [
        {
            "observed_at": record.observed_at,
            "window": record.phase,
            "mower_state": record.mower_state,
        }
        for record in recorder_records
        if record.kind == "state"
        and record.phase in after_window_set
        and record.mower_state != MowerState.PAUSED.value
    ]
    checks["mower_state"] = {
        "status": "passed" if not state_transitions else "failed",
        "unexpected_transitions": state_transitions,
    }
    failures = [name for name, check in checks.items() if check["status"] != "passed"]
    return {
        "status": "passed" if not failures else "inconclusive",
        "result": "postconditions-passed" if not failures else "postconditions-failed",
        "failed_checks": failures,
        "checks": checks,
    }


def _area_split_report(  # noqa: PLR0913
    recorder: MqttTrafficRecorder,
    config: AreaSplitCaptureConfig,
    machine: AreaSplitStateMachine,
    precondition: Mapping[str, Any],
    *,
    save_attribution: Mapping[str, Any] | None,
    comparison: Mapping[str, Any] | None,
    postcondition: Mapping[str, Any] | None = None,
    manual_save_confirmed_at: str | None,
    windows: Mapping[str, str | None],
) -> dict[str, Any]:
    report = recorder.report()
    edit_started = any(
        item["to"] == AreaSplitState.SPLIT_EDIT.value for item in machine.history
    )
    operation = config.operation
    operation_report_label = (
        "rename_restore"
        if config.rename_restore
        else "noop_save"
        if operation == "noop-save"
        else "same_name_resubmission"
        if operation == "same-name-resubmission"
        else operation
    )
    rendered_windows = {
        _operation_label_value(config, key.replace("_", "-"))
        .replace("-", "_"): value
        for key, value in windows.items()
    }
    report["experiment"] = {
        **asdict(config),
        "capture_mode": (
            "controlled-area-rename-restore"
            if config.rename_restore
            else "controlled-area-noop-save"
            if operation == "noop-save"
            else "controlled-area-same-name-resubmission"
            if operation == "same-name-resubmission"
            else f"controlled-area-{operation}"
        ),
        "mqtt": "normal-mq",
        "jmq": "none",
        "diagnostic_control_actions": [],
        "official_app_external_control_allowed_in_marked_windows": True,
        "marked_external_control_windows": [
            window for window in rendered_windows.values() if window is not None
        ],
        "payload_decoding": "representation-and-structural-views-only",
    }
    delta_complete = (
        precondition["status"] == "passed"
        and postcondition is not None
        and postcondition["status"] == "passed"
        and comparison is not None
    )
    experiment_status = "complete" if delta_complete else "inconclusive"
    delta_status = (
        "controlled-structural-evidence"
        if delta_complete
        else "not-comparable"
        if precondition["status"] != "passed"
        else "inconclusive"
    )
    write_attribution = (
        dict(save_attribution)
        if save_attribution is not None
        else {
            "status": "not-evaluated",
            "authoritative_network_timestamp": None,
            "authoritative_command": None,
        }
    )
    controlled_key = f"controlled_area_{operation_report_label}"
    report[controlled_key] = {
        "status": experiment_status,
        "experiment_status": experiment_status,
        "delta_status": delta_status,
        "state": (
            _operation_state_label(config, machine.state)
            if machine.state is not None
            else None
        ),
        "state_history": [
            {
                **item,
                "from": _operation_label_value(config, item["from"]),
                "to": _operation_label_value(config, item["to"]),
            }
            for item in machine.history
        ],
        "windows": rendered_windows,
        "precondition": dict(precondition),
        "write_attribution": write_attribution,
        "manual_save_confirmed_at": manual_save_confirmed_at,
        "manual_save_marker_is_authoritative": False,
        "comparison": dict(comparison) if comparison is not None else None,
        "postcondition": dict(postcondition) if postcondition is not None else None,
        "areas_must_remain_split_pending_verification": (
            edit_started if operation == "split" else False
        ),
        "merged_areas_must_remain_unchanged_pending_verification": (
            edit_started if operation == "merge" else False
        ),
        "temporary_name_must_remain_pending_verification": (
            edit_started if operation == "rename" and not config.rename_restore else False
        ),
        "restored_name_must_remain_pending_verification": (
            edit_started if config.rename_restore else False
        ),
        "no_op_save_state_must_remain_pending_verification": (
            edit_started if operation == "noop-save" else False
        ),
        "same_name_state_must_remain_pending_verification": (
            edit_started if operation == "same-name-resubmission" else False
        ),
        "operator_name_metadata": (
            {
                "old_utf8_byte_length": config.old_name_utf8_byte_length,
                "new_utf8_byte_length": config.new_name_utf8_byte_length,
                "lengths_equal": (
                    config.old_name_utf8_byte_length
                    == config.new_name_utf8_byte_length
                ),
                "new_name_ascii_operator_confirmed": True,
                "actual_names_recorded": False,
            }
            if operation in {"rename", "same-name-resubmission"}
            else None
        ),
        "semantic_parser": False,
        "geometry_interpretation": False,
    }
    return report


def _operation_state_label(
    config: AreaSplitCaptureConfig,
    state: AreaSplitState,
) -> str:
    """Render operation-specific research window names without changing the guard."""
    return _operation_label_value(config, state.value)


def _operation_label_value(config: AreaSplitCaptureConfig, value: str) -> str:
    if config.operation == "split" or value in {"initial", "inconclusive", "completed"}:
        return value
    replacements: tuple[tuple[str, str], ...]
    if config.operation == "merge" and config.post_merge_recovery:
        replacements = (
            ("pre-split", "post-merge"),
            ("split-edit", "merge-edit"),
            ("split-save", "merge-save"),
        )
    elif config.rename_restore:
        replacements = (
            ("pre-split", "pre-restore"),
            ("post-split", "post-restore"),
            ("split-edit", "restore-edit"),
            ("split-save", "restore-save"),
        )
    elif config.operation == "rename":
        replacements = (
            ("pre-split", "pre-rename"),
            ("post-split", "post-rename"),
            ("split-edit", "rename-edit"),
            ("split-save", "rename-save"),
        )
    elif config.operation == "noop-save":
        replacements = (
            ("pre-split", "pre-noop-save"),
            ("post-split", "post-noop-save"),
            ("split-edit", "no-op-edit"),
            ("split-save", "no-op-save"),
        )
    elif config.operation == "same-name-resubmission":
        replacements = (
            ("pre-split", "pre-same-name"),
            ("post-split", "post-same-name"),
            ("split-edit", "same-name-edit"),
            ("split-save", "same-name-save"),
        )
    else:
        replacements = (
            ("pre-split", "pre-merge"),
            ("post-split", "post-merge"),
            ("split-edit", "merge-edit"),
            ("split-save", "merge-save"),
        )
    for old, new in replacements:
        value = value.replace(old, new)
    return value


def _assembled_on_ari_report(
    window: str,
    identity_digest: str,
    observed_at: Sequence[str],
    assembled: Any,
) -> dict[str, Any]:
    info_size = _optional_int(assembled.identity.info_size)
    structural_error: str | None = None
    signature: str | None = None
    context_class: str | None = None
    remainder_length: int | None = None
    remainder_digest: str | None = None
    common_length: int | None = None
    common_digest: str | None = None
    tail_length: int | None = None
    tail_digest: str | None = None
    try:
        header = recognize_structural_header(
            assembled.derived_concatenation,
            envelope_info_size=info_size,
        )
        inner = recognize_inner_structure(
            header,
            envelope_serial=assembled.identity.serial,
        )
        signature = inner.context_signature_raw.hex()
        context_class = inner.observed_context_class
        remainder_length = len(inner.remainder)
        remainder_digest = sha256(inner.remainder).hexdigest()
        if (
            context_class == "observed-onArI-b4-signature"
            and len(inner.remainder) >= _OPAQUE_COMMON_BODY_LENGTH
        ):
            common = inner.remainder[:_OPAQUE_COMMON_BODY_LENGTH]
            tail = inner.remainder[_OPAQUE_COMMON_BODY_LENGTH:]
            common_length = len(common)
            common_digest = sha256(common).hexdigest()
            tail_length = len(tail)
            tail_digest = sha256(tail).hexdigest()
    except (StructuralHeaderError, ValueError) as err:
        structural_error = type(err).__name__
    return {
        "window": window,
        "observed_at": sorted(observed_at),
        "identity_sha256": identity_digest,
        "mid": str(assembled.identity.mid),
        "type": str(assembled.identity.type),
        "using": str(assembled.identity.using),
        "serial": assembled.identity.serial,
        "info_size": info_size,
        "segment_count": len(assembled.segments),
        "segment_original_lengths": [
            item.original_representation_length for item in assembled.segments
        ],
        "segment_original_sha256": [
            item.original_representation_sha256 for item in assembled.segments
        ],
        "derived_length": assembled.derived_concatenation_length,
        "derived_sha256": assembled.derived_concatenation_sha256,
        "context_signature_hex": signature,
        "observed_context_class": context_class,
        "opaque_remainder_length": remainder_length,
        "opaque_remainder_sha256": remainder_digest,
        "opaque_common_body_region_length": common_length,
        "opaque_common_body_region_sha256": common_digest,
        "opaque_after_701_length": tail_length,
        "opaque_after_701_sha256": tail_digest,
        "structural_error": structural_error,
    }


def _comparable_on_mi_check(
    left: Sequence[Mapping[str, Any]],
    right: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    roles = (
        "request-associated",
        "cadence-associated",
        "unclassified",
    )
    for role in roles:
        left_values = {
            (item["original_length"], item["original_sha256"])
            for item in left
            if item["association"] == role
        }
        right_values = {
            (item["original_length"], item["original_sha256"])
            for item in right
            if item["association"] == role
        }
        if not left_values or not right_values:
            continue
        if len(left_values) == 1 and left_values == right_values:
            length, digest = next(iter(left_values))
            return {
                "status": "passed",
                "reason": None,
                "comparable_role": role,
                "original_length": length,
                "original_sha256": digest,
            }
        return {
            "status": "failed",
            "reason": "comparable-role-has-different-or-ambiguous-onMI-values",
            "comparable_role": role,
            "left_variants": _variant_pairs(left_values),
            "right_variants": _variant_pairs(right_values),
        }
    return {
        "status": "failed",
        "reason": "no-comparable-onMI-role-in-both-app-init-windows",
        "comparable_role": None,
    }


def _same_area_set_check(
    left: Sequence[Mapping[str, Any]],
    right: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    left_values = _area_set_variants(left)
    right_values = _area_set_variants(right)
    if not left_values or not right_values:
        return {
            "status": "failed",
            "reason": "one-or-both-app-init-windows-have-no-getAreaSet-readback",
            "left_keys": _serialized_keys(left_values),
            "right_keys": _serialized_keys(right_values),
        }
    if set(left_values) != set(right_values):
        return {
            "status": "failed",
            "reason": "getAreaSet-key-set-differs",
            "left_keys": _serialized_keys(left_values),
            "right_keys": _serialized_keys(right_values),
        }
    if any(
        len(values) != 1 for values in (*left_values.values(), *right_values.values())
    ):
        return {
            "status": "failed",
            "reason": "getAreaSet-key-has-multiple-subsets-variants",
            "left_keys": _serialized_keys(left_values),
            "right_keys": _serialized_keys(right_values),
        }
    if left_values != right_values:
        return {
            "status": "failed",
            "reason": "getAreaSet-subsets-digest-or-length-differs",
            "left_keys": _serialized_keys(left_values),
            "right_keys": _serialized_keys(right_values),
        }
    return {
        "status": "passed",
        "reason": None,
        "keys": _serialized_keys(left_values),
    }


def compare_area_split_observations(
    before: Sequence[Mapping[str, Any]],
    after: Sequence[Mapping[str, Any]],
    *,
    key_fields: Sequence[str],
    value_fields: Sequence[str],
) -> dict[str, Any]:
    """Compare values and occurrence counts without inferring byte deltas."""
    before_grouped = _group_observations(before, key_fields, value_fields)
    after_grouped = _group_observations(after, key_fields, value_fields)
    reports: list[dict[str, Any]] = []
    for frozen_key in sorted(
        set(before_grouped) | set(after_grouped),
        key=repr,
    ):
        before_values = before_grouped.get(frozen_key, Counter())
        after_values = after_grouped.get(frozen_key, Counter())
        if not before_values:
            status: ComparisonStatus = "after-only"
        elif not after_values:
            status = "before-only"
        elif set(before_values) != set(after_values):
            status = "value-changed"
        elif before_values != after_values:
            status = "occurrence-count-changed"
        else:
            status = "unchanged"
        reports.append(
            {
                "key": _thaw_object(frozen_key),
                "status": status,
                "before": _counter_report(before_values),
                "after": _counter_report(after_values),
                "byte_comparison_available": status
                not in {"before-only", "after-only"},
                "byte_delta_proven": False,
            }
        )
    return {
        "statuses": dict(sorted(Counter(item["status"] for item in reports).items())),
        "groups": reports,
        "presence_absence_is_byte_delta": False,
    }


def _compare_capture_segments(
    records: Sequence[Mapping[str, Any]],
    *,
    before_windows: set[str],
    after_windows: set[str],
    commands: set[str],
) -> dict[str, Any]:
    before: list[dict[str, Any]] = []
    after: list[dict[str, Any]] = []
    for record in records:
        if record.get("command") not in commands:
            continue
        window = record.get("window")
        destination = (
            before
            if window in before_windows
            else after
            if window in after_windows
            else None
        )
        if destination is None:
            continue
        for segment in record.get("opaque_segments", []):
            original = segment.get("representations", {}).get("original")
            if not isinstance(original, Mapping):
                continue
            destination.append(
                {
                    "command": record.get("command"),
                    "direction": record.get("direction"),
                    "source_path": segment.get("source_path"),
                    "byte_length": original.get("byte_length"),
                    "sha256": original.get("sha256"),
                }
            )
    return compare_area_split_observations(
        before,
        after,
        key_fields=("command", "direction", "source_path"),
        value_fields=("byte_length", "sha256"),
    )


def _group_observations(
    observations: Sequence[Mapping[str, Any]],
    key_fields: Sequence[str],
    value_fields: Sequence[str],
) -> dict[Any, Counter[Any]]:
    grouped: dict[Any, Counter[Any]] = defaultdict(Counter)
    for item in observations:
        key = _freeze_object({field: item.get(field) for field in key_fields})
        value = _freeze_object({field: item.get(field) for field in value_fields})
        grouped[key][value] += 1
    return grouped


def _counter_report(counter: Counter[Any]) -> list[dict[str, Any]]:
    return [
        {"value": _thaw_object(value), "count": count}
        for value, count in sorted(counter.items(), key=lambda item: repr(item[0]))
    ]


def _freeze_object(value: Any) -> Any:
    if isinstance(value, Mapping):
        return tuple(
            (str(key), _freeze_object(item))
            for key, item in sorted(value.items(), key=lambda item: str(item[0]))
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_object(item) for item in value)
    return value


def _thaw_object(value: Any) -> Any:
    if isinstance(value, tuple):
        if all(
            isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str)
            for item in value
        ):
            return {item[0]: _thaw_object(item[1]) for item in value}
        return [_thaw_object(item) for item in value]
    return value


def _static_mids(
    on_mi: Sequence[Mapping[str, Any]],
    area_set: Sequence[Mapping[str, Any]],
    on_ari: Sequence[Mapping[str, Any]],
) -> list[str]:
    return sorted(
        {
            str(item["mid"])
            for collection in (on_mi, area_set, on_ari)
            for item in collection
            if item.get("mid") is not None
        }
    )


def _area_set_variants(
    observations: Sequence[Mapping[str, Any]],
) -> dict[tuple[str, str, str], set[tuple[int, str]]]:
    result: dict[tuple[str, str, str], set[tuple[int, str]]] = defaultdict(set)
    for item in observations:
        key = (str(item["mid"]), str(item["aid"]), str(item["type"]))
        result[key].add((int(item["subsets_length"]), str(item["subsets_sha256"])))
    return result


def _serialized_keys(
    values: Mapping[tuple[str, str, str], set[tuple[int, str]]],
) -> list[dict[str, Any]]:
    return [
        {
            "mid": key[0],
            "aid": key[1],
            "type": key[2],
            "variants": [
                {"byte_length": length, "sha256": digest}
                for length, digest in sorted(variants)
            ],
        }
        for key, variants in sorted(values.items())
    ]


def _unexpected_control_sequences(
    records: Sequence[TrafficRecord],
    *,
    allowed_app_windows: set[str],
) -> list[dict[str, Any]]:
    return [
        {
            "observed_at": record.observed_at,
            "window": record.phase,
            "command": record.command,
            "direction": record.direction,
            "classification": "concurrent-external",
        }
        for record in records
        if record.kind == "mqtt"
        and record.direction == "request"
        and record.phase not in allowed_app_windows
    ]


def _looks_like_map_write(command: str) -> bool:
    lowered = command.casefold()
    if lowered.startswith(("get", "on")):
        return False
    return lowered.startswith("set") or any(
        hint in lowered for hint in _MAP_WRITE_HINTS
    )


def _on_mi_association(
    observed_at: datetime,
    get_mi_requests: Sequence[datetime],
    *,
    original_length: int,
) -> str:
    preceding = [timestamp for timestamp in get_mi_requests if timestamp <= observed_at]
    if (
        preceding
        and (observed_at - max(preceding)).total_seconds()
        <= _REQUEST_ASSOCIATION_SECONDS
    ):
        return "request-associated"
    if original_length == 52:
        return "cadence-associated"
    return "unclassified"


def _payload_data(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        body = value.get("body")
        body_data = body.get("data") if isinstance(body, Mapping) else None
        if isinstance(body_data, Mapping):
            return {str(key): item for key, item in body_data.items()}
        direct_data = value.get("data")
        if isinstance(direct_data, Mapping):
            return {str(key): item for key, item in direct_data.items()}
    raise ValueError("Payload has no object-valued body.data")


def _required_string(value: Mapping[str, Any], key: str) -> str:
    item = value[key]
    if not isinstance(item, str) or not item:
        message = f"{key} must be a non-empty string"
        raise TypeError(message)
    return item


def _required_scalar(value: Mapping[str, Any], key: str) -> str:
    item = value[key]
    if isinstance(item, bool) or not isinstance(item, (str, int)):
        message = f"{key} must be a string or integer"
        raise TypeError(message)
    return str(item)


def _required_int(
    value: Mapping[str, Any],
    key: str,
    *,
    allow_zero: bool = False,
) -> int:
    return normalize_segment_cardinality(
        key,
        value[key],
        allow_zero=allow_zero,
    )


def _required_envelope_value(
    value: Mapping[str, Any],
    key: str,
) -> str | int:
    item = value[key]
    if isinstance(item, bool) or not isinstance(item, (str, int)):
        message = f"{key} must be a string or integer"
        raise TypeError(message)
    return item


def _optional_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return None


def _segment_identity_tuple(segment: OpaqueSegmentInput) -> tuple[Any, ...]:
    return (
        segment.batid,
        segment.serial,
        segment.info_size,
        segment.mid,
        segment.type,
        segment.using,
    )


def _identity_digest(identity: tuple[Any, ...]) -> str:
    return sha256(orjson.dumps(identity)).hexdigest()


def _variant_pairs(values: set[tuple[Any, Any]]) -> list[dict[str, Any]]:
    return [
        {"original_length": length, "original_sha256": digest}
        for length, digest in sorted(values)
    ]


def _topic_details(topic: str) -> tuple[str, str]:
    parts = topic.split("/")
    command = parts[2] if len(parts) > 2 else "<unknown>"
    if topic.startswith("iot/atr/"):
        return command, "event"
    if topic.startswith("iot/p2p/"):
        return command, "request" if len(parts) > 9 and parts[9] == "q" else "response"
    return command, "unknown"


def _capture_state(state: State) -> MowerState:
    return {
        State.DOCKED: MowerState.DOCKED,
        State.IDLE: MowerState.IDLE,
        State.CLEANING: MowerState.MOWING,
        State.PAUSED: MowerState.PAUSED,
        State.RETURNING: MowerState.RETURNING,
    }.get(state, MowerState.UNKNOWN)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
