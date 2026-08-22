"""Timing-only helpers for a non-editing GOAT map repeatability capture."""

from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import time
from typing import TYPE_CHECKING, Any

import orjson

from deebot_client.mqtt_client import MqttConfiguration, MqttObserver

from .goat_map_delta import (
    VerifiedArtifactRecord,
    VerifiedOpaqueSegment,
    load_verified_phase2_artifact,
)
from .goat_map_refresh import MowerState
from .goat_map_representation import (
    RepresentationDecodeError,
    decode_strict_base64_representation,
)

if TYPE_CHECKING:
    from collections.abc import Collection
    from pathlib import Path

    from aiomqtt import Message

_SHORT_REPRESENTATION_LENGTH = 52
_SHORT_DECODED_LENGTH = 38
_LONG_REPRESENTATION_LENGTH = 876
_CONTROL_ASSOCIATION_SECONDS = 10.0
_DEFAULT_BOUNDARY_TOLERANCE_SECONDS = 8.0
_ANALYSIS_VERSION = "goat-repeatability-timing/v2"
_MICROSECONDS_PER_SECOND = 1_000_000
_EXPECTED_ON_ARI_FAMILIES = {
    "1838bb93b779295729ddd47290dadf2f92f94a149eff3f292e8a37d909ed137b": {
        "length": 820,
        "on_mi_length": 52,
    },
    "5542faa1d353156ac4e123bc5bd657577b6984811dcebe22891993aee909704d": {
        "length": 1024,
        "on_mi_length": 876,
    },
    "f3d6a1c0f3a9d2e610d1f81c5e8ca3cb9e26942c820a76e928c45150774a8603": {
        "length": 896,
        "on_mi_length": 876,
    },
}
_FIXTURE_CANDIDATES = (
    (
        "onMI",
        "$.body.data.info",
        876,
        "12cbcb330c3b91334f72b41470e09361310853554f8292bc83e4dd72dfbdd5bb",
        15,
        9,
    ),
    (
        "onMI",
        "$.body.data.info",
        52,
        "d7d0e5374acebd6b57c06fd2b5a6a62a6136f6664845ca6e86892dab93181ba1",
        17,
        9,
    ),
    (
        "onArI",
        "$.body.data.info",
        820,
        "1838bb93b779295729ddd47290dadf2f92f94a149eff3f292e8a37d909ed137b",
        6,
        4,
    ),
    (
        "onArI",
        "$.body.data.info",
        1024,
        "5542faa1d353156ac4e123bc5bd657577b6984811dcebe22891993aee909704d",
        6,
        5,
    ),
    (
        "onArI",
        "$.body.data.info",
        896,
        "f3d6a1c0f3a9d2e610d1f81c5e8ca3cb9e26942c820a76e928c45150774a8603",
        6,
        5,
    ),
    (
        "getAreaSet",
        "$.body.data.subsets",
        124,
        "72ebe704cb5890adb28ec1be05c228a6ef9addff0738df811808f671e0afd855",
        32,
        6,
    ),
    (
        "getAreaSet",
        "$.body.data.subsets",
        24,
        "1e01a6d271fbf47823e02e56d20cdf2a8db654afb1d11f703ed3a49d255c1255",
        24,
        6,
    ),
)


@dataclass(frozen=True, kw_only=True)
class RepeatabilityConfig:
    """Bounds for one deterministic capture inside a single presence lease."""

    phase: str = "p2-08-repeatability"
    mower_state: MowerState = MowerState.MOWING
    baseline_seconds: float = 30
    cadence_timeout_seconds: float = 150
    control_offset_seconds: float = 25
    cadence_min_seconds: float = 45
    cadence_max_seconds: float = 75
    cadence_boundary_tolerance_seconds: float = _DEFAULT_BOUNDARY_TOLERANCE_SECONDS
    final_event_grace_seconds: float = 3
    presence_lease_budget_seconds: float = 285
    connect_timeout: float = 30

    def __post_init__(self) -> None:
        if self.mower_state is not MowerState.MOWING:
            raise ValueError("Repeatability capture requires active mowing")
        if not 0 <= self.baseline_seconds <= 60:
            raise ValueError("Repeatability baseline must be between 0 and 60 seconds")
        if not 60 <= self.cadence_timeout_seconds <= 180:
            raise ValueError("Cadence timeout must be between 60 and 180 seconds")
        if not 20 <= self.control_offset_seconds <= 30:
            raise ValueError("Control offset must be between 20 and 30 seconds")
        if not 30 <= self.cadence_min_seconds < self.cadence_max_seconds <= 90:
            raise ValueError("Cadence bounds are invalid")
        if not 1 <= self.cadence_boundary_tolerance_seconds <= 15:
            raise ValueError("Cadence boundary tolerance must be 1--15 seconds")
        if not 0 <= self.final_event_grace_seconds <= 10:
            raise ValueError("Final event grace must be 0--10 seconds")
        if not 240 <= self.presence_lease_budget_seconds <= 295:
            raise ValueError("Presence lease budget must be 240--295 seconds")
        if self.connect_timeout <= 0:
            raise ValueError("Connection timeout must be positive")


@dataclass(frozen=True, slots=True)
class ShortFormObservation:
    """Sanitized timing metadata for one proven 52-byte representation."""

    observed_at: str
    monotonic_seconds: float
    original_sha256: str


@dataclass(frozen=True, slots=True)
class EstablishedCadence:
    """Two equal 52-byte forms with an observed bounded interval."""

    first: ShortFormObservation
    second: ShortFormObservation
    interval_seconds: float


@dataclass(frozen=True, slots=True)
class _ControlMarker:
    """Sanitized timestamp/transport for one controlled getMI action."""

    observed_at: str
    transport: str


class ShortOnMiCadenceObserver(MqttObserver):
    """Observe only timing/digest metadata for strict-Base64 52-byte onMI.info."""

    def __init__(self) -> None:
        self._observations: list[ShortFormObservation] = []

    @property
    def observations(self) -> tuple[ShortFormObservation, ...]:
        """Return immutable observation metadata in arrival order."""
        return tuple(self._observations)

    def on_connected(self, _: MqttConfiguration) -> None:
        """Ignore broker lifecycle."""

    def on_disconnected(self, _: MqttConfiguration) -> None:
        """Ignore broker lifecycle."""

    def on_message(self, _: MqttConfiguration, message: Message) -> None:
        """Inspect one MQTT payload without retaining its opaque representation."""
        self.observe(message.topic.value, message.payload)

    def observe(
        self,
        topic: str,
        payload: str | bytes | bytearray,
        *,
        observed_at: datetime | None = None,
        monotonic_seconds: float | None = None,
    ) -> None:
        """Record metadata only when onMI.info proves the known short form."""
        if not topic.startswith("iot/atr/onMI/"):
            return
        raw = payload.encode() if isinstance(payload, str) else bytes(payload)
        try:
            parsed = orjson.loads(raw)
        except orjson.JSONDecodeError:
            return
        info = _nested_info(parsed)
        if not isinstance(info, str):
            return
        try:
            encoded = info.encode("ascii")
            decoded = decode_strict_base64_representation(info)
        except UnicodeEncodeError, RepresentationDecodeError:
            return
        if len(encoded) != _SHORT_REPRESENTATION_LENGTH or len(decoded) != (
            _SHORT_DECODED_LENGTH
        ):
            return
        timestamp = (observed_at or datetime.now(UTC)).astimezone(UTC)
        self._observations.append(
            ShortFormObservation(
                observed_at=timestamp.isoformat(),
                monotonic_seconds=(
                    time.monotonic() if monotonic_seconds is None else monotonic_seconds
                ),
                original_sha256=sha256(encoded).hexdigest(),
            )
        )

    async def wait_for_cadence(
        self,
        *,
        after_count: int = 0,
        timeout_seconds: float,
        min_interval_seconds: float,
        max_interval_seconds: float,
    ) -> EstablishedCadence | None:
        """Wait for two equal short forms with a bounded observed interval."""
        try:
            async with asyncio.timeout(timeout_seconds):
                while True:
                    if cadence := self.established_cadence(
                        after_count=after_count,
                        min_interval_seconds=min_interval_seconds,
                        max_interval_seconds=max_interval_seconds,
                    ):
                        return cadence
                    await asyncio.sleep(0.1)
        except TimeoutError:
            return None

    async def wait_for_next(
        self,
        *,
        after_count: int,
        digest: str,
        timeout_seconds: float,
    ) -> ShortFormObservation | None:
        """Wait for a later occurrence of the established opaque representation."""
        try:
            async with asyncio.timeout(timeout_seconds):
                while True:
                    for observation in self._observations[after_count:]:
                        if observation.original_sha256 == digest:
                            return observation
                    await asyncio.sleep(0.1)
        except TimeoutError:
            return None

    def established_cadence(
        self,
        *,
        after_count: int = 0,
        min_interval_seconds: float,
        max_interval_seconds: float,
    ) -> EstablishedCadence | None:
        """Return the latest qualifying pair without assigning a semantic role."""
        selected = self._observations[after_count:]
        for first, second in zip(
            reversed(selected[:-1]),
            reversed(selected[1:]),
            strict=True,
        ):
            interval = second.monotonic_seconds - first.monotonic_seconds
            if (
                first.original_sha256 == second.original_sha256
                and min_interval_seconds <= interval <= max_interval_seconds
            ):
                return EstablishedCadence(
                    first=first,
                    second=second,
                    interval_seconds=interval,
                )
        return None


def analyze_repeatability_artifact(  # noqa: PLR0913
    artifact_dir: Path,
    *,
    cadence_anchor_at: str | None,
    cadence_seconds: float | None,
    boundary_tolerance_seconds: float = _DEFAULT_BOUNDARY_TOLERANCE_SECONDS,
    controlled_get_mi: Collection[Mapping[str, str]] | None = None,
    expected_on_ari_families: Mapping[str, Mapping[str, int]] | None = None,
) -> dict[str, Any]:
    """Classify captured timing after the run without changing opaque bytes."""
    artifact = load_verified_phase2_artifact(artifact_dir)
    anchor = _parse_timestamp(cadence_anchor_at) if cadence_anchor_at else None
    relevant = [
        record
        for record in artifact.records
        if record.direction == "event" and record.command in {"onMI", "onArI"}
    ]
    controls = (
        _validated_control_markers(controlled_get_mi)
        if controlled_get_mi is not None
        else _artifact_control_markers(artifact.records)
    )
    observations = _classified_observations(
        relevant,
        controls,
        anchor=anchor,
        cadence_seconds=cadence_seconds,
        boundary_tolerance_seconds=boundary_tolerance_seconds,
    )
    hypotheses = _hypothesis_report(
        observations,
        controls,
        artifact.records,
        anchor=anchor,
        cadence_seconds=cadence_seconds,
        boundary_tolerance_seconds=boundary_tolerance_seconds,
        expected_on_ari_families=(
            _EXPECTED_ON_ARI_FAMILIES
            if expected_on_ari_families is None
            else expected_on_ari_families
        ),
    )
    return {
        "analysis_version": _ANALYSIS_VERSION,
        "analysis_kind": "timing-only-repeatability-analysis",
        "capture_id": artifact.capture_id,
        "phase": artifact.phase,
        "mower_state": artifact.mower_state,
        "cadence": {
            "anchor_at": cadence_anchor_at,
            "observed_seconds": cadence_seconds,
            "boundary_tolerance_seconds": boundary_tolerance_seconds,
            "established": anchor is not None and cadence_seconds is not None,
        },
        "classification_definitions": {
            "control-associated": (
                "Within 10 seconds after controlled getMI and outside the expected "
                "periodic boundary tolerance."
            ),
            "cadence-associated": (
                "Inside the expected periodic boundary tolerance and not within "
                "10 seconds after controlled getMI."
            ),
            "ambiguous-overlap": (
                "Both control and cadence timing conditions are true."
            ),
            "unclassified": "Neither timing condition is true.",
        },
        "timing_basis": {
            "unit": "integer-microseconds",
            "cadence_conversion": "round(seconds * 1000000)",
            "boundary_formula": "anchor + integer_index * cadence_microseconds",
        },
        "observations": observations,
        "hypotheses": hypotheses,
        "fixture_candidates": _fixture_candidate_report(artifact.records),
        "opaque_artifact_modified": False,
        "semantic_map_decoding": False,
        "interpretation_guard": (
            "Classification is timing-only and does not assign semantic map roles "
            "to any opaque representation."
        ),
    }


def build_corrected_repeatability_report(
    artifact_dir: Path,
    superseded_summary_path: Path,
) -> dict[str, Any]:
    """Reanalyze one immutable artifact and record explicit report provenance."""
    try:
        summary = orjson.loads(superseded_summary_path.read_bytes())
    except (OSError, orjson.JSONDecodeError) as err:
        raise ValueError("Superseded repeatability summary is unreadable") from err
    if not isinstance(summary, dict):
        raise TypeError("Superseded repeatability summary must be an object")
    run = summary.get("repeatability_run")
    capture = summary.get("phase2_capture")
    prior_analysis = summary.get("repeatability_analysis")
    if not isinstance(run, dict) or not isinstance(capture, dict):
        raise TypeError("Superseded summary lacks repeatability provenance")
    controls = run.get("controls")
    if not isinstance(controls, list):
        raise TypeError("Superseded summary lacks controlled getMI markers")
    analysis = analyze_repeatability_artifact(
        artifact_dir,
        cadence_anchor_at=_optional_string(run.get("cadence_anchor_at")),
        cadence_seconds=_optional_number(run.get("cadence_seconds")),
        controlled_get_mi=controls,
    )
    if capture.get("capture_id") != analysis["capture_id"]:
        raise ValueError("Summary capture_id does not match immutable artifact")
    manifest = (artifact_dir / "manifest.json").read_bytes()
    records = (artifact_dir / "records.jsonl").read_bytes()
    prior_statuses = _hypothesis_statuses(prior_analysis)
    corrected_statuses = _hypothesis_statuses(analysis)
    return {
        "schema_version": "goat-repeatability-corrected-report/v1",
        "analysis_version": analysis["analysis_version"],
        "analysis_kind": "corrected-derived-repeatability-analysis",
        "artifact_reference": {
            "capture_id": analysis["capture_id"],
            "phase": analysis["phase"],
            "artifact_directory": artifact_dir.name,
            "manifest_sha256": sha256(manifest).hexdigest(),
            "records_sha256": sha256(records).hexdigest(),
            "artifact_modified": False,
        },
        "superseded_report": {
            "filename": superseded_summary_path.name,
            "status": "superseded",
            "analysis_version": (
                prior_analysis.get("analysis_version", "unversioned-initial")
                if isinstance(prior_analysis, dict)
                else "unversioned-initial"
            ),
            "hypothesis_statuses": prior_statuses,
            "reason": (
                "Fractional-cadence boundaries were compared through separately "
                "rounded timestamp paths, creating a one-microsecond false mismatch."
            ),
        },
        "corrected_hypothesis_statuses": corrected_statuses,
        "corrected_analysis": analysis,
        "provenance_guard": (
            "This report is derived from verified immutable blobs and sanitized "
            "control markers; it contains no opaque payload bytes or identities."
        ),
    }


def _classified_observations(
    records: list[VerifiedArtifactRecord],
    controls: list[_ControlMarker],
    *,
    anchor: datetime | None,
    cadence_seconds: float | None,
    boundary_tolerance_seconds: float,
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    preceding_on_mi: VerifiedArtifactRecord | None = None
    previous_on_mi: dict[tuple[int, str], datetime] = {}
    on_mi_intervals: dict[str, int | None] = {}
    for record in records:
        info = _segment(record, "$.body.data.info")
        if info is None:
            continue
        observed = _parse_timestamp(record.observed_at)
        nearest_control = _nearest_preceding_control(controls, observed)
        boundary = _nearest_boundary(observed, anchor, cadence_seconds)
        control_near = nearest_control is not None and nearest_control[1] <= round(
            _CONTROL_ASSOCIATION_SECONDS * _MICROSECONDS_PER_SECOND
        )
        cadence_near = boundary is not None and abs(boundary[1]) <= round(
            boundary_tolerance_seconds * _MICROSECONDS_PER_SECOND
        )
        classification = _timing_classification(control_near, cadence_near)
        previous_interval_microseconds = None
        preceding = None
        if record.command == "onMI":
            key = (len(info.raw), info.sha256)
            if key in previous_on_mi:
                previous_interval_microseconds = _duration_microseconds(
                    observed - previous_on_mi[key]
                )
            previous_on_mi[key] = observed
            on_mi_intervals[record.observed_at] = previous_interval_microseconds
            preceding_on_mi = record
        elif preceding_on_mi is not None:
            preceding_info = _segment(preceding_on_mi, "$.body.data.info")
            if preceding_info is not None:
                key = (len(preceding_info.raw), preceding_info.sha256)
                preceding_delta_microseconds = _duration_microseconds(
                    observed - _parse_timestamp(preceding_on_mi.observed_at)
                )
                preceding_interval = on_mi_intervals.get(preceding_on_mi.observed_at)
                preceding = {
                    "timestamp": preceding_on_mi.observed_at,
                    "delta_seconds": preceding_delta_microseconds
                    / _MICROSECONDS_PER_SECOND,
                    "delta_microseconds": preceding_delta_microseconds,
                    "representation_length": len(preceding_info.raw),
                    "representation_sha256": preceding_info.sha256,
                    "previous_identical_form_interval_seconds": (
                        preceding_interval / _MICROSECONDS_PER_SECOND
                        if preceding_interval is not None
                        else None
                    ),
                    "previous_identical_form_interval_microseconds": (
                        preceding_interval
                    ),
                }
        observations.append(
            {
                "command": record.command,
                "timestamp": record.observed_at,
                "window": record.window,
                "transport": record.transport,
                "representation_length": len(info.raw),
                "representation_sha256": info.sha256,
                "nearest_preceding_get_mi": (
                    {
                        "timestamp": nearest_control[0].observed_at,
                        "control_transport": nearest_control[0].transport,
                        "delta_seconds": nearest_control[1] / _MICROSECONDS_PER_SECOND,
                        "delta_microseconds": nearest_control[1],
                    }
                    if nearest_control is not None
                    else None
                ),
                "delta_to_previous_identical_on_mi_form_seconds": (
                    previous_interval_microseconds / _MICROSECONDS_PER_SECOND
                    if previous_interval_microseconds is not None
                    else None
                ),
                "delta_to_previous_identical_on_mi_form_microseconds": (
                    previous_interval_microseconds
                ),
                "preceding_on_mi": preceding,
                "expected_periodic_boundary": (
                    {
                        "timestamp": boundary[0].isoformat(),
                        "delta_seconds": boundary[1] / _MICROSECONDS_PER_SECOND,
                        "delta_microseconds": boundary[1],
                    }
                    if boundary is not None
                    else None
                ),
                "classification": classification,
            }
        )
    return observations


def _hypothesis_report(  # noqa: PLR0913
    observations: list[dict[str, Any]],
    controls: list[_ControlMarker],
    records: tuple[VerifiedArtifactRecord, ...],
    *,
    anchor: datetime | None,
    cadence_seconds: float | None,
    boundary_tolerance_seconds: float,
    expected_on_ari_families: Mapping[str, Mapping[str, int]],
) -> dict[str, Any]:
    on_mi = [item for item in observations if item["command"] == "onMI"]
    h1_support: list[dict[str, Any]] = []
    h1_counter: list[dict[str, Any]] = []
    for control in controls:
        after = [
            item
            for item in on_mi
            if item["nearest_preceding_get_mi"] is not None
            and item["nearest_preceding_get_mi"]["timestamp"] == control.observed_at
            and item["nearest_preceding_get_mi"]["delta_microseconds"]
            <= round(_CONTROL_ASSOCIATION_SECONDS * _MICROSECONDS_PER_SECOND)
        ]
        matching = [
            item
            for item in after
            if item["representation_length"] == _LONG_REPRESENTATION_LENGTH
            and item["classification"] == "control-associated"
        ]
        evidence = {
            "control_timestamp": control.observed_at,
            "control_transport": control.transport,
            "following_on_mi": after,
        }
        (h1_support if matching else h1_counter).append(evidence)

    boundaries = _boundaries_in_capture(records, anchor, cadence_seconds)
    h2_support: list[dict[str, Any]] = []
    h2_counter: list[dict[str, Any]] = []
    h3_support: list[dict[str, Any]] = []
    h3_counter: list[dict[str, Any]] = []
    for boundary in boundaries:
        near = [
            item
            for item in on_mi
            if item["expected_periodic_boundary"] is not None
            and item["expected_periodic_boundary"]["timestamp"] == boundary.isoformat()
            and abs(item["expected_periodic_boundary"]["delta_microseconds"])
            <= round(boundary_tolerance_seconds * _MICROSECONDS_PER_SECOND)
        ]
        natural = [
            item
            for item in near
            if item["representation_length"] == _SHORT_REPRESENTATION_LENGTH
            and item["classification"] == "cadence-associated"
        ]
        evidence = {"expected_boundary": boundary.isoformat(), "observations": near}
        (h2_support if natural else h2_counter).append(evidence)
        prior_controls = [
            control
            for control in controls
            if 0
            < _duration_microseconds(boundary - _parse_timestamp(control.observed_at))
            < _cadence_microseconds(cadence_seconds or 0)
        ]
        if prior_controls:
            shifted = not natural
            evidence = {
                **evidence,
                "preceding_controls": [
                    {
                        "timestamp": item.observed_at,
                        "control_transport": item.transport,
                    }
                    for item in prior_controls
                ],
            }
            (h3_counter if shifted else h3_support).append(evidence)

    h4_support: list[dict[str, Any]] = []
    h4_counter: list[dict[str, Any]] = []
    observed_expected_digests: set[str] = set()
    for item in observations:
        expected = expected_on_ari_families.get(item["representation_sha256"])
        if item["command"] != "onArI" or expected is None:
            continue
        observed_expected_digests.add(item["representation_sha256"])
        preceding = item["preceding_on_mi"]
        h4_evidence: dict[str, Any] = {
            "expected": dict(expected),
            "observation": item,
        }
        if (
            item["representation_length"] == expected["length"]
            and preceding is not None
            and preceding["representation_length"] == expected["on_mi_length"]
        ):
            h4_support.append(h4_evidence)
        else:
            h4_counter.append(h4_evidence)
    missing_h4 = sorted(set(expected_on_ari_families) - observed_expected_digests)
    h4_transport_coverage = _h4_transport_coverage(h4_support)
    control_family_digests = [
        digest
        for digest, expected in expected_on_ari_families.items()
        if expected["on_mi_length"] == _LONG_REPRESENTATION_LENGTH
    ]
    missing_transport_coverage = [
        digest
        for digest in control_family_digests
        if not {"legacy", "ngiot"}.issubset(set(h4_transport_coverage.get(digest, [])))
    ]
    h4 = _hypothesis(
        "Stable onArI families follow their observed onMI form independent "
        "of legacy/N-GIoT control transport.",
        h4_support,
        h4_counter,
        required_count=len(expected_on_ari_families),
    )
    if h4["status"] == "supported-in-this-capture" and (
        missing_h4 or missing_transport_coverage
    ):
        h4["status"] = "inconclusive"
    return {
        "H1": _hypothesis(
            "Explicit getMI outside a periodic boundary yields 876-byte onMI.",
            h1_support,
            h1_counter,
            required_count=len(controls),
        ),
        "H2": _hypothesis(
            "Natural periodic boundaries yield 52-byte onMI without recent getMI.",
            h2_support,
            h2_counter,
            required_count=len(boundaries),
        ),
        "H3": _hypothesis(
            "Explicit getMI does not shift or reset the observed 52-byte cadence.",
            h3_support,
            h3_counter,
            required_count=len(controls),
        ),
        "H4": {
            **h4,
            "missing_expected_digests": missing_h4,
            "transport_coverage": h4_transport_coverage,
            "missing_transport_coverage": missing_transport_coverage,
        },
    }


def _hypothesis(
    statement: str,
    supporting: list[dict[str, Any]],
    counterexamples: list[dict[str, Any]],
    *,
    required_count: int,
) -> dict[str, Any]:
    if counterexamples:
        status = "counterexample-observed"
    elif required_count == 0 or len(supporting) < required_count:
        status = "inconclusive"
    else:
        status = "supported-in-this-capture"
    return {
        "statement": statement,
        "status": status,
        "role_proven": False,
        "supporting_observations": supporting,
        "counterexamples": counterexamples,
    }


def _fixture_candidate_report(
    records: tuple[VerifiedArtifactRecord, ...],
) -> list[dict[str, Any]]:
    observed = Counter(
        (record.command, segment.source_path, len(segment.raw), segment.sha256)
        for record in records
        for segment in record.opaque_segments
    )
    return [
        {
            "command": command,
            "source_path": source_path,
            "representation_length": length,
            "representation_sha256": digest,
            "prior_occurrence_count": occurrence_count,
            "prior_capture_count": capture_count,
            "repeatability_occurrence_count": observed[
                (command, source_path, length, digest)
            ],
            "status": "eligible-after-manual-review",
            "opaque_bytes_added_to_repository": False,
        }
        for (
            command,
            source_path,
            length,
            digest,
            occurrence_count,
            capture_count,
        ) in _FIXTURE_CANDIDATES
    ]


def _nearest_preceding_control(
    controls: list[_ControlMarker],
    observed: datetime,
) -> tuple[_ControlMarker, int] | None:
    preceding = [
        (
            record,
            _duration_microseconds(observed - _parse_timestamp(record.observed_at)),
        )
        for record in controls
        if _parse_timestamp(record.observed_at) <= observed
    ]
    if not preceding:
        return None
    record, delta = min(preceding, key=lambda item: item[1])
    return record, delta


def _nearest_boundary(
    observed: datetime,
    anchor: datetime | None,
    cadence_seconds: float | None,
) -> tuple[datetime, int] | None:
    if anchor is None or cadence_seconds is None or observed < anchor:
        return None
    cadence_microseconds = _cadence_microseconds(cadence_seconds)
    elapsed_microseconds = _duration_microseconds(observed - anchor)
    index = (elapsed_microseconds + cadence_microseconds // 2) // cadence_microseconds
    boundary = anchor + timedelta(microseconds=index * cadence_microseconds)
    return boundary, _duration_microseconds(observed - boundary)


def _boundaries_in_capture(
    records: tuple[VerifiedArtifactRecord, ...],
    anchor: datetime | None,
    cadence_seconds: float | None,
) -> list[datetime]:
    if not records or anchor is None or cadence_seconds is None:
        return []
    end = max(_parse_timestamp(record.observed_at) for record in records)
    cadence_microseconds = _cadence_microseconds(cadence_seconds)
    boundaries = []
    index = 1
    while True:
        boundary = anchor + timedelta(microseconds=index * cadence_microseconds)
        if boundary > end:
            break
        boundaries.append(boundary)
        index += 1
    return boundaries


def _cadence_microseconds(cadence_seconds: float) -> int:
    cadence_microseconds = round(cadence_seconds * _MICROSECONDS_PER_SECOND)
    if cadence_microseconds <= 0:
        raise ValueError("Cadence must be positive")
    return cadence_microseconds


def _duration_microseconds(value: timedelta) -> int:
    return (
        value.days * 86_400 * _MICROSECONDS_PER_SECOND
        + value.seconds * _MICROSECONDS_PER_SECOND
        + value.microseconds
    )


def _timing_classification(control_near: bool, cadence_near: bool) -> str:
    if control_near and cadence_near:
        return "ambiguous-overlap"
    if control_near:
        return "control-associated"
    if cadence_near:
        return "cadence-associated"
    return "unclassified"


def _control_transport(window: str) -> str:
    label = window.rsplit(":", maxsplit=1)[-1]
    if "legacy-get-mi" in label:
        return "legacy"
    if "ngiot-get-mi" in label:
        return "ngiot"
    return "unattributed"


def _validated_control_markers(
    controls: Collection[Mapping[str, str]],
) -> list[_ControlMarker]:
    markers: list[_ControlMarker] = []
    for control in controls:
        transport = control.get("transport")
        observed_at = control.get("started_at")
        if transport not in {"legacy", "ngiot"}:
            raise ValueError("Controlled getMI transport must be legacy or ngiot")
        if not observed_at:
            raise ValueError("Controlled getMI marker must have started_at")
        _parse_timestamp(observed_at)
        markers.append(_ControlMarker(observed_at=observed_at, transport=transport))
    return sorted(markers, key=lambda item: _parse_timestamp(item.observed_at))


def _artifact_control_markers(
    records: tuple[VerifiedArtifactRecord, ...],
) -> list[_ControlMarker]:
    return [
        _ControlMarker(
            observed_at=record.observed_at,
            transport=_control_transport(record.window),
        )
        for record in records
        if record.command == "getMI"
        and record.direction == "request"
        and _control_transport(record.window) in {"legacy", "ngiot"}
    ]


def _h4_transport_coverage(supporting: list[dict[str, Any]]) -> dict[str, list[str]]:
    coverage: dict[str, set[str]] = defaultdict(set)
    for evidence in supporting:
        observation = evidence["observation"]
        nearest = observation["nearest_preceding_get_mi"]
        transport = (
            nearest["control_transport"]
            if nearest is not None
            and nearest["delta_microseconds"]
            <= round(_CONTROL_ASSOCIATION_SECONDS * _MICROSECONDS_PER_SECOND)
            else "no-recent-control"
        )
        coverage[observation["representation_sha256"]].add(transport)
    return {
        digest: sorted(transports) for digest, transports in sorted(coverage.items())
    }


def _nested_info(value: Any) -> Any:
    if not isinstance(value, dict):
        return None
    body = value.get("body")
    if not isinstance(body, dict):
        return None
    data = body.get("data")
    return data.get("info") if isinstance(data, dict) else None


def _hypothesis_statuses(analysis: Any) -> dict[str, str]:
    if not isinstance(analysis, Mapping):
        return {}
    hypotheses = analysis.get("hypotheses")
    if not isinstance(hypotheses, Mapping):
        return {}
    return {
        str(name): str(value["status"])
        for name, value in hypotheses.items()
        if isinstance(value, Mapping) and isinstance(value.get("status"), str)
    }


def _optional_string(value: Any) -> str | None:
    if value is None or isinstance(value, str):
        return value
    raise ValueError("Repeatability cadence anchor is invalid")


def _optional_number(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    raise ValueError("Repeatability cadence is invalid")


def _segment(
    record: VerifiedArtifactRecord,
    source_path: str,
) -> VerifiedOpaqueSegment | None:
    return next(
        (item for item in record.opaque_segments if item.source_path == source_path),
        None,
    )


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value)
