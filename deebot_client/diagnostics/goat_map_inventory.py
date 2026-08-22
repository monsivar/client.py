"""Read-only cross-capture inventory for opaque GOAT Phase 2 artifacts."""

from __future__ import annotations

from collections import Counter, defaultdict
import csv
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import io
from itertools import pairwise
from typing import TYPE_CHECKING, Any

import orjson

from .goat_map_delta import (
    ArtifactDeltaError,
    VerifiedArtifactRecord,
    VerifiedOpaqueSegment,
    VerifiedPhase2Artifact,
    load_verified_phase2_artifact,
)
from .goat_map_representation import (
    RepresentationDecodeError,
    decode_strict_base64_representation,
)

if TYPE_CHECKING:
    from collections.abc import Collection, Sequence
    from pathlib import Path

_TIGHT_GET_MI_SECONDS = 10.0
_PERIODIC_MIN_SECONDS = 45.0
_PERIODIC_MAX_SECONDS = 75.0
_PROVEN_BASE64_FIELDS = frozenset({("onMI", "$.body.data.info")})
_FIXTURE_SOURCE_PATHS = frozenset(
    {
        "$.body.data.info",
        "$.body.data.subsets",
    }
)
_SELECTED_FIELDS = ("mid", "aid", "type")
_APP_INIT_TRIGGER_NAMES = frozenset(
    {
        "controlled-map-edit",
        "controlled-special-contour-delete",
        "official-app-open-window",
        "zone-absent-readback",
        "zone-present-readback",
    }
)


class CorpusInventoryError(ValueError):
    """The corpus or its sanitized timing metadata cannot be analyzed safely."""


@dataclass(frozen=True, slots=True)
class _GetMiReference:
    capture_id: str
    phase: str
    observed_at: str
    window: str
    transport: str
    control_transport: str
    delta_seconds: float


@dataclass(frozen=True, slots=True)
class _OnMiReference:
    observed_at: str
    delta_seconds: float
    info_length: int | None
    info_sha256: str | None


@dataclass(slots=True)
class _RecordContext:
    artifact: VerifiedPhase2Artifact
    record: VerifiedArtifactRecord
    trigger: str
    window_started_at: str | None
    seconds_from_window_start: float | None
    nearest_get_mi: _GetMiReference | None
    preceding_on_mi: _OnMiReference | None


def analyze_phase2_corpus(
    artifact_dirs: Sequence[Path],
    *,
    summary_paths: Sequence[Path] = (),
) -> dict[str, Any]:
    """Verify and inventory multiple immutable captures without decoding maps."""
    if not artifact_dirs:
        raise CorpusInventoryError("At least one Phase 2 artifact is required")
    try:
        artifacts = sorted(
            (load_verified_phase2_artifact(path) for path in artifact_dirs),
            key=lambda item: item.phase,
        )
    except ArtifactDeltaError as err:
        raise CorpusInventoryError(str(err)) from err
    capture_ids = [artifact.capture_id for artifact in artifacts]
    if len(capture_ids) != len(set(capture_ids)):
        raise CorpusInventoryError("Corpus contains a duplicate capture_id")

    window_starts, summary_metadata = _load_summary_window_starts(summary_paths)
    contexts = _record_contexts(artifacts, window_starts)
    inventory = _inventory_rows(contexts)
    on_mi = _analyze_on_mi(inventory)
    on_ari = _analyze_on_ari(inventory)
    area_set = _analyze_area_set(inventory)
    fixture_candidates = _fixture_candidates(inventory)
    assessment = _assess_corpus(on_mi, on_ari, area_set, fixture_candidates)
    return {
        "schema_version": "goat-cross-capture-inventory/v1",
        "analysis_kind": "opaque-read-only-cross-capture-inventory",
        "semantic_map_decoding": False,
        "geometry_field_mapping": False,
        "artifact_modification": False,
        "thresholds": {
            "tight_get_mi_seconds": _TIGHT_GET_MI_SECONDS,
            "approximate_periodic_interval_seconds": [
                _PERIODIC_MIN_SECONDS,
                _PERIODIC_MAX_SECONDS,
            ],
        },
        "corpus": {
            "capture_count": len(artifacts),
            "record_count": sum(len(item.records) for item in artifacts),
            "inventory_row_count": len(inventory),
            "captures": [
                {
                    "capture_id": item.capture_id,
                    "phase": item.phase,
                    "mower_state": item.mower_state,
                    "record_count": len(item.records),
                }
                for item in artifacts
            ],
            "summary_timing": summary_metadata,
        },
        "inventory": inventory,
        "analysis": {
            "on_mi_info": on_mi,
            "on_ari_info": on_ari,
            "get_area_set_subsets": area_set,
            "fixture_candidates": fixture_candidates,
            "corpus_assessment": assessment,
        },
        "interpretation_guard": (
            "All values remain opaque. Digests, lengths, timing, and occurrence "
            "relationships do not assign coordinates, geometry, areas, or map meaning."
        ),
    }


def inventory_csv(report: dict[str, Any]) -> str:
    """Render the metadata-only inventory as a stable CSV table."""
    rows = report.get("inventory")
    if not isinstance(rows, list):
        raise CorpusInventoryError("Report inventory is missing")
    fieldnames = [
        "capture_id",
        "phase",
        "mower_state",
        "window",
        "trigger",
        "context_labels",
        "command",
        "direction",
        "transport",
        "mid",
        "aid",
        "type",
        "source_path",
        "original_kind",
        "original_length",
        "original_sha256",
        "decoded_length",
        "decoded_sha256",
        "representation_layer_status",
        "timestamp",
        "window_started_at",
        "seconds_from_window_start",
        "nearest_get_mi_transport",
        "nearest_get_mi_control_transport",
        "nearest_get_mi_timestamp",
        "nearest_get_mi_delta_seconds",
    ]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        nearest = row["nearest_preceding_get_mi"] or {}
        writer.writerow(
            {
                **{name: _csv_value(row.get(name)) for name in fieldnames},
                "context_labels": "|".join(row["context_labels"]),
                "nearest_get_mi_transport": nearest.get("transport"),
                "nearest_get_mi_control_transport": nearest.get("control_transport"),
                "nearest_get_mi_timestamp": nearest.get("timestamp"),
                "nearest_get_mi_delta_seconds": nearest.get("delta_seconds"),
            }
        )
    return output.getvalue()


def _load_summary_window_starts(
    summary_paths: Sequence[Path],
) -> tuple[dict[str, str], dict[str, Any]]:
    starts: dict[str, str] = {}
    used: list[str] = []
    rejected: list[dict[str, str]] = []
    for path in sorted(summary_paths, key=str):
        try:
            document = orjson.loads(path.read_bytes())
        except FileNotFoundError as err:
            message = f"Summary file is missing: {path}"
            raise CorpusInventoryError(message) from err
        except orjson.JSONDecodeError as err:
            message = f"Summary is invalid JSON: {path}"
            raise CorpusInventoryError(message) from err
        records = document.get("records") if isinstance(document, dict) else None
        if not isinstance(records, list):
            rejected.append({"file": path.name, "reason": "records-list-missing"})
            continue
        found = False
        for record in records:
            if not isinstance(record, dict):
                continue
            if record.get("kind") != "window" or record.get("state") != "started":
                continue
            phase = record.get("phase")
            observed_at = record.get("observed_at")
            if not isinstance(phase, str) or not isinstance(observed_at, str):
                continue
            _parse_timestamp(observed_at)
            existing = starts.get(phase)
            if existing is None or observed_at < existing:
                starts[phase] = observed_at
            found = True
        if found:
            used.append(path.name)
        else:
            rejected.append({"file": path.name, "reason": "no-window-start-markers"})
    return starts, {
        "provided_file_count": len(summary_paths),
        "used_files": used,
        "ignored_files": rejected,
        "window_start_count": len(starts),
        "missing_marker_behavior": "reported-as-unavailable-not-estimated",
    }


def _record_contexts(
    artifacts: Sequence[VerifiedPhase2Artifact],
    window_starts: dict[str, str],
) -> list[_RecordContext]:
    contexts: list[_RecordContext] = []
    for artifact in artifacts:
        preceding_get_mi: list[VerifiedArtifactRecord] = []
        preceding_on_mi: list[VerifiedArtifactRecord] = []
        for record in artifact.records:
            observed = _parse_timestamp(record.observed_at)
            nearest_get_mi = None
            if preceding_get_mi:
                request = preceding_get_mi[-1]
                nearest_get_mi = _GetMiReference(
                    capture_id=artifact.capture_id,
                    phase=artifact.phase,
                    observed_at=request.observed_at,
                    window=request.window,
                    transport=request.transport,
                    control_transport=_control_transport(request.window),
                    delta_seconds=_seconds_between(request.observed_at, observed),
                )
            preceding_on_mi_ref = None
            if preceding_on_mi:
                previous = preceding_on_mi[-1]
                info = _segment(previous, "$.body.data.info")
                preceding_on_mi_ref = _OnMiReference(
                    observed_at=previous.observed_at,
                    delta_seconds=_seconds_between(previous.observed_at, observed),
                    info_length=len(info.raw) if info is not None else None,
                    info_sha256=info.sha256 if info is not None else None,
                )
            started_at = window_starts.get(record.window)
            contexts.append(
                _RecordContext(
                    artifact=artifact,
                    record=record,
                    trigger=_trigger(record.window),
                    window_started_at=started_at,
                    seconds_from_window_start=(
                        _seconds_between(started_at, observed)
                        if started_at is not None
                        else None
                    ),
                    nearest_get_mi=nearest_get_mi,
                    preceding_on_mi=preceding_on_mi_ref,
                )
            )
            if record.command == "getMI" and record.direction == "request":
                preceding_get_mi.append(record)
            if record.command == "onMI" and record.direction == "event":
                preceding_on_mi.append(record)
    return contexts


def _inventory_rows(contexts: Sequence[_RecordContext]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for context in contexts:
        record = context.record
        fields = _selected_fields(record)
        labels = _context_labels(context)
        for segment in record.opaque_segments:
            decoded_length = None
            decoded_digest = None
            representation_status = "not-proven-for-field"
            if (record.command, segment.source_path) in _PROVEN_BASE64_FIELDS:
                try:
                    decoded = decode_strict_base64_representation(
                        segment.raw.decode("ascii")
                    )
                except RepresentationDecodeError, UnicodeDecodeError:
                    representation_status = "invalid-proven-base64"
                else:
                    decoded_length = len(decoded)
                    decoded_digest = sha256(decoded).hexdigest()
                    representation_status = "strict-base64-round-trip-proven"
            rows.append(
                {
                    "capture_id": context.artifact.capture_id,
                    "phase": context.artifact.phase,
                    "mower_state": record.mower_state,
                    "window": record.window,
                    "trigger": context.trigger,
                    "context_labels": labels,
                    "command": record.command,
                    "direction": record.direction,
                    "transport": record.transport,
                    "mid": fields["mid"],
                    "aid": fields["aid"],
                    "type": fields["type"],
                    "source_path": segment.source_path,
                    "original_kind": segment.kind,
                    "original_length": len(segment.raw),
                    "original_sha256": segment.sha256,
                    "decoded_length": decoded_length,
                    "decoded_sha256": decoded_digest,
                    "representation_layer_status": representation_status,
                    "timestamp": record.observed_at,
                    "window_started_at": context.window_started_at,
                    "seconds_from_window_start": context.seconds_from_window_start,
                    "nearest_preceding_get_mi": _get_mi_dict(context.nearest_get_mi),
                    "preceding_on_mi": _on_mi_dict(context.preceding_on_mi),
                }
            )
    return rows


def _analyze_on_mi(inventory: Sequence[dict[str, Any]]) -> dict[str, Any]:
    occurrences = [
        row
        for row in inventory
        if row["command"] == "onMI"
        and row["direction"] == "event"
        and row["source_path"] == "$.body.data.info"
    ]
    variants = _variant_groups(occurrences)
    form_876 = [row for row in occurrences if row["original_length"] == 876]
    form_52 = [row for row in occurrences if row["original_length"] == 52]
    invalid_base64 = [
        _evidence(row)
        for row in occurrences
        if row["representation_layer_status"] == "invalid-proven-base64"
    ]

    near_876, counter_876 = _partition_by_recent_get_mi(form_876)
    near_52, no_recent_52 = _partition_by_recent_get_mi(form_52)
    periodic_intervals = _same_form_intervals(form_52)
    interval_support = [
        item
        for item in periodic_intervals
        if _PERIODIC_MIN_SECONDS <= item["interval_seconds"] <= _PERIODIC_MAX_SECONDS
    ]
    interval_counterexamples = [
        item for item in periodic_intervals if item not in interval_support
    ]
    return {
        "occurrence_count": len(occurrences),
        "variants": variants,
        "form_876_get_mi_association": {
            "question": "Does every observed 876-byte form follow getMI tightly?",
            "status": _hypothesis_status(form_876, counter_876),
            "tight_threshold_seconds": _TIGHT_GET_MI_SECONDS,
            "supporting_observations": [_evidence(row) for row in near_876],
            "counterexamples": [_evidence(row) for row in counter_876],
            "semantic_role_proven": False,
        },
        "form_52_periodicity": {
            "question": (
                "Does every observed 52-byte form lack a tight preceding getMI and "
                "recur at an approximately periodic interval?"
            ),
            "status": _periodic_hypothesis_status(
                form_52,
                near_52,
                interval_support,
                interval_counterexamples,
            ),
            "tight_get_mi_counterexamples": [_evidence(row) for row in near_52],
            "without_tight_get_mi": [_evidence(row) for row in no_recent_52],
            "intervals": periodic_intervals,
            "interval_counterexamples": interval_counterexamples,
            "semantic_role_proven": False,
        },
        "invalid_proven_base64_observations": invalid_base64,
        "negative_findings": [
            item
            for item in (
                (
                    "No 876-byte onMI.info observations were present."
                    if not form_876
                    else None
                ),
                (
                    "No 52-byte onMI.info observations were present."
                    if not form_52
                    else None
                ),
                (
                    "One or more onMI.info values failed the already-proven strict "
                    "Base64 representation layer."
                    if invalid_base64
                    else None
                ),
            )
            if item is not None
        ],
    }


def _analyze_on_ari(inventory: Sequence[dict[str, Any]]) -> dict[str, Any]:
    occurrences = [
        row
        for row in inventory
        if row["command"] == "onArI"
        and row["direction"] == "event"
        and row["source_path"] == "$.body.data.info"
    ]
    grouped: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in occurrences:
        grouped[(row["original_sha256"], row["original_length"])].append(row)
    variants = []
    for (digest, length), rows in sorted(grouped.items()):
        preceding_forms = Counter(_on_mi_form(row["preceding_on_mi"]) for row in rows)
        transport_counts = Counter(_nearest_control_transport(row) for row in rows)
        variants.append(
            {
                "original_sha256": digest,
                "original_length": length,
                "occurrence_count": len(rows),
                "capture_count": len({row["capture_id"] for row in rows}),
                "preceding_on_mi_forms": dict(sorted(preceding_forms.items())),
                "nearest_get_mi_control_transports": dict(
                    sorted(transport_counts.items())
                ),
                "observations": [
                    {
                        **_evidence(row),
                        "seconds_from_app_init": (
                            row["seconds_from_window_start"]
                            if "app-init-window" in row["context_labels"]
                            else None
                        ),
                        "preceding_on_mi": row["preceding_on_mi"],
                    }
                    for row in rows
                ],
            }
        )
    return {
        "occurrence_count": len(occurrences),
        "variants": variants,
        "transport_comparison": _transport_variant_comparison(occurrences),
        "causality_guard": (
            "Legacy/N-GIoT grouping is temporal context only. Variant differences "
            "are not attributed to transport without a controlled repeatability result."
        ),
        "negative_findings": [
            (
                "Strict Base64-derived bytes are not reported for onArI.info because "
                "that representation layer has not yet been established for this field."
            )
        ],
    }


def _analyze_area_set(inventory: Sequence[dict[str, Any]]) -> dict[str, Any]:
    rows = [
        row
        for row in inventory
        if row["command"] == "getAreaSet"
        and row["direction"] == "response"
        and row["source_path"] == "$.body.data.subsets"
    ]
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[
            (
                _hashable(row["mid"]),
                _hashable(row["aid"]),
                _hashable(row["type"]),
                row["original_sha256"],
                row["original_length"],
            )
        ].append(row)
    groups = [
        {
            "mid": rows_for_group[0]["mid"],
            "aid": rows_for_group[0]["aid"],
            "type": rows_for_group[0]["type"],
            "original_sha256": key[3],
            "original_length": key[4],
            "occurrence_count": len(rows_for_group),
            "capture_count": len({row["capture_id"] for row in rows_for_group}),
            "observations": [_evidence(row) for row in rows_for_group],
        }
        for key, rows_for_group in sorted(
            grouped.items(), key=lambda item: repr(item[0])
        )
    ]
    stability: list[dict[str, Any]] = []
    by_fields: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_fields[
            (_hashable(row["mid"]), _hashable(row["aid"]), _hashable(row["type"]))
        ].append(row)
    for _field_key, field_rows in sorted(
        by_fields.items(), key=lambda item: repr(item[0])
    ):
        capture_variants: dict[str, set[str]] = defaultdict(set)
        for row in field_rows:
            capture_variants[row["capture_id"]].add(row["original_sha256"])
        stability.append(
            {
                "mid": field_rows[0]["mid"],
                "aid": field_rows[0]["aid"],
                "type": field_rows[0]["type"],
                "capture_count": len(capture_variants),
                "digests": sorted({row["original_sha256"] for row in field_rows}),
                "stable_within_each_capture": all(
                    len(digests) == 1 for digests in capture_variants.values()
                ),
                "stable_across_captures": len(
                    {row["original_sha256"] for row in field_rows}
                )
                == 1,
                "per_capture": [
                    {
                        "capture_id": capture_id,
                        "digests": sorted(digests),
                    }
                    for capture_id, digests in sorted(capture_variants.items())
                ],
            }
        )
    type_counts = Counter(str(row["type"]) for row in rows)
    return {
        "occurrence_count": len(rows),
        "groups": groups,
        "stability": stability,
        "types": {
            "ar": type_counts.pop("ar", 0),
            "vw": type_counts.pop("vw", 0),
            "other": dict(sorted(type_counts.items())),
        },
        "semantic_interpretation": False,
        "negative_findings": (
            ["No getAreaSet response subsets were captured."] if not rows else []
        ),
    }


def _fixture_candidates(inventory: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in inventory:
        if row["source_path"] not in _FIXTURE_SOURCE_PATHS:
            continue
        groups[
            (
                row["command"],
                row["direction"],
                row["source_path"],
                row["original_kind"],
                row["original_sha256"],
                row["original_length"],
            )
        ].append(row)
    candidates = []
    for key, rows in sorted(groups.items(), key=lambda item: repr(item[0])):
        captures = sorted({row["capture_id"] for row in rows})
        contexts = sorted({label for row in rows for label in row["context_labels"]})
        if len(rows) < 2 or len(captures) < 2 or len(contexts) < 2:
            continue
        candidates.append(
            {
                "command": key[0],
                "direction": key[1],
                "source_path": key[2],
                "original_kind": key[3],
                "original_sha256": key[4],
                "original_length": key[5],
                "occurrence_count": len(rows),
                "capture_count": len(captures),
                "capture_ids": captures,
                "contexts": contexts,
                "decoded_lengths": sorted(
                    {
                        row["decoded_length"]
                        for row in rows
                        if row["decoded_length"] is not None
                    }
                ),
                "decoded_sha256": sorted(
                    {
                        row["decoded_sha256"]
                        for row in rows
                        if row["decoded_sha256"] is not None
                    }
                ),
                "repository_safe_assessment": "eligible-after-manual-review",
                "assessment_basis": (
                    "Byte-identical in multiple captures and contexts; source "
                    "artifacts passed fail-closed capture validation. Raw content "
                    "must still be manually reviewed before repository inclusion."
                ),
                "observations": [_evidence(row) for row in rows],
            }
        )
    return candidates


def _assess_corpus(
    on_mi: dict[str, Any],
    on_ari: dict[str, Any],
    area_set: dict[str, Any],
    fixtures: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    mi_876 = on_mi["form_876_get_mi_association"]
    mi_52 = on_mi["form_52_periodicity"]
    counterexamples = bool(mi_876["counterexamples"]) or bool(
        mi_52["tight_get_mi_counterexamples"] or mi_52["interval_counterexamples"]
    )
    enough_repetition = bool(fixtures) and on_ari["occurrence_count"] >= 2
    new_capture_needed = counterexamples or not enough_repetition
    reasons = []
    if counterexamples:
        reasons.append(
            "The corpus contains timing counterexamples to at least one proposed "
            "onMI form role."
        )
    if not enough_repetition:
        reasons.append(
            "The corpus lacks repeated cross-capture/context candidates for one or "
            "more requested comparisons."
        )
    if not reasons:
        reasons.append(
            "The existing corpus has repeated opaque values across captures and no "
            "timing counterexample under the declared thresholds."
        )
    if area_set["occurrence_count"] == 0:
        reasons.append("No getAreaSet.subsets observations are available.")
    return {
        "sufficient_for_current_non_semantic_inventory": True,
        "sufficient_to_prove_semantic_roles": False,
        "non_editing_repeatability_capture_needed": new_capture_needed,
        "recommendation": (
            "run-controlled-non-editing-repeatability-capture"
            if new_capture_needed
            else "continue-read-only-framing-research-with-existing-corpus"
        ),
        "reasons": reasons,
        "decision_rule": (
            "Recommend a repeatability capture only when timing counterexamples "
            "exist or repeated cross-capture/context fixture evidence is missing."
        ),
    }


def _variant_groups(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[(row["original_sha256"], row["original_length"])].append(row)
    return [
        {
            "original_sha256": digest,
            "original_length": length,
            "decoded_sha256": sorted(
                {
                    row["decoded_sha256"]
                    for row in grouped_rows
                    if row["decoded_sha256"] is not None
                }
            ),
            "decoded_lengths": sorted(
                {
                    row["decoded_length"]
                    for row in grouped_rows
                    if row["decoded_length"] is not None
                }
            ),
            "occurrence_count": len(grouped_rows),
            "capture_count": len({row["capture_id"] for row in grouped_rows}),
            "observations": [_evidence(row) for row in grouped_rows],
        }
        for (digest, length), grouped_rows in sorted(groups.items())
    ]


def _partition_by_recent_get_mi(
    rows: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    near = []
    not_near = []
    for row in rows:
        reference = row["nearest_preceding_get_mi"]
        if (
            reference is not None
            and reference["delta_seconds"] <= _TIGHT_GET_MI_SECONDS
        ):
            near.append(row)
        else:
            not_near.append(row)
    return near, not_near


def _same_form_intervals(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    by_capture: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_capture[row["capture_id"]].append(row)
    intervals = []
    for capture_id, capture_rows in sorted(by_capture.items()):
        ordered = sorted(capture_rows, key=lambda row: row["timestamp"])
        for before, after in pairwise(ordered):
            intervals.append(
                {
                    "capture_id": capture_id,
                    "phase": before["phase"],
                    "before_timestamp": before["timestamp"],
                    "after_timestamp": after["timestamp"],
                    "interval_seconds": _seconds_between(
                        before["timestamp"], _parse_timestamp(after["timestamp"])
                    ),
                    "original_sha256": before["original_sha256"],
                }
            )
    return intervals


def _hypothesis_status(
    observations: Collection[dict[str, Any]],
    counterexamples: Collection[dict[str, Any]],
) -> str:
    if not observations:
        return "insufficient-observations"
    return "counterexamples-observed" if counterexamples else "consistent-in-corpus"


def _periodic_hypothesis_status(
    observations: Collection[dict[str, Any]],
    near_get_mi: Collection[dict[str, Any]],
    supporting_intervals: Collection[dict[str, Any]],
    interval_counterexamples: Collection[dict[str, Any]],
) -> str:
    if not observations or not supporting_intervals:
        return "insufficient-observations"
    if near_get_mi or interval_counterexamples:
        return "counterexamples-observed"
    return "consistent-in-corpus"


def _transport_variant_comparison(
    rows: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    counts: dict[str, Counter[tuple[str, int]]] = defaultdict(Counter)
    for row in rows:
        counts[_nearest_control_transport(row)][
            (row["original_sha256"], row["original_length"])
        ] += 1
    return [
        {
            "control_transport": transport,
            "variants": [
                {
                    "original_sha256": digest,
                    "original_length": length,
                    "occurrence_count": count,
                }
                for (digest, length), count in sorted(variants.items())
            ],
        }
        for transport, variants in sorted(counts.items())
    ]


def _evidence(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "capture_id": row["capture_id"],
        "phase": row["phase"],
        "timestamp": row["timestamp"],
        "window": row["window"],
        "trigger": row["trigger"],
        "transport": row["transport"],
        "original_sha256": row["original_sha256"],
        "original_length": row["original_length"],
        "nearest_preceding_get_mi": row["nearest_preceding_get_mi"],
    }


def _context_labels(context: _RecordContext) -> list[str]:
    labels = []
    if context.trigger in _APP_INIT_TRIGGER_NAMES:
        labels.append("app-init-window")
    if "legacy-get-mi" in context.trigger or "ngiot-get-mi" in context.trigger:
        labels.append("explicit-getMI-window")
    if context.trigger == "frontend-reload-window":
        labels.append("frontend-reload-window")
    if (
        context.record.direction == "event"
        and context.record.command in {"onMI", "onArI"}
        and (
            context.nearest_get_mi is None
            or context.nearest_get_mi.delta_seconds > _TIGHT_GET_MI_SECONDS
        )
        and "app-init-window" not in labels
    ):
        labels.append("periodic-stream-candidate")
    if not labels:
        labels.append("other-observed-window")
    return labels


def _selected_fields(record: VerifiedArtifactRecord) -> dict[str, Any]:
    fields: dict[str, Any] = dict.fromkeys(_SELECTED_FIELDS)
    for name in _SELECTED_FIELDS:
        values = _find_key_values(record.sanitized_envelope, name)
        visible = [value for value in values if not _is_redacted(value)]
        if visible:
            fields[name] = visible[0] if len(visible) == 1 else visible
        segment = next(
            (
                item
                for item in record.opaque_segments
                if item.source_path.endswith(f".{name}")
            ),
            None,
        )
        if segment is not None:
            fields[name] = _segment_scalar(segment)
    if fields["mid"] is None and len(record.map_ids) == 1:
        fields["mid"] = record.map_ids[0]
    return fields


def _find_key_values(value: Any, key: str) -> list[Any]:
    if isinstance(value, dict):
        found = [item for item_key, item in value.items() if item_key == key]
        for item in value.values():
            found.extend(_find_key_values(item, key))
        return found
    if isinstance(value, list):
        return [found for item in value for found in _find_key_values(item, key)]
    return []


def _segment_scalar(segment: VerifiedOpaqueSegment) -> Any:
    try:
        if segment.kind == "json-string-utf8-value":
            return segment.raw.decode("utf-8")
        if segment.kind == "canonical-json-v1":
            return orjson.loads(segment.raw)
    except (UnicodeDecodeError, orjson.JSONDecodeError) as err:
        message = f"Selected field blob is invalid: {segment.source_path}"
        raise CorpusInventoryError(message) from err
    message = f"Selected field has unsupported representation: {segment.kind}"
    raise CorpusInventoryError(message)


def _segment(
    record: VerifiedArtifactRecord,
    source_path: str,
) -> VerifiedOpaqueSegment | None:
    return next(
        (item for item in record.opaque_segments if item.source_path == source_path),
        None,
    )


def _trigger(window: str) -> str:
    return window.rsplit(":", maxsplit=1)[-1]


def _control_transport(window: str) -> str:
    trigger = _trigger(window)
    if "legacy-get-mi" in trigger:
        return "legacy"
    if "ngiot-get-mi" in trigger:
        return "ngiot"
    return "unattributed-external-or-background"


def _get_mi_dict(reference: _GetMiReference | None) -> dict[str, Any] | None:
    if reference is None:
        return None
    return {
        "capture_id": reference.capture_id,
        "phase": reference.phase,
        "timestamp": reference.observed_at,
        "window": reference.window,
        "transport": reference.transport,
        "control_transport": reference.control_transport,
        "delta_seconds": reference.delta_seconds,
    }


def _on_mi_dict(reference: _OnMiReference | None) -> dict[str, Any] | None:
    if reference is None:
        return None
    return {
        "timestamp": reference.observed_at,
        "delta_seconds": reference.delta_seconds,
        "info_length": reference.info_length,
        "info_sha256": reference.info_sha256,
    }


def _on_mi_form(reference: dict[str, Any] | None) -> str:
    if reference is None:
        return "none"
    length = reference["info_length"]
    if length in {52, 876}:
        return f"{length}-byte"
    return f"other:{length}"


def _nearest_control_transport(row: dict[str, Any]) -> str:
    reference = row["nearest_preceding_get_mi"]
    return (
        reference["control_transport"]
        if reference is not None
        else "no-preceding-getMI"
    )


def _parse_timestamp(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except ValueError as err:
        message = f"Invalid ISO timestamp: {value}"
        raise CorpusInventoryError(message) from err


def _seconds_between(before: str, after: datetime) -> float:
    seconds = (after - _parse_timestamp(before)).total_seconds()
    if seconds < 0:
        raise CorpusInventoryError("Artifact timestamps are not monotonic")
    return round(seconds, 6)


def _is_redacted(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("<redacted:")


def _hashable(value: Any) -> Any:
    return orjson.dumps(value) if isinstance(value, (dict, list)) else value


def _csv_value(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return orjson.dumps(value).decode()
    return value
