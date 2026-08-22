"""Read-only, non-semantic deltas for Phase 2 GOAT capture artifacts."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from hashlib import sha256
from itertools import zip_longest
import re
from typing import TYPE_CHECKING, Any

import orjson

from .goat_map_representation import (
    RepresentationDecodeError,
    decode_strict_base64_representation,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Collection
    from pathlib import Path

_SCHEMA_VERSION = "goat-static-map-capture/v1"
_CAPTURE_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_BLOB_REFERENCE_PATTERN = re.compile(r"^blobs/([0-9a-f]{64})\.bin$")
_SELECTED_FIELD_NAMES = frozenset({"mid", "mapId", "mapID", "aid", "type", "infoSize"})
_MISSING = object()


class ArtifactDeltaError(ValueError):
    """A capture artifact cannot be safely or consistently compared."""


@dataclass(slots=True)
class _Variant:
    raw: bytes
    byte_length: int
    count: int = 0
    sequences: list[int] = field(default_factory=list)


@dataclass(slots=True)
class _Artifact:
    capture_id: str
    phase: str
    selected_record_count: int
    groups: dict[tuple[Any, ...], dict[str, _Variant]]
    fields: dict[tuple[Any, ...], Counter[str]]


@dataclass(frozen=True, slots=True)
class VerifiedOpaqueSegment:
    """One content-addressed opaque value verified against its artifact blob."""

    source_path: str
    kind: str
    sha256: str
    raw: bytes


@dataclass(frozen=True, slots=True)
class VerifiedArtifactRecord:
    """One ordered, sanitized Phase 2 record with verified opaque segments."""

    sequence: int
    observed_at: str
    window: str
    mower_state: str
    command: str
    direction: str
    transport: str
    map_ids: tuple[str, ...]
    sanitized_envelope: dict[str, Any] | list[Any]
    opaque_segments: tuple[VerifiedOpaqueSegment, ...]


@dataclass(frozen=True, slots=True)
class VerifiedPhase2Artifact:
    """Read-only verified artifact data suitable for non-semantic analysis."""

    capture_id: str
    phase: str
    mower_state: str
    records: tuple[VerifiedArtifactRecord, ...]


def compare_phase2_artifacts(
    before_artifact: Path,
    after_artifact: Path,
) -> dict[str, Any]:
    """Verify and compare two artifacts without modifying or interpreting them."""
    before = _load_artifact(before_artifact)
    after = _load_artifact(after_artifact)
    return _compare_loaded_artifacts(before, after)


def compare_phase2_artifact_windows(
    artifact_dir: Path,
    *,
    before_window: str,
    after_window: str,
    commands: Collection[str] | None = None,
) -> dict[str, Any]:
    """Compare two verified record windows in one immutable artifact."""
    command_filter = frozenset(commands) if commands is not None else None

    def selected(window: str) -> Callable[[dict[str, Any]], bool]:
        return lambda record: (
            record.get("window") == window
            and (command_filter is None or record.get("command") in command_filter)
        )

    before = _load_artifact(artifact_dir, record_filter=selected(before_window))
    after = _load_artifact(artifact_dir, record_filter=selected(after_window))
    report = _compare_loaded_artifacts(before, after)
    report["selection"] = {
        "artifact_capture_id": before.capture_id,
        "before_window": before_window,
        "after_window": after_window,
        "commands": sorted(command_filter) if command_filter is not None else None,
    }
    return report


def compare_special_contour_readbacks(artifact_dir: Path) -> dict[str, Any]:
    """Compare zone-present and post-delete SpecialContour readback windows."""
    manifest = _load_manifest(artifact_dir)
    phase = manifest["phase"]
    report = compare_phase2_artifact_windows(
        artifact_dir,
        before_window=f"{phase}:zone-present-readback",
        after_window=f"{phase}:post-delete-readback",
        commands={"getSpecialContour", "onSpecialContour"},
    )
    report["analysis_kind"] = "opaque-special-contour-inverse-operation-delta"
    report["operation_labels"] = {
        "before": "zone-present-readback",
        "after": "post-delete-readback",
        "semantic_interpretation": False,
    }
    return report


def compare_special_contour_present_to_absent(
    present_artifact: Path,
    absent_artifact: Path,
) -> dict[str, Any]:
    """Compare verified present and passive absent-state readback windows."""
    present_manifest = _load_manifest(present_artifact)
    absent_manifest = _load_manifest(absent_artifact)
    commands = frozenset({"getSpecialContour", "onSpecialContour"})

    def selected(window: str) -> Callable[[dict[str, Any]], bool]:
        return lambda record: (
            record.get("window") == window and record.get("command") in commands
        )

    present_window = f"{present_manifest['phase']}:zone-present-readback"
    absent_window = f"{absent_manifest['phase']}:zone-absent-readback"
    before = _load_artifact(
        present_artifact,
        record_filter=selected(present_window),
    )
    after = _load_artifact(
        absent_artifact,
        record_filter=selected(absent_window),
    )
    report = _compare_loaded_artifacts(before, after)
    report["analysis_kind"] = "opaque-special-contour-present-absent-delta"
    report["selection"] = {
        "before_window": present_window,
        "after_window": absent_window,
        "commands": sorted(commands),
    }
    report["operation_labels"] = {
        "before": "zone-present-readback",
        "after": "zone-absent-readback",
        "semantic_interpretation": False,
    }
    return report


def validate_delta_output_path(output: Path, *artifact_dirs: Path) -> None:
    """Prevent a report from modifying any immutable input artifact."""
    output_path = output.resolve()
    for artifact in artifact_dirs:
        artifact_path = artifact.resolve()
        if output_path == artifact_path or artifact_path in output_path.parents:
            raise ValueError("Delta output must be outside all input artifacts")


def load_verified_phase2_artifact(artifact_dir: Path) -> VerifiedPhase2Artifact:
    """Load and cryptographically verify an immutable Phase 2 artifact."""
    manifest = _load_manifest(artifact_dir)
    records_path = artifact_dir / "records.jsonl"
    try:
        lines = records_path.read_bytes().splitlines()
    except FileNotFoundError as err:
        raise ArtifactDeltaError("Artifact records file is missing") from err
    if manifest.get("record_count") != len(lines):
        raise ArtifactDeltaError("Artifact record count does not match manifest")

    records: list[VerifiedArtifactRecord] = []
    for expected_sequence, line in enumerate(lines, start=1):
        record = _parse_record(line, expected_sequence)
        records.append(
            VerifiedArtifactRecord(
                sequence=expected_sequence,
                observed_at=_required_record_string(record, "observed_at"),
                window=_required_record_string(record, "window"),
                mower_state=_required_record_string(record, "mower_state"),
                command=record["command"],
                direction=record["direction"],
                transport=record["transport"],
                map_ids=tuple(record["map_ids"]),
                sanitized_envelope=record["sanitized_envelope"],
                opaque_segments=tuple(
                    VerifiedOpaqueSegment(source_path, kind, digest, raw)
                    for source_path, kind, digest, raw in (
                        _load_segment(artifact_dir, segment)
                        for segment in record["opaque_segments"]
                    )
                ),
            )
        )
    mower_state = manifest.get("mower_state")
    if not isinstance(mower_state, str) or not mower_state:
        raise ArtifactDeltaError("Artifact mower_state is invalid")
    return VerifiedPhase2Artifact(
        capture_id=manifest["capture_id"],
        phase=manifest["phase"],
        mower_state=mower_state,
        records=tuple(records),
    )


def _compare_loaded_artifacts(
    before: _Artifact,
    after: _Artifact,
) -> dict[str, Any]:
    group_keys = sorted(set(before.groups) | set(after.groups), key=repr)
    observed_groups = [
        _compare_group(
            key,
            before.groups.get(key, {}),
            after.groups.get(key, {}),
        )
        for key in group_keys
    ]
    missing_roles = [
        role
        for role, artifact in (("before", before), ("after", after))
        if artifact.selected_record_count == 0
    ]
    presence_absence = [
        _presence_absence_observation(group)
        for group in observed_groups
        if group["status"] in {"before-only", "after-only"}
    ]
    groups = [
        group
        for group in observed_groups
        if group["status"] not in {"before-only", "after-only"}
    ]
    incomplete = bool(missing_roles)
    changed_group_count = (
        None
        if incomplete
        else sum(
            group["status"] in {"changed", "occurrence-count-changed"}
            for group in groups
        )
    )
    proven_byte_delta_group_count = (
        0
        if incomplete
        else sum(_group_has_proven_byte_delta(group) for group in groups)
    )
    return {
        "schema_version": "goat-static-map-delta/v1",
        "analysis_kind": "opaque-artifact-byte-delta",
        "semantic_map_decoding": False,
        "geometry_field_mapping": False,
        "before": {"capture_id": before.capture_id, "phase": before.phase},
        "after": {"capture_id": after.capture_id, "phase": after.phase},
        "comparison_status": "incomplete" if incomplete else "complete",
        "comparison_result": "not_comparable" if incomplete else "comparable",
        "missing_roles": missing_roles,
        "side_record_counts": {
            "before": before.selected_record_count,
            "after": after.selected_record_count,
        },
        "group_count": len(groups),
        "observed_group_count": len(observed_groups),
        "changed_group_count": changed_group_count,
        "proven_byte_delta_group_count": proven_byte_delta_group_count,
        "groups": groups,
        "presence_absence_observations": presence_absence,
        "selected_field_comparison": _compare_fields(before.fields, after.fields),
        "incomplete_reason": (
            "One or more expected comparison roles contain no selected records; "
            "presence/absence observations are not a byte delta."
            if incomplete
            else None
        ),
        "interpretation_guard": (
            "Changed offsets and values are structural observations only; no byte "
            "range is assigned geometry or map semantics."
        ),
    }


def byte_diff(before: bytes, after: bytes) -> dict[str, int | None]:
    """Return offset and length metrics using zero-based, start-aligned offsets."""
    differing_offsets = [
        offset
        for offset, (left, right) in enumerate(
            zip_longest(before, after, fillvalue=_MISSING)
        )
        if left != right
    ]
    return {
        "first_differing_offset": (differing_offsets[0] if differing_offsets else None),
        "last_differing_offset": differing_offsets[-1] if differing_offsets else None,
        "different_byte_count": len(differing_offsets),
        "common_prefix_bytes": _common_prefix(before, after),
        "common_suffix_bytes": _common_suffix(before, after),
        "length_change": len(after) - len(before),
    }


def _load_artifact(
    artifact_dir: Path,
    *,
    record_filter: Callable[[dict[str, Any]], bool] | None = None,
) -> _Artifact:
    verified = load_verified_phase2_artifact(artifact_dir)

    groups: dict[tuple[Any, ...], dict[str, _Variant]] = defaultdict(dict)
    fields: dict[tuple[Any, ...], Counter[str]] = defaultdict(Counter)
    selected_record_count = 0
    for record in verified.records:
        filter_record = {
            "window": record.window,
            "command": record.command,
        }
        if record_filter is not None and not record_filter(filter_record):
            continue
        selected_record_count += 1
        command = record.command
        direction = record.direction
        transport = record.transport
        map_ids = record.map_ids
        _collect_sanitized_fields(
            record.sanitized_envelope,
            fields,
            command=command,
            direction=direction,
            map_ids=map_ids,
        )
        for segment in record.opaque_segments:
            source_path = segment.source_path
            kind = segment.kind
            digest = segment.sha256
            raw = segment.raw
            key = (command, direction, transport, map_ids, source_path, kind)
            variant = groups[key].get(digest)
            if variant is None:
                variant = _Variant(raw=raw, byte_length=len(raw))
                groups[key][digest] = variant
            variant.count += 1
            variant.sequences.append(record.sequence)
            _collect_segment_field(
                fields,
                command=command,
                direction=direction,
                map_ids=map_ids,
                source_path=source_path,
                kind=kind,
                raw=raw,
            )
    return _Artifact(
        capture_id=verified.capture_id,
        phase=verified.phase,
        selected_record_count=selected_record_count,
        groups=dict(groups),
        fields=dict(fields),
    )


def _required_record_string(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        message = f"Artifact record {key} is invalid"
        raise ArtifactDeltaError(message)
    return value


def _presence_absence_observation(group: dict[str, Any]) -> dict[str, Any]:
    """Retain one-sided data without presenting it as a byte comparison."""
    present_role = "before" if group["status"] == "before-only" else "after"
    variants = (
        group["before_variants"]
        if present_role == "before"
        else group["after_variants"]
    )
    return {
        "command": group["command"],
        "direction": group["direction"],
        "transport": group["transport"],
        "map_ids": group["map_ids"],
        "source_path": group["source_path"],
        "original_kind": group["original_kind"],
        "observation": group["status"],
        "present_role": present_role,
        "variants": variants,
        "byte_delta_proven": False,
    }


def _group_has_proven_byte_delta(group: dict[str, Any]) -> bool:
    """Return true only for a paired representation with differing bytes."""
    return any(
        comparison["original_representation_diff"]["different_byte_count"] > 0
        for comparison in group["comparisons"]
    )


def _load_manifest(artifact_dir: Path) -> dict[str, Any]:
    try:
        manifest = orjson.loads((artifact_dir / "manifest.json").read_bytes())
    except FileNotFoundError as err:
        raise ArtifactDeltaError("Artifact manifest is missing") from err
    except orjson.JSONDecodeError as err:
        raise ArtifactDeltaError("Artifact manifest is not valid JSON") from err
    if not isinstance(manifest, dict):
        raise ArtifactDeltaError("Artifact manifest must be an object")
    if manifest.get("schema_version") != _SCHEMA_VERSION:
        raise ArtifactDeltaError("Unsupported artifact schema version")
    capture_id = manifest.get("capture_id")
    if not isinstance(capture_id, str) or not _CAPTURE_ID_PATTERN.fullmatch(capture_id):
        raise ArtifactDeltaError("Artifact capture_id is invalid")
    if manifest.get("records_file") != "records.jsonl":
        raise ArtifactDeltaError("Artifact records path is not canonical")
    if manifest.get("blob_directory") != "blobs":
        raise ArtifactDeltaError("Artifact blob directory is not canonical")
    phase = manifest.get("phase")
    if not isinstance(phase, str) or not phase:
        raise ArtifactDeltaError("Artifact phase is invalid")
    return manifest


def _parse_record(raw: bytes, expected_sequence: int) -> dict[str, Any]:
    try:
        record = orjson.loads(raw)
    except orjson.JSONDecodeError as err:
        raise ArtifactDeltaError("Artifact record is not valid JSON") from err
    if not isinstance(record, dict) or record.get("sequence") != expected_sequence:
        raise ArtifactDeltaError("Artifact record sequence is invalid")
    for key in ("command", "direction", "transport"):
        if not isinstance(record.get(key), str):
            message = f"Artifact record {key} is invalid"
            raise ArtifactDeltaError(message)
    map_ids = record.get("map_ids")
    if not isinstance(map_ids, list) or any(
        not isinstance(item, str) for item in map_ids
    ):
        raise ArtifactDeltaError("Artifact record map_ids are invalid")
    if not isinstance(record.get("sanitized_envelope"), (dict, list)):
        raise ArtifactDeltaError("Artifact sanitized envelope is invalid")
    if not isinstance(record.get("opaque_segments"), list):
        raise ArtifactDeltaError("Artifact opaque segment list is invalid")
    return record


def _load_segment(
    artifact_dir: Path,
    segment: Any,
) -> tuple[str, str, str, bytes]:
    if not isinstance(segment, dict) or not isinstance(segment.get("source_path"), str):
        raise ArtifactDeltaError("Artifact opaque segment is invalid")
    source_path = segment["source_path"]
    representations = segment.get("representations")
    if (
        not isinstance(representations, dict)
        or representations.get("decoded") is not None
    ):
        raise ArtifactDeltaError("Artifact representation structure is unsupported")
    original = representations.get("original")
    if not isinstance(original, dict):
        raise ArtifactDeltaError("Artifact original representation is missing")
    kind = original.get("kind")
    digest = original.get("sha256")
    blob_ref = original.get("blob")
    byte_length = original.get("byte_length")
    if not isinstance(kind, str) or not isinstance(digest, str):
        raise ArtifactDeltaError("Artifact representation metadata is invalid")
    if not isinstance(blob_ref, str) or not isinstance(byte_length, int):
        raise ArtifactDeltaError("Artifact blob metadata is invalid")
    match = _BLOB_REFERENCE_PATTERN.fullmatch(blob_ref)
    if match is None or match.group(1) != digest:
        raise ArtifactDeltaError("Artifact blob reference is not content-addressed")
    try:
        raw = (artifact_dir / "blobs" / f"{digest}.bin").read_bytes()
    except FileNotFoundError as err:
        raise ArtifactDeltaError("Referenced artifact blob is missing") from err
    if len(raw) != byte_length:
        raise ArtifactDeltaError("Artifact blob length does not match metadata")
    if sha256(raw).hexdigest() != digest:
        raise ArtifactDeltaError("Artifact blob SHA-256 does not match content")
    return source_path, kind, digest, raw


def _compare_group(
    key: tuple[Any, ...],
    before: dict[str, _Variant],
    after: dict[str, _Variant],
) -> dict[str, Any]:
    command, direction, transport, map_ids, source_path, kind = key
    common_digests = sorted(set(before) & set(after))
    before_only = set(before) - set(after)
    after_only = set(after) - set(before)
    changed_pairs, before_unpaired, after_unpaired = _pair_changed_variants(
        before,
        after,
        before_only,
        after_only,
    )
    comparisons = [
        _compare_variants(
            digest,
            before[digest],
            digest,
            after[digest],
            pairing="identical-sha256",
            kind=kind,
        )
        for digest in common_digests
    ]
    comparisons.extend(
        _compare_variants(
            before_digest,
            before[before_digest],
            after_digest,
            after[after_digest],
            pairing=pairing,
            kind=kind,
        )
        for before_digest, after_digest, pairing in changed_pairs
    )
    if not before:
        status = "after-only"
    elif not after:
        status = "before-only"
    elif before_only or after_only:
        status = "changed"
    elif any(before[digest].count != after[digest].count for digest in common_digests):
        status = "occurrence-count-changed"
    else:
        status = "unchanged"
    return {
        "command": command,
        "direction": direction,
        "transport": transport,
        "map_ids": list(map_ids),
        "source_path": source_path,
        "original_kind": kind,
        "status": status,
        "before_variants": _variant_summaries(before),
        "after_variants": _variant_summaries(after),
        "comparisons": comparisons,
        "unpaired_before_sha256": sorted(before_unpaired),
        "unpaired_after_sha256": sorted(after_unpaired),
        "pairing_guard": (
            "Changed variants are paired only when byte length uniquely matches "
            "or exactly one unmatched variant remains on each side."
        ),
    }


def _pair_changed_variants(
    before: dict[str, _Variant],
    after: dict[str, _Variant],
    before_only: set[str],
    after_only: set[str],
) -> tuple[list[tuple[str, str, str]], set[str], set[str]]:
    pairs: list[tuple[str, str, str]] = []
    remaining_before = set(before_only)
    remaining_after = set(after_only)
    lengths = sorted(
        {before[digest].byte_length for digest in remaining_before}
        | {after[digest].byte_length for digest in remaining_after}
    )
    for byte_length in lengths:
        before_at_length = sorted(
            digest
            for digest in remaining_before
            if before[digest].byte_length == byte_length
        )
        after_at_length = sorted(
            digest
            for digest in remaining_after
            if after[digest].byte_length == byte_length
        )
        if len(before_at_length) == len(after_at_length) == 1:
            before_digest = before_at_length[0]
            after_digest = after_at_length[0]
            pairs.append((before_digest, after_digest, "unique-equal-byte-length"))
            remaining_before.remove(before_digest)
            remaining_after.remove(after_digest)
    if len(remaining_before) == len(remaining_after) == 1:
        pairs.append(
            (
                next(iter(remaining_before)),
                next(iter(remaining_after)),
                "sole-unmatched-variant",
            )
        )
        remaining_before.clear()
        remaining_after.clear()
    return pairs, remaining_before, remaining_after


def _compare_variants(  # noqa: PLR0913
    before_digest: str,
    before: _Variant,
    after_digest: str,
    after: _Variant,
    *,
    pairing: str,
    kind: str,
) -> dict[str, Any]:
    comparison: dict[str, Any] = {
        "pairing": pairing,
        "before": _variant_summary(before_digest, before),
        "after": _variant_summary(after_digest, after),
        "original_representation_diff": byte_diff(before.raw, after.raw),
        "decoded_representation": None,
    }
    if kind == "json-string-utf8-value":
        decoded = _strict_base64_pair(before.raw, after.raw)
        if decoded is not None:
            before_decoded, after_decoded = decoded
            comparison["decoded_representation"] = {
                "encoding": "strict-canonical-base64",
                "before": _raw_summary(before_decoded),
                "after": _raw_summary(after_decoded),
                "byte_diff": byte_diff(before_decoded, after_decoded),
                "semantic_interpretation": False,
            }
    return comparison


def _strict_base64_pair(before: bytes, after: bytes) -> tuple[bytes, bytes] | None:
    try:
        before_text = before.decode("ascii")
        after_text = after.decode("ascii")
        return (
            decode_strict_base64_representation(before_text),
            decode_strict_base64_representation(after_text),
        )
    except UnicodeDecodeError, RepresentationDecodeError:
        return None


def _variant_summaries(variants: dict[str, _Variant]) -> list[dict[str, Any]]:
    return [_variant_summary(digest, variants[digest]) for digest in sorted(variants)]


def _variant_summary(digest: str, variant: _Variant) -> dict[str, Any]:
    return {
        "sha256": digest,
        "byte_length": variant.byte_length,
        "occurrence_count": variant.count,
        "sequences": variant.sequences,
    }


def _raw_summary(raw: bytes) -> dict[str, Any]:
    return {"sha256": sha256(raw).hexdigest(), "byte_length": len(raw)}


def _common_prefix(before: bytes, after: bytes) -> int:
    count = 0
    for left, right in zip(before, after, strict=False):
        if left != right:
            break
        count += 1
    return count


def _common_suffix(before: bytes, after: bytes) -> int:
    count = 0
    for left, right in zip(reversed(before), reversed(after), strict=False):
        if left != right:
            break
        count += 1
    return count


def _collect_sanitized_fields(  # noqa: PLR0913
    value: Any,
    target: dict[tuple[Any, ...], Counter[str]],
    *,
    command: str,
    direction: str,
    map_ids: tuple[str, ...],
    path: str = "$",
) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            item_path = f"{path}.{key}"
            if key in _SELECTED_FIELD_NAMES and _is_public_scalar(item):
                target[(command, direction, map_ids, item_path)][
                    _serialize_scalar(item)
                ] += 1
            _collect_sanitized_fields(
                item,
                target,
                command=command,
                direction=direction,
                map_ids=map_ids,
                path=item_path,
            )
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _collect_sanitized_fields(
                item,
                target,
                command=command,
                direction=direction,
                map_ids=map_ids,
                path=f"{path}[{index}]",
            )


def _collect_segment_field(  # noqa: PLR0913
    target: dict[tuple[Any, ...], Counter[str]],
    *,
    command: str,
    direction: str,
    map_ids: tuple[str, ...],
    source_path: str,
    kind: str,
    raw: bytes,
) -> None:
    field_name = source_path.rsplit(".", maxsplit=1)[-1]
    if field_name not in _SELECTED_FIELD_NAMES:
        return
    value = _safe_segment_scalar(kind, raw)
    if value is not None:
        target[(command, direction, map_ids, source_path)][
            _serialize_scalar(value)
        ] += 1


def _safe_segment_scalar(kind: str, raw: bytes) -> str | int | float | bool | None:
    if len(raw) > 128:
        return None
    if kind == "json-string-utf8-value":
        try:
            value: Any = raw.decode("ascii")
        except UnicodeDecodeError:
            return None
    elif kind == "canonical-json-v1":
        try:
            value = orjson.loads(raw)
        except orjson.JSONDecodeError:
            return None
    else:
        return None
    return value if _is_public_scalar(value) else None


def _is_public_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) and not (
        isinstance(value, str) and value.startswith("<redacted:")
    )


def _serialize_scalar(value: str | float | bool) -> str:
    return orjson.dumps(value).decode()


def _compare_fields(
    before: dict[tuple[Any, ...], Counter[str]],
    after: dict[tuple[Any, ...], Counter[str]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for key in sorted(set(before) | set(after), key=repr):
        command, direction, map_ids, source_path = key
        before_values = before.get(key, Counter())
        after_values = after.get(key, Counter())
        result.append(
            {
                "command": command,
                "direction": direction,
                "map_ids": list(map_ids),
                "source_path": source_path,
                "status": _field_comparison_status(before_values, after_values),
                "before_values": _field_values(before_values),
                "after_values": _field_values(after_values),
            }
        )
    return result


def _field_comparison_status(
    before_values: Counter[str],
    after_values: Counter[str],
) -> str:
    """Classify value and occurrence changes independently."""
    if not before_values:
        return "after-only"
    if not after_values:
        return "before-only"
    if set(before_values) != set(after_values):
        return "value-changed"
    if before_values != after_values:
        return "occurrence-count-changed"
    return "identical"


def _field_values(values: Counter[str]) -> list[dict[str, Any]]:
    return [
        {"value": orjson.loads(serialized), "occurrence_count": values[serialized]}
        for serialized in sorted(values)
    ]
