"""Capture opaque GOAT static-map payloads without decoding them."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
import asyncio
from getpass import getpass
import logging
from pathlib import Path
import sys
from typing import TYPE_CHECKING, Any

from aiohttp import ClientSession
import orjson

if TYPE_CHECKING:
    from collections.abc import Mapping

from deebot_client.api_client import ApiClient
from deebot_client.authentication import Authenticator, create_rest_config
from deebot_client.diagnostics.goat_map_area_merge import (
    analyze_area_merge_recovery_artifact,
)
from deebot_client.diagnostics.goat_map_area_noop_save import (
    analyze_area_noop_save_artifact,
)
from deebot_client.diagnostics.goat_map_area_rename_restore import (
    analyze_area_rename_restore_artifact,
)
from deebot_client.diagnostics.goat_map_area_same_name import (
    analyze_area_same_name_artifact,
)
from deebot_client.diagnostics.goat_map_area_split import (
    AreaSplitCaptureConfig,
    GoatMapAreaSplitExperiment,
)
from deebot_client.diagnostics.goat_map_capture import (
    CONTROLLED_MAP_EDIT_CAPTURE_COMMANDS,
    CaptureLimits,
    GoatMapCaptureWriter,
)
from deebot_client.diagnostics.goat_map_phase2 import (
    ControlledMapEditConfig,
    FrontendReloadAttributionConfig,
    GoatMapControlledMapEditExperiment,
    GoatMapFrontendReloadAttributionExperiment,
    GoatMapPhase2CaptureExperiment,
    GoatMapPollerIsolationExperiment,
    GoatMapRepeatabilityExperiment,
    GoatMapSpecialContourDeleteExperiment,
    GoatMapZoneAbsentReadbackExperiment,
    Phase2CaptureConfig,
    PollerIsolationConfig,
    SpecialContourDeleteConfig,
    ZoneAbsentReadbackConfig,
)
from deebot_client.diagnostics.goat_map_refresh import MowerState
from deebot_client.diagnostics.goat_map_repeatability import (
    RepeatabilityConfig,
    analyze_repeatability_artifact,
)
from deebot_client.util import md5
from scripts.goat_map_refresh_diagnostic import (
    _prompt_verification_code,
    _run_with_compatible_event_loop,
    _select_device,
    authenticate_with_device_verification,
    load_or_create_client_device_id,
)

_DEFAULT_CLIENT_STATE_FILE = Path(".goat-map-refresh-state.json")
_DEFAULT_ARTIFACT_DIR = Path(".goat-map-phase2/p2-01-getmi-paired-mowing")
_PAIRED_MODE = "paired-get-mi"
_FRONTEND_RELOAD_MODE = "frontend-reload-attribution"
_OFFICIAL_APP_OPEN_MODE = "official-app-open-attribution"
_CONTROLLED_MAP_EDIT_MODE = "controlled-map-edit"
_SPECIAL_CONTOUR_DELETE_MODE = "controlled-special-contour-delete"
_ZONE_ABSENT_READBACK_MODE = "zone-absent-readback"
_REPEATABILITY_MODE = "repeatability"
_CONTROLLED_AREA_SPLIT_MODE = "controlled-area-split"
_CONTROLLED_AREA_MERGE_MODE = "controlled-area-merge"
_CONTROLLED_AREA_MERGE_RECOVERY_MODE = "controlled-area-merge-recovery"
_CONTROLLED_AREA_RENAME_MODE = "controlled-area-rename"
_CONTROLLED_AREA_RENAME_RESTORE_MODE = "controlled-area-rename-restore"
_CONTROLLED_AREA_NOOP_SAVE_MODE = "controlled-area-noop-save"
_CONTROLLED_AREA_SAME_NAME_MODE = "controlled-area-same-name-resubmission"
_POLLER_ISOLATION_MODE = "poller-isolation"
_P2_09C_CAPTURE_ID = "212a37d365b54f77bbb6c0424ff94246"
_P2_10_PRE_MERGE_CAPTURE_ID = "3e4377c4cb784a749696309bfcc7178d"
_P2_10D_CAPTURE_ID = "fad46b96aab44781881ce37b230ecf39"
_P2_11_CAPTURE_ID = "861a4bfd6d1f4fa9b0b24e370c6e2454"
_P2_12C_CAPTURE_ID = "12f3b733c49748ebb41e9f6f99dca307"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Capture byte-identical opaque GOAT static-map payloads into a "
            "fail-closed local artifact. No payload decoding is performed."
        )
    )
    parser.add_argument("--country", required=True, help="ISO alpha-2 country")
    parser.add_argument(
        "--mode",
        choices=[
            _PAIRED_MODE,
            _FRONTEND_RELOAD_MODE,
            _OFFICIAL_APP_OPEN_MODE,
            _CONTROLLED_MAP_EDIT_MODE,
            _SPECIAL_CONTOUR_DELETE_MODE,
            _ZONE_ABSENT_READBACK_MODE,
            _REPEATABILITY_MODE,
            _CONTROLLED_AREA_SPLIT_MODE,
            _CONTROLLED_AREA_MERGE_MODE,
            _CONTROLLED_AREA_MERGE_RECOVERY_MODE,
            _CONTROLLED_AREA_RENAME_MODE,
            _CONTROLLED_AREA_RENAME_RESTORE_MODE,
            _CONTROLLED_AREA_NOOP_SAVE_MODE,
            _CONTROLLED_AREA_SAME_NAME_MODE,
            _POLLER_ISOLATION_MODE,
        ],
        default=_PAIRED_MODE,
        help="Controlled capture sequence to run",
    )
    parser.add_argument(
        "--phase",
        default="p2-01-getmi-paired-mowing",
        help="Stable capture phase label",
    )
    parser.add_argument(
        "--mower-state",
        required=True,
        choices=[state.value for state in MowerState],
    )
    parser.add_argument("--device-class", required=True)
    parser.add_argument("--baseline-seconds", type=float, default=30)
    parser.add_argument("--live-confirmation-timeout", type=float, default=30)
    parser.add_argument("--post-get-mi-seconds", type=float, default=45)
    parser.add_argument("--cooldown-seconds", type=float, default=30)
    parser.add_argument("--tail-seconds", type=float, default=30)
    parser.add_argument("--cadence-timeout-seconds", type=float, default=150)
    parser.add_argument("--control-offset-seconds", type=float, default=25)
    parser.add_argument("--cadence-min-seconds", type=float, default=45)
    parser.add_argument("--cadence-max-seconds", type=float, default=75)
    parser.add_argument(
        "--cadence-boundary-tolerance-seconds",
        type=float,
        default=8,
    )
    parser.add_argument("--final-event-grace-seconds", type=float, default=3)
    parser.add_argument("--presence-lease-budget-seconds", type=float, default=285)
    parser.add_argument(
        "--app-init-seconds",
        type=float,
        default=45,
        help="Duration of each marked, passive pre-split app-init window",
    )
    parser.add_argument(
        "--between-init-quiet-seconds",
        type=float,
        default=10,
        help="App-closed quiet interval between pre-split app-init rounds",
    )
    parser.add_argument(
        "--post-split-seconds",
        "--post-merge-seconds",
        "--post-rename-seconds",
        "--post-restore-seconds",
        "--post-noop-save-seconds",
        "--post-same-name-seconds",
        type=float,
        default=150,
        help="Passive post-save readback duration",
    )
    parser.add_argument(
        "--post-split-reopen",
        "--post-merge-reopen",
        "--post-rename-reopen",
        "--post-restore-reopen",
        "--post-noop-save-reopen",
        "--post-same-name-reopen",
        action="store_true",
        help="Add one passive app reopen after the primary post-split readback",
    )
    parser.add_argument(
        "--post-reopen-seconds",
        "--post-merge-reopen-seconds",
        "--post-rename-reopen-seconds",
        "--post-restore-reopen-seconds",
        "--post-noop-save-reopen-seconds",
        "--post-same-name-reopen-seconds",
        type=float,
        default=60,
        help="Passive observation duration for the optional app reopen",
    )
    parser.add_argument(
        "--restoration-reference-artifact",
        type=Path,
        default=Path(".goat-map-phase2/p2-09c-controlled-area-split"),
        help="Immutable successful Divide artifact used by Area Merge",
    )
    parser.add_argument(
        "--pre-merge-reference-artifact",
        type=Path,
        default=Path(".goat-map-phase2/p2-10-controlled-area-merge"),
        help="Immutable successful pre-merge readback used by recovery analysis",
    )
    parser.add_argument(
        "--rename-reference-artifact",
        type=Path,
        default=Path(".goat-map-phase2/p2-10d-controlled-area-merge-recovery"),
        help="Immutable clean post-Merge C-state used by the rename gate",
    )
    parser.add_argument(
        "--rename-restore-reference-artifact",
        type=Path,
        default=Path(".goat-map-phase2/p2-11-controlled-area-rename"),
        help="Immutable P2-11 A/B capture used by controlled rename restore",
    )
    parser.add_argument(
        "--noop-save-reference-artifact",
        type=Path,
        default=Path(".goat-map-phase2/p2-12c-controlled-area-rename-restore"),
        help="Immutable P2-12c C-state used by the controlled no-op Save gate",
    )
    parser.add_argument(
        "--same-name-reference-artifact",
        type=Path,
        default=Path(".goat-map-phase2/p2-12c-controlled-area-rename-restore"),
        help="Immutable P2-12c C-state used by the same-name gate",
    )
    parser.add_argument(
        "--same-name-write-reference-artifact",
        type=Path,
        default=Path(".goat-map-phase2/p2-11-controlled-area-rename"),
        help="Immutable P2-11 Rename capture used for request-shape comparison",
    )
    parser.add_argument(
        "--divide-write-reference-artifact",
        type=Path,
        default=Path(".goat-map-phase2/p2-09c-controlled-area-split"),
        help="Immutable Divide capture used only for setAreaSet request-shape comparison",
    )
    parser.add_argument("--old-name-utf8-byte-length", type=int)
    parser.add_argument("--new-name-utf8-byte-length", type=int)
    parser.add_argument(
        "--post-save-seconds",
        type=float,
        default=90,
        help="Passive observation duration after the controlled save marker",
    )
    parser.add_argument(
        "--initial-readback-timeout",
        type=float,
        default=45,
        help="Maximum wait for zone-present getSpecialContour response",
    )
    parser.add_argument(
        "--post-delete-seconds",
        type=float,
        default=120,
        help="Passive observation duration after the delete action",
    )
    parser.add_argument(
        "--readback-seconds",
        type=float,
        default=120,
        help="Passive observation duration after official-app map open",
    )
    parser.add_argument(
        "--reload-window-seconds",
        "--trigger-window-seconds",
        dest="reload_window_seconds",
        type=float,
        default=90,
        help="Passive observation duration after the marked external trigger",
    )
    parser.add_argument("--connect-timeout", type=float, default=30)
    parser.add_argument(
        "--quiet-seconds",
        type=float,
        default=480,
        help="Uninterrupted passive poller-isolation observation duration",
    )
    parser.add_argument("--max-blob-mib", type=int, default=16)
    parser.add_argument("--max-total-mib", type=int, default=64)
    parser.add_argument(
        "--client-state-file",
        type=Path,
        default=_DEFAULT_CLIENT_STATE_FILE,
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=_DEFAULT_ARTIFACT_DIR,
        help="New git-ignored artifact directory; it must not already exist",
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        default=Path("goat-map-p2-01-summary.json"),
        help="Sanitized metadata-only summary report",
    )
    return parser


def _validate_args(args: argparse.Namespace) -> None:
    if args.mode in {
        _CONTROLLED_AREA_SPLIT_MODE,
        _CONTROLLED_AREA_MERGE_MODE,
        _CONTROLLED_AREA_MERGE_RECOVERY_MODE,
        _CONTROLLED_AREA_RENAME_MODE,
        _CONTROLLED_AREA_RENAME_RESTORE_MODE,
        _CONTROLLED_AREA_NOOP_SAVE_MODE,
        _CONTROLLED_AREA_SAME_NAME_MODE,
    }:
        is_merge = args.mode in {
            _CONTROLLED_AREA_MERGE_MODE,
            _CONTROLLED_AREA_MERGE_RECOVERY_MODE,
        }
        is_recovery = args.mode == _CONTROLLED_AREA_MERGE_RECOVERY_MODE
        is_rename = args.mode == _CONTROLLED_AREA_RENAME_MODE
        is_rename_restore = args.mode == _CONTROLLED_AREA_RENAME_RESTORE_MODE
        is_noop_save = args.mode == _CONTROLLED_AREA_NOOP_SAVE_MODE
        is_same_name = args.mode == _CONTROLLED_AREA_SAME_NAME_MODE
        AreaSplitCaptureConfig(
            phase=args.phase,
            mower_state=MowerState(args.mower_state),
            baseline_seconds=args.baseline_seconds,
            app_init_seconds=args.app_init_seconds,
            between_init_quiet_seconds=args.between_init_quiet_seconds,
            post_split_seconds=args.post_split_seconds,
            post_split_reopen=args.post_split_reopen,
            post_reopen_seconds=args.post_reopen_seconds,
            connect_timeout=args.connect_timeout,
            operation=(
                "same-name-resubmission"
                if is_same_name
                else "noop-save"
                if is_noop_save
                else "rename"
                if is_rename or is_rename_restore
                else "merge"
                if is_merge
                else "split"
            ),
            reference_artifact_dir=(
                str(args.same_name_reference_artifact)
                if is_same_name
                else str(args.noop_save_reference_artifact)
                if is_noop_save
                else str(args.rename_restore_reference_artifact)
                if is_rename_restore
                else str(args.rename_reference_artifact)
                if is_rename
                else str(args.restoration_reference_artifact)
                if is_merge
                else None
            ),
            expected_reference_capture_id=(
                _P2_12C_CAPTURE_ID
                if is_noop_save or is_same_name
                else _P2_11_CAPTURE_ID
                if is_rename_restore
                else _P2_10D_CAPTURE_ID
                if is_rename
                else _P2_09C_CAPTURE_ID
                if is_merge
                else None
            ),
            divide_reference_artifact_dir=(
                str(args.divide_write_reference_artifact)
                if is_rename or is_rename_restore
                else None
            ),
            expected_divide_reference_capture_id=(
                _P2_09C_CAPTURE_ID if is_rename or is_rename_restore else None
            ),
            old_name_utf8_byte_length=(
                args.old_name_utf8_byte_length
                if is_rename or is_rename_restore or is_same_name
                else None
            ),
            new_name_utf8_byte_length=(
                args.new_name_utf8_byte_length
                if is_rename or is_rename_restore or is_same_name
                else None
            ),
            rename_restore=is_rename_restore,
            post_merge_recovery=is_recovery,
            pre_merge_artifact_dir=(
                str(args.pre_merge_reference_artifact) if is_recovery else None
            ),
            expected_pre_merge_capture_id=(
                _P2_10_PRE_MERGE_CAPTURE_ID if is_recovery else None
            ),
        )
    elif args.mode == _POLLER_ISOLATION_MODE:
        PollerIsolationConfig(
            phase=args.phase,
            mower_state=MowerState(args.mower_state),
            quiet_seconds=args.quiet_seconds,
            connect_timeout=args.connect_timeout,
        )
    elif args.mode == _REPEATABILITY_MODE:
        RepeatabilityConfig(
            phase=args.phase,
            mower_state=MowerState(args.mower_state),
            baseline_seconds=args.baseline_seconds,
            cadence_timeout_seconds=args.cadence_timeout_seconds,
            control_offset_seconds=args.control_offset_seconds,
            cadence_min_seconds=args.cadence_min_seconds,
            cadence_max_seconds=args.cadence_max_seconds,
            cadence_boundary_tolerance_seconds=(
                args.cadence_boundary_tolerance_seconds
            ),
            final_event_grace_seconds=args.final_event_grace_seconds,
            presence_lease_budget_seconds=args.presence_lease_budget_seconds,
            connect_timeout=args.connect_timeout,
        )
    elif args.mode == _ZONE_ABSENT_READBACK_MODE:
        ZoneAbsentReadbackConfig(
            phase=args.phase,
            mower_state=MowerState(args.mower_state),
            baseline_seconds=args.baseline_seconds,
            readback_seconds=args.readback_seconds,
            connect_timeout=args.connect_timeout,
        )
    elif args.mode == _SPECIAL_CONTOUR_DELETE_MODE:
        SpecialContourDeleteConfig(
            phase=args.phase,
            mower_state=MowerState(args.mower_state),
            baseline_seconds=args.baseline_seconds,
            initial_readback_timeout=args.initial_readback_timeout,
            post_delete_seconds=args.post_delete_seconds,
            connect_timeout=args.connect_timeout,
        )
    elif args.mode == _CONTROLLED_MAP_EDIT_MODE:
        ControlledMapEditConfig(
            phase=args.phase,
            mower_state=MowerState(args.mower_state),
            baseline_seconds=args.baseline_seconds,
            post_save_seconds=args.post_save_seconds,
            connect_timeout=args.connect_timeout,
        )
    elif args.mode in {_FRONTEND_RELOAD_MODE, _OFFICIAL_APP_OPEN_MODE}:
        FrontendReloadAttributionConfig(
            phase=args.phase,
            mower_state=MowerState(args.mower_state),
            trigger=(
                "official-app-open"
                if args.mode == _OFFICIAL_APP_OPEN_MODE
                else "frontend-reload"
            ),
            baseline_seconds=args.baseline_seconds,
            reload_window_seconds=args.reload_window_seconds,
            connect_timeout=args.connect_timeout,
        )
    else:
        Phase2CaptureConfig(
            phase=args.phase,
            mower_state=MowerState(args.mower_state),
            baseline_seconds=args.baseline_seconds,
            live_confirmation_timeout=args.live_confirmation_timeout,
            post_get_mi_seconds=args.post_get_mi_seconds,
            cooldown_seconds=args.cooldown_seconds,
            tail_seconds=args.tail_seconds,
            connect_timeout=args.connect_timeout,
        )
    CaptureLimits(
        max_blob_bytes=args.max_blob_mib * 1024 * 1024,
        max_total_bytes=args.max_total_mib * 1024 * 1024,
    )
    if args.artifact_dir.exists():
        message = f"Capture artifact already exists: {args.artifact_dir}"
        raise FileExistsError(message)


async def _run(  # noqa: C901, PLR0912, PLR0915
    args: argparse.Namespace,
    account: str,
    password: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    app_device_id = load_or_create_client_device_id(args.client_state_file)
    async with ClientSession() as session:
        rest_config = create_rest_config(
            session,
            device_id=app_device_id,
            alpha_2_country=args.country,
        )
        authenticator = Authenticator(rest_config, account, md5(password))
        try:
            await authenticate_with_device_verification(
                authenticator,
                _prompt_verification_code,
            )
            credentials = await authenticator.authenticate()
            devices = await ApiClient(authenticator).get_devices()
            mower = _select_device(devices.mqtt, args.device_class)
            passive_attribution = args.mode in {
                _FRONTEND_RELOAD_MODE,
                _OFFICIAL_APP_OPEN_MODE,
            }
            controlled_map_edit = args.mode == _CONTROLLED_MAP_EDIT_MODE
            special_contour_delete = args.mode == _SPECIAL_CONTOUR_DELETE_MODE
            zone_absent_readback = args.mode == _ZONE_ABSENT_READBACK_MODE
            repeatability = args.mode == _REPEATABILITY_MODE
            controlled_area_split = args.mode == _CONTROLLED_AREA_SPLIT_MODE
            controlled_area_merge = args.mode == _CONTROLLED_AREA_MERGE_MODE
            controlled_area_merge_recovery = (
                args.mode == _CONTROLLED_AREA_MERGE_RECOVERY_MODE
            )
            controlled_area_rename = args.mode == _CONTROLLED_AREA_RENAME_MODE
            controlled_area_rename_restore = (
                args.mode == _CONTROLLED_AREA_RENAME_RESTORE_MODE
            )
            controlled_area_noop_save = args.mode == _CONTROLLED_AREA_NOOP_SAVE_MODE
            controlled_area_same_name = args.mode == _CONTROLLED_AREA_SAME_NAME_MODE
            poller_isolation = args.mode == _POLLER_ISOLATION_MODE
            passive_capture = (
                passive_attribution
                or controlled_map_edit
                or special_contour_delete
                or zone_absent_readback
                or controlled_area_split
                or controlled_area_merge
                or controlled_area_merge_recovery
                or controlled_area_rename
                or controlled_area_rename_restore
                or controlled_area_noop_save
                or controlled_area_same_name
                or poller_isolation
            )
            attribution_trigger = (
                "official-app-open"
                if args.mode == _OFFICIAL_APP_OPEN_MODE
                else "frontend-reload"
            )
            writer = GoatMapCaptureWriter(
                args.artifact_dir,
                phase=args.phase,
                mower_state=MowerState(args.mower_state),
                device_class=mower.api["class"],
                factors={
                    "mqtt": "normal-mq",
                    "jmq": "none",
                    "appping": "none" if passive_capture else "ngiot",
                    "get_mi_sequence": ([] if passive_capture else ["legacy", "ngiot"]),
                },
                forbidden_values=(
                    account,
                    password,
                    md5(password),
                    app_device_id,
                    credentials.token,
                    credentials.user_id,
                    mower.api["did"],
                    mower.api["resource"],
                ),
                limits=CaptureLimits(
                    max_blob_bytes=args.max_blob_mib * 1024 * 1024,
                    max_total_bytes=args.max_total_mib * 1024 * 1024,
                ),
                capture_commands=(
                    CONTROLLED_MAP_EDIT_CAPTURE_COMMANDS
                    if (
                        controlled_map_edit
                        or special_contour_delete
                        or zone_absent_readback
                        or controlled_area_split
                        or controlled_area_merge
                        or controlled_area_merge_recovery
                        or controlled_area_rename
                        or controlled_area_rename_restore
                        or controlled_area_noop_save
                        or controlled_area_same_name
                    )
                    else None
                ),
            )
            if poller_isolation:
                await asyncio.to_thread(
                    input,
                    "Before the passive isolation check: confirm GOAT is paused "
                    "and stationary, Home Assistant Core is fully stopped, the "
                    "official Ecovacs app is force-closed on all known devices, "
                    "other Ecovacs/deebot_client scripts and automations are "
                    "stopped, and the app will remain closed for the entire quiet "
                    "window. Press ENTER to start the read-only observation: ",
                )
                poller_experiment = GoatMapPollerIsolationExperiment(
                    authenticator=authenticator,
                    device_info=mower,
                    device_id=app_device_id,
                    country=args.country,
                    writer=writer,
                )
                report = await poller_experiment.run(
                    PollerIsolationConfig(
                        phase=args.phase,
                        mower_state=MowerState(args.mower_state),
                        quiet_seconds=args.quiet_seconds,
                        connect_timeout=args.connect_timeout,
                    )
                )
            elif controlled_area_same_name:
                await asyncio.to_thread(
                    input,
                    "Before capture: confirm GOAT is paused and stationary, Home "
                    "Assistant Core/Ecovacs integration is stopped, the official "
                    "app is closed, no other Ecovacs client is active, and the "
                    "immutable P2-12c post-restore map state with current area "
                    "name temp1 is unchanged. This is a same-value metadata "
                    "resubmission, not a no-op. Press ENTER to start the passive "
                    "baseline: ",
                )
                same_name_experiment = GoatMapAreaSplitExperiment(
                    authenticator=authenticator,
                    device_info=mower,
                    device_id=app_device_id,
                    country=args.country,
                    writer=writer,
                )

                async def arm_same_name_app_init_1() -> None:
                    await asyncio.to_thread(
                        input,
                        "Baseline complete. Confirm the app is closed and GOAT is "
                        "paused. Press ENTER, then open the official app directly "
                        "to the temp1 map for pre-resubmission app-init 1. Make no "
                        "changes: ",
                    )

                async def prepare_same_name_app_init_2() -> None:
                    await asyncio.to_thread(
                        input,
                        "Pre-resubmission app-init 1 complete. Close the official "
                        "app. Press ENTER when it is fully closed to begin the "
                        "marked quiet interval: ",
                    )

                async def arm_same_name_app_init_2() -> None:
                    await asyncio.to_thread(
                        input,
                        "Quiet interval complete. Press ENTER, then reopen the "
                        "same temp1 map for pre-resubmission app-init 2. Make no "
                        "changes: ",
                    )

                def announce_same_name_precondition(result: Mapping[str, Any]) -> None:
                    print(
                        "PRECONDITION EVALUATION: "
                        f"status={result['status']} "
                        "gate_open="
                        f"{result['same_name_resubmission_edit_gate_open']}"
                    )
                    if result["status"] != "passed":
                        reasons = ", ".join(
                            f"{item['check']}={item['reason']}"
                            for item in result["failures"]
                        )
                        print(f"SAME-NAME RESUBMISSION ABORTED: {reasons}")

                async def arm_same_name_edit() -> None:
                    await asyncio.to_thread(
                        input,
                        "PRECONDITION PASSED. The same-name edit gate is open. "
                        "In the official app, select the same work area used in "
                        "P2-11/P2-12c and open its Rename flow. Do not change any "
                        "other value. Press ENTER when the Rename input is ready: ",
                    )

                async def confirm_same_name_ready() -> bool:
                    response = await asyncio.to_thread(
                        input,
                        'Enter exactly the currently visible area name "temp1" '
                        "again. Do not change any other value. Before Save, confirm "
                        "that the existing name was temp1, the submitted name is "
                        "also temp1, and no other value changed. Type SAME to arm "
                        "the Save window; anything else aborts before Save: ",
                    )
                    confirmed = response.strip() == "SAME"
                    if not confirmed:
                        print(
                            "SAME-NAME RESUBMISSION ABORTED BEFORE SAVE: operator "
                            "confirmation was not provided."
                        )
                    return confirmed

                async def confirm_same_name_save() -> None:
                    await asyncio.to_thread(
                        input,
                        "SAME-NAME RESUBMISSION SAVE WINDOW ARMED. Press Save "
                        "exactly once now. Press ENTER after the app shows "
                        "completion. Network timestamps are authoritative; this "
                        "marker is operator context only: ",
                    )

                async def arm_same_name_post_reopen() -> None:
                    await asyncio.to_thread(
                        input,
                        "Primary post-resubmission readback complete. Close the "
                        "app and press ENTER when it is fully closed; then reopen "
                        "the same map once without making changes: ",
                    )

                report = await same_name_experiment.run(
                    AreaSplitCaptureConfig(
                        phase=args.phase,
                        mower_state=MowerState(args.mower_state),
                        baseline_seconds=args.baseline_seconds,
                        app_init_seconds=args.app_init_seconds,
                        between_init_quiet_seconds=args.between_init_quiet_seconds,
                        post_split_seconds=args.post_split_seconds,
                        post_split_reopen=True,
                        post_reopen_seconds=args.post_reopen_seconds,
                        connect_timeout=args.connect_timeout,
                        operation="same-name-resubmission",
                        reference_artifact_dir=str(args.same_name_reference_artifact),
                        expected_reference_capture_id=_P2_12C_CAPTURE_ID,
                        old_name_utf8_byte_length=args.old_name_utf8_byte_length,
                        new_name_utf8_byte_length=args.new_name_utf8_byte_length,
                    ),
                    arm_app_init_1=arm_same_name_app_init_1,
                    prepare_app_init_2=prepare_same_name_app_init_2,
                    arm_app_init_2=arm_same_name_app_init_2,
                    arm_split_edit=arm_same_name_edit,
                    confirm_split_ready=confirm_same_name_ready,
                    confirm_save=confirm_same_name_save,
                    arm_post_reopen=arm_same_name_post_reopen,
                    announce_precondition=announce_same_name_precondition,
                )
            elif controlled_area_noop_save:
                await asyncio.to_thread(
                    input,
                    "Before capture: confirm GOAT is paused and stationary, Home "
                    "Assistant Core/Ecovacs integration is stopped, the official "
                    "app is closed, no other Ecovacs client is active, and the "
                    "immutable P2-12c post-restore map state is unchanged. Do not "
                    "open the app until requested. Press ENTER to start the "
                    "passive pre-save baseline: ",
                )
                noop_experiment = GoatMapAreaSplitExperiment(
                    authenticator=authenticator,
                    device_info=mower,
                    device_id=app_device_id,
                    country=args.country,
                    writer=writer,
                )

                async def arm_noop_app_init_1() -> None:
                    await asyncio.to_thread(
                        input,
                        "Baseline complete. Confirm the app is closed and GOAT is "
                        "paused. Press ENTER, then open the official app directly "
                        "to the unchanged map for pre-save app-init 1. Make no "
                        "changes: ",
                    )

                async def prepare_noop_app_init_2() -> None:
                    await asyncio.to_thread(
                        input,
                        "Pre-save app-init 1 complete. Close the official app. "
                        "Press ENTER when it is fully closed to begin the marked "
                        "quiet interval: ",
                    )

                async def arm_noop_app_init_2() -> None:
                    await asyncio.to_thread(
                        input,
                        "Quiet interval complete. Press ENTER, then reopen the "
                        "same unchanged map for pre-save app-init 2. Make no "
                        "changes: ",
                    )

                def announce_noop_precondition(result: Mapping[str, Any]) -> None:
                    print(
                        "PRECONDITION EVALUATION: "
                        f"status={result['status']} "
                        f"gate_open={result['noop_save_edit_gate_open']}"
                    )
                    if result["status"] != "passed":
                        reasons = ", ".join(
                            f"{item['check']}={item['reason']}"
                            for item in result["failures"]
                        )
                        print(f"NO-OP SAVE EDIT ABORTED: {reasons}")

                async def arm_noop_edit() -> None:
                    await asyncio.to_thread(
                        input,
                        "PRECONDITION PASSED. The no-op edit gate is open. In "
                        "the official app, enter Map Editing > Area and select "
                        "exactly one existing work area. Do not change anything. "
                        "Press ENTER when the Area editor is open: ",
                    )

                async def confirm_noop_ready() -> bool:
                    response = await asyncio.to_thread(
                        input,
                        "SAFETY CHECK BEFORE SAVE: confirm the Area editor is "
                        "open, no name, boundary, setting, or other data has been "
                        "changed, and Save is still active. Type NOOP to arm the "
                        "Save window. Enter anything else to abort before Save: ",
                    )
                    confirmed = response.strip() == "NOOP"
                    if not confirmed:
                        print(
                            "NO-OP SAVE ABORTED BEFORE SAVE: operator safety "
                            "confirmation was not provided."
                        )
                    return confirmed

                async def confirm_noop_save() -> None:
                    await asyncio.to_thread(
                        input,
                        "NO-OP SAVE WINDOW ARMED. Press Save exactly once now "
                        "without changing any data. Press ENTER after the app "
                        "shows completion. Network timestamps are authoritative; "
                        "this marker is operator context only: ",
                    )

                async def arm_noop_post_reopen() -> None:
                    await asyncio.to_thread(
                        input,
                        "Primary post-save readback complete. Close the app and "
                        "press ENTER when it is fully closed; then reopen the same "
                        "map once without making changes: ",
                    )

                report = await noop_experiment.run(
                    AreaSplitCaptureConfig(
                        phase=args.phase,
                        mower_state=MowerState(args.mower_state),
                        baseline_seconds=args.baseline_seconds,
                        app_init_seconds=args.app_init_seconds,
                        between_init_quiet_seconds=args.between_init_quiet_seconds,
                        post_split_seconds=args.post_split_seconds,
                        post_split_reopen=True,
                        post_reopen_seconds=args.post_reopen_seconds,
                        connect_timeout=args.connect_timeout,
                        operation="noop-save",
                        reference_artifact_dir=str(args.noop_save_reference_artifact),
                        expected_reference_capture_id=_P2_12C_CAPTURE_ID,
                    ),
                    arm_app_init_1=arm_noop_app_init_1,
                    prepare_app_init_2=prepare_noop_app_init_2,
                    arm_app_init_2=arm_noop_app_init_2,
                    arm_split_edit=arm_noop_edit,
                    confirm_split_ready=confirm_noop_ready,
                    confirm_save=confirm_noop_save,
                    arm_post_reopen=arm_noop_post_reopen,
                    announce_precondition=announce_noop_precondition,
                )
            elif controlled_area_rename_restore:
                await asyncio.to_thread(
                    input,
                    "Before capture: confirm GOAT is paused and stationary, Home "
                    "Assistant/Ecovacs integration is stopped, the official app "
                    "is closed, no other Ecovacs client is active, and the P2-11 "
                    "temporary name is still present. This controlled action is "
                    "exactly temp2 to temp1; both names are five UTF-8 bytes and "
                    "neither name is stored in the report. Press ENTER to start "
                    "the passive pre-restore baseline: ",
                )
                restore_experiment = GoatMapAreaSplitExperiment(
                    authenticator=authenticator,
                    device_info=mower,
                    device_id=app_device_id,
                    country=args.country,
                    writer=writer,
                )

                async def arm_restore_app_init_1() -> None:
                    await asyncio.to_thread(
                        input,
                        "Baseline complete. Confirm the app is closed and GOAT is "
                        "paused. Press ENTER, then open the official app directly "
                        "to the temp2 map for pre-restore app-init 1. Make no "
                        "changes: ",
                    )

                async def prepare_restore_app_init_2() -> None:
                    await asyncio.to_thread(
                        input,
                        "Pre-restore app-init 1 complete. Close the official app. "
                        "Press ENTER when it is fully closed to begin the marked "
                        "quiet interval: ",
                    )

                async def arm_restore_app_init_2() -> None:
                    await asyncio.to_thread(
                        input,
                        "Quiet interval complete. Press ENTER, then reopen the "
                        "same temp2 map for pre-restore app-init 2. Make no "
                        "changes: ",
                    )

                def announce_restore_precondition(result: Mapping[str, Any]) -> None:
                    print(
                        "PRECONDITION EVALUATION: "
                        f"status={result['status']} "
                        f"gate_open={result['rename_restore_edit_gate_open']}"
                    )
                    if result["status"] != "passed":
                        reasons = ", ".join(
                            f"{item['check']}={item['reason']}"
                            for item in result["failures"]
                        )
                        print(f"RESTORE EDIT ABORTED: {reasons}")

                async def arm_restore_edit() -> None:
                    await asyncio.to_thread(
                        input,
                        "PRECONDITION PASSED. The restore-edit gate is open. In "
                        "the official app, enter Map Editing > Area and select "
                        "exactly the same work area renamed by P2-11. Open only "
                        "its rename control. Do not change anything yet. Press "
                        "ENTER when ready: ",
                    )

                async def confirm_restore_ready() -> None:
                    await asyncio.to_thread(
                        input,
                        "Change only that area's name from temp2 back to temp1. "
                        "Do not Divide, Merge, change contours, paths, mowing "
                        "settings, or any other map object. Do not save yet. Press "
                        "ENTER when the restore preview is ready: ",
                    )

                async def confirm_restore_save() -> None:
                    await asyncio.to_thread(
                        input,
                        "RESTORE-SAVE WINDOW ARMED. Save exactly once now. Press "
                        "ENTER after the app shows completion. Network timestamps "
                        "are authoritative; this marker is operator context only: ",
                    )

                async def arm_restore_post_reopen() -> None:
                    await asyncio.to_thread(
                        input,
                        "Primary post-restore readback complete. Close the app and "
                        "press ENTER when it is fully closed; then reopen the same "
                        "map once without making changes: ",
                    )

                report = await restore_experiment.run(
                    AreaSplitCaptureConfig(
                        phase=args.phase,
                        mower_state=MowerState(args.mower_state),
                        baseline_seconds=args.baseline_seconds,
                        app_init_seconds=args.app_init_seconds,
                        between_init_quiet_seconds=args.between_init_quiet_seconds,
                        post_split_seconds=args.post_split_seconds,
                        post_split_reopen=True,
                        post_reopen_seconds=args.post_reopen_seconds,
                        connect_timeout=args.connect_timeout,
                        operation="rename",
                        reference_artifact_dir=str(
                            args.rename_restore_reference_artifact
                        ),
                        expected_reference_capture_id=_P2_11_CAPTURE_ID,
                        divide_reference_artifact_dir=str(
                            args.divide_write_reference_artifact
                        ),
                        expected_divide_reference_capture_id=_P2_09C_CAPTURE_ID,
                        old_name_utf8_byte_length=args.old_name_utf8_byte_length,
                        new_name_utf8_byte_length=args.new_name_utf8_byte_length,
                        rename_restore=True,
                    ),
                    arm_app_init_1=arm_restore_app_init_1,
                    prepare_app_init_2=prepare_restore_app_init_2,
                    arm_app_init_2=arm_restore_app_init_2,
                    arm_split_edit=arm_restore_edit,
                    confirm_split_ready=confirm_restore_ready,
                    confirm_save=confirm_restore_save,
                    arm_post_reopen=arm_restore_post_reopen,
                    announce_precondition=announce_restore_precondition,
                )
            elif controlled_area_rename:
                await asyncio.to_thread(
                    input,
                    "Before capture: confirm GOAT is paused and stationary, Home "
                    "Assistant/Ecovacs integration is stopped, the official app "
                    "is closed, no other Ecovacs client is active, the current "
                    "post-Merge map is unchanged, and one temporary ASCII-only "
                    "area name has been selected. The supplied byte lengths must "
                    "describe the old and new names; do not enter either name into "
                    "this diagnostic. Press ENTER to start the passive baseline: ",
                )
                rename_experiment = GoatMapAreaSplitExperiment(
                    authenticator=authenticator,
                    device_info=mower,
                    device_id=app_device_id,
                    country=args.country,
                    writer=writer,
                )

                async def arm_rename_app_init_1() -> None:
                    await asyncio.to_thread(
                        input,
                        "Baseline complete. Confirm the app is closed and GOAT is "
                        "paused. Press ENTER, then open the official app directly "
                        "to the current merged map for pre-rename app-init 1. Make "
                        "no changes: ",
                    )

                async def prepare_rename_app_init_2() -> None:
                    await asyncio.to_thread(
                        input,
                        "Pre-rename app-init 1 complete. Close the official app. "
                        "Press ENTER when it is fully closed to begin the marked "
                        "quiet interval: ",
                    )

                async def arm_rename_app_init_2() -> None:
                    await asyncio.to_thread(
                        input,
                        "Quiet interval complete. Press ENTER, then reopen the same "
                        "merged map for pre-rename app-init 2. Make no changes: ",
                    )

                def announce_rename_precondition(result: Mapping[str, Any]) -> None:
                    print(
                        "PRECONDITION EVALUATION: "
                        f"status={result['status']} "
                        f"gate_open={result['rename_edit_gate_open']}"
                    )
                    if result["status"] != "passed":
                        reasons = ", ".join(
                            f"{item['check']}={item['reason']}"
                            for item in result["failures"]
                        )
                        print(f"RENAME EDIT ABORTED: {reasons}")

                async def arm_rename_edit() -> None:
                    await asyncio.to_thread(
                        input,
                        "PRECONDITION PASSED. The rename-edit gate is open. In the "
                        "official app, enter Map Editing > Area and select exactly "
                        "one existing work area. Open only its rename control. Do "
                        "not change anything yet. Press ENTER when ready: ",
                    )

                async def confirm_rename_ready() -> None:
                    await asyncio.to_thread(
                        input,
                        "Change only that area's name to the preselected temporary "
                        "ASCII name. Do not Divide, Merge, change contours, paths, "
                        "mowing settings, or any other map object. Do not save yet. "
                        "Press ENTER when the rename preview is ready: ",
                    )

                async def confirm_rename_save() -> None:
                    await asyncio.to_thread(
                        input,
                        "RENAME-SAVE WINDOW ARMED. Save exactly once now. Press "
                        "ENTER after the app shows completion. Network timestamps "
                        "are authoritative; this marker is operator context only: ",
                    )

                async def arm_rename_post_reopen() -> None:
                    await asyncio.to_thread(
                        input,
                        "Primary post-rename readback complete. Close the app and "
                        "press ENTER when it is fully closed; then reopen the same "
                        "map once without making changes: ",
                    )

                report = await rename_experiment.run(
                    AreaSplitCaptureConfig(
                        phase=args.phase,
                        mower_state=MowerState(args.mower_state),
                        baseline_seconds=args.baseline_seconds,
                        app_init_seconds=args.app_init_seconds,
                        between_init_quiet_seconds=args.between_init_quiet_seconds,
                        post_split_seconds=args.post_split_seconds,
                        post_split_reopen=True,
                        post_reopen_seconds=args.post_reopen_seconds,
                        connect_timeout=args.connect_timeout,
                        operation="rename",
                        reference_artifact_dir=str(args.rename_reference_artifact),
                        expected_reference_capture_id=_P2_10D_CAPTURE_ID,
                        divide_reference_artifact_dir=str(
                            args.divide_write_reference_artifact
                        ),
                        expected_divide_reference_capture_id=_P2_09C_CAPTURE_ID,
                        old_name_utf8_byte_length=args.old_name_utf8_byte_length,
                        new_name_utf8_byte_length=args.new_name_utf8_byte_length,
                    ),
                    arm_app_init_1=arm_rename_app_init_1,
                    prepare_app_init_2=prepare_rename_app_init_2,
                    arm_app_init_2=arm_rename_app_init_2,
                    arm_split_edit=arm_rename_edit,
                    confirm_split_ready=confirm_rename_ready,
                    confirm_save=confirm_rename_save,
                    arm_post_reopen=arm_rename_post_reopen,
                    announce_precondition=announce_rename_precondition,
                )
            elif controlled_area_merge_recovery:
                await asyncio.to_thread(
                    input,
                    "Post-merge recovery only: confirm GOAT is paused and "
                    "stationary, Home Assistant/Ecovacs integration is stopped, "
                    "the official app is closed, no other client is active, and "
                    "the two P2-09c areas are now merged. Make no map changes. "
                    "Press ENTER to start the passive baseline: ",
                )
                recovery_experiment = GoatMapAreaSplitExperiment(
                    authenticator=authenticator,
                    device_info=mower,
                    device_id=app_device_id,
                    country=args.country,
                    writer=writer,
                )

                async def arm_recovery_init_1() -> None:
                    await asyncio.to_thread(
                        input,
                        "Baseline complete. Press ENTER, then open the official "
                        "app directly to the merged mower map for post-merge "
                        "app-init 1. Make no changes: ",
                    )

                async def prepare_recovery_init_2() -> None:
                    await asyncio.to_thread(
                        input,
                        "Post-merge app-init 1 complete. Close the official app. "
                        "Press ENTER when it is fully closed to begin the marked "
                        "quiet interval: ",
                    )

                async def arm_recovery_init_2() -> None:
                    await asyncio.to_thread(
                        input,
                        "Quiet interval complete. Press ENTER, then reopen the "
                        "same merged mower map for post-merge app-init 2. Make no "
                        "changes: ",
                    )

                def announce_recovery(result: Mapping[str, Any]) -> None:
                    print(
                        "POST-MERGE READBACK EVALUATION: "
                        f"status={result['status']}"
                    )
                    if result["status"] != "passed":
                        reasons = ", ".join(
                            f"{item['check']}={item['reason']}"
                            for item in result["failures"]
                        )
                        print(f"RECOVERY READBACK INCONCLUSIVE: {reasons}")

                async def unreachable_edit_callback() -> None:
                    raise RuntimeError("Recovery mode must never open an edit gate")

                report = await recovery_experiment.run(
                    AreaSplitCaptureConfig(
                        phase=args.phase,
                        mower_state=MowerState(args.mower_state),
                        baseline_seconds=args.baseline_seconds,
                        app_init_seconds=args.app_init_seconds,
                        between_init_quiet_seconds=args.between_init_quiet_seconds,
                        post_split_seconds=args.post_split_seconds,
                        post_split_reopen=False,
                        post_reopen_seconds=args.post_reopen_seconds,
                        connect_timeout=args.connect_timeout,
                        operation="merge",
                        reference_artifact_dir=str(args.restoration_reference_artifact),
                        expected_reference_capture_id=_P2_09C_CAPTURE_ID,
                        post_merge_recovery=True,
                        pre_merge_artifact_dir=str(args.pre_merge_reference_artifact),
                        expected_pre_merge_capture_id=_P2_10_PRE_MERGE_CAPTURE_ID,
                    ),
                    arm_app_init_1=arm_recovery_init_1,
                    prepare_app_init_2=prepare_recovery_init_2,
                    arm_app_init_2=arm_recovery_init_2,
                    arm_split_edit=unreachable_edit_callback,
                    confirm_split_ready=unreachable_edit_callback,
                    confirm_save=unreachable_edit_callback,
                    announce_precondition=announce_recovery,
                )
            elif controlled_area_merge:
                await asyncio.to_thread(
                    input,
                    "Before capture: confirm GOAT is paused and stationary, Home "
                    "Assistant/Ecovacs integration is stopped, the official app "
                    "is closed, no map update is in progress, no other Ecovacs "
                    "client is active, and the two areas made by P2-09c remain "
                    "separate. Press ENTER to start the passive pre-merge baseline: ",
                )
                merge_experiment = GoatMapAreaSplitExperiment(
                    authenticator=authenticator,
                    device_info=mower,
                    device_id=app_device_id,
                    country=args.country,
                    writer=writer,
                )

                async def arm_merge_app_init_1() -> None:
                    await asyncio.to_thread(
                        input,
                        "Baseline complete. Confirm the app is closed and GOAT is "
                        "paused. Press ENTER, then open the official app directly "
                        "to the split mower map for pre-merge app-init 1. Make no "
                        "changes: ",
                    )

                async def prepare_merge_app_init_2() -> None:
                    await asyncio.to_thread(
                        input,
                        "Pre-merge app-init 1 complete. Close the official app. "
                        "Press ENTER when it is fully closed to begin the marked "
                        "quiet interval: ",
                    )

                async def arm_merge_app_init_2() -> None:
                    await asyncio.to_thread(
                        input,
                        "Quiet interval complete. Press ENTER, then reopen the "
                        "same split mower map for pre-merge app-init 2. Make no "
                        "changes: ",
                    )

                def announce_merge_precondition(result: Mapping[str, Any]) -> None:
                    print(
                        "PRECONDITION EVALUATION: "
                        f"status={result['status']} "
                        f"gate_open={result['merge_edit_gate_open']}"
                    )
                    if result["status"] != "passed":
                        reasons = ", ".join(
                            f"{item['check']}={item['reason']}"
                            for item in result["failures"]
                        )
                        print(f"MERGE EDIT ABORTED: {reasons}")

                async def arm_merge_edit() -> None:
                    await asyncio.to_thread(
                        input,
                        "PRECONDITION PASSED. The merge-edit gate is open. In the "
                        "official app, enter Map Editing > Area > Merge and select "
                        "only the two work areas created by P2-09c. Press ENTER "
                        "when exactly those two areas are selected: ",
                    )

                async def confirm_merge_ready() -> None:
                    await asyncio.to_thread(
                        input,
                        "Prepare exactly one Merge of those two areas. Do not save "
                        "yet and do not change names, settings, or other map "
                        "objects. Press ENTER when the merge preview is ready: ",
                    )

                async def confirm_merge_save() -> None:
                    await asyncio.to_thread(
                        input,
                        "MERGE-SAVE WINDOW ARMED. Save exactly once now. Press "
                        "ENTER after the app shows completion. Network timestamps "
                        "are authoritative; this marker is operator context only: ",
                    )

                async def arm_merge_post_reopen() -> None:
                    await asyncio.to_thread(
                        input,
                        "Primary post-merge readback complete. Close the app and "
                        "press ENTER when it is fully closed; then reopen the same "
                        "map once without making changes: ",
                    )

                report = await merge_experiment.run(
                    AreaSplitCaptureConfig(
                        phase=args.phase,
                        mower_state=MowerState(args.mower_state),
                        baseline_seconds=args.baseline_seconds,
                        app_init_seconds=args.app_init_seconds,
                        between_init_quiet_seconds=args.between_init_quiet_seconds,
                        post_split_seconds=args.post_split_seconds,
                        post_split_reopen=args.post_split_reopen,
                        post_reopen_seconds=args.post_reopen_seconds,
                        connect_timeout=args.connect_timeout,
                        operation="merge",
                        reference_artifact_dir=str(args.restoration_reference_artifact),
                        expected_reference_capture_id=_P2_09C_CAPTURE_ID,
                    ),
                    arm_app_init_1=arm_merge_app_init_1,
                    prepare_app_init_2=prepare_merge_app_init_2,
                    arm_app_init_2=arm_merge_app_init_2,
                    arm_split_edit=arm_merge_edit,
                    confirm_split_ready=confirm_merge_ready,
                    confirm_save=confirm_merge_save,
                    arm_post_reopen=(
                        arm_merge_post_reopen if args.post_split_reopen else None
                    ),
                    announce_precondition=announce_merge_precondition,
                )
            elif controlled_area_split:
                await asyncio.to_thread(
                    input,
                    "Before capture: confirm GOAT is paused and stationary, the "
                    "official app is closed, no map update is in progress, other "
                    "users will not open the mower map, and Map Editing > Area > "
                    "Divide is available without physical boundary mapping. "
                    "Press ENTER to start the passive pre-split baseline: ",
                )
                split_experiment = GoatMapAreaSplitExperiment(
                    authenticator=authenticator,
                    device_info=mower,
                    device_id=app_device_id,
                    country=args.country,
                    writer=writer,
                )

                async def arm_split_app_init_1() -> None:
                    prompt = (
                        "Baseline complete. Confirm the official Ecovacs app is "
                        "closed and the mower is paused. Press ENTER, then open "
                        "the app directly to the mower map for pre-split app-init "
                        "1. Make no changes: "
                    )
                    await asyncio.to_thread(input, prompt)

                async def prepare_split_app_init_2() -> None:
                    prompt = (
                        "Pre-split app-init 1 complete. Close the official app. "
                        "Press ENTER when it is fully closed to begin the marked "
                        "quiet interval: "
                    )
                    await asyncio.to_thread(input, prompt)

                async def arm_split_app_init_2() -> None:
                    prompt = (
                        "Quiet interval complete. Press ENTER, then reopen the "
                        "same mower map for pre-split app-init 2. Make no changes: "
                    )
                    await asyncio.to_thread(input, prompt)

                def announce_split_precondition(result: Mapping[str, Any]) -> None:
                    print(
                        "PRECONDITION EVALUATION: "
                        f"status={result['status']} "
                        f"gate_open={result['split_edit_gate_open']}"
                    )
                    if result["status"] != "passed":
                        reasons = ", ".join(
                            f"{item['check']}={item['reason']}"
                            for item in result["failures"]
                        )
                        print(f"SPLIT EDIT ABORTED: {reasons}")

                async def arm_split_edit() -> None:
                    prompt = (
                        "PRECONDITION PASSED. The split-edit gate is open. In the "
                        "official app, enter Map Editing > Area > Divide and select "
                        "only the agreed existing work area. Press ENTER when the "
                        "divide editor is open: "
                    )
                    await asyncio.to_thread(input, prompt)

                async def confirm_split_ready() -> None:
                    prompt = (
                        "Create exactly one dividing line so one existing work "
                        "area becomes exactly two. Do not save yet and do not "
                        "change names or settings. Press ENTER when the preview is "
                        "ready: "
                    )
                    await asyncio.to_thread(input, prompt)

                async def confirm_split_save() -> None:
                    prompt = (
                        "SPLIT-SAVE WINDOW ARMED. Save exactly once now. Press "
                        "ENTER after the app shows completion. Network timestamps "
                        "are authoritative; this marker is operator context only: "
                    )
                    await asyncio.to_thread(input, prompt)

                async def arm_split_post_reopen() -> None:
                    prompt = (
                        "Primary post-split readback complete. Close the app and "
                        "press ENTER when it is fully closed; then reopen the same "
                        "map once without making changes: "
                    )
                    await asyncio.to_thread(input, prompt)

                report = await split_experiment.run(
                    AreaSplitCaptureConfig(
                        phase=args.phase,
                        mower_state=MowerState(args.mower_state),
                        baseline_seconds=args.baseline_seconds,
                        app_init_seconds=args.app_init_seconds,
                        between_init_quiet_seconds=args.between_init_quiet_seconds,
                        post_split_seconds=args.post_split_seconds,
                        post_split_reopen=args.post_split_reopen,
                        post_reopen_seconds=args.post_reopen_seconds,
                        connect_timeout=args.connect_timeout,
                    ),
                    arm_app_init_1=arm_split_app_init_1,
                    prepare_app_init_2=prepare_split_app_init_2,
                    arm_app_init_2=arm_split_app_init_2,
                    arm_split_edit=arm_split_edit,
                    confirm_split_ready=confirm_split_ready,
                    confirm_save=confirm_split_save,
                    arm_post_reopen=(
                        arm_split_post_reopen if args.post_split_reopen else None
                    ),
                    announce_precondition=announce_split_precondition,
                )
            elif repeatability:
                await asyncio.to_thread(
                    input,
                    "Confirm the official Ecovacs app is closed and the mower is "
                    "physically mowing. Press ENTER to begin the non-editing "
                    "repeatability capture: ",
                )
                repeatability_experiment = GoatMapRepeatabilityExperiment(
                    authenticator=authenticator,
                    device_info=mower,
                    device_id=app_device_id,
                    country=args.country,
                    http_session=session,
                    writer=writer,
                )
                report = await repeatability_experiment.run(
                    RepeatabilityConfig(
                        phase=args.phase,
                        mower_state=MowerState(args.mower_state),
                        baseline_seconds=args.baseline_seconds,
                        cadence_timeout_seconds=args.cadence_timeout_seconds,
                        control_offset_seconds=args.control_offset_seconds,
                        cadence_min_seconds=args.cadence_min_seconds,
                        cadence_max_seconds=args.cadence_max_seconds,
                        cadence_boundary_tolerance_seconds=(
                            args.cadence_boundary_tolerance_seconds
                        ),
                        final_event_grace_seconds=args.final_event_grace_seconds,
                        presence_lease_budget_seconds=args.presence_lease_budget_seconds,
                        connect_timeout=args.connect_timeout,
                    )
                )
            elif zone_absent_readback:
                readback_experiment = GoatMapZoneAbsentReadbackExperiment(
                    authenticator=authenticator,
                    device_info=mower,
                    device_id=app_device_id,
                    country=args.country,
                    writer=writer,
                )

                async def arm_zone_absent_app_open() -> None:
                    prompt = (
                        "Baseline complete. Confirm the official app is closed and "
                        f"the mower state is {args.mower_state}. Press ENTER, then "
                        "open the official Ecovacs app directly to the same mower "
                        "map. Make no map changes: "
                    )
                    await asyncio.to_thread(input, prompt)

                def announce_zone_absent_window(observed_at: str) -> None:
                    print(f"ZONE-ABSENT READBACK WINDOW STARTED ({observed_at})")

                report = await readback_experiment.run(
                    ZoneAbsentReadbackConfig(
                        phase=args.phase,
                        mower_state=MowerState(args.mower_state),
                        baseline_seconds=args.baseline_seconds,
                        readback_seconds=args.readback_seconds,
                        connect_timeout=args.connect_timeout,
                    ),
                    arm_app_open=arm_zone_absent_app_open,
                    announce_readback_window=announce_zone_absent_window,
                )
            elif special_contour_delete:
                delete_experiment = GoatMapSpecialContourDeleteExperiment(
                    authenticator=authenticator,
                    device_info=mower,
                    device_id=app_device_id,
                    country=args.country,
                    writer=writer,
                )

                async def arm_special_contour_app_open() -> None:
                    prompt = (
                        "Baseline complete. Confirm the mower is paused and the "
                        "official app is closed. Press ENTER, then open the mower "
                        "map. Do not delete the reduced-avoidance zone yet: "
                    )
                    await asyncio.to_thread(input, prompt)

                async def confirm_special_contour_delete() -> None:
                    prompt = (
                        "Zone-present getSpecialContour readback is captured. Delete "
                        "only the same reduced-avoidance zone. Press ENTER after the "
                        "app shows save/confirm completion: "
                    )
                    await asyncio.to_thread(input, prompt)

                def announce_present_readback(observed_at: str) -> None:
                    print(
                        f"ZONE-PRESENT SPECIALCONTOUR READBACK OBSERVED ({observed_at})"
                    )

                report = await delete_experiment.run(
                    SpecialContourDeleteConfig(
                        phase=args.phase,
                        mower_state=MowerState(args.mower_state),
                        baseline_seconds=args.baseline_seconds,
                        initial_readback_timeout=args.initial_readback_timeout,
                        post_delete_seconds=args.post_delete_seconds,
                        connect_timeout=args.connect_timeout,
                    ),
                    arm_app_open=arm_special_contour_app_open,
                    confirm_delete_save=confirm_special_contour_delete,
                    announce_present_readback=announce_present_readback,
                )
            elif controlled_map_edit:
                edit_experiment = GoatMapControlledMapEditExperiment(
                    authenticator=authenticator,
                    device_info=mower,
                    device_id=app_device_id,
                    country=args.country,
                    writer=writer,
                )

                async def arm_edit() -> None:
                    prompt = (
                        "Baseline complete. Confirm the mower is paused and the "
                        "official app is closed. Press ENTER to start the marked "
                        "controlled-map-edit window, then open the app: "
                    )
                    await asyncio.to_thread(input, prompt)

                async def confirm_save() -> None:
                    prompt = (
                        "Perform exactly one pre-agreed controlled map edit. "
                        "Press ENTER immediately after SAVE/CONFIRM: "
                    )
                    await asyncio.to_thread(input, prompt)

                def announce_edit_window(observed_at: str) -> None:
                    print(f"CONTROLLED MAP EDIT STARTED ({observed_at})")

                report = await edit_experiment.run(
                    ControlledMapEditConfig(
                        phase=args.phase,
                        mower_state=MowerState(args.mower_state),
                        baseline_seconds=args.baseline_seconds,
                        post_save_seconds=args.post_save_seconds,
                        connect_timeout=args.connect_timeout,
                    ),
                    arm_edit=arm_edit,
                    confirm_save=confirm_save,
                    announce_edit_window=announce_edit_window,
                )
            elif passive_attribution:
                reload_experiment = GoatMapFrontendReloadAttributionExperiment(
                    authenticator=authenticator,
                    device_info=mower,
                    device_id=app_device_id,
                    country=args.country,
                    writer=writer,
                )

                async def arm_reload() -> None:
                    if attribution_trigger == "official-app-open":
                        prompt = (
                            "Baseline complete. Press ENTER to start the marked "
                            "window, then immediately open the official Ecovacs "
                            "app directly to the mower map without other actions: "
                        )
                    else:
                        prompt = (
                            "Baseline complete. Press ENTER to start the marked "
                            "window, then immediately return to the same Home "
                            "Assistant dashboard and press F5 exactly once: "
                        )
                    await asyncio.to_thread(input, prompt)

                def announce_reload_window(observed_at: str) -> None:
                    action = (
                        "OPEN ECOVACS APP NOW"
                        if attribution_trigger == "official-app-open"
                        else "RELOAD NOW"
                    )
                    print(f"{action} (window started {observed_at})")

                report = await reload_experiment.run(
                    FrontendReloadAttributionConfig(
                        phase=args.phase,
                        mower_state=MowerState(args.mower_state),
                        trigger=attribution_trigger,
                        baseline_seconds=args.baseline_seconds,
                        reload_window_seconds=args.reload_window_seconds,
                        connect_timeout=args.connect_timeout,
                    ),
                    arm_reload=arm_reload,
                    announce_reload_window=announce_reload_window,
                )
            else:
                paired_experiment = GoatMapPhase2CaptureExperiment(
                    authenticator=authenticator,
                    device_info=mower,
                    device_id=app_device_id,
                    country=args.country,
                    http_session=session,
                    writer=writer,
                )
                report = await paired_experiment.run(
                    Phase2CaptureConfig(
                        phase=args.phase,
                        mower_state=MowerState(args.mower_state),
                        baseline_seconds=args.baseline_seconds,
                        live_confirmation_timeout=args.live_confirmation_timeout,
                        post_get_mi_seconds=args.post_get_mi_seconds,
                        cooldown_seconds=args.cooldown_seconds,
                        tail_seconds=args.tail_seconds,
                        connect_timeout=args.connect_timeout,
                    )
                )
            manifest = writer.finalize()
            report["phase2_capture"] = manifest
            if controlled_area_same_name:
                controlled = report["controlled_area_same_name_resubmission"]
                if controlled.get("state") == "completed":
                    same_name_analysis = analyze_area_same_name_artifact(
                        args.artifact_dir,
                        p2_12c_artifact_dir=args.same_name_reference_artifact,
                        p2_11_artifact_dir=args.same_name_write_reference_artifact,
                        report=report,
                    )
                    report["area_same_name_resubmission_analysis"] = (
                        same_name_analysis
                    )
                    controlled["experiment_status"] = same_name_analysis[
                        "experiment_status"
                    ]
                    controlled["delta_status"] = same_name_analysis["delta_status"]
                    controlled["role_comparison"] = same_name_analysis[
                        "role_comparison"
                    ]
                    controlled["family_comparisons"] = same_name_analysis[
                        "family_comparisons"
                    ]
                    controlled["AreaSet_ar_delta"] = same_name_analysis[
                        "AreaSet_ar_delta"
                    ]
                    controlled["write_shape_comparison"] = same_name_analysis[
                        "write_shape_comparison"
                    ]
            if controlled_area_noop_save:
                controlled = report["controlled_area_noop_save"]
                if controlled.get("state") == "completed":
                    noop_analysis = analyze_area_noop_save_artifact(
                        args.artifact_dir,
                        p2_12c_artifact_dir=args.noop_save_reference_artifact,
                        report=report,
                    )
                    report["area_noop_save_analysis"] = noop_analysis
                    controlled["experiment_status"] = noop_analysis[
                        "experiment_status"
                    ]
                    controlled["delta_status"] = noop_analysis["delta_status"]
                    controlled["role_comparison"] = noop_analysis[
                        "role_comparison"
                    ]
                    controlled["family_comparisons"] = noop_analysis[
                        "family_comparisons"
                    ]
                    controlled["AreaSet_ar_delta"] = noop_analysis[
                        "AreaSet_ar_delta"
                    ]
            if controlled_area_rename_restore:
                restore_analysis = analyze_area_rename_restore_artifact(
                    args.artifact_dir,
                    p2_11_artifact_dir=args.rename_restore_reference_artifact,
                    divide_artifact_dir=args.divide_write_reference_artifact,
                    report=report,
                )
                report["area_rename_restore_analysis"] = restore_analysis
                controlled = report["controlled_area_rename_restore"]
                controlled["experiment_status"] = restore_analysis[
                    "experiment_status"
                ]
                controlled["delta_status"] = restore_analysis["delta_status"]
                controlled["role_comparison"] = restore_analysis["role_comparison"]
                controlled["family_comparisons"] = restore_analysis[
                    "family_comparisons"
                ]
                controlled["AreaSet_ar_three_state"] = restore_analysis[
                    "AreaSet_ar_three_state"
                ]
                controlled["write_shape_comparison"] = restore_analysis[
                    "write_shape_comparison"
                ]
            if controlled_area_merge_recovery:
                recovery_precondition = report["controlled_area_merge"]["precondition"]
                isolation = recovery_precondition["checks"][
                    "controlled_source_isolation"
                ]
                recovery_analysis = analyze_area_merge_recovery_artifact(
                    args.artifact_dir,
                    original_artifact_dir=args.restoration_reference_artifact,
                    pre_merge_artifact_dir=args.pre_merge_reference_artifact,
                    expected_original_capture_id=_P2_09C_CAPTURE_ID,
                    expected_pre_merge_capture_id=_P2_10_PRE_MERGE_CAPTURE_ID,
                    recovery_precondition_status=recovery_precondition["status"],
                    unexpected_control_sequences=isolation["unexpected_sequences"],
                )
                report["area_merge_recovery_analysis"] = recovery_analysis
                controlled = report["controlled_area_merge"]
                controlled["experiment_status"] = recovery_analysis[
                    "experiment_status"
                ]
                controlled["delta_status"] = recovery_analysis["delta_status"]
                controlled["write_attribution"] = recovery_analysis[
                    "write_attribution"
                ]
                controlled["restoration_status"] = recovery_analysis[
                    "cross_experiment_restoration"
                ]["status"]
            if repeatability:
                repeatability_run = report["repeatability_run"]
                report["repeatability_analysis"] = analyze_repeatability_artifact(
                    args.artifact_dir,
                    cadence_anchor_at=repeatability_run["cadence_anchor_at"],
                    cadence_seconds=repeatability_run["cadence_seconds"],
                    boundary_tolerance_seconds=(
                        args.cadence_boundary_tolerance_seconds
                    ),
                    controlled_get_mi=repeatability_run["controls"],
                )
            return report, manifest
        finally:
            await authenticator.teardown()


def main() -> int:  # noqa: C901, PLR0912, PLR0915
    """Run one approved Phase 2 capture mode."""
    args = _parser().parse_args()
    logging.getLogger("deebot_client.authentication").setLevel(logging.INFO)
    _validate_args(args)
    account = input("Ecovacs account: ").strip()
    password = getpass("Ecovacs password: ")
    if not account or not password:
        raise ValueError("Account and password must be non-empty")
    report, manifest = _run_with_compatible_event_loop(_run(args, account, password))
    args.report_output.parent.mkdir(parents=True, exist_ok=True)
    args.report_output.write_bytes(
        orjson.dumps(report, option=orjson.OPT_INDENT_2) + b"\n"
    )
    print(f"Sanitized report: {args.report_output.resolve()}")
    print(f"Local opaque artifact: {args.artifact_dir.resolve()}")
    print(
        "Capture: "
        f"id={manifest['capture_id']} records={manifest['record_count']} "
        f"unique_blobs={manifest['unique_blob_count']} "
        f"bytes={manifest['total_blob_bytes']}"
    )
    print("Payload decoding: disabled")
    poller_isolation = report.get("poller_isolation")
    if poller_isolation:
        commands = poller_isolation.get("commands") or {}
        battery = commands.get("getBattery") or {}
        periodicity = battery.get("periodicity") or {}
        print(
            "Poller isolation: "
            f"status={poller_isolation['quiet_environment_status']} "
            f"external_requests={poller_isolation['external_request_count']} "
            f"getBattery={battery.get('request_count', 0)} "
            f"periodicity={periodicity.get('status')} "
            f"source={poller_isolation['source_attribution']}"
        )
    attribution = report.get("frontend_reload_attribution") or report.get(
        "official_app_open_attribution"
    )
    if attribution:
        print(
            "External trigger: "
            f"classification={attribution['classification']} "
            f"source={attribution['client_source']} "
            f"pattern={attribution['pattern_result']} "
            f"getAreaSet_messages={attribution['get_area_set_count']} "
            f"getAreaSet_requests={attribution['get_area_set_request_count']}"
        )
    controlled_edit = report.get("controlled_map_edit")
    if controlled_edit:
        print(
            "Controlled map edit: "
            f"started={controlled_edit['window_started_at']} "
            f"saved={controlled_edit['save_confirmed_at']} "
            f"ended={controlled_edit['window_ended_at']} "
            f"commands={len(controlled_edit['commands'])}"
        )
    special_delete = report.get("controlled_special_contour_delete")
    if special_delete:
        print(
            "Controlled SpecialContour delete: "
            f"present={special_delete['zone_present_readback_at']} "
            f"set-request={special_delete['set_request_at']} "
            f"manual={special_delete['manual_save_confirmed_at']} "
            f"post-readbacks={special_delete['post_delete_readback_count']}"
        )
    zone_absent = report.get("zone_absent_readback")
    if zone_absent:
        print(
            "Zone-absent readback: "
            f"state={','.join(zone_absent['mower_states'])} "
            f"special-readbacks={zone_absent['special_contour_readback_count']} "
            f"first={zone_absent['first_special_contour_readback_at']} "
            f"last={zone_absent['last_special_contour_readback_at']}"
        )
    repeatability = report.get("repeatability_run")
    if repeatability:
        hypotheses = report["repeatability_analysis"]["hypotheses"]
        print(
            "Repeatability: "
            f"status={repeatability['status']} "
            f"reason={repeatability['inconclusive_reason']} "
            f"cadence={repeatability['cadence_seconds']} "
            f"controls={','.join(item['transport'] for item in repeatability['controls'])}"
        )
        print(
            "Hypotheses: "
            + " ".join(
                f"{name}={result['status']}" for name, result in hypotheses.items()
            )
        )
    area_split = report.get("controlled_area_split")
    if area_split:
        write_attribution = area_split.get("write_attribution") or {}
        postcondition = area_split.get("postcondition") or {}
        print(
            "Controlled Area split: "
            f"experiment={area_split['experiment_status']} "
            f"delta={area_split['delta_status']} "
            f"state={area_split['state']} "
            f"gate_open={area_split['precondition']['split_edit_gate_open']} "
            f"write_attribution={write_attribution.get('status')} "
            f"command={write_attribution.get('authoritative_command')} "
            f"postconditions={postcondition.get('status')}"
        )
        if area_split["experiment_status"] != "complete":
            failed = area_split["precondition"].get("failures", [])
            post_failed = postcondition.get("failed_checks", [])
            print(
                "Area split inconclusive: "
                f"precondition_failures={len(failed)} "
                f"postcondition_failures={','.join(post_failed)}"
            )
    area_merge = report.get("controlled_area_merge")
    if area_merge:
        write_attribution = area_merge.get("write_attribution") or {}
        postcondition = area_merge.get("postcondition") or {}
        recovery = area_merge.get("post_merge_recovery", False)
        gate_open = area_merge["precondition"].get("merge_edit_gate_open", False)
        area_merge_label = (
            "Area merge recovery: " if recovery else "Controlled Area merge: "
        )
        print(
            f"{area_merge_label}experiment={area_merge['experiment_status']} "
            f"delta={area_merge['delta_status']} "
            f"restoration={area_merge.get('restoration_status')} "
            f"state={area_merge['state']} "
            f"gate_open={gate_open} "
            f"write_attribution={write_attribution.get('status')} "
            f"command={write_attribution.get('authoritative_command')} "
            f"postconditions={postcondition.get('status')}"
        )
        if area_merge["experiment_status"] in {"inconclusive", "not-comparable"}:
            failed = area_merge["precondition"].get("failures", [])
            post_failed = postcondition.get("failed_checks", [])
            print(
                "Area merge inconclusive: "
                f"precondition_failures={len(failed)} "
                f"postcondition_failures={','.join(post_failed)}"
            )
    area_rename = report.get("controlled_area_rename")
    if area_rename:
        write_attribution = area_rename.get("write_attribution") or {}
        postcondition = area_rename.get("postcondition") or {}
        rename_analysis = area_rename.get("rename_analysis") or {}
        gate_open = area_rename["precondition"].get("rename_edit_gate_open", False)
        print(
            "Controlled Area rename: "
            f"experiment={area_rename['experiment_status']} "
            f"delta={area_rename['delta_status']} "
            f"classification={rename_analysis.get('result_classification')} "
            f"state={area_rename['state']} "
            f"gate_open={gate_open} "
            f"write_attribution={write_attribution.get('status')} "
            f"command={write_attribution.get('authoritative_command')} "
            f"postconditions={postcondition.get('status')}"
        )
        if area_rename["experiment_status"] != "complete":
            failed = area_rename["precondition"].get("failures", [])
            post_failed = postcondition.get("failed_checks", [])
            print(
                "Area rename inconclusive: "
                f"precondition_failures={len(failed)} "
                f"postcondition_failures={','.join(post_failed)}"
            )
    area_rename_restore = report.get("controlled_area_rename_restore")
    if area_rename_restore:
        write_attribution = area_rename_restore.get("write_attribution") or {}
        postcondition = area_rename_restore.get("postcondition") or {}
        role_comparison = area_rename_restore.get("role_comparison") or {}
        three_state = area_rename_restore.get("AreaSet_ar_three_state") or {}
        gate_open = area_rename_restore["precondition"].get(
            "rename_restore_edit_gate_open", False
        )
        print(
            "Controlled Area rename restore: "
            f"experiment={area_rename_restore['experiment_status']} "
            f"delta={area_rename_restore['delta_status']} "
            f"AreaSet_ar={three_state.get('classification')} "
            f"role_comparison={role_comparison.get('status')} "
            f"state={area_rename_restore['state']} "
            f"gate_open={gate_open} "
            f"write_attribution={write_attribution.get('status')} "
            f"command={write_attribution.get('authoritative_command')} "
            f"postconditions={postcondition.get('status')}"
        )
        if area_rename_restore["experiment_status"] != "completed-action":
            failed = area_rename_restore["precondition"].get("failures", [])
            post_failed = postcondition.get("failed_checks", [])
            print(
                "Area rename restore inconclusive: "
                f"precondition_failures={len(failed)} "
                f"postcondition_failures={','.join(post_failed)}"
            )
    area_noop_save = report.get("controlled_area_noop_save")
    if area_noop_save:
        write_attribution = area_noop_save.get("write_attribution") or {}
        postcondition = area_noop_save.get("postcondition") or {}
        role_comparison = area_noop_save.get("role_comparison") or {}
        area_delta = area_noop_save.get("AreaSet_ar_delta") or {}
        gate_open = area_noop_save["precondition"].get(
            "noop_save_edit_gate_open", False
        )
        print(
            "Controlled Area no-op Save: "
            f"experiment={area_noop_save['experiment_status']} "
            f"delta={area_noop_save['delta_status']} "
            f"AreaSet_ar={area_delta.get('classification')} "
            f"role_comparison={role_comparison.get('status')} "
            f"state={area_noop_save['state']} "
            f"gate_open={gate_open} "
            f"write_attribution={write_attribution.get('status')} "
            f"command={write_attribution.get('authoritative_command')} "
            f"postconditions={postcondition.get('status')}"
        )
        if area_noop_save["experiment_status"] != "completed-action":
            failed = area_noop_save["precondition"].get("failures", [])
            post_failed = postcondition.get("failed_checks", [])
            print(
                "Area no-op Save incomplete: "
                f"precondition_failures={len(failed)} "
                f"postcondition_failures={','.join(post_failed)}"
            )
    same_name = report.get("controlled_area_same_name_resubmission")
    if same_name:
        write_attribution = same_name.get("write_attribution") or {}
        postcondition = same_name.get("postcondition") or {}
        role_comparison = same_name.get("role_comparison") or {}
        area_delta = same_name.get("AreaSet_ar_delta") or {}
        gate_open = same_name["precondition"].get(
            "same_name_resubmission_edit_gate_open", False
        )
        print(
            "Controlled Area same-name resubmission: "
            f"experiment={same_name['experiment_status']} "
            f"delta={same_name['delta_status']} "
            f"AreaSet_ar={area_delta.get('classification')} "
            f"role_comparison={role_comparison.get('status')} "
            f"state={same_name['state']} "
            f"gate_open={gate_open} "
            f"write_attribution={write_attribution.get('status')} "
            f"command={write_attribution.get('authoritative_command')} "
            f"postconditions={postcondition.get('status')}"
        )
        if same_name["experiment_status"] != "completed-action":
            failed = same_name["precondition"].get("failures", [])
            post_failed = postcondition.get("failed_checks", [])
            print(
                "Area same-name resubmission incomplete: "
                f"precondition_failures={len(failed)} "
                f"postcondition_failures={','.join(post_failed)}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
