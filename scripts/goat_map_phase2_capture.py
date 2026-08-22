"""Capture opaque GOAT static-map payloads without decoding them."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
import asyncio
from getpass import getpass
import logging
from pathlib import Path
import sys
from typing import Any

from aiohttp import ClientSession
import orjson

from deebot_client.api_client import ApiClient
from deebot_client.authentication import Authenticator, create_rest_config
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
    GoatMapRepeatabilityExperiment,
    GoatMapSpecialContourDeleteExperiment,
    GoatMapZoneAbsentReadbackExperiment,
    Phase2CaptureConfig,
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
    if args.mode == _REPEATABILITY_MODE:
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


async def _run(  # noqa: C901, PLR0915
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
            passive_capture = (
                passive_attribution
                or controlled_map_edit
                or special_contour_delete
                or zone_absent_readback
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
                    )
                    else None
                ),
            )
            if repeatability:
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


def main() -> int:
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
