"""Run the opt-in GOAT map refresh protocol diagnostic."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Awaitable, Callable, Coroutine
from getpass import getpass
import logging
import os
from pathlib import Path
import re
import sys
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from aiohttp import ClientSession
import orjson

from deebot_client.api_client import ApiClient
from deebot_client.authentication import Authenticator, create_rest_config
from deebot_client.diagnostics.goat_map_refresh import (
    ControlTransport,
    ExperimentConfig,
    GoatMapDiagnosticExperiment,
    JmqMode,
    MowerState,
)
from deebot_client.exceptions import DeviceVerificationRequiredError
from deebot_client.util import md5

if TYPE_CHECKING:
    from deebot_client.models import DeviceInfo

_DEFAULT_CLIENT_STATE_FILE = Path(".goat-map-refresh-state.json")
_CLIENT_STATE_VERSION = 1
_CLIENT_DEVICE_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
VerificationCodeProvider = Callable[[], Awaitable[str]]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run additive GOAT MQTT/control research and write a sanitized JSON "
            "report. Account and password are requested interactively."
        )
    )
    parser.add_argument("--country", required=True, help="ISO alpha-2 country")
    parser.add_argument("--phase", required=True, help="Stable test phase label")
    parser.add_argument(
        "--mower-state",
        required=True,
        choices=[state.value for state in MowerState],
        help="Observed mower state at the start of this run",
    )
    parser.add_argument(
        "--jmq",
        choices=[mode.value for mode in JmqMode],
        default=JmqMode.NONE.value,
    )
    parser.add_argument(
        "--appping",
        choices=[transport.value for transport in ControlTransport],
        default=ControlTransport.NONE.value,
    )
    parser.add_argument(
        "--get-mi",
        choices=[transport.value for transport in ControlTransport],
        default=ControlTransport.NONE.value,
    )
    parser.add_argument(
        "--device-class",
        help="Select a mower by its non-secret device class when needed",
    )
    parser.add_argument("--baseline-seconds", type=float, default=60)
    parser.add_argument("--observation-seconds", type=float, default=60)
    parser.add_argument(
        "--renew-appping-after-seconds",
        type=float,
        help=(
            "Enable presence-renewal mode and send a second appping this many "
            "seconds after the first"
        ),
    )
    parser.add_argument(
        "--presence-total-seconds",
        type=float,
        help=(
            "In renewal mode, observe for this many seconds from the first "
            "appping (recommended: 700)"
        ),
    )
    parser.add_argument("--connect-timeout", type=float, default=30)
    parser.add_argument(
        "--client-state-file",
        type=Path,
        default=_DEFAULT_CLIENT_STATE_FILE,
        help=(
            "Git-ignored local file containing the stable client device ID "
            f"(default: {_DEFAULT_CLIENT_STATE_FILE})"
        ),
    )
    parser.add_argument(
        "--output", required=True, type=Path, help="Sanitized JSON output path"
    )
    return parser


def load_or_create_client_device_id(
    state_file: Path,
    *,
    create_id: Callable[[], str] | None = None,
) -> str:
    """Load a stable client resource or create it with owner-only permissions."""
    try:
        data = orjson.loads(state_file.read_bytes())
    except FileNotFoundError:
        client_device_id = (create_id or _new_client_device_id)()
        if not _CLIENT_DEVICE_ID_PATTERN.fullmatch(client_device_id):
            raise ValueError(
                "Generated client device ID has an invalid shape"
            ) from None
        state_file.parent.mkdir(parents=True, exist_ok=True)
        encoded = orjson.dumps(
            {
                "version": _CLIENT_STATE_VERSION,
                "client_device_id": client_device_id,
            },
            option=orjson.OPT_INDENT_2,
        )
        try:
            descriptor = os.open(
                state_file,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            return load_or_create_client_device_id(state_file)
        with os.fdopen(descriptor, "wb") as file:
            file.write(encoded)
            file.write(b"\n")
        return client_device_id
    except orjson.JSONDecodeError as ex:
        raise ValueError("Client state file is not valid JSON") from ex

    if not isinstance(data, dict) or data.get("version") != _CLIENT_STATE_VERSION:
        raise ValueError("Client state file has an unsupported shape or version")
    loaded_client_device_id = data.get("client_device_id")
    if not isinstance(
        loaded_client_device_id, str
    ) or not _CLIENT_DEVICE_ID_PATTERN.fullmatch(loaded_client_device_id):
        raise ValueError("Client state file contains an invalid client device ID")
    return loaded_client_device_id


def _new_client_device_id() -> str:
    return uuid4().hex


def _validate_args(args: argparse.Namespace) -> None:
    """Validate factor combinations before requesting account credentials."""
    if args.baseline_seconds < 0 or args.observation_seconds < 0:
        raise ValueError("Measurement durations cannot be negative")
    renew_after = args.renew_appping_after_seconds
    total = args.presence_total_seconds
    if (renew_after is None) != (total is None):
        raise ValueError(
            "Presence renewal requires both --renew-appping-after-seconds and "
            "--presence-total-seconds"
        )
    if renew_after is None:
        return
    if renew_after <= 0 or total <= renew_after:
        raise ValueError(
            "Presence renewal durations must be positive and total must exceed "
            "the renewal time"
        )
    if args.appping == ControlTransport.NONE.value:
        raise ValueError("Presence renewal requires --appping legacy or ngiot")
    if args.jmq != JmqMode.NONE.value or args.get_mi != ControlTransport.NONE.value:
        raise ValueError("Presence renewal must run with --jmq none and --get-mi none")


async def authenticate_with_device_verification(
    authenticator: Authenticator,
    verification_code_provider: VerificationCodeProvider,
) -> None:
    """Authenticate and complete Ecovacs device verification when requested."""
    try:
        await authenticator.authenticate()
    except DeviceVerificationRequiredError:
        await authenticator.request_device_verification_code()
        verification_code = (await verification_code_provider()).strip()
        if not verification_code:
            raise ValueError("Verification code must be non-empty") from None
        await authenticator.verify_device(verification_code)


async def _prompt_verification_code() -> str:
    return await asyncio.to_thread(
        getpass, "Ecovacs device verification code (input hidden): "
    )


def _run_with_compatible_event_loop[T](
    coroutine: Coroutine[Any, Any, T], *, platform: str = sys.platform
) -> T:
    """Run aiomqtt with a selector loop, which supports socket readers on Windows."""
    if platform == "win32":
        with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop) as runner:
            return runner.run(coroutine)
    return asyncio.run(coroutine)


def _select_device(devices: list[DeviceInfo], device_class: str | None) -> DeviceInfo:
    if device_class:
        selected = [item for item in devices if item.api["class"] == device_class]
    else:
        selected = [
            item
            for item in devices
            if "goat" in item.api.get("deviceName", "").casefold()
        ]
        if not selected and len(devices) == 1:
            selected = devices
    if len(selected) != 1:
        classes = sorted({item.api["class"] for item in devices})
        message = (
            "Expected exactly one mower. Pass --device-class. "
            f"Available classes: {', '.join(classes) or '<none>'}"
        )
        raise ValueError(message)
    return selected[0]


def _print_summary(report: dict[str, Any], output: Path) -> None:
    print(f"Sanitized report: {output.resolve()}")
    experiment = report["experiment"]
    print(
        "Factors: "
        f"phase={experiment['phase']} state={experiment['mower_state']} "
        f"jmq={experiment['jmq']} appping={experiment['appping']} "
        f"getMI={experiment['get_mi']}"
    )
    for record in report["records"]:
        if record["kind"] == "endpoint":
            print(
                "Endpoint: "
                f"service={record['session']} host={record['broker']} "
                f"source={record['endpoint_source']}"
            )
    for session, summary in report["sessions"].items():
        print(
            "MQTT: "
            f"session={session} messages={summary['message_count']} "
            f"onPos={summary['on_pos']} "
            f"interesting={summary['interesting_commands']}"
        )
    print(f"Correlated map IDs: {sorted(report['mid_correlation'])}")
    print(f"Non-map numeric IDs: {sorted(report['other_numeric_id_observations'])}")
    if renewal := report.get("presence_renewal"):
        print(
            "Presence renewal: "
            f"first={renewal['first_appping_issued_at']} "
            f"renewal={renewal['renewal_appping_issued_at']} "
            f"elapsed={renewal['renewal_elapsed_seconds']}s "
            f"ended={renewal['observation_ended_at']} "
            f"stream-confirmed-before-renewal="
            f"{renewal['live_stream_confirmed_before_renewal']}"
        )
        for command, stream in renewal["streams"].items():
            print(
                "Presence stream: "
                f"command={command} count={stream['count']} "
                f"first={stream['first_at']} last={stream['last_at']} "
                f"tail_gap={stream['tail_gap_seconds']}s "
                f"interruptions={len(stream['interruptions'])}"
            )


async def _run(
    args: argparse.Namespace,
    account: str,
    password: str,
    verification_code_provider: VerificationCodeProvider = _prompt_verification_code,
) -> dict[str, Any]:
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
                authenticator, verification_code_provider
            )
            devices = await ApiClient(authenticator).get_devices()
            mower = _select_device(devices.mqtt, args.device_class)
            experiment = GoatMapDiagnosticExperiment(
                authenticator=authenticator,
                device_info=mower,
                device_id=app_device_id,
                country=args.country,
                http_session=session,
            )
            return await experiment.run(
                ExperimentConfig(
                    phase=args.phase,
                    mower_state=MowerState(args.mower_state),
                    jmq=JmqMode(args.jmq),
                    appping=ControlTransport(args.appping),
                    get_mi=ControlTransport(args.get_mi),
                ),
                baseline_seconds=args.baseline_seconds,
                observation_seconds=args.observation_seconds,
                appping_renew_after_seconds=getattr(
                    args, "renew_appping_after_seconds", None
                ),
                presence_total_seconds=getattr(args, "presence_total_seconds", None),
                connect_timeout=args.connect_timeout,
            )
        finally:
            await authenticator.teardown()


def main() -> int:
    """Parse arguments and run the diagnostic."""
    args = _parser().parse_args()
    logging.getLogger("deebot_client.authentication").setLevel(logging.INFO)
    _validate_args(args)
    account = input("Ecovacs account: ").strip()
    password = getpass("Ecovacs password: ")
    if not account or not password:
        raise ValueError("Account and password must be non-empty")
    report = _run_with_compatible_event_loop(_run(args, account, password))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(orjson.dumps(report, option=orjson.OPT_INDENT_2))
    _print_summary(report, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
