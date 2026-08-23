from __future__ import annotations

from deebot_client.commands.json import GetPos
from deebot_client.events import FirmwareEvent, Position, PositionsEvent
from deebot_client.rs.map import PositionType
from tests.fixtures.o1200_position import O1200_ON_POS_PAYLOAD
from tests.messages import assert_message


def test_onPos_o1200_capture() -> None:
    """The O1200 onPos capture uses the shared getPos message handler."""
    assert_message(
        GetPos,
        O1200_ON_POS_PAYLOAD,
        (
            FirmwareEvent("1.9.16"),
            PositionsEvent(
                positions=[Position(type=PositionType.DEEBOT, x=5770, y=10646, a=-55)]
            ),
        ),
        device_class="2i0fns",
    )
