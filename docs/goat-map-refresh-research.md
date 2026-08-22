# GOAT map refresh: Phase 1 protocol research

Status: Phase 1 diagnostic research complete. This phase does not implement a
GOAT map entity, decode mower map payloads, or replace an existing transport.

## Scope and safety

- All new behavior is opt-in through `deebot_client.diagnostics` or
  `scripts/goat_map_refresh_diagnostic.py`.
- Normal MQTT and the existing `Command` transport are unchanged when no
  diagnostic observer is supplied.
- Reports contain sanitized endpoint/session metadata, topic shapes, command
  names, timing, mower state, map IDs, and sanitized control responses.
- Tokens, SST tokens, passwords, account IDs, MQTT identities, request IDs,
  complete device topics, and opaque map blobs are not retained.
- Unknown `getMI` and `getMapTrack` payloads remain opaque in Phase 1. The
  diagnostic captures only sanitized metadata and does not decode their bodies.

## Existing architecture

`authentication.py` performs the Ecovacs account login and retains portal
credentials. `ApiClient.get_devices()` merges the legacy and global device-list
responses. The raw API device dictionary survives inside `DeviceInfo`, including
advertised `service.jmq` and `service.mqs` values.

`create_mqtt_config()` selects the normal broker as
`mq{continent-postfix}.ecouser.net:443`, for example `mq-eu.ecouser.net`. Normal
MQTT uses the portal user ID/token and a client ID shaped as
`<user>@ecouser/<app-device-id>`. It subscribes to the device's ATR and P2P topic
families.

Every normal `Command` still calls `iot/devmanager.do`. The diagnostic legacy
`getMI` and legacy `appping` controls deliberately use this existing path. The
N-GIoT probe is a separate class and does not become a new `Command` transport.

The existing vacuum-oriented map pipeline does not handle `onMI`, `onArI`,
`onMapTrack`, `onMapState`, or `onAreaSet`. Phase 1 records these message names
and their `mid`/`mapId` values without interpreting payloads.

## Direct observations

These are facts observed directly in this repository or in sanitized runtime
data, not conclusions inferred from another implementation.

- Normal client MQTT resolves to `mq*.ecouser.net` unless explicitly
  overridden.
- Device discovery retains raw `service.jmq` and `service.mqs` values.
- Existing commands use `iot/devmanager.do`.
- `GetPos` is an existing normal JSON command and can be available without a
  complete map capability. This makes legacy `getMI` a necessary control rather
  than an assumed unsupported path.
- Active-mowing diagnostic runs now establish that `appping` activates the
  normal-MQ map stream for this mower. Neither JMQ nor a particular control
  transport was necessary in the successful control runs.
- State tests show materially different traffic shapes: declared paused state
  produced only two isolated `onPos` events, while a confirmed return-to-dock
  task produced dense `onPos` until docking. Map-track traffic during the
  return capture was limited to an initial burst before `appping`.

### External Home Assistant state correlation

After Phase 12, the operator reported that the mower had docked to charge
during parts of the test series. A same-day Home Assistant activity export was
then correlated with the report timestamps. HA is incomplete and does not
contain all device traffic, so these are supporting state indications rather
than protocol-ground-truth:

| Diagnostic interval (UTC) | Last-known HA state | Interpretation |
| --- | --- | --- |
| Phase 01, 08:25:22–08:26:22 | `docked` from 08:25:14 | Reclassify as a docked baseline, despite the manual `mowing` label. |
| Phases 02–11, 08:30:31–09:38:52 | `mowing` from 08:28:50; next change was `paused` at 09:45:50 | Supports active mowing throughout the key factor matrix. |
| Phase 12, 09:56:02–10:08:42 | `docked` from 09:46:35 | First ping was very likely docked; the supplied HA export does not safely cover the full later window. |

The HA sequence around Phase 12 was `mowing` at 08:28:50, `paused` at
09:45:50, and `docked` at 09:46:35. The operator independently confirmed that
charging occurred during testing. Report `mower_state` fields remain the
manually supplied labels and must not be retroactively treated as observed
state events.

### Phase 01 baseline: normal MQ only

Sanitized run `01-baseline` on 2026-08-22 observed a 60-second window against
`mq-eu.ecouser.net:443` with JMQ, `appping`, and `getMI` disabled. Normal MQ
connected and disconnected cleanly and received eight ATR events:

- `onFwBuryPoint-bd_batterystate`: 1;
- `onFwBuryPoint-bd_machine`: 4;
- `onFwBuryPoint-bd_wifiinfo`: 1; and
- `onNetworkSwitch`: 2.

The window contained no `onPos`, `onMI`, `onArI`, `onMapTrack`, `onMapState`, or
`onAreaSet`, and no `mid`/`mapId`. This directly confirms that ordinary MQ was
functional while no map/position stream was present in this baseline window.
The state was manually declared as `mowing`; no supported state event arrived
during the window to independently confirm or change it. The later HA export
instead places this entire window in `docked`, so Phase 01 is a docked baseline
and cannot serve as negative active-mowing evidence. It remains direct evidence
that ordinary MQ functioned while no map/position stream was present.

### Phase 02: legacy `getMI` without JMQ

Sanitized run `02-legacy-get-mi` on 2026-08-22 used normal MQ, no JMQ and no
`appping`, with a 60-second pre-control window followed by legacy `getMI` and a
60-second post-control window. The mower state was manually declared as
`mowing` and was not independently confirmed by a supported state event.

Normal MQ was already receiving the live-map stream before the command. The
pre-control window contained 116 `onPos`, 28 `onMapTrack`, one `onMI`, and one
`onArI`; its first `onPos` arrived about 8.7 seconds after the window started.
The post-control window contained 109 `onPos`, 27 `onMapTrack`, one `onMI`, and
three `onArI`. The reported `onPos` rates were about 2.25 Hz before and 1.83 Hz
after the command, with median intervals of about 508 ms and 513 ms. This run
therefore does not show that legacy `getMI` activated the already-running push
stream.

It does directly show that legacy `getMI` was accepted through the existing
transport: the sanitized response had `ret=ok` and `body.code=0`. Normal MQ
observed the outgoing `getMI`, then an `onMI` with map ID `1` about 79 ms later.
That close timing is evidence that legacy `getMI` can solicit `onMI`, although
it is not evidence that it starts the sustained position/map-track stream.
Across the run, `onPos` and `onMapTrack` correlated with map ID `0`, while
`onMI` and `onArI` correlated with map ID `1`. Unknown payload bodies remain
undecoded.

Compared with Phase 01 roughly four minutes earlier, the observed behavior
changed from no map events to an active stream on ordinary MQ. The available
captures do not isolate whether this was caused by mower activity, retained
server/app presence, another external app session, or timing. Subsequent
phases must use their own before/after windows and must not treat Phase 02 as a
clean trigger experiment.

### Phase 03: correct JMQ app-presence alone

Sanitized run `03-jmq-app-presence` on 2026-08-22 used a 60-second normal-MQ
baseline and a 60-second window after opening the reference-shaped JMQ
app-presence session. Both sessions connected and disconnected cleanly. JMQ
selected `jmq-ngiot-eu.dc.ww.ecouser.net:443` directly from the mower's
advertised `service.jmq`, not from the regional fallback.

The normal-MQ baseline contained four ordinary machine telemetry events and no
map events. After JMQ connected, normal MQ received five ordinary telemetry
events and no `onPos`, `onMI`, `onArI`, `onMapTrack`, `onMapState`, or
`onAreaSet`. The JMQ session itself received no messages. No controls were sent
and no map IDs were observed. This confirms that opening JMQ did not disrupt
ordinary MQ, but it did not activate a map stream in this window either.

The mower state was manually declared as `mowing` and was not independently
confirmed by a supported state event. Consequently this is direct negative
evidence for JMQ app-presence alone under the declared test conditions, not a
general conclusion that JMQ is irrelevant. In particular, it does not test
JMQ combined with either `getMI` or N-GIoT `appping`.

### Phase 04: JMQ app-presence plus legacy `getMI`

Sanitized run `04-jmq-legacy-get-mi` on 2026-08-22 measured three 60-second
windows: normal MQ alone, after correct JMQ app-presence, and after legacy
`getMI`. JMQ again selected the mower-advertised
`jmq-ngiot-eu.dc.ww.ecouser.net:443` endpoint and connected cleanly. It received
no messages. Normal MQ received ordinary battery/machine telemetry throughout,
confirming that the additive JMQ session did not interrupt the existing
connection.

None of the three windows contained `onPos`, `onMI`, `onArI`, `onMapTrack`,
`onMapState`, or `onAreaSet`, and no map ID was observed. The legacy `getMI`
exchange was visible on normal MQ as one request and its matching response; it
was not two control calls. Its sanitized control result again had `ret=ok` and
`body.code=0`, but unlike Phase 02 it produced no separate `onMI` event during
the action or following 60-second window.

This directly shows that a successful legacy `getMI` acknowledgement does not
guarantee an `onMI` push or activate sustained map traffic, even while JMQ
app-presence is connected. Phase 02's closely timed `onMI` therefore remains a
real observation but is conditional on state or other unknown factors. The
mower state in Phase 04 was manually declared as `mowing` and was not
independently confirmed by a supported state event.

### Phase 05: JMQ app-presence plus N-GIoT `getMI`

Sanitized run `05-jmq-ngiot-get-mi` on 2026-08-22 measured normal MQ alone,
then correct JMQ app-presence, and finally N-GIoT `getMI`, each with a 60-second
observation window. JMQ and MQS control were selected from the mower's
advertised services. SST issuance used the documented regional fallback
`api-base.dc-eu.ww.ecouser.net:443`; no token or request ID was supplied from a
capture.

SST issuance and the N-GIoT control path completed successfully. The sanitized
`getMI` response had `body.code=0` and `body.msg=ok`. Normal MQ observed the
resulting `getMI` P2P request to the mower and its matching response, confirming
that `/api/iot/endpoint/control` delivered the command rather than merely
returning an unrelated HTTP success. This exchange is observably similar to
the legacy control exchange at the MQTT layer.

No window contained `onPos`, `onMI`, `onArI`, `onMapTrack`, `onMapState`, or
`onAreaSet`; JMQ received no messages and no map ID was observed. Therefore
N-GIoT `getMI`, even with JMQ app-presence, did not activate map traffic in this
run. The test does not yet include the reference implementation's N-GIoT
`appping`. The mower state was manually declared as `mowing` and was not
independently confirmed by a supported state event.

### Phase 06: JMQ app-presence plus N-GIoT `appping`

Sanitized run `06-jmq-ngiot-appping` on 2026-08-22 produced the first isolated
activation result. The 60-second normal-MQ baseline and the 60-second window
after connecting correct JMQ app-presence contained ordinary telemetry but no
map events. N-GIoT `appping` then used a legitimately issued SST and the
mower-advertised MQS control endpoint.

Normal MQ observed the `appping` P2P request at 08:50:56.135 UTC. The first
`onPos` arrived about 1.34 seconds later and the first `onMapTrack` about 1.98
seconds later. The first paired `onMI`/`onArI` arrived about 10.45 seconds after
the request. During the roughly 20-second action interval, normal MQ received
38 `onPos` at about 2.00 Hz, 10 `onMapTrack`, one `onMI`, and one `onArI`. In
the following 60-second window it received another 114 `onPos` at about 1.90
Hz, 27 `onMapTrack`, one `onMI`, and one `onArI`.

The `appping` HTTP request completed without an HTTP status error after about
20 seconds, but its decoded JSON response was `null` and no matching P2P
response was observed. Map pushes began while that HTTP request was still in
progress. This behavior differs from the ordinary `getMI` request/response
exchange and is consistent with `appping` acting as an app-presence trigger,
although the exact server/device mechanism remains a hypothesis.

As in Phase 02, `onPos` and `onMapTrack` correlated with map ID `0`, while
`onMI` and `onArI` correlated with map ID `1`. JMQ itself received no messages;
all map events arrived on the existing normal MQ session. This is strong direct
evidence that the additive sequence of correct JMQ presence followed by
N-GIoT `appping` activates normal-MQ live-map pushes under the declared test
conditions. It does not yet isolate whether JMQ is necessary when N-GIoT
`appping` is sent. The mower state was manually declared as `mowing` and was
not independently confirmed by a supported state event.

### Phase 07: N-GIoT `appping` followed by legacy `getMI`

Sanitized run `07-appping-legacy-get-mi` on 2026-08-22 also captured carry-over
from Phase 06. The Phase 07 baseline initially received `onPos`/`onMapTrack`,
but the stream stopped at 08:55:54.955 UTC. That was about 298.82 seconds after
the Phase 06 `appping` request at 08:50:56.135 UTC. JMQ was then opened, but no
map events occurred during the following 60-second JMQ-only window. This is
strong timing evidence for an approximately five-minute app-presence lifetime
created by `appping`; confirmation requires another expiry capture.

A new N-GIoT `appping` request was observed at 08:57:09.337 UTC after roughly
75 seconds without a map event. `onPos` resumed about 140 ms later and
`onMapTrack` followed about 2.85 seconds after the request. During the action
and next 60-second window, normal MQ received 147 `onPos` and 35 `onMapTrack`.
JMQ again received no messages. This repeat makes a coincidental mower-only
activation less likely and strengthens the conclusion that N-GIoT `appping`
is the immediate live-stream trigger in the tested sequence.

Legacy `getMI` was then sent while the appping-triggered stream was active. Its
sanitized response again had `ret=ok` and `body.code=0`; an `onMI` with map ID
`1` followed the request after about 163 ms, and `onArI` followed after about
191 ms. The existing `onPos`/`onMapTrack` stream continued with map ID `0`.
The following window's aggregate `onPos` rate was lower than the preceding
window, but its median interval remained about 512 ms, so this single run does
not establish that legacy `getMI` changed the sustained stream cadence.

The mower state was manually declared as `mowing` and was not independently
confirmed by a supported state event. No unknown map payload was decoded.

### Phase 08: N-GIoT `appping` followed by N-GIoT `getMI`

Sanitized run `08-appping-ngiot-get-mi` on 2026-08-22 independently repeated
the likely presence expiry. Carry-over traffic from Phase 07 stopped at
09:02:08.635 UTC, about 299.30 seconds after the Phase 07 `appping` request.
The following JMQ-only window again contained no map events. Two consecutive
captures therefore place the observed stream lifetime very close to five
minutes.

The Phase 08 N-GIoT `appping` request was observed at 09:03:27.749 UTC.
`onPos` restarted about 247 ms later and `onMapTrack` about 350 ms later. The
action interval and following window contained 140 `onPos` and 36
`onMapTrack`, all on normal MQ. This is a third activation associated with
N-GIoT `appping`; JMQ continued to receive no messages.

N-GIoT `getMI` was then sent while the stream was active. The mower's P2P
response and sanitized N-GIoT response (`body.code=0`) completed about 104 ms
after the request. An `onMI` with map ID `1` arrived after about 103 ms, along
with two near-simultaneous `onArI` ATR records on the same sanitized topic.
They are retained as two observed events without attempting to explain or
decode the duplicate payloads.

The 60-second windows before and after N-GIoT `getMI` had nearly identical
`onPos` behavior: about 1.73 versus 1.74 Hz, with median intervals of about
510.7 versus 511.0 ms. Periodic paired `onMI`/`onArI` events also continued at
roughly 60-second intervals, in addition to the immediate pair solicited by
`getMI`. This indicates that N-GIoT and legacy `getMI` can both solicit an
immediate map-info/area-info update while app presence is active, but neither
has shown a sustained cadence change. Map IDs remained `0` for
`onPos`/`onMapTrack` and `1` for `onMI`/`onArI`.

The mower state was manually declared as `mowing` and was not independently
confirmed by a supported state event. No unknown map payload was decoded.

### Phase 09: N-GIoT `appping` without JMQ

Sanitized run `09-ngiot-appping-no-jmq` on 2026-08-22 isolated the JMQ factor.
Only normal MQ was connected. A 360-second baseline received ordinary
telemetry but no `onPos`, `onMI`, `onArI`, `onMapTrack`, `onMapState`, or
`onAreaSet`, ruling out carry-over from the preceding five-minute presence
period within the measured window.

N-GIoT `appping` then used the mower-advertised MQS control endpoint and a
legitimately issued SST, with no JMQ session present at any point. Normal MQ
observed the request at 09:16:49.829 UTC. The first `onPos` arrived about 288 ms
later and the first `onMapTrack` about 367 ms later. Across the action and
following 60-second window, normal MQ received 116 `onPos`, 27 `onMapTrack`,
two `onMI`, and two `onArI`; map IDs retained the established `0`/`1`
correlation.

This directly demonstrates that JMQ is not required for N-GIoT `appping` to
activate the live-map stream on normal MQ under the declared test conditions.
The original hypothesis that a separate JMQ session is necessary for fast GOAT
map/position pushes is therefore rejected for this mower/run. JMQ may still
serve another app-presence, notification, or account-level purpose, but the
captures provide no positive evidence for such a role in map refresh.

The mower state was manually declared as `mowing` and was not independently
confirmed by a supported state event. No unknown map payload was decoded.

### Phase 10: experimental legacy `appping` without JMQ

Sanitized run `10-legacy-appping-no-jmq` on 2026-08-22 tested the explicitly
experimental legacy transport. Carry-over from Phase 09 was visible at the
start of the 360-second baseline and stopped at 09:21:49.547 UTC, about 299.72
seconds after the Phase 09 N-GIoT `appping`. The remaining baseline was silent
for more than four minutes, providing another independent observation of the
approximately five-minute presence lifetime.

Legacy `appping` was then sent through the existing `Command` /
`iot/devmanager.do` transport at 09:26:07.044 UTC, with no JMQ session present.
The first `onPos` arrived about 449 ms later and the first `onMapTrack` about
1.17 seconds later. Across the roughly 20-second action interval and following
60-second window, normal MQ received 137 `onPos`, 35 `onMapTrack`, one `onMI`,
and one `onArI`. The established map ID correlation remained unchanged.

The legacy command did not receive an ordinary P2P response and returned an
empty sanitized result after about 20 seconds, causing the expected diagnostic
warning. That absence is not evidence that presence activation failed: the map
stream began while the command was awaiting its response and continued for the
full post-control window. N-GIoT `appping` similarly did not produce a normal
P2P response.

This experimental control demonstrates that, for this mower, neither JMQ nor
the N-GIoT control transport is necessary to activate live-map pushes. The
shared causal factor across the successful runs is the `appping` command
itself. The official/reference sequence still uses N-GIoT, so this finding does
not redefine the observed app protocol or select a production implementation.

The mower state was manually declared as `mowing` and was not independently
confirmed by a supported state event. No unknown map payload was decoded.

### Phase 11: ordinary MQTT identity against JMQ

Sanitized run `11-jmq-normal-credentials-control` on 2026-08-22 completed the
experimental JMQ negative control. A 360-second normal-MQ baseline contained
28 ordinary telemetry events and no map events. A second `MqttClient` then
connected successfully to the mower-advertised JMQ endpoint using the same
ordinary portal credentials, client `device_id`, identity shape, and topic
subscriptions as normal MQ.

During the following 60 seconds, the JMQ control session received five ordinary
events: three machine bury-point events, one battery event, and one battery-info
bury-point event. It received no map events or map IDs. Normal MQ received no
events in the same post-connect window. Both sessions remained connected until
the diagnostic shut them down cleanly.

The capture confirms that JMQ accepts the ordinary MQTT identity and can carry
ordinary device telemetry, but that identity/session does not activate map
traffic without `appping`. Because normal MQ became silent while the same
identity on JMQ received telemetry, a reasonable inference is that backend
delivery shifted to the later JMQ session. One window cannot prove the routing
rule, but it demonstrates that this negative control may affect where existing
MQTT traffic is delivered. It must remain explicit, opt-in, and unsuitable as
the primary app-presence test.

The mower state was manually declared as `mowing` and was not independently
confirmed by a supported state event. No unknown map payload was decoded.

### Phase 12: presence renewal while likely docked

Sanitized run `12-presence-renewal-ngiot` on 2026-08-22 exercised the renewal
scheduler correctly but did not meet the stream precondition. The baseline ran
from 09:56:02 to 09:57:02 UTC. The first N-GIoT `appping` marker was recorded at
09:57:02.774 and its request appeared on normal MQ at 09:57:03.023. The renewal
marker was recorded 240.009 seconds later at 10:01:02.782, with its MQTT request
at 10:01:02.905. Observation ended 700.004 seconds after the first marker at
10:08:42.778.

Both legitimate N-GIoT calls completed with the previously observed null
response shape, and normal MQ remained functional with 40 battery/machine
telemetry records. However, the entire run contained zero `onPos`,
`onMapTrack`, `onMI`, or `onArI`; consequently
`live_stream_confirmed_before_renewal` was false and no stream expiry or
extension could be measured.

The HA export records `paused` at 09:45:50 and `docked` at 09:46:35, with no
later transition before the portion of the export covering the first ping. The
operator also confirmed that the mower had returned to charge. The second ping
and final observation boundary extend beyond the safely covered HA interval,
so later state is unknown rather than proven docked. This run is classified as
**inconclusive for presence renewal / precondition failed**, not as negative
evidence for `appping`. It is only preliminary evidence that a docked mower does
not emit the live mowing stream in response to `appping`.

### Phase 12b: successful presence renewal while mowing

Sanitized run `12b-presence-renewal-ngiot-mowing` on 2026-08-22 repeated the
same schedule while the operator confirmed that the mower remained actively
mowing for the full run. Normal MQ was the only MQTT session. The first N-GIoT
`appping` marker was recorded at 10:16:11.033 UTC and the renewal marker at
10:20:11.044, an elapsed 240.011 seconds. Observation continued until
10:27:51.042, 700.010 seconds after the first marker.

Live traffic was confirmed before renewal. The baseline already contained an
active stream, so this run does not isolate activation by its first ping. It
does isolate the renewal boundary: traffic continued through the original
first-ping expiry near 10:21:11 and stopped near the renewed expiry instead.
The final `onPos` arrived at 10:25:10.577, 299.534 seconds after the renewal
marker. The final `onMapTrack` arrived at 10:25:09.932, 298.889 seconds after
the renewal marker. No further map/position event arrived during the remaining
160–161 seconds, although the mower continued mowing and ordinary MQTT stayed
connected.

The one flagged `onPos` interruption lasted 27.95 seconds from 10:24:12.747 to
10:24:40.697 and recovered well before final expiry. `onMapTrack` had six gaps
of 16–38 seconds, including the same late gap; these reflect its less regular
cadence and do not align with either expiry boundary. At renewal itself,
`onPos` continued from 10:20:10.646 to 10:20:11.138 without an interruption.
Periodic `onMI`/`onArI` pairs continued at roughly 60-second cadence through
10:25:08 and then stopped with the other live traffic. Map IDs remained `0`
for `onPos`/`onMapTrack` and `1` for `onMI`/`onArI`.

This confirms that `appping` resets an approximately 300-second presence lease.
A single renewal at 240 seconds extends the stream to roughly 540 seconds from
the first ping; it does not make presence permanent. A client that needs an
uninterrupted live stream must repeat `appping` before each lease expires, with
240 seconds now supported as a conservative research interval. This is a
protocol finding, not a decision to implement a production map refresh loop.

### Phase 13: paused state plus N-GIoT `appping`

Sanitized run `13-state-paused-ngiot-appping` on 2026-08-22 used normal MQ only,
with the mower manually declared as `paused`. Its 30-second baseline contained
ordinary telemetry and no map or position events. N-GIoT `appping` was observed
on normal MQ at 10:32:03.599 UTC.

Two isolated `onPos` events with map ID `0` followed at 10:32:13.099 and
10:32:15.144: about 9.50 and 11.54 seconds after the request, separated by
2.045 seconds. Both occurred while the approximately 20-second `appping` call
was pending. No `onMapTrack`, `onMI`, `onArI`, `onMapState`, or `onAreaSet`
arrived, and no further `onPos` occurred during the following 120-second
window.

Under the declared paused condition, `appping` therefore did not activate the
sustained mowing stream. It was closely associated with two transient position
updates, which may represent a stationary/current-position response; their
payloads remain deliberately undecoded. No supported state event independently
confirmed the manual `paused` label, so operator/HA state confirmation remains
part of the interpretation.

### Phase 14: return-to-dock transition plus N-GIoT `appping`

Sanitized run `14-state-returning-ngiot-appping` on 2026-08-22 used normal MQ
only and began with the mower manually declared as `returning`. The report also
captured direct transition telemetry: `onFwBuryPoint-bd_task-return-normal-start`
at 10:38:44.083 UTC, `onChargeState` at 10:40:16.648, charge-task start at
10:40:17.983, and `onFwBuryPoint-bd_task-return-normal-stop` at 10:40:18.659.
The mower therefore reached the dock about 26 seconds before the 90-second
post-control observation window ended.

Six `onMapTrack` events with map ID `0` arrived as a short startup burst from
10:38:41.913 to 10:38:42.883, before both the explicit return-task-start event
and `appping`. One `onMI` and one `onArI`, each with map ID `1`, arrived at
10:38:45.911 and 10:38:45.921. The first `onPos` followed at 10:38:45.928.
N-GIoT `appping` became visible on normal MQ at 10:38:50.393, after six
`onPos` events had already arrived. This timing means the capture does not by
itself prove that `appping` initiated the returning stream.

The run contained 107 `onPos` events with map ID `0`. The median interval was
513 ms. The final `onPos` arrived at 10:40:16.649, effectively simultaneous
with the observed charge-state transition; no position event followed while
docked. Cadence became intermittent near the dock, including gaps of 6.03 and
11.48 seconds, rather than remaining a uniform 2 Hz stream. No `onMapTrack`
arrived after the initial startup burst.

The original Phase 14 report's generic ID union also printed `221558440`. In
this capture that value occurs only in firmware bury-point events for pause,
relocation, return start, and return stop. It does not occur in `onPos`, `onMI`,
`onArI`, or `onMapTrack`, so it was a false positive and must not be treated as
a correlated map ID. The relevant map-event correlation remains `0` for
position/track and `1` for MI/area-info. Opaque payloads remain deliberately
undecoded.

The Phase 1 cleanup fixes this at the diagnostic boundary. `mid_correlation`
now accepts `mid`/`mapId` only from an explicit allowlist of map and position
commands. Numeric ID-bearing fields in other commands, including the
`221558440` bury-point value, are written to
`other_numeric_id_observations` with field and command context. They never
contribute to per-session/per-phase `map_ids` or the console's correlated map
ID list. A regression test covers the Phase 14 value directly.

The live state provider changed the report label from `returning` to `paused`
after an `onCleanInfo` event at 10:38:41.988 and to `docked` at
10:40:16.648. The explicit return-task start/stop events and the operator's
starting-state confirmation are stronger evidence that the intervening period
was a return task. This exposes a diagnostic labeling limitation: current state
normalization does not infer `returning` from the bury-point task event.

Together, Phases 13 and 14 complete the planned short state comparison. A
missing map response while docked, idle, or paused remains condition-dependent
and is not by itself negative evidence for the active-mowing live-map behavior.

## Reference implementation behavior

The following describes `Janverhu/ecovacs-goat-g1`; it is reference behavior,
not yet a local observation from our mower.

- App-presence opens a separate MQTT 3.1.1 session. Its client ID is
  `<user-id>@USER/<realm>`, where `realm` is read from the account token's `r`
  claim. Its username combines the mower DID with base64-encoded feature and
  role metadata. See
  [mower_mqtt.py](https://github.com/Janverhu/ecovacs-goat-g1/blob/main/custom_components/ecovacs_goat_g1/mower_mqtt.py).
- `appping` is sent through N-GIoT `api.control()`, not through the legacy
  command path. See
  [mower_coordinator.py](https://github.com/Janverhu/ecovacs-goat-g1/blob/main/custom_components/ecovacs_goat_g1/mower_coordinator.py).
- Every N-GIoT control call generates a new `uuid4().hex`, uses it as both `si`
  and `x-eco-request-id`, and sends `ct`, `eid`, `et`, `er`, `apn`, and `fmt`.
- Before control, a short-lived SST token is issued at
  `/api/new-perm/token/sst/issue` using the legitimate account token and an ACL
  limited to `Control` for the selected endpoint. See
  [mower_api.py](https://github.com/Janverhu/ecovacs-goat-g1/blob/main/custom_components/ecovacs_goat_g1/mower_api.py).

The diagnostic implements these identity and authentication shapes but chooses
the mower's advertised endpoints first, as described below.

## Hypotheses and current status

1. `service.jmq` is a separate N-GIoT/app-presence MQTT service. Its advertised
   endpoint accepts both the reference-shaped session and an ordinary MQTT
   identity. The reference-shaped session received no messages; the ordinary
   identity received standard telemetry but no map events. JMQ was not
   necessary for map-stream activation, and its remaining app-specific purpose
   is unresolved.
2. `service.mqs` is the N-GIoT HTTP/control service rather than a second MQTT
   broker. This is confirmed by successful SST-authenticated `appping` and
   `getMI` calls to `/api/iot/endpoint/control`.
3. Fast GOAT `onPos` and map pushes require correct JMQ app-presence, N-GIoT
   `appping`, or both. The JMQ requirement is rejected for this mower. The
   `appping` trigger is confirmed, and both N-GIoT and experimental legacy
   transport activated the stream.
4. O-series `getMI` may require N-GIoT control. This is rejected for this
   mower: both legacy and N-GIoT transports delivered successful P2P exchanges.
5. `getMI` may return data synchronously, trigger `onMI`, or do both. Both
   transports returned acknowledgement metadata and solicited an immediate
   `onMI`/`onArI` update while presence was active; neither started or changed
   the sustained stream in the controlled runs.
6. A single `appping` creates an approximately five-minute presence lifetime.
   Three initial expiry observations and the Phase 12b renewed expiry are all
   within about two seconds of 300 seconds. Phase 12b confirms that a second
   ping at 240 seconds resets the lease; without another ping, traffic stops at
   the renewed boundary.
7. Mower state affects the stream shape. Active mowing supports sustained
   `onPos` plus repeated `onMapTrack`; paused state produced only two transient
   positions; a return-to-dock task produced dense but increasingly intermittent
   `onPos` until docking, while its map-track messages were confined to an
   initial burst. The return capture cannot isolate the causal contribution of
   `appping` because position traffic began before the ping.

## Completed presence-renewal and state follow-up

The broad Phase 1 matrix is complete. The bounded renewal experiment used this
sequence to test whether a second `appping` resets the observed lifetime:

1. Connect only the existing normal MQ session.
2. Record a short pre-control baseline.
3. Send N-GIoT `appping` and confirm both `onPos` and `onMapTrack` before the
   renewal deadline.
4. Send one new N-GIoT `appping` approximately 240 seconds after the first.
5. Continue observing until 700 seconds after the first ping. This spans both
   the original approximately 300-second boundary and the renewed boundary at
   approximately 540 seconds.

Renewal mode is enabled only when both `--renew-appping-after-seconds` and
`--presence-total-seconds` are supplied. It rejects JMQ and `getMI` factors so
the presence control remains isolated. Legacy `appping` is supported for a
later explicit control, but N-GIoT is the primary reference flow.

The sanitized report adds `presence_renewal`, containing:

- exact scheduler timestamps for the first and renewal `appping`;
- MQTT-observed `appping` request timestamps;
- whether `onPos` and `onMapTrack` were both confirmed before renewal;
- last-before and first-after timestamps around each ping;
- first/last timestamps for both streams;
- interruptions of at least five seconds for `onPos` and ten seconds for
  `onMapTrack`; and
- tail silence from the final event to the 700-second observation boundary.

The thresholds only flag periods for analysis; they do not interpret or decode
map payloads. The scheduler anchors both the renewal and final deadline to the
first ping, so the roughly 20-second `appping` HTTP wait does not shift either
deadline.

Recommended PowerShell command while the mower remains actively mowing and the
official app is closed:

```powershell
.venv\Scripts\python.exe scripts\goat_map_refresh_diagnostic.py `
  --country NO `
  --phase 12-presence-renewal-ngiot `
  --mower-state mowing `
  --device-class 2i0fns `
  --jmq none `
  --appping ngiot `
  --get-mi none `
  --baseline-seconds 60 `
  --observation-seconds 60 `
  --renew-appping-after-seconds 240 `
  --presence-total-seconds 700 `
  --output goat-map-12-presence-renewal-ngiot.json
```

Phase 12b confirmed renewal and expiry at the renewed boundary. Phases 13 and
14 then completed the short paused and returning comparisons. No additional
broad Phase 1 matrix run is currently required before designing Phase 2.

## Experimental controls

- `JmqMode.NORMAL_CREDENTIALS_CONTROL` connects the ordinary `MqttClient`
  identity to the JMQ endpoint. It is an experimental/negative control only.
  Correct `JmqMode.APP_PRESENCE` is the main JMQ test.
- Legacy `appping` is an experimental control. It is not the sequence observed
  in the reference implementation.
- Legacy `getMI` is a first-class control and must be tested before and after
  opening app-presence.
- Region-derived JMQ/MQS hosts are fallbacks, not preferred endpoints.

## Independent factors and presets

The runner accepts independent values:

| Factor | Values |
| --- | --- |
| JMQ | `none`, `app-presence`, `normal-credentials-control` |
| `appping` | `none`, `legacy`, `ngiot` |
| `getMI` | `none`, `legacy`, `ngiot` |
| mower state | `docked`, `idle`, `mowing`, `paused`, `returning`, `unknown` |

The A-D enums remain convenience presets only:

| Preset | JMQ | `appping` | `getMI` |
| --- | --- | --- | --- |
| A | none | none | none |
| B | app-presence | none | none |
| C | app-presence | N-GIoT | none |
| D | app-presence | N-GIoT | N-GIoT |

Custom factor combinations are the primary way to run the full comparison.

## Endpoint selection

Endpoint selection is deterministic and is written to sanitized `endpoint`
records:

1. `service.jmq` from device-info; otherwise regional
   `jmq-ngiot-<continent>.dc.robotww.ecouser.net`.
2. `service.mqs` from device-info; otherwise regional
   `api-ngiot.dc-<continent>.ww.ecouser.net`.
3. SST issuance uses the regional
   `api-base.dc-<continent>.ww.ecouser.net`, because device-info does not
   advertise an SST service.

Each record says `device service` or `fallback`. Hostnames are not credentials.

## Measurement and report model

Every MQTT, control, endpoint, session, state, and window record contains:

- timestamp;
- test phase;
- mower state;
- session or transport;
- command/topic metadata where applicable;
- `map_ids` only when known `mid`/`mapId` fields occur in an allowlisted map or
  position command; and
- separately classified numeric ID fields in `other_numeric_ids` when they are
  not map IDs.

The runner creates separate measurement windows for baseline, after JMQ,
after `appping`, and after `getMI`, depending on selected factors. An optional
state provider can update the declared state before each window. Incoming
supported `StateEvent` messages also update the recorder (`cleaning` is recorded
as `mowing`). The report includes a cross-transport `mid_correlation` index for
map IDs only, a separate `other_numeric_id_observations` index, per-session
`onPos` frequency, and normal-MQ traffic before/after JMQ connect.

## Recommended factor-based test order

Use comparable window lengths and repeat the key phases while the mower is
actively mowing:

1. Normal MQ baseline, no controls.
2. Legacy `getMI`, without JMQ.
3. Correct JMQ app-presence, without `appping` or `getMI`.
4. Correct JMQ app-presence plus legacy `getMI`.
5. Correct JMQ app-presence plus N-GIoT `getMI`, still without `appping`.
6. Correct JMQ app-presence plus N-GIoT `appping`.
7. After N-GIoT `appping`, repeat legacy `getMI`.
8. After N-GIoT `appping`, repeat N-GIoT `getMI`.
9. Only after the reference-shaped tests, run legacy `appping` and ordinary
   credentials on JMQ as experimental controls.

Runs 2-8 should preferably be captured during the same active mowing session.
If state changes, start a new run with the new state label or supply a state
provider. Do not classify absence during a docked window as a failed live-map
test.

## Running the diagnostic

The script prompts for the account and password; neither is accepted as a CLI
argument or written to the report. It stores a stable random client `device_id`
in the git-ignored `.goat-map-refresh-state.json`. The same file is reused on
later runs so Ecovacs sees the same verified client resource. Do not delete this
file between experiment phases. A different location can be selected with
`--client-state-file`, but that same path must then be supplied on every run.

On the first run Ecovacs may require device verification. The script catches
that specific response, requests the email verification code, asks for it with
hidden terminal input, verifies the same client resource, and continues the
same diagnostic run. Verification codes and returned authentication data are
not added to the report. Example baseline from PowerShell:

On Windows the CLI runs the diagnostic in an asyncio Selector event loop.
`aiomqtt` requires socket `add_reader`/`add_writer` support, which the default
Windows Proactor loop does not provide.

```powershell
.venv\Scripts\python.exe scripts\goat_map_refresh_diagnostic.py `
  --country NO `
  --phase 01-baseline `
  --mower-state mowing `
  --jmq none `
  --appping none `
  --get-mi none `
  --baseline-seconds 60 `
  --observation-seconds 60 `
  --output goat-map-baseline.json
```

If more than one GOAT is present, add `--device-class <class>`. Use `--help` to
see all factor values. Reports are written only after a completed run.

For the first comparison, repeat the command with a new phase/output and
`--get-mi legacy`. Then use `--jmq app-presence`, first with no control and then
with each `getMI` transport. N-GIoT options fetch SST automatically; no capture
token or request ID is accepted by the tool.

## Results to retain for analysis

Return the sanitized JSON report, or at minimum these report sections:

- `experiment`;
- all `endpoint`, `session`, `window`, `state`, and `control` records;
- MQTT records whose command is `onPos`, `onMI`, `onArI`, `onMapTrack`,
  `onMapState`, or `onAreaSet`;
- `sessions`, including `on_pos` rates;
- `normal_mq_around_jmq_connect`; and
- `mid_correlation`; and
- `other_numeric_id_observations`.

Also report whether mowing remained active for the full window and any visible
app/mower behavior. Do not return raw application captures, tokens, request
headers, or unredacted MQTT topics.

## Proposed Phase 2 plan

Phase 2 should remain capture- and evidence-driven. No existing MQTT or
`Command` transport is replaced, and no `Map` capability integration starts
until both the static-map and track formats have stable fixtures and tests.

### 2.1 Controlled `getMI` acquisition

1. Add a separate opt-in Phase 2 capture mode; keep the Phase 1 metadata-only
   mode unchanged.
2. Run while mower state is independently confirmed, preferably active mowing,
   with the official app closed and normal MQ connected.
3. Record a quiet baseline, activate N-GIoT `appping`, then send exactly one
   `getMI` per selected transport. Capture each control response and its
   following `onMI`/`onArI` window with exact timestamps and map IDs.
4. Use legacy `getMI` first because it exercises the existing client transport,
   then repeat with N-GIoT `getMI` under the same presence lease as a paired
   control. Do not mix additional JMQ or control factors into these runs.
5. Repeat enough times to distinguish stable static fields from request IDs,
   timestamps, state-dependent fields, and transport-specific envelopes.

Exit criterion: reproducible `getMI` to `onMI`/`onArI` captures with matching
map-ID context and no secrets in the artifact.

### 2.2 Raw, sanitized capture artifacts

The implemented capture infrastructure stores Phase 2 data in an explicit,
git-ignored `.goat-map-phase2/` artifact selected by CLI option. Its
`manifest.json` has schema version `goat-static-map-capture/v1` and a new random
`uuid4().hex` `capture_id`. This ID is generated locally and is not derived from
an account, client resource, or mower identity.

`records.jsonl` can preserve all members of the static-map capture family:
`getMI`, `onMI`, `onArI`, `getAreaSet`, and `onAreaSet`. Supporting these
commands does not imply that all are required or share an encoding. The first
test sends only `getMI`; area-set messages are retained only if observed.

Each record contains sanitized envelope structure, command, direction,
transport/session, timestamp, mower state, map IDs, source representation, and
opaque segment references. Opaque segment bytes are content-addressed under
`blobs/<sha256>.bin`, with byte length and SHA-256. Identical segments share one
blob. Each reference is shaped conceptually as:

```json
{
  "source_path": "$.body.data.info",
  "representations": {
    "original": {
      "kind": "json-string-utf8-value",
      "blob": "blobs/<sha256>.bin",
      "sha256": "<sha256>",
      "byte_length": 123
    },
    "decoded": null
  }
}
```

`original` is the exact captured opaque value representation. `decoded` remains
`null`; a later decoder can add a distinct derived representation without
overwriting or reinterpreting the original blob. JSON strings are stored as
their exact UTF-8 logical value. Structured opaque values are labeled
`canonical-json-v1`, so they are never misrepresented as original HTTP/MQTT
wire framing.

The writer is fail-closed. Before publishing anything, it rejects invalid JSON,
registered secret canaries, sensitive fields, request-shaped IDs, known
account/device/client values, or configured byte-limit violations. A known
transport `reqid` inside the protocol `header` is handled as removable envelope
metadata: it is redacted in the sanitized envelope and excluded from opaque
segment extraction. The same field outside that allowlisted location still
rejects the entire artifact. The writer stores data in memory first and
atomically publishes only after a successful run. Credentials, tokens, SST
tokens, request IDs, account/device identities, and complete MQTT topics are
never part of the artifact. Nothing opaque is printed to the console or copied
into the sanitized summary report.

Use a versioned capture schema and enforce size limits. Add tests proving both
round-trip preservation of permitted opaque fields and removal of all known
secret fields. Captures supplied as fixtures must be explicitly sanitized and
reduced before they enter the repository.

Exit criterion: the same raw map-bearing value can be reproduced byte-for-byte
from the local artifact, while a secret-canary test proves sensitive auth and
identity data cannot survive serialization.

### 2.2.1 First capture: `p2-01-getmi-paired-mowing`

Run only while mowing is independently confirmed and the official app is
closed. The runner uses normal MQ without JMQ, records a 30-second baseline,
sends N-GIoT `appping`, confirms a new `onPos`, sends one legacy `getMI`, waits
45 seconds, uses a 30-second cooldown, sends one N-GIoT `getMI`, then records a
45-second response window and a 30-second tail. This remains within one
presence lease under normal response timing.

PowerShell command:

```powershell
.venv\Scripts\python.exe scripts\goat_map_phase2_capture.py `
  --country NO `
  --phase p2-01-getmi-paired-mowing `
  --mower-state mowing `
  --device-class 2i0fns `
  --baseline-seconds 30 `
  --live-confirmation-timeout 30 `
  --post-get-mi-seconds 45 `
  --cooldown-seconds 30 `
  --tail-seconds 30 `
  --artifact-dir .goat-map-phase2\p2-01-getmi-paired-mowing `
  --report-output goat-map-p2-01-summary.json
```

The artifact directory must not exist before the run. Send back only the
sanitized summary JSON and the console summary initially; retain the opaque
artifact locally until its contents and sharing procedure have been reviewed.

#### P2-01 paired capture result

Capture `p2-01-getmi-paired-mowing` completed on 2026-08-22 with normal MQ,
N-GIoT `appping`, legacy `getMI`, and N-GIoT `getMI`, in that order. The mower
state remained recorded as `mowing`; this run did not independently establish
the physical state beyond the declared/observed diagnostic context. The
30-second baseline contained no `onPos`, `onMapTrack`, `onMI`, or `onArI`.

N-GIoT `appping` was observed on normal MQ at 12:15:02.404 UTC. The first
`onPos` followed after about 184 ms and the first `onMapTrack` after about
1.72 seconds. Across the full capture normal MQ retained 286 `onPos` events,
64 `onMapTrack`, four `onMI`, and six `onArI`; `onPos` had a median interval of
about 511 ms. Live position/track events retained map ID `0`, while every
captured `onMI`/`onArI` retained map ID `1`.

The legacy `getMI` request was observed at 12:15:22.547 UTC. `onMI` followed
about 111 ms later and two distinct `onArI` events about 117 ms later. The
normal-MQ response and legacy command result completed in the same interval.
The N-GIoT `getMI` request was observed at 12:16:37.800 UTC. Its `onMI` followed
about 119 ms later, followed by two distinct `onArI` events within 120 ms; the
normal-MQ and N-GIoT HTTP responses completed within about 124 ms. Thus both
control transports directly produced the same observable static-map event
family and nearly identical response timing in this run.

The immediate legacy and N-GIoT `onMI` records contain byte-identical opaque
`body.data.info` values (876 bytes and the same SHA-256 digest). Their recorded
`centerX` and `centerY` values also have matching digests. Later periodic
`onMI` records contain a different, shorter `info` value (52 bytes), which is
itself byte-identical across two observations roughly 60 seconds apart. The
paired immediate `onArI` records have distinct `info` digests and lengths:
1024/844 bytes after legacy and 1024/876 bytes after N-GIoT. These are direct
representation-level observations only; no chunking, compression, encoding,
or semantic role is inferred yet.

The normal-MQ response to each `getMI` and the N-GIoT HTTP response share the
same retained header-segment digests and contain no captured opaque map value.
The legacy command result adds only legacy wrapper metadata to the equivalent
response. This indicates that, for this capture, the map-bearing values arrived
through `onMI`/`onArI`, not in the direct `getMI` acknowledgement. No
`getAreaSet` or `onAreaSet` was observed. The local artifact contains 16 records,
33 unique deduplicated blobs, and 6387 opaque bytes. Payload decoding remained
disabled throughout.

#### P2-02 paired repeat result

The first P2-02 attempt did not satisfy the live-stream precondition: no
`onPos` arrived within 30 seconds after N-GIoT `appping`, so the run aborted
before either `getMI` action and published neither artifact nor summary. This is
not negative map-format evidence; the mower's physical state was not
independently established by that failed attempt.

The successful repeat later completed with 44 static-family records, 39 unique
blobs, and 3946 opaque bytes. Its baseline was not quiet: it already contained
67 `onPos`, 17 `onMapTrack`, one `onMI`, and one `onArI`. The run therefore
confirms an active stream but cannot independently attribute activation to its
own `appping` call. Across the complete run normal MQ observed 372 `onPos`, 98
`onMapTrack`, seven `onMI`, and eleven `onArI`; no `onAreaSet` was observed.

The `appping` window also contained a broad group of control requests that the
capture script does not issue, including `getInfo`, `getPos`, `getMapTrack`,
`getMI`, and `getAreaSet`. Eight `getAreaSet` requests and eight matching
responses were retained. This sequence is classified as `concurrent-external`,
with the note `temporally correlated with Home Assistant frontend reload`.
The operator pressed F5/reload in the Home Assistant browser at approximately
14:28 local time and did not knowingly open the Ecovacs app. Other household
members may nevertheless have had the official app open at the same time; that
possibility cannot currently be excluded. Temporal correlation therefore does
not establish causation or identify which client issued the requests. The
sequence is retained as a valuable observation but is excluded from controlled
transport evidence until its source is confirmed.

Source inspection on 2026-08-22 narrows, but does not resolve, the attribution.
The built-in Home Assistant Ecovacs mower entity subscribes only to mower state
and exposes start, pause, and dock actions; the local `2i0fns` capability profile
does not expose the existing `Map` capability. A normal Lovelace reload of that
built-in entity therefore does not by itself explain this GOAT map-command
family.

The optional card in `Janverhu/ecovacs-goat-g1` is a plausible HA-side trigger.
Its `connectedCallback()` invokes `request_live_position_stream` when the card
is visible and the mower state is `mowing`; visibility/intersection changes can
invoke the same service. The inspected coordinator starts app-presence MQTT and
issues `getPos` for the O-series live-position path. Its regular coordinator
refresh also emits grouped `getInfo` requests containing commands observed in
the concurrent sequence, including `getOta` and `getScheduleLatestTask`, plus a
separate `getLifeSpan`. This could explain part of the broad refresh near the
reload. However, the inspected O-series live-position service does not itself
issue `getMI`, `getAreaSet`, or `getMapTrack`, so it does not yet explain the
complete sequence. An official app session belonging to another household
member, a different installed card/integration version, or another GOAT client
remains possible. The retained classification is therefore
`concurrent-external`, not Home Assistant traffic and not official-app traffic.

Despite that confounder, the explicitly labelled paired actions repeat the
central representation result. Legacy `getMI` produced `onMI` after about
148 ms and its two `onArI` events within about 150 ms. N-GIoT `getMI` produced
the same event family after about 4.49 seconds in this run. Every immediate
`onMI`, including the concurrently solicited events, contains the same 876-byte
`body.data.info` digest observed in P2-01. The periodic 52-byte `onMI.info`
digest is also identical across P2-01 and P2-02. This establishes byte-level
stability of both observed `onMI` forms across two captures and both explicit
control transports, without assigning either form a decoded meaning.

Within P2-02 each immediate `onArI` pair repeats the same two opaque values
(1024 and 888 bytes respectively), across concurrent, legacy, and N-GIoT
requests. The periodic `onArI` form is independently stable at 800 bytes. These
digests differ from P2-01's `onArI` values, so `onArI` is not yet demonstrated
to be invariant across runs. No encoding or segmentation explanation is
assumed.

The captured `getAreaSet` envelope exposes request metadata fields `mid`, `aid`,
and `type`. Its response adds `subsets` and `infoSize`. Two opaque `subsets`
representations recur (124 and 24 bytes), but they remain out of decode scope
until `onMI`/`onArI` is understood. All records retained map ID `1` for the
static-map family and map ID `0` for live position/track traffic.

#### P2-03 controlled frontend-reload attribution

Before using the concurrent P2-02 `getAreaSet` sequence as evidence, run one
passive attribution control while active mowing is physically confirmed. The
official Ecovacs app should be closed on known devices as far as practical.
The diagnostic connects only normal MQ, issues no `appping`, `getMI`, or other
control action, records a 45-second baseline, then waits for the operator to arm
the reload window. Once the console prints `RELOAD NOW`, press F5 exactly once
on the same Home Assistant dashboard containing the GOAT card. The following
90 seconds are labelled `frontend-reload-window`; this label is temporal and
does not attribute a client source.

```powershell
.venv\Scripts\python.exe scripts\goat_map_phase2_capture.py `
  --mode frontend-reload-attribution `
  --country NO `
  --phase p2-03-ha-frontend-reload-attribution `
  --mower-state mowing `
  --device-class 2i0fns `
  --baseline-seconds 45 `
  --reload-window-seconds 90 `
  --artifact-dir .goat-map-phase2\p2-03-ha-frontend-reload-attribution `
  --report-output goat-map-p2-03-summary.json
```

The summary retains exact timestamps and offsets from the window marker for
`getInfo`, `getPos`, `getMapTrack`, `getMI`, and `getAreaSet`, including separate
request/response/event counts. It always records classification
`concurrent-external` and client source `unattributed`. A tightly repeated full
pattern would be strong evidence for HA/GOAT-card-related initiation, but not
proof of the exact process. A `getInfo`/`getPos`-only result with no
`getMapTrack`, `getMI`, or `getAreaSet` would instead strengthen the other-client
hypothesis. The static-map artifact remains byte-preserving and decoder-free.

The completed P2-03 run started its reload window at
13:04:16.315536 UTC. No `getInfo`, `getPos`, `getMapTrack`, `getMI`, or
`getAreaSet` request or response appeared anywhere in the following 90 seconds;
`getAreaSet` count was zero. The broad P2-02 control sequence therefore did not
reproduce after this F5 action.

Live pushes were already active before F5. The 45-second baseline contained 72
`onPos` and six `onMapTrack`; the reload window contained 153 and 35
respectively. `onPos` occurred 0.378 seconds before and 0.137 seconds after the
window marker, while `onMapTrack` occurred 1.556 seconds before and 0.464
seconds after it. This is an uninterrupted existing stream, not evidence that
F5 activated it. One `onMI`/`onArI` pair arrived at 13:03:54.868/54.875 UTC and
the next at 13:04:55.048/55.048 UTC, intervals of approximately 60.180 and
60.174 seconds. The stable 52-byte `onMI.info` digest repeated. Their cadence
is consistent with periodic traffic and not a response tightly following the
reload marker.

This result strengthens the hypothesis that P2-02's broad request sequence came
from another client, including a possible household Ecovacs app session. It
does not prove that conclusion: the HA/GOAT coordinator may suppress a repeated
live-stream request while an existing presence/stream lease is active. The
P2-02 sequence remains `concurrent-external`, and the P2-03 trigger remains
temporally labelled rather than client-attributed.

#### P2-04 official-app-open positive control

Use the same passive design as a positive control. Physically confirm mowing,
force-close the official app on the operator-controlled device, leave the HA
dashboard untouched, and start the command below. At the marker, open the
official Ecovacs app directly to this mower's map view without performing other
actions. The tool still issues no device-control command and labels the window
`official-app-open-window`; client source remains `unattributed` until the
observed timing is evaluated.

```powershell
.venv\Scripts\python.exe scripts\goat_map_phase2_capture.py `
  --mode official-app-open-attribution `
  --country NO `
  --phase p2-04-official-app-open-attribution `
  --mower-state mowing `
  --device-class 2i0fns `
  --baseline-seconds 45 `
  --trigger-window-seconds 90 `
  --artifact-dir .goat-map-phase2\p2-04-official-app-open-attribution `
  --report-output goat-map-p2-04-summary.json
```

Reproduction of the full request family tightly after the app-open marker would
provide a positive signature to compare with P2-02. Absence of that family must
still be interpreted in light of app caching, an already-active session, and
whether the mower map view was actually initialized.

The completed P2-04 positive control had a quiet 45-second baseline: none of
the target requests or fast map/position pushes was present. The
`official-app-open-window` began at 13:13:23.673444 UTC. The first observed app
control request was `GetWKVer` at +3.171 seconds, followed by `getOta` at +3.184
seconds. N-GIoT `appping` appeared at +4.769 seconds, and the broad map/control
burst followed immediately:

- five `getInfo` request/response pairs, first request at +4.852 seconds;
- nine `getAreaSet` request/response pairs, first request at +5.146 seconds;
- one `getMI` pair, requested at +5.264 seconds;
- two `getMapTrack` pairs, first requested at +5.298 seconds;
- one `getPos` pair, requested at +5.326 seconds.

The same burst also included `getLifeSpan`, `getNetworkSwitch`,
`getRelocationState`, `getScheduleLatestTask`, `getScheduleTaskInfo`,
`getSchedules`, `getSpecialContour`, and `getVoice`. Its immediate `getMI`
request was followed after about 500 ms by `onMI`, then two `onArI` events
within about 527 ms. No `onAreaSet` was observed. The full 90-second window
contained 156 `onPos`, 45 `onMapTrack`, two `onMI`, and three `onArI`. Static-map
events and area requests used map ID `1`; position and track used map ID `0`.
The immediate 876-byte and periodic 52-byte `onMI.info` values are byte-identical
to the corresponding P2-01/P2-02 digests, adding a third independent capture
without extending their interpretation.

This is controlled evidence that opening the official app's mower map can
produce the complete command family previously seen as the P2-02 confounder.
The P2-02 concurrent burst is a close fingerprint match: eight `getInfo`, two
`getPos`, two `getMapTrack`, two `getMI`, and eight `getAreaSet`
request/response pairs, plus the same lifespan, OTA, schedule, and special-
contour families. Counts vary, but both are dense multi-command initialization
bursts. P2-02 remains classified `concurrent-external` because its exact client
was not observed directly; the positive control now makes an official-app
session from another household user a strong source hypothesis. The controlled
F5 test did not reproduce this fingerprint.

#### Read-only `onMI.info` representation inspection

`scripts/goat_map_blob_inspect.py` reads and digest-verifies existing artifact
blobs without modifying them. It reports byte length, unique-byte count,
Shannon entropy, ASCII/UTF-8 printability, hex/Base64 character coverage, strict
text-encoding candidates, leading bytes and known compression signatures after
an exact-round-trip text layer, plus pairwise prefix/suffix and length
differences. Syntax matches are explicitly not map decoding.

Inspection of both P2-01 and P2-02 reproduces the same two `onMI.info` digests.
The 52-byte and 876-byte originals are both printable ASCII and strict Base64
with exact round-trip. Removing only that proven representation layer yields
38 and 657 bytes respectively. Their decoded leading bytes are
`5d00000400190000` and `5d00000400dc0600`; neither raw nor Base64-derived bytes
match the currently checked gzip, zlib, bzip2, xz, ZIP, Zstandard, or LZ4 frame
signatures. Original-byte Shannon entropy is approximately 4.423 and 5.939 bits
per byte. The original representations share six leading bytes and no suffix;
after the strict Base64 layer they share five leading bytes and one trailing
byte, with the first difference at offset five. This is structural evidence
only. No field meaning, framing, geometry, or decoded-map claim follows from it.

Read-only command:

```powershell
.venv\Scripts\python.exe scripts\goat_map_blob_inspect.py `
  --artifact-dir .goat-map-phase2\p2-01-getmi-paired-mowing
```

#### Proven representation layer and golden forms

`deebot_client.diagnostics.goat_map_representation` now contains the only
decode operation justified by the captures: strict, canonical Base64 removal
for `onMI.info`. It rejects empty, non-ASCII, malformed, non-canonical, or
incorrectly padded input. Its result is uninterpreted bytes. The helper retains
the original text, the SHA-256 of that original representation, the derived
bytes, and a separate SHA-256 of those bytes. This is **representation
decoding**, not map decoding.

The two stable captured forms are checked in as golden fixtures after the data
owner explicitly confirmed that this dataset does not contain map geometry
requiring privacy protection. The fixture contains only the opaque `onMI.info`
representations, their observed `infoSize`, lengths, labels, and digests; it
contains no account/device identity, credentials, token, request ID, or MQTT
topic. Strict Base64 produces these byte-identical forms:

- periodic: 52 representation bytes -> 38 opaque bytes;
- immediate: 876 representation bytes -> 657 opaque bytes.

Tests verify exact round-trip, both original and derived digests, and explicit
rejection of invalid or non-canonical Base64.

#### Framing research without semantic interpretation

`scripts/goat_map_framing_inspect.py` performs a deterministic, read-only
comparison of the golden pair. It does not implement a framing parser. Current
observations are:

- decoded bytes 0 through 4 are identical; the first difference is offset 5;
- offsets 5 through 6 are `19 00` and `dc 06`; interpreted as little-endian
  unsigned 16-bit values they are 25 (`0x0019`) and 1756 (`0x06dc`);
- those values exactly equal the independently captured envelope `infoSize`
  values in both samples;
- a little-endian 32-bit read at the same offset yields the same values because
  bytes 7 and 8 are zero in both samples, so the field width remains ambiguous;
- neither candidate equals the decoded totals (38/657) or remaining decoded
  bytes after the candidate field (31/650); the short sample's value 25 also
  happens to equal `decoded_length - 13`, but the long sample disproves that as
  a general length relation;
- bytes 7 through 20 are identical; within the 38-byte overlap, the other
  differing range is offsets 21 through 37;
- both forms end in `00`, but this single common trailing byte is only a
  terminator/padding/checksum candidate;
- none of sum, XOR, CRC-32, or Adler-32 matches the trailing 1-, 2-, or 4-byte
  values under the tested byte orders;
- aligned fixed-width blocks of 4, 8, or 16 bytes do not repeat, and 2-byte
  repetition is sparse; no simple periodic record structure is evident;
- overlapping four-byte windows at offsets 9, 10, 12, 13, and 16 can be read
  as finite, moderately sized floats in at least one byte order. Their bytes
  are shared by both forms, but no field boundary, alignment, unit, or meaning
  has been established. They are not described as coordinates.

The `infoSize` correlation proves the start of one metadata-bearing field at
offset 5, but not its width or payload purpose. No second field boundary is yet
proved, so a general framing parser would be premature.

Read-only framing command:

```powershell
.venv\Scripts\python.exe scripts\goat_map_framing_inspect.py
```

#### Historical P2-05 controlled map-delta plan

This subsection records design history only. No No-Entry Zone was created or
attempted during P2-05, P2-06, or P2-07. Before execution, the operator
deliberately selected **Sone med redusert unnvikelse** as the controlled change
because it was simple and reversible without ending the mowing task, docking
the mower, or physically remote-driving a new boundary. The paragraphs below
must not be read as an execution log.

The preferred first geometry-changing control is one temporary no-go/exclusion
zone at the minimum size allowed by the official app, placed wholly inside a
large, open, already mapped lawn area. This has better diagnostic value than a
name or mowing-setting change because it should produce one localized geometry
delta, while being safer and easier to reverse than moving the outer boundary
or expanding the mowable area. It must not overlap the boundary, dock, guide
path, an existing exclusion, or a narrow transit route.

The mower should be paused for the edit itself. Before and after datasets must
otherwise use the same mower, map, normal-MQ passive capture, active-mowing
state, app map-init procedure, observation durations, and capture software.
After adding the zone, restore active mowing and wait for state stabilization
before the after-capture. Do not delete the zone until that capture is complete;
then remove it as a separate cleanup action, not as part of the measured delta.
The capture sequence is:

1. Capture one complete official-app map initialization before the edit,
   preserving `getMI`, `onMI`, `onArI`, `getAreaSet`, and `onAreaSet` if seen.
2. Record the trigger timestamp, pause the mower, and add exactly one minimum-
   size internal exclusion zone. Make no other map or mower-setting change.
3. Resume mowing, confirm the same state and map, then capture the identical app
   initialization sequence after the edit.
4. Compare records by command, role, map ID, timing, original/derived digest,
   length, common prefix/suffix, and differing byte ranges. Preserve all opaque
   bytes; do not infer geometry solely from a changed offset.
5. Revert the exclusion only after the paired artifact is complete and retain
   the revert as operational metadata outside the measured before/after pair.

A non-geometric area rename was retained as a fallback because it might only
alter UI metadata or `getAreaSet`. This design predates the completed P2-05
run. It was superseded before execution by the deliberately selected
reduced-avoidance control described below; it does not describe an attempted
No-Entry Zone operation.

#### P2-05 controlled reduced-avoidance-zone delta procedure

P2-05, P2-06, and P2-07 exclusively tested one official-app feature labelled
**Sone med redusert unnvikelse** (reduced-avoidance zone). No No-Entry Zone was
created or attempted. This was a deliberate low-impact choice, not a fallback
after a failed No-Entry Zone action. Existing artifact/report filenames retain
the earlier `controlled-nogo-delta` planning label only as immutable run
identifiers; they must not be used as the experiment classification.

The implemented P2-05 procedure uses three independent artifacts. The before
and after captures both use the unchanged paired legacy/N-GIoT `getMI` method.
The intervening edit capture is passive normal MQ: it sends no diagnostic
`appping`, `getMI`, or other device command. Its artifact window is labelled
`controlled-map-edit`, and the sanitized report retains exact window-start,
operator save/confirm, and window-end timestamps.

The edit artifact byte-preserves only an explicit map-command allowlist:
`getMI`, `onMI`, `onArI`, `getAreaSet`, `onAreaSet`, `getMapState`,
`onMapState`, `getMapTrack`, `onMapTrack`, and `setAreaSet`. All MQTT command
names and timing remain visible in the sanitized report even if an observed
write command is not yet in that blob allowlist. This permits command discovery
without retaining arbitrary MQTT payloads.

With the mower actively mowing and the official app closed, run the before
capture:

```powershell
.venv\Scripts\python.exe scripts\goat_map_phase2_capture.py `
  --mode paired-get-mi `
  --country NO `
  --phase p2-05-controlled-nogo-delta-before `
  --mower-state mowing `
  --device-class 2i0fns `
  --baseline-seconds 30 `
  --live-confirmation-timeout 30 `
  --post-get-mi-seconds 45 `
  --cooldown-seconds 30 `
  --tail-seconds 30 `
  --artifact-dir .goat-map-phase2\p2-05-controlled-nogo-delta-before `
  --report-output goat-map-p2-05-before-summary.json
```

After it completes, pause the mower and keep the app closed. Start the separate
edit capture:

```powershell
.venv\Scripts\python.exe scripts\goat_map_phase2_capture.py `
  --mode controlled-map-edit `
  --country NO `
  --phase p2-05-controlled-nogo-delta-edit `
  --mower-state paused `
  --device-class 2i0fns `
  --baseline-seconds 30 `
  --post-save-seconds 90 `
  --artifact-dir .goat-map-phase2\p2-05-controlled-nogo-delta-edit `
  --report-output goat-map-p2-05-edit-summary.json
```

At the first prompt, the mower was verified paused before opening the official
app. The operator then deliberately created exactly one minimum-size **Sone med
redusert unnvikelse** in the preselected safe lawn area, with no other map
change. The No-Entry Zone workflow was not entered. The second Enter retained
the operator's save/confirm context; the network timestamps remain
authoritative. The tool then observed 90 seconds after that marker.

When the edit capture completes, close the app, resume mowing, and physically
confirm that mowing has stabilized. Run the matching after capture:

```powershell
.venv\Scripts\python.exe scripts\goat_map_phase2_capture.py `
  --mode paired-get-mi `
  --country NO `
  --phase p2-05-controlled-nogo-delta-after `
  --mower-state mowing `
  --device-class 2i0fns `
  --baseline-seconds 30 `
  --live-confirmation-timeout 30 `
  --post-get-mi-seconds 45 `
  --cooldown-seconds 30 `
  --tail-seconds 30 `
  --artifact-dir .goat-map-phase2\p2-05-controlled-nogo-delta-after `
  --report-output goat-map-p2-05-after-summary.json
```

Finally, compare only the before and after artifacts. The edit artifact is not
an input to this delta:

```powershell
.venv\Scripts\python.exe scripts\goat_map_phase2_delta.py `
  --before-artifact .goat-map-phase2\p2-05-controlled-nogo-delta-before `
  --after-artifact .goat-map-phase2\p2-05-controlled-nogo-delta-after `
  --output goat-map-p2-05-controlled-nogo-delta.json
```

The reader is fail-closed: it verifies schema, anonymous capture ID, canonical
blob paths, record count, blob length, and SHA-256 before comparison. Groups are
matched by command, direction, transport, map ID, source path, and original
representation kind. Identical digests are matched first. A changed pair is
only inferred when byte length uniquely identifies one variant on each side,
or exactly one unmatched variant remains on each side; ambiguous variants stay
explicitly unpaired.

For each paired variant the report contains original SHA-256/length/count,
first and last differing start-aligned offset, differing-byte count, common
prefix/suffix, and length change. If both original string representations pass
strict canonical Base64, the same metrics and separate SHA-256 values are
reported for the derived bytes. `mid`/`mapId`, `aid`, `type`, and `infoSize` are
reported in a separate selected-field comparison. No changed byte range is
assigned geometry or map semantics.

Stop after verifying this delta report. Keep the temporary reduced-avoidance
zone through P2-06 so its deletion can serve as the controlled inverse
operation.

The completed run found byte-stable `onMI.info` before/after and byte-stable
`getAreaSet` `ar`/`vw` responses throughout the edit window. These remain
negative observations. `onArI.info` differed before/after, but the before
capture was internally unstable and the eventual after variants were already
observed during app initialization before the controlled write. The `onArI`
delta is therefore not attributed to the reduced-avoidance-zone change.

The network sequence most tightly correlated with creation was
`setSpecialContour`, followed by `onSpecialContour`, `onMI`/`onArI`, and
`getSpecialContour`/other refresh traffic. The manual save marker occurred
about 6.6 seconds after the request; network timestamps are authoritative and
the manual marker is operator context only. P2-05 did not byte-preserve the
`SpecialContour` family, so it supports create/delete envelope and timing
comparison but cannot provide a raw create-payload byte comparison.

#### P2-06 controlled inverse SpecialContour deletion

P2-06 preserves `setSpecialContour`, `getSpecialContour`, and
`onSpecialContour` opaque segments byte-for-byte under the existing fail-closed
security policy. The broader known map allowlist is also active so immediate
refresh events remain available, while every MQTT command name/timestamp stays
visible in the sanitized report. No payload interpretation is performed.

The experiment refuses to offer the deletion prompt until it observes an
actual `getSpecialContour` response after the official app map is opened. That
response is retained in `zone-present-readback`. At the first observed
`setSpecialContour` request, the MQTT observer records the authoritative
network timestamp and moves subsequent payloads into `post-delete-readback`.
The operator's later Enter/save marker cannot change this boundary.

With the reduced-avoidance zone still present, pause the mower, close the app,
and run:

```powershell
.venv\Scripts\python.exe scripts\goat_map_phase2_capture.py `
  --mode controlled-special-contour-delete `
  --country NO `
  --phase p2-06-controlled-special-contour-delete `
  --mower-state paused `
  --device-class 2i0fns `
  --baseline-seconds 30 `
  --initial-readback-timeout 60 `
  --post-delete-seconds 120 `
  --artifact-dir .goat-map-phase2\p2-06-controlled-special-contour-delete `
  --report-output goat-map-p2-06-special-contour-delete-summary.json
```

At the first prompt, press Enter and open the mower map in the official app,
but do not delete anything. Wait for the console to print
`ZONE-PRESENT SPECIALCONTOUR READBACK OBSERVED`. Only then delete the same
reduced-avoidance zone created in P2-05, make no other change, and press Enter
after the app reports save/confirm completion. The tool continues passively for
120 seconds. If the initial readback times out, do not delete the zone; rerun
with a new `-retry1` artifact directory.

After a successful capture, compare the present and post-delete readback
windows without modifying the artifact:

```powershell
.venv\Scripts\python.exe scripts\goat_map_special_contour_delta.py `
  --artifact .goat-map-phase2\p2-06-controlled-special-contour-delete `
  --output goat-map-p2-06-special-contour-delta.json
```

The report groups by command, direction, transport, map ID, source path, and
original representation kind. It reports lengths/digests and byte differences
for unambiguous pairs. Strict canonical Base64 is removed only when both values
prove that representation by exact round-trip; derived-byte digests and
offsets remain non-semantic. P2-05 and P2-06 sanitized summaries provide the
create/delete command-envelope and timing comparison, while P2-06 alone
provides byte-preserved present/delete readbacks. One cycle is insufficient for
a `SpecialContour` parser.

##### Aborted first P2-06 attempt and recovery

The first deletion attempt observed a zone-present `getSpecialContour`
response at `2026-08-22T16:57:25.126203+00:00`, after which the operator deleted
the intended reduced-avoidance zone. The capture writer then rejected a known
map/subset field named `mssid` because the earlier broad secret-key check
mistook the `ssid` substring for a Wi-Fi SSID. The writer remained fail-closed,
published neither artifact nor sanitized report, and the in-memory opaque
zone-present/delete data cannot be recovered from the terminal output. This
attempt is therefore an aborted capture, not inverse-delta evidence.

Existing map command code already treats `mssid` as a map subset identifier.
The capture policy now allows exactly `mssid`, while actual network identity
keys `ssid`, `bssid`, and `essid` remain fail-closed. The MQTT capture observer
also reports only the first rejection rather than logging the same follow-on
failure for every subsequent allowlisted message.

Because the zone was deleted during the aborted attempt, the controlled
recovery is a fresh symmetric cycle: capture creation of exactly one new
minimum-size **Sone med redusert unnvikelse**, then capture deletion of that same
zone using a new `-retry1` artifact. The creation artifact preserves the absent
readback, create request/event, and subsequent present readback when observed;
the deletion artifact preserves the present readback, inverse request/event,
and subsequent absent readback. No data from the aborted in-memory attempt is
treated as byte-level evidence.

##### Completed retry and required passive absent-state readback

The recovery create capture observed two `onSpecialContour` events immediately
before the operator marker. Their `info` representations were 92 and 88 bytes;
both passed strict Base64 validation and produced 67 and 65 representation-
decoded bytes respectively. They were structurally different and are not
treated as one stable create representation.

The retry deletion capture observed the same 88-byte `onSpecialContour.info`
digest three times during app initialization, establishing a stable pre-delete
representation for that window. The controlled deletion was temporally
correlated with an `onSpecialContour` event at
`2026-08-22T17:11:45.650459+00:00`; the operator marker followed about 1.862
seconds later. In that event, the observed representations for `info`, `batid`,
and `update` were empty and the observed `infoSize` value was `0`. These are
structural observations only; no field semantics are assigned. `onMI` and
`onArI` followed about 138--139 ms later.

No `setSpecialContour` request was visible on the diagnostic normal-MQ session,
and no post-delete `getSpecialContour` readback was observed. The original
retry delta therefore had an empty `post-delete-readback` side. It has been
regenerated with `comparison_status=incomplete`,
`comparison_result=not_comparable`, `missing_roles=["after"]`, no ordinary
comparison groups, and no `changed_group_count`. Its one-sided variants are
retained only as presence/absence observations and are not byte-delta evidence.

The next capture is read-only. It sends no diagnostic device-control command;
opening the official Ecovacs map is only an external trigger. With the app
closed and the mower's actual state supplied explicitly, run:

```powershell
.venv\Scripts\python.exe scripts\goat_map_phase2_capture.py `
  --mode zone-absent-readback `
  --country NO `
  --phase p2-07-zone-absent-readback `
  --mower-state paused `
  --device-class 2i0fns `
  --baseline-seconds 30 `
  --readback-seconds 120 `
  --artifact-dir .goat-map-phase2\p2-07-zone-absent-readback `
  --report-output goat-map-p2-07-zone-absent-summary.json
```

At the prompt, open the official app directly to the same mower map and make no
map change. After capture, compare the stable pre-delete and passive absent
readbacks with:

```powershell
.venv\Scripts\python.exe scripts\goat_map_special_contour_delta.py `
  --artifact .goat-map-phase2\p2-06-controlled-special-contour-delete-retry1 `
  --absent-artifact .goat-map-phase2\p2-07-zone-absent-readback `
  --output goat-map-p2-07-present-to-absent-delta.json
```

Only a non-empty, complete comparison may report ordinary changed groups. A
one-sided record remains a separate presence/absence observation with
`byte_delta_proven=false`.

##### P2-07 conclusion and selected-field reporting

The passive P2-07 capture observed three `SpecialContour` readbacks between
`2026-08-22T17:55:16.950215+00:00` and
`2026-08-22T17:55:18.972675+00:00`. Together with the stable pre-delete
representation and the empty deletion event, this completes the structural
sequence:

`present-state -> empty delete-event -> persistent absent-state`

This is strong presence/absence evidence for the single **Sone med redusert
unnvikelse** used in P2-05/P2-06. It is not a present-byte to absent-byte delta:
the absent state is represented by absence of the former opaque value rather
than a paired replacement blob. It does not justify a `SpecialContour` parser,
and the zone must not be recreated for further format inference.

Selected scalar fields are now classified independently from blob-group
changes. The possible statuses are `identical`, `occurrence-count-changed`,
`value-changed`, `before-only`, and `after-only`. In the regenerated P2-07
report, `mid="1"` and `type=0` have identical value sets but occur twice in the
pre-delete artifact and three times in the passive absent-state artifact. Both
are therefore `occurrence-count-changed`, not value changes. This changes only
derived analysis output; no capture artifact was modified.

#### Deferred candidate: true No-Entry Zone discovery

Official GOAT documentation distinguishes a **No-Entry Zone** from the
reduced-avoidance feature used in P2-05. The official O-series instructions
define it as a zone GOAT will not enter and instruct the operator to create it
from map editing by remotely driving GOAT around a closed boundary and back to
the starting point. The O800/O1200 RTK documentation also identifies pools,
flowerbeds, vegetable plots, exposed wires, and similar protected areas as
appropriate uses. If a later experiment specifically needs a true exclusion
zone, this is the concrete app function to use; a generic special-contour or
reduced-avoidance action is not an equivalent substitute.

Primary references:

- [GOAT O800/O1200 RTK installation manual](https://site-static.ecovacs.com/upload/global/file/product_manual_edit/2026/04/04/053505_1093%24GOATO800RTKO1200RTKInstallationManualpdf.pdf), section 4.3;
- [GOAT O1200 LiDAR Pro instruction manual](https://site-static.ecovacs.com/upload/file/support/2026/01/26/051846_4011%24GOATO1200LiDARPROInstructionManual-UK.pdf), section 4.2.2;
- [official O800 RTK No-Entry Zone FAQ](https://help.ecovacs.com/global/support/goat-o800-rtk-white/faq-detail?id=2137&product_id=121).

This experiment is deferred and is not an automatic or mandatory next step. It
requires ending or interrupting the current task, positioning the mower, and
physically remote-driving a closed boundary. Its extra operator cost is
justified only if discovering the exclusion-zone command family or correlating
a controlled exclusion geometry would answer a remaining question that cannot
be resolved from lower-impact captures.

If it is selected later, the exact localized label must first be confirmed in
the installed app. The required function is the one whose help text says GOAT
will not enter the area and whose workflow requires closing a physically driven
boundary. A label such as **Sone med redusert unnvikelse** does not meet that
criterion.

Any later true No-Entry Zone test should initially be a decoder-free, passive
discovery capture. Passive means the diagnostic sends no device-control
command; the official app remains the external source of the remote-driving and
save actions. The proposed windows are:

1. Record 30--45 seconds with the app closed and the stationary mower's actual
   state recorded.
2. Mark app/map-edit initialization separately, before selecting No-Entry Zone.
3. Mark the physical boundary-drawing window from selecting the feature until
   the closed loop returns to its start. Record mower state transitions and
   app-originated motion commands separately from map writes.
4. Create exactly one safe, minimum-compliant closed zone and save once. Make
   no other map or mower-setting changes. Network timestamps are authoritative;
   operator markers provide context only.
5. Continue passive observation for 120--180 seconds to retain post-save
   events and app readback. Keep the new zone until capture completeness is
   verified.

The capture must discover command names without assuming a protocol family and
byte-preserve only payloads that pass the existing bounded, fail-closed policy.
It should cover newly observed map-related `set*` and `on*` traffic as well as
`getAreaSet`/`onAreaSet`, `getSpecialContour`/`onSpecialContour`,
`getMI`/`onMI`/`onArI`, and map-state calls around save. Movement-control
traffic must be retained only as sanitized timing/context and must not be
mistaken for the zone representation. No field meaning, encoding, or decoder
is assumed at this stage.

#### Recommended next analysis after the SpecialContour control

The SpecialContour result narrows rather than expands the immediate scope:

- creation and deletion were most tightly associated with the
  `SpecialContour` command family;
- `onMI.info` remained stable through the controlled change;
- the observed `getAreaSet` `ar`/`vw` values also remained stable;
- the observed `onArI` variation cannot be attributed to the controlled change;
- the stable present representation, empty delete event, and persistent absent
  state establish structural lifecycle evidence without a replacement
  absent-state blob.

These observations do not presently show that a true No-Entry Zone is needed
to understand the first decode target, `onMI`/`onArI`. The most informative
next step is therefore read-only cross-capture analysis of the data already
collected from P2-01 through P2-07. Build an inventory by command, source path,
representation length, SHA-256, mower state, trigger/window, and timing relative
to `getMI` or app initialization. Use it to answer, without semantic parsing:

1. whether the 52- and 876-byte `onMI.info` forms are consistently periodic
   versus request-associated;
2. which `onArI.info` variants recur, which `onMI` form each accompanies, and
   whether their variation follows time, app initialization, or transport;
3. whether `getAreaSet.subsets` values remain stable when grouped by observed
   `mid`/`aid`/`type` and capture context;
4. which opaque variants are stable enough to become repository-safe fixtures
   for representation/framing research.

Only if the existing corpus cannot separate those factors should a new,
non-editing repeatability capture be considered: app closed, physically
confirmed mowing, one presence lease, and a deterministic sequence of legacy
and N-GIoT `getMI` calls. A true No-Entry Zone remains a later optional control
for a distinct exclusion-geometry or protocol-family question, not the default
next experiment.

##### Completed P2-01--P2-07 cross-capture inventory

`scripts/goat_map_phase2_inventory.py` implements the read-only inventory. It
verifies each manifest, record sequence, blob path, byte length, and SHA-256
before analysis. It reads only sanitized `window started` markers from the
separate Phase 2 summary files; a missing marker is reported as unavailable and
is never estimated. It emits metadata-only JSON and CSV outside the immutable
artifact directories. No device client, control command, payload parser, or
semantic map model is involved.

The completed run covered ten artifacts spanning P2-01 through P2-07, with 293
captured records and 1441 opaque-segment inventory rows:

```powershell
.venv\Scripts\python.exe scripts\goat_map_phase2_inventory.py `
  --artifact-root .goat-map-phase2 `
  --summary-root . `
  --output goat-map-p2-01-07-inventory.json `
  --inventory-csv goat-map-p2-01-07-inventory.csv
```

The two observed `onMI.info` forms are each represented by one stable original
digest across nine captures:

- The 876-byte representation, SHA-256
  `12cbcb330c3b91334f72b41470e09361310853554f8292bc83e4dd72dfbdd5bb`,
  occurred 15 times. The already-proven strict Base64 layer produced 657 bytes,
  SHA-256
  `9a023cb8ffcb8ed19c66fc08430b2069c02e5de44a1153aadb5ea0d8ca35a1e2`.
  Every occurrence followed an observed `getMI` request by 0.059959--4.492470
  seconds. This is consistent in the current corpus, but it does not prove a
  semantic role.
- The 52-byte representation, SHA-256
  `d7d0e5374acebd6b57c06fd2b5a6a62a6136f6664845ca6e86892dab93181ba1`,
  occurred 17 times. Strict Base64 produced 38 bytes, SHA-256
  `d1878e21ccbdc2110e35bc2a15950c2b618f71ddbf7e1709134c6fc9502870bf`.
  Eight within-capture intervals ranged from 58.839491 to 68.160949 seconds,
  supporting an approximately periodic cadence in this corpus.

There is one explicit counterexample to the stronger claim that the 52-byte
form never occurs near `getMI`. In capture
`5f2ef129fa0742208be6d0a1c58a9349`, phase
`p2-05-controlled-nogo-delta-before`, it occurred at
`2026-08-22T16:20:46.880322+00:00`, 9.637864 seconds after the preceding legacy
`getMI` request at `2026-08-22T16:20:37.242458+00:00`. The next identical form
arrived 60.063876 seconds later. This may be a periodic event that happened to
fall shortly after the request, but the capture cannot establish that
causality. The 52-byte role is therefore not proven.

The corpus contains 47 `onArI.info` observations and 24 distinct digest/length
variants. Every grouped observation reports its preceding `onMI`, nearest
`getMI`, window start, and timestamps. Three cross-capture variants are stable
enough to be fixture candidates after manual review:

- 820 bytes, SHA-256
  `1838bb93b779295729ddd47290dadf2f92f94a149eff3f292e8a37d909ed137b`,
  six occurrences across four captures, always following the 52-byte `onMI`;
- 1024 bytes, SHA-256
  `5542faa1d353156ac4e123bc5bd657577b6984811dcebe22891993aee909704d`,
  six occurrences across five captures, always following the 876-byte `onMI`;
- 896 bytes, SHA-256
  `f3d6a1c0f3a9d2e610d1f81c5e8ca3cb9e26942c820a76e928c45150774a8603`,
  six occurrences across five captures, always following the 876-byte `onMI`.

The remaining `onArI` variants include many single-capture/single-occurrence
values. Recurring variants appear after both legacy and N-GIoT contexts, while
both contexts also contain unique variants. These differences are not
attributed to transport.

Fifty-six `getAreaSet.subsets` responses were captured. For observed
`mid="1"`, `aid="0"`:

- `type="ar"`: 32 occurrences across six captures, one stable 124-byte digest
  `72ebe704cb5890adb28ec1be05c228a6ef9addff0738df811808f671e0afd855`;
- `type="vw"`: 24 occurrences across six captures, one stable 24-byte digest
  `1e01a6d271fbf47823e02e56d20cdf2a8db654afb1d11f703ed3a49d255c1255`.

No other `type` was observed, and neither `subsets` value is interpreted.

Seven opaque values meet the inventory's fixture-candidate rule: byte-identical
in multiple captures and more than one relevant context. They comprise the two
`onMI.info` forms, the three recurring `onArI.info` forms above, and the stable
`ar`/`vw` `subsets` forms. They are only `eligible-after-manual-review`; the tool
does not add them to the repository.

The corpus is sufficient for the requested non-semantic inventory and for
selecting repeatable representation/framing fixtures. It is not sufficient to
prove the 52-/876-byte roles or explain `onArI` variability. A controlled,
non-editing repeatability capture is therefore justified if resolving those
timing roles is required before framing work continues. Its purpose should be
to place several legacy/N-GIoT `getMI` requests at known offsets relative to an
already observed 52-byte cadence, not to make another map edit.

##### P2-08 non-editing repeatability capture

The implemented `repeatability` mode is independent of the deferred true
No-Entry Zone candidate. It performs no map edit, does not open the official
app, does not use JMQ, and retains the existing byte-preserving/fail-closed
artifact policy. Before connecting, the operator must explicitly confirm that
the official app is closed and the mower is physically mowing.

The runner opens normal MQ and sends exactly one N-GIoT `appping`. Only 52-byte
`onMI.info` values that pass the already-proven strict Base64 representation
layer and yield 38 uninterpreted bytes are used for timing. The bytes are not
semantically parsed. The runner requires two identical short representations
45--75 seconds apart before it establishes a cadence. If that precondition is
not met within the configured timeout, no `getMI` is sent and the capture is
reported as `inconclusive` rather than guessing a schedule.

After cadence establishment, the runner sends legacy `getMI` 20--30 seconds
after the last observed short form, waits through the next expected cadence
boundary, then sends N-GIoT `getMI` at the same offset after that later short
form. It waits for one further cadence boundary. Before issuing either control,
it verifies that the projected experiment still fits within the single,
conservatively bounded presence lease; it never renews `appping` during this
capture.

The report records the exact controlled-action timestamps independently of
whether an outbound request is visible on MQTT. Each captured `onMI`/`onArI`
entry includes its timestamp, original representation length/digest, nearest
preceding controlled `getMI` and transport, distance to that control, nearest
expected cadence boundary, and preceding `onMI` context. Classification happens
only after artifact finalization and is one of `control-associated`,
`cadence-associated`, `ambiguous-overlap`, or `unclassified`. It is timing-only
metadata and does not alter opaque payloads.

H1--H4 are reported with supporting timestamps/digests and explicit
counterexamples. A result can be `supported-in-this-capture`, but
`role_proven` remains false; any counterexample produces
`counterexample-observed`. The seven inventory candidates remain
`eligible-after-manual-review`, and P2-08 adds no opaque fixture bytes to the
repository.

Run the experiment only while the mower is continuously and physically mowing:

```powershell
.venv\Scripts\python.exe scripts\goat_map_phase2_capture.py `
  --mode repeatability `
  --country NO `
  --phase p2-08-repeatability `
  --mower-state mowing `
  --device-class 2i0fns `
  --baseline-seconds 30 `
  --cadence-timeout-seconds 150 `
  --control-offset-seconds 25 `
  --cadence-min-seconds 45 `
  --cadence-max-seconds 75 `
  --cadence-boundary-tolerance-seconds 8 `
  --final-event-grace-seconds 3 `
  --presence-lease-budget-seconds 285 `
  --artifact-dir .goat-map-phase2\p2-08-repeatability `
  --report-output goat-map-p2-08-repeatability-summary.json
```

No application or dashboard should be opened during the run. If the terminal
reports an inconclusive precondition, retain that artifact and use a new
`-retry1` directory for any retry.

###### Completed P2-08 result

Capture `35d1313e9d0241a1b773f9f526276eb1` completed under operator-confirmed
`mowing` with a measured 52-form cadence of `60.01633050000237` seconds. The
single N-GIoT `appping` began at `2026-08-22T18:54:41.028167+00:00` and returned
at `2026-08-22T18:55:01.294664+00:00`. The cadence-establishing 52-byte
representations had the known digest
`d7d0e5374acebd6b57c06fd2b5a6a62a6136f6664845ca6e86892dab93181ba1`
at `18:55:20.253107` and `18:56:20.268637` UTC.

The legacy control started at `18:56:45.272766` UTC, 25.004 seconds after the
cadence anchor. The known 876-byte representation
`12cbcb330c3b91334f72b41470e09361310853554f8292bc83e4dd72dfbdd5bb`
arrived 0.278080 seconds later. The next 52-byte event arrived at
`18:57:20.188403`, 59.919766 seconds after its preceding identical form and
0.096696 seconds before the predicted boundary. The N-GIoT control then began
at `18:57:45.199679`, again about 25 seconds after the short form; the same
876-byte representation arrived 0.216537 seconds later. A further 52-byte event
arrived at `18:58:20.443485`, 60.255082 seconds after the preceding identical
form and 0.142056 seconds after the predicted boundary.

The initial generated report incorrectly labelled that final boundary as a
counterexample to H2/H3. Repeated addition of the fractional cadence rounded
the second boundary to `...301430`, while per-event classification calculated
the mathematically equivalent boundary as `...301429`; exact timestamp-string
matching then failed. The analysis now derives every boundary directly as
`anchor + n * cadence`, with a regression test using the observed fractional
cadence. Read-only reanalysis of the unchanged artifact gives:

- H1: `supported-in-this-capture`;
- H2: `supported-in-this-capture`;
- H3: `supported-in-this-capture`;
- H4: `inconclusive`.

H1--H3 remain timing-supported hypotheses, not proven representation roles.
The result supplies no counterexample to the natural cadence: both explicitly
scheduled controls produced the 876 form promptly, and neither reset or shifted
the next 52 form outside the observed tolerance. It also provides a plausible
explanation for P2-05's 52-byte event shortly after `getMI`: a control and the
independent cadence can occur near each other, although P2-05 alone cannot
establish that attribution.

H4 is genuinely inconclusive rather than a timing-analysis error. None of the
three earlier exact `onArI` fixture-candidate digests appeared. P2-08 instead
observed these opaque families without interpreting their contents:

- one 780-byte value following a 52-byte `onMI` during the pre-presence
  baseline;
- one 796-byte digest repeated four times, each immediately following the
  52-byte form;
- one 1024-byte digest repeated after both legacy- and N-GIoT-associated
  876-byte forms;
- one 872-byte digest repeated after both legacy- and N-GIoT-associated
  876-byte forms.

The identical 1024/872 pair under both control transports supports transport
independence for that P2-08 response family. The absence of the earlier
820/1024/896 fixture-candidate digests means their proposed cross-context role
cannot be confirmed by this capture, and the new lengths show that fixed
`onArI` lengths must not be treated as universal roles. No new opaque value is
promoted to a fixture without a separate manual review.

After review, H1--H3 are accepted as supported protocol behavior for continued
research. The only permitted role labels are therefore:

- 876-byte `onMI.info`: **request-associated form**;
- 52-byte `onMI.info`: **cadence-associated form**;
- in the controlled P2-08 run, explicit `getMI` did not reset the established
  approximately 60-second cadence.

These labels describe timing/transport association only. They do not mean full
map, metadata, geometry, boundary, or any other semantic map concept. H4
remains `inconclusive`, and no `onArI.info` length is a universal role.

###### Corrected P2-08 provenance

The initial `goat-map-p2-08-repeatability-summary.json` is explicitly
superseded because its unversioned timing analysis produced the one-microsecond
false boundary mismatch described above. It is retained only as historical run
output and is not an authoritative hypothesis report.

`scripts/goat_map_repeatability_reanalyze.py` verifies the immutable artifact,
uses sanitized controlled-action markers from the old summary, converts the
observed cadence once to integer microseconds, and calculates every boundary as
`anchor + integer_index * cadence_microseconds`. It writes a separate corrected
report containing the capture ID, phase, manifest SHA-256, records SHA-256,
analysis version, old/new hypothesis statuses, and the explicit supersession
reason. It never writes inside the artifact:

```powershell
.venv\Scripts\python.exe scripts\goat_map_repeatability_reanalyze.py `
  --artifact .goat-map-phase2\p2-08-repeatability `
  --superseded-report goat-map-p2-08-repeatability-summary.json `
  --output goat-map-p2-08-repeatability-corrected.json
```

The generated report references capture
`35d1313e9d0241a1b773f9f526276eb1`, uses analysis version
`goat-repeatability-timing/v2`, and records H1/H2/H3 as
`supported-in-this-capture` and H4 as `inconclusive`. The referenced artifact's
manifest and records digests are respectively
`90d74271bf26389a5289ed0fa81b3fb638fac24bd4e96549af38563735f0c74e`
and `d6aeb4440b9eee670c88c9c4ac22fadf70e57466598b953285cb4316761bd262`.
The artifact was not modified.

##### P2-01--P2-08 onArI burst/framing inventory

`scripts/goat_map_on_ari_analyze.py` performs the approved read-only structural
analysis across all eleven artifact directories whose phases begin P2-01
through P2-08. A burst is only a deterministic proximity group: consecutive
`onArI` events no more than 250,000 microseconds apart. It is not a logical
record, chunk group, or reconstruction.

```powershell
.venv\Scripts\python.exe scripts\goat_map_on_ari_analyze.py `
  --artifact-root .goat-map-phase2 `
  --output goat-map-p2-01-08-onari-burst-analysis.json
```

The corpus contains 56 `onArI.info` occurrences in 38 proximity bursts: 22
single-message and 16 multi-message bursts. Every observed representation is
ASCII, canonical strict Base64 with exact round-trip. This establishes the
Base64 representation layer for the observed `onArI.info` corpus, but not any
meaning for its derived bytes.

All 22 cadence-associated bursts contain exactly one `onArI`. Their observed
envelope values consistently include `serial="1"`, `index="0"`, and
`type="-1"`. Original representation lengths range across 780, 784, 792, 796,
800, 808, 812, 816, 820, and 840 characters; the same 840-character length even
has two different decoded lengths (628 and 630 bytes). The recurring 820 form
is only one member of this family, not a universal cadence-associated length.

All 16 request-associated proximity bursts begin with a 1024-character
representation that strict-Base64 decodes to exactly 768 bytes. Fifteen are
two-message groups with observed `serial="2"`, `index="0"/"1"`, and
`type="0"`. Within each pair, `batid`, `infoSize`, `mid`, `serial`, `type`, and
`using` are identical while `index` changes from `0` to `1`. Field names and
values are reported as observed; no sequence/chunk meaning is assigned.

The second representation is variable. Observed two-message patterns include
1024 plus 844, 872, 876, 888, 896, 908, or 920 Base64 characters. In particular:

- P2-08 contains two `1024 + 872` bursts, decoding to `768 + 653` bytes;
- six bursts across five earlier captures contain `1024 + 896`, decoding to
  `768 + 672` bytes;
- the 872 and 896 patterns have the same envelope field/status structure.

For all fifteen two-message groups, concatenating the Base64 representations in
observed order remains strict canonical Base64, and its derived bytes equal the
ordered concatenation of the two separately derived byte strings. This is a
structural concatenation candidate only. It is not evidence that the bytes form
one reconstructed record.

One P2-02 proximity group contains four messages with pattern
`1024 + 888 + 1024 + 888` over 98,165 microseconds. It references two distinct
preceding `onMI` events, `batid` changes between ordinals 2 and 3, and the
observed index returns from `1` to `0`. The complete four-representation text is
not strict Base64 because it contains an internal padded ending. This is an
explicit counterexample to treating time proximity alone as a logical chunk
boundary; the report marks the possible 2/3 boundary structurally without
splitting or reconstructing it.

Within each multi-message group, `infoSize` is stable across its messages, but
no observed value equals either the summed Base64 representation length or the
summed Base64-derived byte length. No individual derived value or ordered
derived-part concatenation begins with any tested gzip, zlib, zip, bzip2, xz,
zstd, or LZ4-frame signature. These are negative structural observations, not
evidence against an unknown framing or encoding.

Fixture assessment is now intentionally asymmetric:

- the 876-byte request-associated and 52-byte cadence-associated `onMI.info`
  values are strong golden-fixture candidates after manual review (17 and 22
  observations respectively, each across ten captures);
- stable `getAreaSet.subsets` `ar`/`vw` representations remain strong candidates
  after manual review (32 and 24 observations across six captures);
- every `onArI.info` variant remains a
  `structural-example-only-not-canonical` candidate, regardless of recurrence.

No fixture bytes were added, no artifact was changed, and no parser,
reassembler, framing model, or semantic map decoder was implemented.

##### P2-01--P2-08 envelope-grouped onArI framing research

`scripts/goat_map_on_ari_framing_analyze.py` replaces proximity as the grouping
basis with the approved structural identity: capture, `batid`, `serial`,
`infoSize`, `mid`, `type`, and `using`. Each group is validated as strict
canonical Base64, sorted by `index`, required to contain exactly
`0..serial-1`, and assembled only as uninterpreted derived bytes. Raw `batid`
values and complete opaque representations/derived values are not written to
the report.

```powershell
.venv\Scripts\python.exe scripts\goat_map_on_ari_framing_analyze.py `
  --artifact-root .goat-map-phase2 `
  --output goat-map-p2-01-08-onari-grouped-framing.json
```

The verified corpus contains 39 complete groups from eleven captures with no
excluded group: 17 observed `serial=2` request-associated groups and 22
observed `serial=1` cadence-associated groups. The previous P2-02
`0/1/0/1` proximity sequence is structurally separated by its different
`batid` values rather than treated as one four-part group.

All 39 derived concatenations share exactly the first five bytes
`5d00000400`. The first differing offset across the complete corpus is offset
5. An unsigned little-endian reading beginning at offset 5 equals the opaque
envelope `infoSize` value for all 39 groups, across all eleven captures, both
serial forms, and every observed derived length. There are no counterexamples
in this corpus. Both a two-byte and a four-byte reading support the relation
because bytes 7 and 8 are zero for every observation. The evidence therefore
supports the start offset and little-endian value relation, but does not yet
distinguish a two-byte field from a wider field whose high bytes are zero. No
parser boundary is adopted.

`infoSize` remains envelope metadata and is not treated as direct byte length.
Observed `serial=1` examples pair `infoSize` values 1250--1361 with derived
lengths 583--630; observed `serial=2` examples pair values 6241--6382 with
derived lengths 1401--1457. The integer scan found no supported internal field
equal to the derived total length and no supported field equal to envelope
`serial`. Zero-valued readings that happen to belong to the envelope index set
are retained only as non-discriminating `candidate` results, not supported
fields.

Four same-capture legacy/N-GIoT comparisons are available. P2-02, P2-05 after,
and P2-08 have byte-identical derived groups for their paired control
transports. P2-01 is an explicit counterexample to universal byte identity:
the legacy-associated group is 1401 bytes and the N-GIoT-associated group is
1424 bytes with a different digest. All four pairs retain the common five-byte
prefix and the offset-5/`infoSize` relation. The evidence supports a framing
relationship stable across transport, but does not show that body contents are
transport-determined or transport-independent in every capture.

There is no common suffix across all groups. Individual trailing zero runs are
0, 1, or 2 bytes, so padding is not yet stable. The conservative repeated-block
scan found no candidate repeated block, and no first-64-byte position matches a
tested gzip, zlib, zip, bzip2, xz, zstd, or LZ4-frame signature. No checksum or
hash algorithm was tested because no concrete trailer field candidate was
established. No codec was executed.

The generated JSON contains group identity digests, context, segment/combined
lengths and SHA-256 values, a maximum 64-byte leading hex preview, pairwise
prefix/suffix/first-difference measurements, integer-field candidates with all
supporting examples and counterexamples, and negative results. It contains no
complete opaque blob. The artifacts were read through the existing verified
read-only loader and were not modified.

This documents one supported internal field-start/value relation with multiple
independent examples, but leaves its width and the remainder of the framing
unknown. No framing parser, semantic field model, geometry decoder, or
production integration is implemented.

##### P2-01--P2-08 cross-family common-header analysis

`scripts/goat_map_common_header_analyze.py` combines every occurrence of the
two stable `onMI.info` forms with every complete envelope-grouped `onArI`
derived stream. It performs a 64-column byte inventory grouped by message
family, request/cadence association, and `infoSize`, but writes no complete
opaque value:

```powershell
.venv\Scripts\python.exe scripts\goat_map_common_header_analyze.py `
  --artifact-root .goat-map-phase2 `
  --output goat-map-p2-01-08-common-header-analysis.json
```

The verified corpus contains 78 samples from eleven captures with no excluded
sample: 39 `onMI` occurrences and 39 complete grouped `onArI` streams. The
`onMI` side consists only of the stable 38-derived-byte cadence-associated form
(22 occurrences across ten captures) and stable 657-derived-byte
request-associated form (17 occurrences across ten captures). The association
distribution over both families is 44 cadence-associated and 34
request-associated samples.

The longest raw common prefix is five bytes, `5d00000400`, for the complete
corpus and separately within each message family. The prefix stops at offset 5
because `infoSize` varies both between and within the families.

Both explicit little-endian hypotheses remain supported as value relations:

- bytes 5--6 interpreted as unsigned 16-bit equal envelope `infoSize` in all 78
  samples;
- bytes 5--8 interpreted as unsigned 32-bit equal envelope `infoSize` in all 78
  samples.

They cannot be distinguished with this corpus because every observed
`infoSize` fits in 16 bits and bytes 7--8 are zero in every sample. Under the
16-bit hypothesis, bytes 7--8 are therefore retained as a separate unknown
two-byte `candidate`. They are not `supported`: their only observed value is
zero and they have no varying relation to observable metadata. Under the
32-bit hypothesis they remain the high zero bytes of that candidate field.
Neither interpretation is selected.

After the 32-bit candidate, bytes 9--15 are invariant across all 78 samples and
all eleven captures: `002d96c042005e`. This seven-byte run is `supported` as a
shared structural invariant because it includes stable non-zero values and is
not inferred from a small zero-only subset. It is not assigned a semantic name
or consumed by a parser.

Offset 16 is the first variable column after that invariant. It has a fully
supported message-family relation with no counterexamples:

- every `onMI` sample has byte `0x11`;
- every grouped `onArI` sample has byte `0x14`.

Both values are observed 39 times over the independent capture corpus. This is
the next documented structural change after `infoSize`: a shared invariant run
ends at offset 15 and a family-correlated byte begins at offset 16. It remains
a field candidate, not a type parser.

The clean family-only relation stops immediately after offset 16. At offset 17,
`onMI` remains `0xd8`, while grouped `onArI` splits between `0x63` for the
cadence-associated samples and `0xb4` for the request-associated samples. The
family-only offset-17 candidate therefore has 17 counterexamples and is
`rejected`. Later columns continue to vary by family/association and sometimes
within the same metadata groups. No standalone association field is supported
by the first 64 columns.

No 16- or 32-bit integer position after offset 6 is supported as the derived
total length. This is a negative result against a simple internal direct-length
field in the inspected columns, not evidence that no length exists elsewhere
or under another relation.

The report includes the complete byte-column stability inventory, all
supporting sample/capture/timestamp references, and every counterexample for
reported candidates. Artifact hashes remain unchanged. No parser, decoder,
geometry model, semantic field mapping, codec execution, or production
integration was added.

##### P2-01--P2-08 offset-17+ inner-structure analysis

`scripts/goat_map_inner_structure_analyze.py` uses the structural header view
only as an entry guard, then inventories opaque bytes at offsets 17--63. It
does not extend that view or consume any offset as a parsed field:

```powershell
.venv\Scripts\python.exe scripts\goat_map_inner_structure_analyze.py `
  --artifact-root .goat-map-phase2 `
  --output goat-map-p2-01-08-inner-structure-analysis.json
```

The verified corpus again contains 78 samples from eleven captures with no
exclusions: 39 stable-form `onMI` values and 39 complete grouped `onArI`
streams. SHA-256 inventories of all 364 artifact files were identical before
and after the analysis.

Offset 17 has three observed raw values:

- `0x63`: 22 samples across ten captures, all cadence-associated
  `serial=1 onArI`;
- `0xb4`: 17 samples across ten captures, all request-associated
  `serial=2 onArI`;
- `0xd8`: all 39 `onMI` samples across eleven captures, including both
  request- and cadence-associated forms.

Neither message family nor request/cadence association alone explains offset
17. The family-only candidate is `rejected` by all 17 request-associated
`onArI` samples because the modal `onArI` value is `0x63`; the association-only
candidate is `rejected` by 39 of 78 samples because each association occurs in
both families. The combined observable context is stable without
counterexamples, however. Within `onArI`, the same split is also stable for the
observed envelope `serial` values: `serial=1 -> 0x63` and
`serial=2 -> 0xb4`. This is a structural correlation in the captured corpus,
not evidence that offset 17 is a protocol field named after either context.

The context-stable relation continues through offset 33. The complete observed
17-byte runs are:

- `onMI` cadence-associated: `d87941b0124e4b661976770c2fe196de4f`;
- `onMI` request-associated: `d87941b05cc7ff714f1e78d8dc93bd81d1`;
- grouped `onArI` cadence-associated / `serial=1`:
  `63d1dceaf6490fc728b85a4e13e18bae5c`;
- grouped `onArI` request-associated / `serial=2`:
  `b4fc81d4375de7a0f636f001dc016fe0ca`.

Each run is observed in ten independent captures and has no counterexample at
offsets 17--33. It is therefore reported as a `supported`
context-stable-byte-run candidate. It is not reported as one field, and no
internal field boundary or semantic role is assigned.

Offset 34 provides the limiting counterexample. The cadence-associated
`serial=1 onArI` group contains 21 occurrences of `0xe6` and one occurrence of
`0xf9`; therefore the no-counterexample run stops at offset 33. Other contexts
being stable at offset 34 does not override that counterexample.

Explicit one-, two-, and four-byte scans from offset 17 found no supported
field equal to envelope `infoSize` or derived total length. The byte-column
inventory still groups every raw value by family, association, `serial`,
`infoSize`, derived length, and control transport so negative results and
within-context variation remain visible.

There are eight same-capture legacy/N-GIoT control comparisons. Seven are
byte-identical. The single different pair is the known P2-01
request-associated `onArI` comparison (1401 versus 1424 derived bytes). Its
first overall difference is at offset 5 because `infoSize` differs; from offset
17 the streams share 941 bytes and first differ at absolute offset 958. This is
retained only as a control observation and is not attributed causally to
transport.

No structural-header API extension is recommended from this analysis alone.
No parser, decoder, coordinates, floats, protobuf hypothesis, geometry model,
or production integration was added.

##### Minimal offset-17--33 inner-structure view

After review of the offset-17+ evidence, a separate pure structural layer was
added in `deebot_client/diagnostics/goat_map_inner_structure_view.py`. It takes
an already validated `StructuralHeaderView`; it does not add fields to or
reinterpret the outer header. The view requires bytes through offset 33,
preserves bytes 17--33 as `context_signature_raw`, and preserves everything
from offset 34 as an opaque byte-identical `remainder`.

The repository-safe `onMI` golden values make an important distinction
explicit. Their raw 17-byte signatures are not identical:

- 52-representation form: `d87941b0124e4b661976770c2fe196de4f`;
- 876-representation form: `d87941b05cc7ff714f1e78d8dc93bd81d1`.

Both raw patterns map to the same `observed-onMI` context class. The binary
classification therefore does not use or expose timing-based
request/cadence roles, while still preserving the actual byte evidence rather
than collapsing two different representations into one claimed signature.

The two observed grouped `onArI` signatures map to
`observed-onArI-serial-1` and `observed-onArI-serial-2`. Envelope `serial` is
optional validating metadata; a known signature paired with the other
observed serial raises an explicit mismatch. Unknown signatures retain their
raw bytes, return class `unknown`, and are not rejected when the outer framing
is otherwise valid. A known signature that conflicts with the already
validated outer family is a separate explicit structural mismatch.

No byte inside the context signature is exposed as a subfield. Offset 34 and
later remain opaque, and variation at offset 34 does not affect context
classification. No timing input, parser, decoder, map model, or production
integration is involved.

### 2.3 Decode the static map first

1. Compare repeated `onMI` and `onArI` captures structurally without assuming
   an encoding.
2. Identify the outer representation first: JSON fields, base64/hex wrapping,
   compression, framing, checksums, and chunk ordering only when demonstrated
   by the captures.
3. Implement small pure decoders one layer at a time, backed by sanitized golden
   fixtures and explicit failure behavior for unknown versions.
4. Model only verified static concepts such as map identity, bounds, boundary,
   areas, exclusions, and charging-station position. Preserve unknown fields as
   opaque metadata rather than guessing their meaning.

Exit criterion: at least two captures of the same static map decode
deterministically, and a controlled map edit causes an explainable fixture
change.

### 2.4 Decode `onMapTrack` second

After the static coordinate system is understood, capture `onMapTrack` during
active mowing under a renewed presence lease. Correlate it with `onPos`, static
map ID, timestamps, sequence/chunk metadata, and a manually noted movement
window. Determine from evidence whether track messages are full snapshots,
chunks, or deltas before implementing reconstruction. Test ordering,
duplication, gaps, reconnects, and map-ID mismatch without silently merging
incompatible streams.

Exit criterion: a recorded track can be reconstructed deterministically against
its static-map fixture and invalid/incomplete sequences are rejected safely.

### 2.5 Integrate only after formats are understood

Once static map and track models are stable, add an adapter into the existing
`Map` capability rather than changing MQTT or `Command` transport. Keep GOAT
handling isolated by capability/device support, preserve existing vacuum map
behavior, and introduce static-map exposure before live-track updates. Add
compatibility, lifecycle, reconnect, and no-capability regression tests before
enabling any production refresh behavior.
