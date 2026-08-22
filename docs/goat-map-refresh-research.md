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
   `getMI`. Capture the control response and the following `onMI`/`onArI` window
   with exact timestamps and map IDs.
4. Use legacy `getMI` first because it exercises the existing client transport,
   then repeat with N-GIoT `getMI` under the same presence lease as a paired
   control. Do not mix additional JMQ or control factors into these runs.
5. Repeat enough times to distinguish stable static fields from request IDs,
   timestamps, state-dependent fields, and transport-specific envelopes.

Exit criterion: reproducible `getMI` to `onMI`/`onArI` captures with matching
map-ID context and no secrets in the artifact.

### 2.2 Raw, sanitized capture artifacts

Store Phase 2 captures in an explicit, git-ignored local artifact selected by a
new CLI option. Each record should retain the sanitized protocol envelope,
command, direction, transport/session, timestamp, mower state, map ID, payload
type/encoding, byte length, and SHA-256 digest. Opaque map-bearing fields needed
for later decoding may be retained verbatim in that local artifact, while
credentials, tokens, request IDs, account/device identities, and complete MQTT
topics remain redacted or omitted. Nothing opaque is printed to the console.

Use a versioned capture schema and enforce size limits. Add tests proving both
round-trip preservation of permitted opaque fields and removal of all known
secret fields. Captures supplied as fixtures must be explicitly sanitized and
reduced before they enter the repository.

Exit criterion: the same raw map-bearing value can be reproduced byte-for-byte
from the local artifact, while a secret-canary test proves sensitive auth and
identity data cannot survive serialization.

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
