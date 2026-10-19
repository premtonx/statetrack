# StateTrack × Zabbix (6.4 / 7.0)

Import `zabbix_template_statetrack.yaml` to monitor each host's configuration
change activity through the StateTrack unified summary endpoint.

---

## 1. Import

1. **Data collection → Templates → Import**
2. Select `integrations/zabbix/zabbix_template_statetrack.yaml`
3. Leave **Create new** ticked for template groups, templates, item keys and
   trigger names.
4. Import.

Zabbix reports a clean error naming the offending line if the file is malformed;
the file is validated in CI by `TestZabbixTemplateShape` in
`server/internal/integrations`, which also asserts the master/dependent
architecture below.

---

## 2. Architecture — one request per host per minute

```
statetrack.host.summary   (HTTP Agent master item, 1m)
        │  GET {$STATETRACK.URL}/api/v1/hosts/{HOST.HOST}/summary?window={$STATETRACK.WINDOW}
        │  Authorization: Bearer {$STATETRACK.TOKEN}
        ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ statetrack.agent.online        ← $.online            (0/1)   │
   │ statetrack.changes.critical    ← $.counts.l1_critical        │
   │ statetrack.changes.grouped     ← $.counts.l2_grouped         │
   │ statetrack.changes.drift       ← $.counts.l3_drift           │
   │ statetrack.drift.targets       ← $.drift_targets_count       │
   │ statetrack.latest.summary      ← $.latest_critical.summary   │
   │ statetrack.latest.actor        ← $.latest_critical.actor     │
   │ statetrack.latest.tool         ← $.latest_critical.tool      │
   │ statetrack.latest.target       ← $.latest_critical.target    │
   │ statetrack.latest.link         ← $.latest_critical.deep_link │
   └─────────────────────────────────────────────────────────────┘
        (dependent items: JSONPath preprocessing only, zero extra I/O)
```

Only the **master item** talks to the network. Every other item is a *dependent
item* (`delay: 0`) that runs JSONPath preprocessing over the master's stored
value. That is what makes this template safe for a large fleet: adding a monitor
costs Zabbix CPU, not another API call.

The master item stores its raw JSON for 1 hour so an operator can inspect the
exact payload a trigger fired on (**Monitoring → Latest data → History**).

---

## 3. Macro configuration

Set these on the **template** (fleet-wide defaults), on a **host**, or on a
**host group** — Zabbix resolves them most-specific-first.

| Macro | Default | Notes |
| ----- | ------- | ----- |
| `{$STATETRACK.URL}` | `http://statetrack-server:8080` | Base URL, **no trailing slash** (the item appends `/api/v1/...`). |
| `{$STATETRACK.UI_URL}` | `http://statetrack-console:5173` | Console base URL. Used as the trigger `url`, which Zabbix renders as a clickable link. |
| `{$STATETRACK.TOKEN}` | *(empty)* | API bearer token. Declared `SECRET_TEXT`, so it is masked in the UI and in exports. Leave blank only for an unauthenticated dev server. |
| `{$STATETRACK.WINDOW}` | `15m` | Lookback window: `15m`, `1h`, `24h`, `7d`. |
| `{$STATETRACK.CRIT_L1}` | `1` | HIGH trigger fires at this many L1 changes in the window. |
| `{$STATETRACK.WARN_DRIFT}` | `5` | WARNING trigger fires at this many L3 drift changes. |

### Per-host tokens and windows

Because the macros can be overridden per host, a shared-server deployment can
hand each host its own credential and window:

```
Host: prod-web-01
  {$STATETRACK.TOKEN}   = st_web_xxxx
  {$STATETRACK.WINDOW}  = 15m
  {$STATETRACK.CRIT_L1} = 1

Host: build-runner-07
  {$STATETRACK.TOKEN}   = st_runner_yyyy
  {$STATETRACK.WINDOW}  = 1h      # noisy host: widen the window, then raise
  {$STATETRACK.CRIT_L1} = 3       # the threshold so it does not flap
```

### Hostname alignment — the one thing to get right

`{HOST.HOST}` is the **Zabbix host name**, and it is sent verbatim as the
StateTrack host key. The API accepts either:

- a **hostname** (what the enrolled agent reported), or
- a **host UUID**.

So either name your Zabbix hosts exactly as the machines are named, or set the
Zabbix host name to the StateTrack UUID. A mismatch shows up immediately as
HTTP 404 on the master item, with the item becoming unsupported.

Quick check before wiring anything up:

```bash
curl -s "http://statetrack:8080/api/v1/hosts/prod-web-01/summary?window=15m" | head -c 400
```

---

## 4. Items

| Item key | Type | Value | Description |
| -------- | ---- | ----- | ----------- |
| `statetrack.host.summary` | HTTP Agent | Text | Raw JSON rollup (master, 1m, retained 1h). |
| `statetrack.agent.online` | Dependent | Numeric (0/1) | `$.online` via `BOOLEAN_TO_DECIMAL`. |
| `statetrack.changes.critical` | Dependent | Numeric | `$.counts.l1_critical`. |
| `statetrack.changes.grouped` | Dependent | Numeric | `$.counts.l2_grouped`. |
| `statetrack.changes.drift` | Dependent | Numeric | `$.counts.l3_drift`. |
| `statetrack.drift.targets` | Dependent | Numeric | `$.drift_targets_count` (a missing value normalises to `0`). |
| `statetrack.latest.summary` | Dependent | Text | `$.latest_critical.summary`. |
| `statetrack.latest.actor` | Dependent | Text | `$.latest_critical.actor`. |
| `statetrack.latest.tool` | Dependent | Text | `$.latest_critical.tool`. |
| `statetrack.latest.target` | Dependent | Text | `$.latest_critical.target`. |
| `statetrack.latest.link` | Dependent | Text | `$.latest_critical.deep_link` — opens the diff drawer. |

The master item also runs `CHECK_JSON_ERROR`, so a 200 response carrying an HTML
login page (a proxy in front of the API, an expired session) marks the item
unsupported with a clear cause rather than silently poisoning every dependent
item with an empty value.

Dependent items apply a **JavaScript** step that maps an absent field to `0` or
`""`. Without it, a host with no critical change in the window produces an empty
JSONPath result and the item goes unsupported — which looks like a monitoring
failure instead of good news.

---

## 5. Triggers

| Name | Severity | Condition |
| ---- | -------- | --------- |
| **Critical configuration mutation detected on {HOST.HOST}** | High | `statetrack.changes.critical >= {$STATETRACK.CRIT_L1}` |
| **StateTrack agent offline on {HOST.HOST}** | Average | `statetrack.agent.online = 0` |
| **Configuration drift detected on {HOST.HOST}** | Warning | `statetrack.changes.drift >= {$STATETRACK.WARN_DRIFT}` |

### Alert content

The High trigger's operational data includes the actor, tool, target and deep
link, so the notification is actionable without opening Zabbix:

```
actor=alice target=/etc/nginx/nginx.conf tool=vim
link=http://localhost:5173/events/00002798-...?tab=diff
```

The trigger description expands the same values plus the summary, and
`manual_close: YES` keeps a critical change on the board until an operator
acknowledges it. Auto-resolving when the 15-minute window rolls over would hide
an unreviewed production change — the window is a *detection* range, not an
indication that anyone looked.

`{$STATETRACK.UI_URL}` is set as the trigger `url`, so Zabbix renders a
clickable link on the event.

---

## 6. Verify

**Test the API first** (from the Zabbix server, using the same macro values):

```bash
curl -s -H "Authorization: Bearer $STATETRACK_TOKEN" \
  "http://statetrack:8080/api/v1/hosts/prod-web-01/summary?window=15m"
```

**Then the master item:** *Monitoring → Latest data*, filter host + template →
the master item's **History** shows the JSON. A 404/401 here means the macro or
the hostname is wrong.

**Then the dependents:** select any dependent item; a value with a recent
timestamp confirms the JSONPath resolved.

**Then the trigger:** temporarily set `{$STATETRACK.CRIT_L1}` to `0` and wait one
collection cycle. Revert immediately afterwards.

**From the CLI** (handy for a batch check across the fleet):

```bash
zabbix_get -s monitored-host -k 'statetrack.host.summary'
```

---

## 7. Troubleshooting

| Symptom | Cause and fix |
| ------- | ------------- |
| Master item: *Unsupported — timeout* | Lower `{$STATETRACK.WINDOW}` or raise the item timeout (Zabbix 6.4 caps HTTP Agent timeouts server-side; the default is generous for a summary query). |
| Master item: HTTP 404 | `{HOST.HOST}` does not match a StateTrack hostname/UUID, or `{$STATETRACK.URL}` has a trailing slash. |
| Master item: HTTP 401 | `{$STATETRACK.TOKEN}` missing or expired. |
| Dependents unsupported, master fine | The JSONPath no longer matches the API — check `$.counts.*` against the live response. |
| `statetrack.latest.*` unsupported | Expected on a host with no critical change; the JavaScript step maps it to an empty string / zero. |
| Agent offline trigger flaps | The host heartbeats on a schedule; widen the window or accept a short flap as a genuine signal that the agent restarted. |
