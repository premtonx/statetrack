# Grafana integration

Three halves, designed to be used together:

- **Push** — StateTrack posts a Grafana annotation for every high-impact change,
  so a spike on any panel has a clickable explanation attached to it.
- **Pull** — Grafana queries StateTrack directly (annotations and flattened
  events) through the JSON/Infinity datasource.
- **Query** — the bundled dashboard reads the StateTrack database straight
  through Grafana's Postgres datasource, so every count is an exact integer and
  every table is a join, not an inference from a counter.

The bundled dashboard,
[`statetrack-overview-dashboard.json`](statetrack-overview-dashboard.json), is
**StateTrack – Change Impact**: a five-zone board over `now-1h` with eight KPI
cards, a full-width telemetry hero, three breakdown panels and two detail tables.

---

## Why two datasources

| Datasource | uid | Answers | Populated |
| --- | --- | --- | --- |
| Postgres | `statetrack-postgres` | *how many, which, who* — counts, tables, joins | immediately |
| Prometheus | `statetrack-prometheus` | *how fast* — rates, counters, exporter liveness | after a scrape |

Prometheus stores samples, so an event count expressed through it is a fractional
`rate()` that has to be rounded somewhere — that is where `Critical changes: 11.1`
came from. Postgres stores the rows, so `count(*)::int` is an integer, a target
path is a string, and "top affected hosts" is a `GROUP BY`.

Prometheus is also **empty at boot**: a chart meant to cover an hour has nothing
to draw for its first hour. The hero panel avoids that by generating its own
timeline with `generate_series()` and joining the L1 change minutes onto it, so
the graph is complete on first render and the spikes land on the annotation
lines — both are derived from the same `events` rows.

Both are provisioned from
[`deploy/grafana/provisioning/datasources/statetrack.yml`](../../deploy/grafana/provisioning/datasources/statetrack.yml),
and the dashboard declares them as hidden `DS_PROMETHEUS` / `DS_POSTGRES`
variables so an import can bind them by uid.

---

## The five zones

### Zone 1 — KPI grid (`y: 0`–`y: 6`)

| Row | Card | Figure | Colour |
| --- | --- | --- | --- |
| 1 | `Critical changes` | `count(*)` where `impact_level = 1`, integer | red `#ef4444` |
| 1 | `Changes / minute` | events per minute, one decimal | amber `#f59e0b` |
| 1 | `Hosts affected` | `count(DISTINCT host_id)`, integer | blue `#3b82f6` |
| 1 | `Agents online` | `4 / 4`, subtitle `100% healthy` | green `#22c55e`; red `#ef4444` if any agent is quiet |
| 2 | `Tracked targets` | distinct `target_id` in `host_current_state` | neutral |
| 2 | `Storm throttles` | events with `action = 8` | neutral |
| 2 | `Notification deliveries` | `100%`, subtitle `success rate` | neutral |
| 2 | `Change categories` | `count(DISTINCT category)`, integer | neutral |

The first row carries a sparkline per card. The sparklines are deliberately
annotation-free: eight flag layers drawn on eight 6×3 panels is noise, and the
hero is where the correlation belongs.

### Zone 2 — Hero (`y: 6`, full width, `h: 9`)

> **Infrastructure signals + change events**

| Series | Colour | Shape |
| --- | --- | --- |
| `CPU utilization` | green `#22c55e` | hovers 34–44% |
| `Latency (p95)` | blue `#3b82f6` | ~120 ms baseline, spikes at L1 |
| `Error rate` | red `#ef4444` | ~2% baseline, spikes to 55–68% at L1 |

One SQL query produces all three: a `generate_series()` of 61 one-minute
buckets, `LEFT JOIN`ed against the distinct minutes a Level 1 change landed.
Where the join hits, latency and error rate jump — so the red `L1` annotation
line pierces the peak of the red error spike instead of merely sitting near it.
The right-hand legend shows `avg` and `current`.

### Zone 3 — Breakdown (`y: 15`, three equal columns)

1. **`Changes by impact over time`** — stacked bars (`drawStyle: bars`,
   `stacking: normal`) in 2-minute buckets: `L1 (Critical)` red `#ef4444`,
   `L2 (High)` purple `#8b5cf6`, `L3 (Medium)` amber `#f59e0b`, `L4 (Low)` blue
   `#3b82f6`.
2. **`Top affected hosts`** — table with `#`, `Host`, `Events` and a volume bar,
   ranked by event count.
3. **`Change distribution by category`** — donut with a right-side legend showing
   percentages across `config`, `service`, `package`, `user`, `registry`, `other`.

### Zone 4 — Detail (`y: 23`, two columns)

1. **`Recent critical changes`** (width 16) — `Time`, coloured `Impact` pill
   (`L1` red, `L2` purple, `L3` amber), `Host`, `Target`, `Actor`,
   `Change summary`, and an `Inspect ↗` data link to
   `${STATETRACK_UI_URL}/events/${__data.fields.id}?tab=diff`.
2. **`Pipeline & system health`** (width 8) — `Ingest latency`,
   `Storm throttles`, `Webhook delivery`, `Agent connectivity`, each with a
   `Healthy` / `Degraded` pill. A window with no delivery attempts reports
   `none in window · Healthy`, not `0% success rate`.

---

## Annotations

The dashboard ships two annotation layers, one per impact level — the colour is a
property of the layer, so `L1` and `L2` cannot share one:

| Layer | Tag | Colour |
| --- | --- | --- |
| `L1 critical changes` | `statetrack`, `level:L1` | red `#ef4444` |
| `L2 grouped changes` | `statetrack`, `level:L2` | amber `#f59e0b` |

Three properties matter, and each fixes a specific artifact:

1. **Point annotations only.** Grafana renders an annotation as a translucent
   *region curtain* whenever it receives a `timeEnd` (or `isRegion`), and a
   curtain spanning the panel hides the very data it is meant to explain. The
   pusher therefore posts `time` alone — see `integrations.Annotation`, which has
   no field capable of expressing an end time.
2. **Scoped to the hero.** `filter: { exclude: false, ids: [30] }` binds each
   layer to panel `30`, so the KPI cards and breakdown panels stay clean.
3. **Hidden from the toolbar.** `hide: true`, because the flags are part of the
   panel's meaning, not a toggle a viewer should be able to lose.

Hovering a flag shows what changed, who did it to which host, and where to go:

```
[L1] Modified /etc/nginx/nginx.conf (+4 -2)
alice · prod-web-01
Inspect in StateTrack →
```

### Seeding the flags

`grafana-seed` reads the changes marked `metadata->>'annotate' = 'true'` in
Postgres and pushes one annotation per change, at `now - 52m` (L2), `-34m` (L1,
`nginx.conf`, `alice`, `prod-web-01`), `-18m` (L2) and `-4m` (L1, the Windows
registry `LogLevel`, `CORP\Administrator`, `win-app-02`). Before pushing it
deletes every annotation carrying `grafana-seed` **or** `statetrack` inside the
cleanup window — two passes because Grafana's tag filter is an AND with no OR —
which also removes region-style leftovers written by older versions of the tool.

`dev.ps1 seed` performs the same purge-and-push itself, so a single seed is
enough to keep the dashboard honest. The ordering is the contract: events are
written first, then the flags are rebuilt by reading those rows back, so the UUID
in a deep link is the one PostgreSQL stored rather than the one the seeder meant
to store. The seed finishes by re-reading those ids and asserting each resolves;
a flag can therefore only link to a row that exists.

> **Never push an annotation before its event exists.** An annotation whose link
> points at a deleted row is what produces `Failed to load event <uuid>` in the
> console. Because every re-anchor deletes the previous timeline, the purge has to
> run on every seed — a stale flag is not merely outdated, it is a dead link.

#### Why `Agents online` is coloured by value mappings, not thresholds

The card's value is a *string* (`4 / 4`), and a Grafana threshold cannot compare
one to a number: the check is `NaN < 4`, which is false, so the last step wins and
a perfectly healthy fleet renders in the critical colour. The green/red split is
therefore expressed as regex value mappings over the rendered text, plus a
numeric threshold of `4` kept as the documented fallback (it is what colours the
card if the query ever returns a number).

Three details of Grafana's mapping engine are load-bearing, and each silently
produces the wrong card when missed:

| Behaviour | Consequence |
| --- | --- |
| Patterns are anchored to the whole value | `^100%` never matches `100% healthy`; use `^…$` |
| `$0` is not substituted | The text must echo captures explicitly, as `$1` / `$2` |
| `displayName` runs before `reduceOptions.fields` | Renaming a selected field yields `No data` |

The healthy rule is `^([0-9]+) / \1$`, a backreference rather than a hardcoded
`4 / 4`, so the card reads green for a fleet of any size and turns red the moment
the two counts differ. `TestGrafanaAgentsCardColoursByRenderedText` pins all four
properties.

---

## Local demo stack

`docker compose up` starts everything the dashboard needs:

| Service | Port | Role |
| --- | --- | --- |
| `grafana` | 3000 | Dashboard and annotations (`admin` / `admin`) |
| `postgres` | 5432 | The events/hosts/targets/actors tables the dashboard reads |
| `prometheus` | 9090 | Scrapes `statetrack:8080/metrics` + the exporter |
| `node-exporter` | 9100 | Supplies the scrape-side metrics |

Grafana's datasources are provisioned from
[`deploy/grafana/provisioning/datasources/statetrack.yml`](../../deploy/grafana/provisioning/datasources/statetrack.yml),
and the scrape jobs live in
[`deploy/prometheus/prometheus.yml`](../../deploy/prometheus/prometheus.yml).

`windows_exporter` is **not** started by compose — a container cannot see the
host's Windows services. Point the `windows_exporter` job at a real instance
(the default target is `host.docker.internal:9182`) when you have one running.

### Staying fresh for days without reseeding

A recorded demo is often re-opened the next morning, and two things decay:

1. **The fleet reads offline.** `Agents online` counts a host as online only
   when `last_seen_at` is inside the last 15 minutes, and the seeded fleet has no
   agent process behind it. With `STATETRACK_DEMO_MODE=1` the backend therefore
   starts a heartbeat (`server/internal/demo`) that stamps the four seeded hosts
   every 30 seconds. The tick is 30× tighter than the 15-minute window, so the
   card survives a laptop sleep or a slow rebuild, and the `UPDATE` is scoped to
   the four seeded hostnames rather than the whole table — a genuinely dark host
   enrolled next to them still reports offline.
2. **The flags point at yesterday's rows.** Every seed re-anchors the timeline,
   which deletes the previous events. `dev.ps1 seed` re-pushes the annotations as
   part of the same run, so a stale flag (and its dead "Inspect in StateTrack"
   link) cannot outlive the row it references.

Both are demo-only behaviours and both are gated: the heartbeat on
`STATETRACK_DEMO_MODE`, the annotation sync on Grafana simply being reachable
(a missing Grafana warns and leaves the database timeline intact).

### One command to a recordable dashboard

```powershell
.\scripts\dev.ps1 up            # Grafana + Postgres + Prometheus + exporters
.\scripts\dev.ps1 migrate       # schema
.\scripts\dev.ps1 seed          # last-hour change timeline in Postgres
.\scripts\dev.ps1 grafana-seed  # import dashboard + push point annotations
```

`grafana-seed` (equivalently `make grafana-seed`, or
`go run ./server/cmd/statetrack-grafana-seed`) then:

1. waits for Grafana and resolves **both** datasources (accepting either the
   `postgres` or the `grafana-postgresql-datasource` plugin type),
2. imports this dashboard, binding `DS_PROMETHEUS` and `DS_POSTGRES`,
3. clears previous seed annotations, then pushes one point annotation per
   flagged change,
4. and (unless `-live=false`) mints a Grafana service-account token, saves it
   into StateTrack's Grafana settings, and enables live annotation pushing.

It is idempotent, and every run prints the exact Grafana URL with the pinned
`now-1h` range that covers both the annotations and the generated telemetry.

```
go run ./server/cmd/statetrack-grafana-seed -grafana http://localhost:3000 -live=false
```

### Making the Prometheus panels move

`seed` writes straight to Postgres — which is what the whole dashboard reads, so
every count, table and chart is already correct. What it does **not** do is
advance `/metrics`, because `statetrack_mutations_total` is incremented by the
server as it ingests agent batches. Replaying seeded events is no fix either: the
server de-skews each batch into server time, so a replayed `09:02` event lands
under "now" as a duplicate row.

Start the traffic generator instead. It submits *new* realistic changes through
the real gRPC `IngestionService`, so the counter climbs and any Prometheus-backed
series moves:

```powershell
.\scripts\dev.ps1 demo-traffic -Duration 2m       # foreground, easy to watch
.\scripts\dev.ps1 demo-traffic                    # background, until stopped
```

Confirm the counter is moving:

```
http://localhost:9090/graph?g0.expr=increase(statetrack_mutations_total%7Blevel%3D%22L1%22%7D%5B5m%5D)
```

### Template variables

| Variable | Type | Default |
| --- | --- | --- |
| `Environment` | custom | `Production` |
| `Host` | query over `hosts` | `All` |
| `Impact level` | custom | `All` |
| `Category` | custom | `All` |
| `DS_PROMETHEUS` / `DS_POSTGRES` | datasource, hidden | bound on import |

`Host` is populated from the **hosts table**, not from
`label_values(statetrack_mutations_total, host)`, because the fleet is the
enrolled hosts rather than whatever a scrape has published so far.

Every panel that uses `host IN ($host)` therefore reads Postgres. The remaining
Prometheus panels must target a metric that actually carries a `host` label —
the fleet family does (`statetrack_mutations_total`, `statetrack_drift_targets`,
`statetrack_active_agents`, `statetrack_storm_throttles_total`), the ingest/SLI
family does not (`statetrack_ingest_*`, `statetrack_webhook_deliveries_total`).

Filtering a metric by a label it lacks returns an **empty vector**, which Grafana
renders as "No data" — indistinguishable from a healthy zero. That is what once
made *Agents online* read "No data" while the fleet was online.
`TestGrafanaPanelsFilterOnlyHostLabelledMetrics` fails the build if a panel
filters a non-host-labelled metric that way.

---

## Importing by hand

The dashboard is a plain Grafana export and imports without any tooling:

1. Dashboards → **New** → **Import** → upload the JSON.
2. When prompted for **Prometheus**, pick the datasource that scrapes
   `statetrack-server:8080/metrics` *and* your exporters.
3. When prompted for **StateTrack Postgres**, pick a Postgres datasource pointed
   at the StateTrack database (read-only user recommended).

Any Grafana 11+ will render it; the bundled minimum is 11.2 (`pluginVersion` in
the JSON).

---

## Pull: the StateTrack datasource

Instead of (or as well as) pushing, Grafana can query StateTrack. Both endpoints
accept `host`, `from` and `to` (`from`/`to` as RFC3339 or epoch milliseconds),
and in demo mode they are readable anonymously — a real deployment requires a
`read`-scoped API key.

| Endpoint | Returns |
| --- | --- |
| `GET /api/v1/grafana/annotations` | root events shaped as `{time, text, tags}` |
| `GET /api/v1/grafana/events` | flattened event rows for tables and state timelines |

With the [Infinity datasource](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/):

- **Type** `JSON`, **URL** `{base}/api/v1/grafana/annotations`
- **Query params**: `host=${host}`, `from=${__from}`, `to=${__to}`, `limit=100`
- **Rows/Root** `annotations`, **Columns**: `time`, `text`, `tags`

The settings page in the console (**Integrations → Observability**) renders this
configuration and probes it with a **Test** button.

---

## Push: the server side

Configure the endpoint and token in **Integrations → Observability**, or
directly:

```http
PUT /api/v1/integrations/grafana
{
  "url": "http://localhost:3000",
  "api_token": "glsa_…",
  "push_l1": true,
  "push_l2": true,
  "push_l3": false,
  "enabled": true
}
```

Use a [service account](https://grafana.com/docs/grafana/latest/administration/service-accounts/)
token with the **Editor** role (scope `annotations:create`). `grafana-seed`
creates one for you when running locally. Level 1 and Level 2 are on by default;
Level 3 drift is opt-in because routine file churn would otherwise flood the
timeline.

Each delivery is recorded in `annotation_log`, surfaced in the hub's
**Recent Annotations** table, so *"Grafana is down"* is distinguishable from
*"nothing happened"*. Prometheus counts the same traffic as
`statetrack_webhook_deliveries_total{provider="grafana_annotations"}`.
