/**
 * Strongly-typed fallback data for presentation views that do not yet have a
 * live database table behind them (Reports, Settings, Grafana status) and for
 * the dashboard widgets that aggregate over a window the REST API does not
 * expose as a single call.
 *
 * Shapes mirror the Go backend structs in `server/internal/storage/store.go`
 * and `server/internal/integrations/pusher.go` so swapping in real endpoints
 * later is a drop-in change.
 */
import type {
  AISettingsResponse,
  ChangeTicket,
  Compliance,
  ComplianceEvent,
  DriftRow,
  Event,
  GrafanaAnnotation,
  GrafanaSettings,
  Host,
  ITSMSettingsView,
  PolicyRule,
  Recommendation,
  WatchImpactLevel,
  WatchRule,
  WatchTargetType,
  WebhookChannel,
  WebhookDelivery,
} from '../types'
import { FLEET_SCOPE } from '../types'

/** Rolling window for the dashboard/aggregate fallback series. */export const HOURS_24: string[] = Array.from({ length: 24 }, (_, i) =>
  `${String(i).padStart(2, '0')}:00`,
)

/** Events per hour by impact level — drives the "Changes Over Time" chart. */
export interface StackedPoint {
  label: string
  /** Value per impact level id (1…4). Missing keys count as zero. */
  values: Partial<Record<1 | 2 | 3 | 4, number>>
}

export const CHANGES_OVER_TIME: StackedPoint[] = HOURS_24.map((hour, i) => {
  // A quiet night ramps into the morning deploy window (08:00–11:00) and a
  // second, smaller evening burst around 19:00.
  const night = 1 + ((i * 3) % 4)
  const morning = i >= 8 && i <= 11 ? 14 - Math.abs(10 - i) * 3 : 0
  const evening = i >= 18 && i <= 20 ? 6 : 0
  const l2 = Math.max(0, morning + Math.round(night * 0.6))
  return {
    label: hour,
    values: {
      1: Math.max(1, Math.round((morning + night) * 0.28) + (i === 9 ? 2 : 0)),
      2: l2,
      3: Math.max(1, Math.round((morning + night + evening) * 0.5)),
      4: i >= 9 && i <= 10 ? 3 : Math.max(0, Math.round(night * 0.2) - 1),
    },
  }
})

export const KPI_DELTAS = {
  total: { value: '+12%', positive: true },
  critical: { value: '+22%', positive: false },
  grouped: { value: '-8%', positive: true },
  drift: { value: '+18%', positive: false },
} as const

/** Deterministic UUID-ish ids so mock rows stay stable between renders. */
function mockId(seed: string, n: number): string {
  const hex = (s: string, salt: number) =>
    Array.from(s).reduce((a, c) => (a * 31 + c.charCodeAt(0) + salt) % 0xffffffff, 7)
  const a = hex(seed, n).toString(16).padStart(8, '0')
  const b = hex(seed + n, n * 3).toString(16).padStart(8, '0')
  return `${a}-0000-4000-8000-${b}0000`
}

function hoursAgo(h: number, m = 0): string {
  return new Date(Date.now() - (h * 60 + m) * 60_000).toISOString()
}

export const FALLBACK_HOSTS: Host[] = [
  {
    id: mockId('host', 1),
    hostname: 'prod-web-01',
    os_family: 'linux',
    os_version: 'Ubuntu 24.04 LTS',
    agent_version: 'v1.0.0',
    clock_offset_ms: 12,
    last_seen_at: hoursAgo(0, 0),
    status: 'online',
  },
  {
    id: mockId('host', 2),
    hostname: 'prod-web-02',
    os_family: 'linux',
    os_version: 'Ubuntu 24.04 LTS',
    agent_version: 'v1.0.0',
    clock_offset_ms: -8,
    last_seen_at: hoursAgo(0, 0),
    status: 'online',
  },
  {
    id: mockId('host', 3),
    hostname: 'prod-db-01',
    os_family: 'linux',
    os_version: 'Debian 12',
    agent_version: 'v1.0.0',
    clock_offset_ms: 41,
    last_seen_at: hoursAgo(0, 1),
    status: 'online',
  },
  {
    id: mockId('host', 4),
    hostname: 'prod-app-01',
    os_family: 'linux',
    os_version: 'RHEL 9.4',
    agent_version: 'v0.9.8',
    clock_offset_ms: 0,
    last_seen_at: hoursAgo(0, 0),
    status: 'online',
  },
  {
    id: mockId('host', 5),
    hostname: 'prod-cache-01',
    os_family: 'linux',
    os_version: 'Alpine 3.20',
    agent_version: 'v0.9.8',
    clock_offset_ms: 5,
    last_seen_at: hoursAgo(0, 0),
    status: 'online',
  },
  {
    id: mockId('host', 6),
    hostname: 'win-app-01',
    os_family: 'windows',
    os_version: 'Windows Server 2022',
    agent_version: 'v1.0.0',
    clock_offset_ms: -3,
    last_seen_at: hoursAgo(0, 0),
    status: 'online',
  },
  {
    id: mockId('host', 7),
    hostname: 'win-app-02',
    os_family: 'windows',
    os_version: 'Windows Server 2019',
    agent_version: 'v1.0.0',
    clock_offset_ms: 0,
    last_seen_at: hoursAgo(0, 2),
    status: 'online',
  },
  {
    id: mockId('host', 8),
    hostname: 'staging-web-01',
    os_family: 'linux',
    os_version: 'Ubuntu 22.04 LTS',
    agent_version: 'v0.9.8',
    clock_offset_ms: 0,
    last_seen_at: hoursAgo(19),
    status: 'offline',
  },
  {
    id: mockId('host', 9),
    hostname: 'prod-k8s-01',
    os_family: 'kubernetes',
    os_version: 'Kubernetes v1.31.2',
    agent_version: 'v1.0.0',
    clock_offset_ms: 7,
    last_seen_at: hoursAgo(0, 0),
    status: 'online',
  },
]

/** Fallback timeline rows used when the events API returns nothing. */
export const FALLBACK_EVENTS: Event[] = [
  {
    id: mockId('ev', 1),
    host_id: FALLBACK_HOSTS[0].id,
    hostname: 'prod-web-01',
    occurred_at: hoursAgo(0, 6),
    impact_level: 1,
    category: 1,
    action: 2,
    summary: 'Modified /etc/nginx/nginx.conf',
    target_type: 'file',
    path_or_key: '/etc/nginx/nginx.conf',
    actor_username: 'alice',
    process_name: 'vim',
    process_lineage: ['sshd', 'bash', 'vim'],
    remote_ip: '192.168.1.50',
    pid: 4242,
    cmdline: 'vim /etc/nginx/nginx.conf',
    hash_before: '8f14e45fceea167a5a36dedd4bea2543',
    hash_after: 'c4ca4238a0b923820dcc509a6f75849b',
    child_count: 0,
    has_diff: true,
    diff_source: 'inline',
    metadata: {
      classification: 'rule:shop.example.com [L1]',
      rule_name: 'shop.example.com [L1]',
      rule_tags: 'nginx_vhost,auto-discovered,host:prod-web-01',
    },
  },
  {
    id: mockId('ev', 2),
    host_id: FALLBACK_HOSTS[2].id,
    hostname: 'prod-db-01',
    occurred_at: hoursAgo(0, 25),
    impact_level: 2,
    category: 2,
    action: 7,
    summary: 'apt transaction: 134 related changes (134 packages)',
    target_type: 'transaction',
    path_or_key: 'apt-get install --only-upgrade postgresql',
    actor_username: 'root',
    process_name: 'apt-get',
    process_lineage: ['sshd', 'bash', 'sudo', 'apt-get'],
    child_count: 134,
    has_diff: false,
    diff_source: '',
    metadata: { tool: 'apt', packages: 'postgresql 16.3 → 16.4' },
  },
  {
    id: mockId('ev', 3),
    host_id: FALLBACK_HOSTS[3].id,
    hostname: 'prod-app-01',
    occurred_at: hoursAgo(1, 4),
    impact_level: 1,
    category: 3,
    action: 4,
    summary: 'Restarted app.service',
    target_type: 'service',
    path_or_key: 'app.service',
    actor_username: 'root',
    process_name: 'systemctl',
    process_lineage: ['systemd', 'systemctl'],
    child_count: 0,
    has_diff: false,
    diff_source: '',
  },
  {
    id: mockId('ev', 4),
    host_id: FALLBACK_HOSTS[0].id,
    hostname: 'prod-web-01',
    occurred_at: hoursAgo(2, 12),
    impact_level: 3,
    category: 1,
    action: 2,
    summary: 'Modified /var/www/html/index.html',
    target_type: 'file',
    path_or_key: '/var/www/html/index.html',
    actor_username: 'deploy-bot',
    process_name: 'rsync',
    process_lineage: ['systemd', 'deploy-bot', 'bash', 'rsync'],
    hash_before: '45c48cce2e2d7fbdea1afc51c7c6ad26',
    hash_after: 'd3d9446802a44259755d38e6d163e820',
    child_count: 0,
    has_diff: true,
    diff_source: 'inline',
    metadata: { classification: 'drift' },
  },
  {
    id: mockId('ev', 5),
    host_id: FALLBACK_HOSTS[5].id,
    hostname: 'win-app-01',
    occurred_at: hoursAgo(3, 2),
    impact_level: 1,
    category: 5,
    action: 2,
    summary: 'Modified HKLM\\Software\\Company\\App\\LogLevel (INFO -> DEBUG)',
    target_type: 'registry',
    path_or_key: 'HKLM\\Software\\Company\\App\\LogLevel',
    actor_username: 'CORP\\Administrator',
    actor_sid: 'S-1-5-21-1104746749-1936075387-2494913302-500',
    process_name: 'powershell.exe',
    process_lineage: ['services.exe', 'powershell.exe'],
    remote_ip: '10.20.0.5',
    version_before: 'INFO',
    version_after: 'DEBUG',
    child_count: 0,
    has_diff: true,
    diff_source: 'inline',
  },
  {
    id: mockId('ev', 6),
    host_id: FALLBACK_HOSTS[6].id,
    hostname: 'win-app-02',
    occurred_at: hoursAgo(4, 40),
    impact_level: 1,
    category: 4,
    action: 1,
    summary: 'Added public key to administrators_authorized_keys',
    target_type: 'file',
    path_or_key: 'C:\\ProgramData\\ssh\\administrators_authorized_keys',
    actor_username: 'CORP\\jdoe',
    process_name: 'sshd.exe',
    remote_ip: '203.0.113.19',
    child_count: 0,
    has_diff: true,
    diff_source: 'inline',
    metadata: {
      classification: 'rule:CheckoutApp [L1]',
      rule_name: 'CheckoutApp [L1]',
      rule_tags: 'iis_site,auto-discovered,host:win-app-02',
    },
  },
  {
    id: mockId('ev', 7),
    host_id: FALLBACK_HOSTS[1].id,
    hostname: 'prod-web-02',
    occurred_at: hoursAgo(6, 15),
    impact_level: 3,
    category: 1,
    action: 2,
    summary: 'Modified /etc/nginx/conf.d/upstream.conf',
    target_type: 'file',
    path_or_key: '/etc/nginx/conf.d/upstream.conf',
    actor_username: 'alice',
    process_name: 'vim',
    process_lineage: ['sshd', 'bash', 'vim'],
    child_count: 0,
    has_diff: false,
    diff_source: '',
  },
  {
    id: mockId('ev', 8),
    host_id: FALLBACK_HOSTS[4].id,
    hostname: 'prod-cache-01',
    occurred_at: hoursAgo(8, 5),
    impact_level: 2,
    category: 2,
    action: 7,
    summary: 'apk transaction: 12 related changes (12 packages)',
    target_type: 'transaction',
    path_or_key: 'apk upgrade redis',
    actor_username: 'root',
    process_name: 'apk',
    process_lineage: ['systemd', 'apk'],
    child_count: 12,
    has_diff: false,
    diff_source: '',
    metadata: { tool: 'apk', packages: 'redis 7.2.4 → 7.2.5' },
  },
  {
    id: mockId('ev', 9),
    host_id: FALLBACK_HOSTS[2].id,
    hostname: 'prod-db-01',
    occurred_at: hoursAgo(11, 30),
    impact_level: 4,
    category: 7,
    action: 5,
    summary: 'Forensic: unexpected outbound connection from postgres',
    target_type: 'process',
    path_or_key: 'postgres [28411]',
    actor_username: 'postgres',
    process_name: 'postgres',
    process_lineage: ['systemd', 'postgres'],
    remote_ip: '203.0.113.77',
    child_count: 0,
    has_diff: false,
    diff_source: '',
  },
  {
    id: mockId('ev', 10),
    host_id: FALLBACK_HOSTS[0].id,
    hostname: 'prod-web-01',
    occurred_at: hoursAgo(13, 45),
    impact_level: 1,
    category: 4,
    action: 2,
    summary: 'Rotated /root/.ssh/authorized_keys (1 key removed)',
    target_type: 'file',
    path_or_key: '/root/.ssh/authorized_keys',
    actor_username: 'root',
    process_name: 'ssh-keygen',
    process_lineage: ['sshd', 'bash', 'ssh-keygen'],
    child_count: 0,
    has_diff: true,
    diff_source: 's3',
  },
  // ---- Kubernetes cluster (prod-k8s-01) -------------------------------
  //
  // The cluster is a "host" like any other and its resources flow through the
  // same diff engine, so the timeline, drift matrix and post-mortem export all
  // read cluster changes exactly as they read a file edit. Paths follow the
  // agent's canonical `/k8s/<cluster>/<namespace>/<plural>/<name>` shape.
  {
    id: mockId('ev', 11),
    host_id: FALLBACK_HOSTS[8].id,
    hostname: 'prod-k8s-01',
    occurred_at: hoursAgo(0, 42),
    impact_level: 1,
    category: 1,
    action: 2,
    summary: 'Modified ConfigMap payments/checkout-config (+3 -1)',
    target_type: 'k8s_configmap',
    path_or_key: '/k8s/prod-k8s-01/payments/configmaps/checkout-config',
    actor_username: 'argocd-controller',
    process_name: 'kubectl',
    process_lineage: ['argocd-application-controller', 'kubectl'],
    remote_ip: '10.42.0.7',
    child_count: 0,
    has_diff: true,
    diff_source: 'inline',
    metadata: {
      attribution: 'kubernetes-managed-fields',
      classification: 'rule:prod-k8s-01 ConfigMaps [L1]',
      rule_name: 'prod-k8s-01 ConfigMaps [L1]',
      rule_tags: 'k8s_configmap,auto-discovered,namespace:payments',
      kubernetes_namespace: 'payments',
      kubernetes_resource: 'checkout-config',
      change_ticket: 'CHG-1042',
    },
  },
  {
    id: mockId('ev', 12),
    host_id: FALLBACK_HOSTS[8].id,
    hostname: 'prod-k8s-01',
    occurred_at: hoursAgo(1, 18),
    impact_level: 1,
    category: 1,
    action: 2,
    // The stub is what the *agent's* edge scrubber produced: the report and the
    // diff both carry the deterministic marker, never the payload.
    summary: 'Rotated Secret payments/api-keys (CHECKOUT_API_KEY rotated, values redacted at the edge)',
    target_type: 'k8s_secret',
    path_or_key: '/k8s/prod-k8s-01/payments/secrets/api-keys',
    actor_username: 'argocd-controller',
    process_name: 'kubectl',
    process_lineage: ['argocd-application-controller', 'kubectl'],
    remote_ip: '10.42.0.7',
    child_count: 0,
    has_diff: true,
    diff_source: 'inline',
    metadata: {
      attribution: 'kubernetes-managed-fields',
      classification: 'rule:prod-k8s-01 Secrets [L1]',
      rule_name: 'prod-k8s-01 Secrets [L1]',
      rule_tags: 'k8s_secret,auto-discovered,namespace:payments',
      kubernetes_namespace: 'payments',
      kubernetes_resource: 'api-keys',
    },
  },
  {
    id: mockId('ev', 13),
    host_id: FALLBACK_HOSTS[8].id,
    hostname: 'prod-k8s-01',
    occurred_at: hoursAgo(2, 5),
    impact_level: 1,
    category: 3,
    action: 4,
    summary: 'Rolled out Deployment messaging/rabbitmq (revision 7 → 8)',
    target_type: 'k8s_deployment',
    path_or_key: '/k8s/prod-k8s-01/messaging/deployments/rabbitmq',
    actor_username: 'argocd-controller',
    process_name: 'kubectl',
    process_lineage: ['argocd-application-controller', 'kubectl'],
    remote_ip: '10.42.0.7',
    child_count: 0,
    has_diff: true,
    diff_source: 'inline',
    metadata: {
      attribution: 'kubernetes-managed-fields',
      classification: 'rule:prod-k8s-01 Deployments [L1]',
      rule_name: 'prod-k8s-01 Deployments [L1]',
      rule_tags: 'k8s_deployment,auto-discovered,namespace:messaging',
      kubernetes_namespace: 'messaging',
      kubernetes_resource: 'rabbitmq',
      change_ticket: 'CHG-1108',
    },
  },
  {
    id: mockId('ev', 14),
    host_id: FALLBACK_HOSTS[8].id,
    hostname: 'prod-k8s-01',
    occurred_at: hoursAgo(5, 30),
    impact_level: 3,
    category: 1,
    action: 2,
    summary: 'Modified Ingress staging/checkout-preview (host rule added)',
    target_type: 'k8s_ingress',
    path_or_key: '/k8s/prod-k8s-01/staging/ingresses/checkout-preview',
    actor_username: 'kubectl',
    process_name: 'kubectl',
    process_lineage: ['bash', 'kubectl'],
    remote_ip: '10.42.0.14',
    child_count: 0,
    has_diff: false,
    diff_source: '',
    metadata: {
      attribution: 'kubernetes-managed-fields',
      classification: 'drift',
      kubernetes_namespace: 'staging',
      kubernetes_resource: 'checkout-preview',
    },
  },
]

/**
 * Resolves an event (root or child) from the seeded timeline by id.
 *
 * The console renders this seed whenever the API has nothing in the selected
 * window, so an operator can click "View" on a row before any agent has
 * reported. Those ids are client-generated and unknown to Postgres, so the
 * detail drawer must be able to resolve them locally instead of surfacing a
 * 404 as "Failed to load event".
 */
export function fallbackEventById(id: string): Event | undefined {
  if (!id) return undefined
  return FALLBACK_EVENTS.find((e) => e.id === id)
}

/**
 * Builds a plausible unified diff for a seeded event, derived from its real
 * metadata so the inspector shows a coherent before/after rather than an
 * empty pane. Deterministic per event id — no randomness, no layout shift.
 */
export function fallbackDiffFor(event: Event): string {
  const path = event?.path_or_key || event?.summary || 'target'

  const header = [
    `--- a${path}`,
    `+++ b${path}`,
    `@@ -1,6 +1,7 @@`,
  ]

  // Steer the sample body by target type so files, registry keys, services and
  // package transactions each read like their real counterpart.
  switch (event?.target_type) {
    case 'service':
      return [
        ...header,
        ` [Unit]`,
        ` Description=${path}`,
        `-ExecStart=/usr/bin/app --workers 4`,
        `+ExecStart=/usr/bin/app --workers 8`,
        ` Restart=on-failure`,
        `-Environment=LOG_LEVEL=info`,
        `+Environment=LOG_LEVEL=debug`,
      ].join('\n')
    case 'k8s_secret':
      // A Secret's diff shows the *redaction stub* the agent produced, never a
      // value. Rendering the stub here keeps the preview honest about what the
      // console can actually show.
      return [
        `--- a${path}`,
        `+++ b${path}`,
        `@@ -3,5 +3,5 @@`,
        ` apiVersion: v1`,
        ` kind: Secret`,
        ` data:`,
        `-  POSTGRES_PASSWORD: [REDACTED:sha256:9f2b1c07]`,
        `+  POSTGRES_PASSWORD: [REDACTED:sha256:4f1a9c31]`,
        `   POSTGRES_HOST: cG9zdGdyZXM=`,
      ].join('\n')
    case 'k8s_configmap':
    case 'k8s_deployment':
    case 'k8s_statefulset':
    case 'k8s_ingress':
      return [
        `--- a${path}`,
        `+++ b${path}`,
        `@@ -8,6 +8,8 @@`,
        ` metadata:`,
        `   name: ${path.split('/').pop()}`,
        ` spec:`,
        `-  replicas: 2`,
        `+  replicas: 4`,
        `+  progressDeadlineSeconds: 900`,
        `   template:`,
        `     spec:`,
      ].join('\n')
    case 'registry':
      return [
        ...header,
        ` [HKEY_LOCAL_MACHINE\\Software\\Company\\App]`,
        `-"LogLevel"="INFO"`,
        `+"LogLevel"="DEBUG"`,
        ` "Endpoint"="https://api.internal"`,
        ` "Retries"=dword:00000003`,
      ].join('\n')
    case 'transaction':
      return [
        `--- apt/dpkg`,
        `+++ apt/dpkg`,
        `@@ -1,4 +1,4 @@`,
        ` postgresql-16 16.3-1  amd64  [installed]`,
        `-  libpq5 16.3-1  amd64  [installed]`,
        `+  libpq5 16.4-1  amd64  [upgraded]`,
        `+postgresql-16 16.4-1  amd64  [upgraded]`,
      ].join('\n')
    default:
      return [
        ...header,
        ` # ${path}`,
        ` server {`,
        `-  worker_processes 4;`,
        `+  worker_processes 8;`,
        `-  client_max_body_size 10m;`,
        `+  client_max_body_size 50m;`,
        `   keepalive_timeout 65;`,
      ].join('\n')
  }
}

/**
 * Cross-host matrix rows for the Drift page. `hosts` order matches
 * DRIFT_MATRIX_HOSTS; each cell is a status, not a hash, because the matrix
 * is a presentation roll-up of the pairwise drift endpoint.
 */
export type DriftCellStatus = 'sync' | 'drift' | 'modified' | 'missing'

export interface DriftMatrixRow {
  path_or_key: string
  target_type: string
  category: string
  cells: Record<string, DriftCellStatus>
}

export const DRIFT_MATRIX_HOSTS = [
  { id: 'web-01', hostname: 'prod-web-01', os: 'linux' as const },
  { id: 'db-01', hostname: 'prod-db-01', os: 'linux' as const },
  { id: 'app-01', hostname: 'prod-app-01', os: 'linux' as const },
  { id: 'k8s-01', hostname: 'prod-k8s-01', os: 'kubernetes' as const },
  { id: 'win-01', hostname: 'win-app-01', os: 'windows' as const },
  { id: 'win-02', hostname: 'win-app-02', os: 'windows' as const },
]

export const FALLBACK_DRIFT_MATRIX: DriftMatrixRow[] = [
  {
    path_or_key: '/etc/nginx/nginx.conf',
    target_type: 'file',
    category: 'Config',
    cells: {
      'web-01': 'modified',
      'db-01': 'sync',
      'app-01': 'drift',
      'k8s-01': 'missing',
      'win-01': 'missing',
      'win-02': 'missing',
    },
  },
  {
    path_or_key: '/etc/ssh/sshd_config',
    target_type: 'file',
    category: 'Config',
    cells: {
      'web-01': 'sync',
      'db-01': 'sync',
      'app-01': 'sync',
      'k8s-01': 'missing',
      'win-01': 'missing',
      'win-02': 'missing',
    },
  },
  {
    path_or_key: '/var/www/html/index.php',
    target_type: 'file',
    category: 'Config',
    cells: {
      'web-01': 'modified',
      'db-01': 'missing',
      'app-01': 'drift',
      'k8s-01': 'missing',
      'win-01': 'missing',
      'win-02': 'missing',
    },
  },
  {
    path_or_key: '/etc/systemd/system/app.service',
    target_type: 'file',
    category: 'Service',
    cells: {
      'web-01': 'sync',
      'db-01': 'drift',
      'app-01': 'sync',
      'k8s-01': 'missing',
      'win-01': 'missing',
      'win-02': 'missing',
    },
  },
  {
    path_or_key: '/etc/nginx/conf.d/upstream.conf',
    target_type: 'file',
    category: 'Config',
    cells: {
      'web-01': 'missing',
      'db-01': 'missing',
      'app-01': 'sync',
      'k8s-01': 'missing',
      'win-01': 'missing',
      'win-02': 'missing',
    },
  },
  {
    path_or_key: 'HKLM\\Software\\Company\\App',
    target_type: 'registry',
    category: 'Registry',
    cells: {
      'web-01': 'missing',
      'db-01': 'missing',
      'app-01': 'missing',
      'k8s-01': 'missing',
      'win-01': 'modified',
      'win-02': 'drift',
    },
  },
  {
    path_or_key: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\StateTrackAgent',
    target_type: 'registry',
    category: 'Registry',
    cells: {
      'web-01': 'missing',
      'db-01': 'missing',
      'app-01': 'missing',
      'k8s-01': 'missing',
      'win-01': 'sync',
      'win-02': 'sync',
    },
  },
  {
    path_or_key: 'C:\\ProgramData\\ssh\\administrators_authorized_keys',
    target_type: 'file',
    category: 'Security',
    cells: {
      'web-01': 'missing',
      'db-01': 'missing',
      'app-01': 'missing',
      'k8s-01': 'missing',
      'win-01': 'modified',
      'win-02': 'drift',
    },
  },
  {
    path_or_key: 'nginx',
    target_type: 'package',
    category: 'Package',
    cells: {
      'web-01': 'sync',
      'db-01': 'missing',
      'app-01': 'drift',
      'k8s-01': 'missing',
      'win-01': 'missing',
      'win-02': 'missing',
    },
  },
  {
    path_or_key: 'postgresql-16',
    target_type: 'package',
    category: 'Package',
    cells: {
      'web-01': 'missing',
      'db-01': 'modified',
      'app-01': 'missing',
      'k8s-01': 'missing',
      'win-01': 'missing',
      'win-02': 'missing',
    },
  },
  // ---- Kubernetes cluster resources ------------------------------------
  //
  // A cluster is one column, not one per namespace: the matrix compares like
  // with like, and a ConfigMap on prod-k8s-01 has no counterpart on a VM, so
  // its row reads as "not present" everywhere else — which is the honest
  // answer and the one that makes a cross-environment leak visible.
  {
    path_or_key: '/k8s/prod-k8s-01/payments/configmaps/checkout-config',
    target_type: 'k8s_configmap',
    category: 'Kubernetes',
    cells: {
      'web-01': 'missing',
      'db-01': 'missing',
      'app-01': 'missing',
      'k8s-01': 'modified',
      'win-01': 'missing',
      'win-02': 'missing',
    },
  },
  {
    path_or_key: '/k8s/prod-k8s-01/payments/secrets/api-keys',
    target_type: 'k8s_secret',
    category: 'Kubernetes',
    cells: {
      'web-01': 'missing',
      'db-01': 'missing',
      'app-01': 'missing',
      'k8s-01': 'modified',
      'win-01': 'missing',
      'win-02': 'missing',
    },
  },
  {
    path_or_key: '/k8s/prod-k8s-01/messaging/deployments/rabbitmq',
    target_type: 'k8s_deployment',
    category: 'Kubernetes',
    cells: {
      'web-01': 'missing',
      'db-01': 'missing',
      'app-01': 'missing',
      'k8s-01': 'sync',
      'win-01': 'missing',
      'win-02': 'missing',
    },
  },
  {
    path_or_key: '/k8s/prod-k8s-01/staging/ingresses/checkout-preview',
    target_type: 'k8s_ingress',
    category: 'Kubernetes',
    cells: {
      'web-01': 'missing',
      'db-01': 'missing',
      'app-01': 'missing',
      'k8s-01': 'drift',
      'win-01': 'missing',
      'win-02': 'missing',
    },
  },
]

/** Pairwise drift rows for the two-host compare drawer (storage.DriftRow). */
export function fallbackPairwiseDrift(hostA: string, hostB: string): DriftRow[] {
  return FALLBACK_DRIFT_MATRIX.filter((row) => {
    const a = row.cells[hostA]
    const b = row.cells[hostB]
    return Boolean(a && b) && a !== b
  }).map((row, i) => ({
    target_id: i + 1,
    target_type: row.target_type,
    path_or_key: row.path_or_key,
    hash_a: row.cells[hostA] === 'sync' || row.cells[hostA] === 'modified' ? 'a'.repeat(40) : '',
    version_a: '',
    hash_b: row.cells[hostB] === 'sync' || row.cells[hostB] === 'modified' ? 'b'.repeat(40) : '',
    version_b: '',
    only_on: row.cells[hostA] === 'missing' ? 'b' : row.cells[hostB] === 'missing' ? 'a' : '',
  }))
}

/* ------------------------------------------------------------------ */
/* Smart recommendations (auto-discovery & asset tiering)              */
/* ------------------------------------------------------------------ */

/**
 * Discovery recommendations mirroring `storage.Recommendation`. Used by the
 * banner and drawer when no agent has reported discovered workloads yet, so
 * the review flow is demonstrable on a cold start.
 */
export const FALLBACK_RECOMMENDATIONS: Recommendation[] = [
  {
    id: mockId('rec', 1),
    host_id: FALLBACK_HOSTS[5].id,
    hostname: 'win-app-01',
    workload_type: 'iis_site',
    name: 'CheckoutApp',
    config_path: 'C:\\inetpub\\wwwroot\\checkout\\web.config',
    suggested_level: 1,
    suggested_diff: true,
    reason: 'Active HTTPS production binding on port 443.',
    status: 'pending',
    created_at: hoursAgo(0, 4),
    updated_at: hoursAgo(0, 4),
  },
  {
    id: mockId('rec', 2),
    host_id: FALLBACK_HOSTS[6].id,
    hostname: 'win-app-02',
    workload_type: 'mssql_instance',
    name: 'MSSQL$PROD',
    config_path: 'C:\\Program Files\\Microsoft SQL Server\\MSSQL16.PROD\\MSSQL\\DATA',
    suggested_level: 1,
    suggested_diff: false,
    reason: 'Named production SQL Server instance with active databases.',
    status: 'pending',
    created_at: hoursAgo(0, 4),
    updated_at: hoursAgo(0, 4),
  },
  {
    id: mockId('rec', 3),
    host_id: FALLBACK_HOSTS[0].id,
    hostname: 'prod-web-01',
    workload_type: 'nginx_vhost',
    name: 'shop.example.com',
    config_path: '/etc/nginx/sites-enabled/shop.conf',
    suggested_level: 1,
    suggested_diff: true,
    reason: 'Active HTTPS vhost on port 443 serving production traffic.',
    status: 'pending',
    created_at: hoursAgo(0, 5),
    updated_at: hoursAgo(0, 5),
  },
  {
    id: mockId('rec', 4),
    host_id: FALLBACK_HOSTS[1].id,
    hostname: 'prod-web-02',
    workload_type: 'nginx_vhost',
    name: 'staging.internal',
    config_path: '/etc/nginx/sites-enabled/staging.conf',
    suggested_level: 3,
    suggested_diff: false,
    reason: 'HTTP-only staging vhost — tracked as drift.',
    status: 'pending',
    created_at: hoursAgo(0, 5),
    updated_at: hoursAgo(0, 5),
  },
  {
    id: mockId('rec', 5),
    host_id: FALLBACK_HOSTS[4].id,
    hostname: 'prod-cache-01',
    workload_type: 'redis',
    name: 'redis',
    config_path: '/etc/redis/redis.conf',
    suggested_level: 1,
    suggested_diff: true,
    reason: 'Active Redis service with a local configuration file.',
    status: 'pending',
    created_at: hoursAgo(0, 6),
    updated_at: hoursAgo(0, 6),
  },
  {
    id: mockId('rec', 6),
    host_id: FALLBACK_HOSTS[0].id,
    hostname: 'prod-web-01',
    workload_type: 'docker',
    name: 'docker',
    config_path: '/etc/docker/daemon.json',
    suggested_level: 3,
    suggested_diff: false,
    reason: 'Docker daemon config present; runtime state excluded.',
    status: 'applied',
    created_at: hoursAgo(3, 10),
    updated_at: hoursAgo(2, 30),
  },
  // ---- Kubernetes workloads (prod-k8s-01) -----------------------------
  //
  // The cluster's catalog-driven discovery reports one recommendation per
  // (namespace, resource) profile, so the review queue looks the same whether
  // the workload was found on a VM or in a cluster.
  {
    id: mockId('rec', 7),
    host_id: FALLBACK_HOSTS[8].id,
    hostname: 'prod-k8s-01',
    workload_type: 'k8s_configmap',
    name: 'payments/configmap',
    config_path: '/k8s/prod-k8s-01/payments/configmaps/**',
    suggested_level: 1,
    suggested_diff: true,
    reason: 'ConfigMaps in the production namespace payments on cluster prod-k8s-01.',
    status: 'pending',
    created_at: hoursAgo(0, 3),
    updated_at: hoursAgo(0, 3),
  },
  {
    id: mockId('rec', 8),
    host_id: FALLBACK_HOSTS[8].id,
    hostname: 'prod-k8s-01',
    workload_type: 'k8s_secret',
    name: 'payments/secret',
    config_path: '/k8s/prod-k8s-01/payments/secrets/**',
    suggested_level: 1,
    suggested_diff: true,
    reason: 'Secrets in the production namespace payments; values are redacted at the agent.',
    status: 'pending',
    created_at: hoursAgo(0, 3),
    updated_at: hoursAgo(0, 3),
  },
  {
    id: mockId('rec', 9),
    host_id: FALLBACK_HOSTS[8].id,
    hostname: 'prod-k8s-01',
    workload_type: 'k8s_deployment',
    name: 'messaging/deployment',
    config_path: '/k8s/prod-k8s-01/messaging/deployments/**',
    suggested_level: 1,
    suggested_diff: false,
    reason: 'Workload specs in the production namespace messaging trigger a rollout when edited.',
    status: 'pending',
    created_at: hoursAgo(0, 6),
    updated_at: hoursAgo(0, 6),
  },
  {
    id: mockId('rec', 10),
    host_id: FALLBACK_HOSTS[8].id,
    hostname: 'prod-k8s-01',
    workload_type: 'k8s_ingress',
    name: 'staging/ingress',
    config_path: '/k8s/prod-k8s-01/staging/ingresses/**',
    suggested_level: 3,
    suggested_diff: false,
    reason: 'Ingresses in the staging namespace — tracked as drift, not alerted.',
    status: 'pending',
    created_at: hoursAgo(0, 6),
    updated_at: hoursAgo(0, 6),
  },
]

/** Rules materialized from the applied recommendations above. */
export const FALLBACK_POLICY_RULES: PolicyRule[] = [
  {
    id: mockId('rule', 1),
    name: 'docker [L3]',
    target_type: 'file',
    pattern: '/etc/docker/daemon.json',
    level: 3,
    diff: false,
    tags: ['docker', 'auto-discovered', 'host:prod-web-01'],
    created_at: hoursAgo(2, 30),
  },
]

/* ------------------------------------------------------------------ */
/* Custom watched targets (the rule builder)                          */
/* ------------------------------------------------------------------ */

/**
 * The builder's Target Type catalog, mirroring the server's
 * `watchTargetCatalog`. Used only when the API is unreachable; the live
 * catalog always wins, because the placeholder an operator copies has to be a
 * path the agent can actually watch.
 */
export const FALLBACK_WATCH_TARGET_TYPES: WatchTargetType[] = [
  {
    value: 'file',
    label: 'File',
    placeholder: 'C:\\inetpub\\wwwroot\\checkout\\web.config',
    help: 'One configuration file. Supports * and ? wildcards in the file name.',
  },
  {
    value: 'directory',
    label: 'Directory',
    placeholder: 'D:\\Apps\\Billing\\Config\\**',
    help: 'A tree. Use ** to include subdirectories.',
  },
  {
    value: 'iis_apppool',
    label: 'IIS App Pool',
    placeholder: 'iis://apppool/CheckoutAppPool',
    help: 'State, identity and recycling. A pool that stops is Level 1.',
    platforms: ['windows'],
  },
  {
    value: 'iis_site',
    label: 'IIS Site',
    placeholder: 'iis://site/Checkout',
    help: 'Bindings, SSL thumbprint and physical path.',
    platforms: ['windows'],
  },
  {
    value: 'database_table',
    label: 'Database Table',
    placeholder: 'db://postgres/settings_db/tables/public.app_settings',
    help: 'A configuration table, read-only, ordered by primary key.',
  },
  {
    value: 'registry',
    label: 'Registry Key',
    placeholder: 'HKLM\\Software\\Company\\App\\**',
    help: 'A registry key and its values.',
    platforms: ['windows'],
  },
  {
    value: 'service',
    label: 'Service',
    placeholder: 'W3SVC',
    help: 'One Windows service or systemd unit by name.',
  },
  {
    value: 'k8s_object',
    label: 'Kubernetes Object',
    placeholder: '/k8s/prod-k8s-01/production/configmaps/checkout-config',
    help: 'One object by tracked path.',
  },
]

/** The two capture modes the builder offers. */
export const FALLBACK_WATCH_IMPACT_LEVELS: WatchImpactLevel[] = [
  {
    value: 1,
    label: 'Level 1 Critical',
    help: 'Full text diff and an instant alert. Use for production configuration.',
    diff: true,
  },
  {
    value: 3,
    label: 'Level 3 Drift',
    help: 'Hash only, no diff. Use for large or low-risk trees.',
    diff: false,
  },
]

/**
 * The watched targets a demo install starts from — the same five surfaces the
 * surgical watchers exist for, one per target type, so the table shows what the
 * builder produces rather than one repeated row.
 */
export const FALLBACK_WATCH_RULES: WatchRule[] = [
  {
    id: mockId('watch', 1),
    host_id: FALLBACK_HOSTS[6].id,
    hostname: 'win-app-02',
    host_scope: 'win-app-02',
    name: 'CheckoutAppPool',
    target_type: 'iis_apppool',
    pattern: 'iis://apppool/CheckoutAppPool',
    level: 1,
    diff: true,
    tags: ['console', 'iis', 'payments'],
    created_by: 'pk@statetrack.io',
    created_at: hoursAgo(26, 0),
    target_label: 'IIS App Pool',
    impact_label: 'Level 1 Critical',
    diff_mode: 'Full diff',
  },
  {
    id: mockId('watch', 2),
    host_id: FALLBACK_HOSTS[0].id,
    hostname: 'prod-web-01',
    host_scope: 'prod-web-01',
    name: 'public.app_settings',
    target_type: 'database_table',
    pattern: 'db://postgres/settings_db/tables/public.app_settings',
    level: 1,
    diff: true,
    tags: ['console', 'database', 'settings_db'],
    created_by: 'pk@statetrack.io',
    created_at: hoursAgo(26, 0),
    target_label: 'Database Table',
    impact_label: 'Level 1 Critical',
    diff_mode: 'Full diff',
  },
  {
    id: mockId('watch', 3),
    host_id: FALLBACK_HOSTS[1].id,
    hostname: 'prod-web-02',
    host_scope: 'prod-web-02',
    name: '**',
    target_type: 'directory',
    pattern: 'D:\\Apps\\Billing\\Config\\**',
    level: 3,
    diff: false,
    tags: ['console', 'billing'],
    created_by: 'compliance@statetrack.io',
    created_at: hoursAgo(48, 20),
    target_label: 'Directory',
    impact_label: 'Level 3 Drift',
    diff_mode: 'Hash only',
  },
  {
    id: mockId('watch', 4),
    host_id: FALLBACK_HOSTS[6].id,
    hostname: 'win-app-02',
    host_scope: 'win-app-02',
    name: '**',
    target_type: 'registry',
    pattern: 'HKLM\\Software\\Company\\App\\**',
    level: 1,
    diff: true,
    tags: ['console', 'registry'],
    created_by: 'pk@statetrack.io',
    created_at: hoursAgo(72, 5),
    target_label: 'Registry Key',
    impact_label: 'Level 1 Critical',
    diff_mode: 'Full diff',
  },
  {
    id: mockId('watch', 5),
    host_id: '',
    hostname: '',
    host_scope: FLEET_SCOPE,
    name: 'W3SVC',
    target_type: 'service',
    pattern: 'W3SVC',
    level: 1,
    diff: true,
    tags: ['console', 'fleet-wide'],
    created_by: 'pk@statetrack.io',
    created_at: hoursAgo(96, 0),
    target_label: 'Service',
    impact_label: 'Level 1 Critical',
    diff_mode: 'Full diff',
  },
]

/* ------------------------------------------------------------------ */
/* Grafana integration                                                */
/* ------------------------------------------------------------------ */

/**
 * Seeded annotation log. The live type is `GrafanaAnnotation` in `types.ts`
 * (mirroring the server's dispatch log); this is the offline preview used when
 * the API is unreachable, so the "Recent Annotations" table is never empty.
 */
export const FALLBACK_GRAFANA_ANNOTATIONS: GrafanaAnnotation[] = FALLBACK_EVENTS.slice(0, 6).map(
  (e, i) => ({
    id: mockId('ann', i + 1),
    event_id: e.id,
    hostname: e.hostname ?? 'unknown',
    impact_level: `L${e.impact_level}`,
    impact_number: e.impact_level,
    summary: e.summary,
    text: `[StateTrack] ${e.summary} · actor ${e.actor_username ?? 'system'} on ${e.hostname ?? 'unknown'}`,
    tags: [`host:${e.hostname ?? ''}`, `level:L${e.impact_level}`, `category:${e.category}`],
    dashboard: i % 3 === 0 ? 'Infra / Linux Overview' : i % 3 === 1 ? 'Databases / Postgres' : 'Apps / Deploys',
    status: 'delivered',
    time: e.occurred_at,
    time_ms: new Date(e.occurred_at).getTime(),
    deep_link: `/events/${e.id}?tab=diff`,
  }),
)

/** The Grafana settings a fresh install starts from (mirrors the server default). */
export const FALLBACK_GRAFANA_SETTINGS: GrafanaSettings = {
  url: 'https://grafana.acme.internal',
  api_token: '',
  org: 'Acme Corporation',
  push_l1: true,
  push_l2: true,
  push_l3: false,
  template: '[StateTrack] {{summary}} · actor {{actor}} on {{hostname}} · {{level}}',
  dashboards: ['Infra / Linux Overview', 'Databases / Postgres'],
  enabled: true,
  last_test_ok: false,
}

export const GRAFANA_DASHBOARDS = [
  'Infra / Linux Overview',
  'Databases / Postgres',
  'Apps / Deploys',
  'Windows / Service Health',
  'Security / Audit Trail',
]

/**
 * Seeded notification channels, matching the server's `DefaultWebhookChannel`
 * shape field for field so a page rendered from this data is indistinguishable
 * from one rendered from the API. Shown only when the API is unreachable, and
 * labelled as preview data so it is never mistaken for saved configuration.
 */
export const FALLBACK_WEBHOOK_CHANNELS: WebhookChannel[] = [
  {
    provider: 'teams',
    url: '',
    token: '',
    label: '',
    severity: '',
    notify_l1: true,
    notify_storms: true,
    enabled: false,
    token_set: false,
  },
  {
    provider: 'slack',
    // A placeholder in the preview data store. It deliberately does not use the
    // hooks.slack.com shape: a string that looks like a live webhook trips
    // secret scanners (including GitHub push protection), and this row is never
    // sent anywhere. Replace it with your own webhook in the console.
    url: 'https://example.invalid/slack-webhook',
    token: '',
    label: '#infra-alerts',
    severity: '',
    notify_l1: true,
    notify_storms: true,
    enabled: true,
    token_set: false,
  },
  {
    provider: 'pagerduty',
    url: 'https://events.pagerduty.com/v2/enqueue',
    token: '',
    label: '',
    severity: 'critical',
    notify_l1: true,
    notify_storms: false,
    enabled: true,
    token_set: false,
  },
  {
    provider: 'webhook',
    url: 'https://siem.acme.internal/ingest/statetrack',
    token: '',
    label: 'SIEM · Splunk HEC relay',
    severity: '',
    notify_l1: true,
    notify_storms: true,
    enabled: true,
    token_set: true,
  },
]

/** Seeded delivery log, newest first, for the hub's status table. */
export const FALLBACK_WEBHOOK_DELIVERIES: WebhookDelivery[] = [
  { provider: 'slack', status_code: 200, latency_ms: 118, sample: false },
  { provider: 'pagerduty', status_code: 202, latency_ms: 143, sample: false },
  { provider: 'webhook', status_code: 200, latency_ms: 87, sample: false },
  { provider: 'teams', status_code: 404, latency_ms: 61, sample: true },
  { provider: 'slack', status_code: 200, latency_ms: 104, sample: true },
  { provider: 'webhook', status_code: 200, latency_ms: 92, sample: false },
].map((d, i) => ({
  id: 900 - i,
  provider: d.provider,
  endpoint: '',
  event_id: '',
  status_code: d.status_code,
  latency_ms: d.latency_ms,
  success: d.status_code >= 200 && d.status_code < 300,
  attempts: d.status_code >= 200 && d.status_code < 300 ? 1 : 3,
  sample: d.sample,
  error: d.status_code >= 300 ? `HTTP ${d.status_code} from the provider` : undefined,
  created_at: new Date(Date.now() - (i + 1) * 4 * 60_000).toISOString(),
}))

/* ------------------------------------------------------------------ */
/* Reports                                                            */
/* ------------------------------------------------------------------ */

export interface TopServer {
  hostname: string
  os: 'linux' | 'windows'
  total: number
  critical: number
  drift: number
  trend: number
}

export const FALLBACK_TOP_SERVERS: TopServer[] = [
  { hostname: 'prod-web-01', os: 'linux', total: 428, critical: 18, drift: 96, trend: 12 },
  { hostname: 'prod-db-01', os: 'linux', total: 312, critical: 9, drift: 141, trend: 4 },
  { hostname: 'win-app-01', os: 'windows', total: 274, critical: 21, drift: 38, trend: -6 },
  { hostname: 'prod-app-01', os: 'linux', total: 205, critical: 6, drift: 74, trend: 8 },
  { hostname: 'win-app-02', os: 'windows', total: 166, critical: 11, drift: 22, trend: -2 },
  { hostname: 'prod-cache-01', os: 'linux', total: 98, critical: 2, drift: 47, trend: 3 },
]

export interface TopActor {
  username: string
  changes: number
  critical: number
  packages: number
  lastSeen: string
}

export const FALLBACK_TOP_ACTORS: TopActor[] = [
  { username: 'root', changes: 612, critical: 34, packages: 188, lastSeen: hoursAgo(0, 12) },
  { username: 'alice', changes: 184, critical: 12, packages: 3, lastSeen: hoursAgo(1, 20) },
  { username: 'deploy-bot', changes: 141, critical: 2, packages: 96, lastSeen: hoursAgo(2, 2) },
  { username: 'CORP\\Administrator', changes: 96, critical: 18, packages: 21, lastSeen: hoursAgo(3, 5) },
  { username: 'CORP\\jdoe', changes: 42, critical: 6, packages: 0, lastSeen: hoursAgo(4, 40) },
]

export interface SecurityEvent {
  time: string
  hostname: string
  summary: string
  actor: string
  source: string
  severity: 'high' | 'medium' | 'low'
}

export const FALLBACK_SECURITY_EVENTS: SecurityEvent[] = [
  {
    time: hoursAgo(0, 6),
    hostname: 'prod-web-01',
    summary: 'authorized_keys modified by interactive session',
    actor: 'alice',
    source: '192.168.1.50',
    severity: 'high',
  },
  {
    time: hoursAgo(4, 40),
    hostname: 'win-app-02',
    summary: 'administrators_authorized_keys gained a new key',
    actor: 'CORP\\jdoe',
    source: '203.0.113.19',
    severity: 'high',
  },
  {
    time: hoursAgo(11, 30),
    hostname: 'prod-db-01',
    summary: 'Unexpected outbound connection from postgres',
    actor: 'postgres',
    source: '203.0.113.77',
    severity: 'medium',
  },
  {
    time: hoursAgo(13, 45),
    hostname: 'prod-web-01',
    summary: 'SSH public key removed from root authorized_keys',
    actor: 'root',
    source: '10.0.4.2',
    severity: 'medium',
  },
  {
    time: hoursAgo(18, 10),
    hostname: 'staging-web-01',
    summary: 'Agent offline — last heartbeat 19h ago',
    actor: 'system',
    source: '—',
    severity: 'low',
  },
]

/* ------------------------------------------------------------------ */
/* Settings                                                           */
/* ------------------------------------------------------------------ */

export const SYSTEM_INFO = {
  version: '1.0.0',
  buildDate: '2026-10-14',
  environment: 'production',
  database: 'PostgreSQL 17',
  storage: 'SeaweedFS / S3',
  agentsOnline: 7,
  retentionDays: 365,
}

export const TIMEZONES = [
  'Europe/Berlin',
  'Europe/London',
  'Europe/Warsaw',
  'UTC',
  'America/New_York',
  'America/Los_Angeles',
  'Asia/Singapore',
]

/** Deterministic bar heights so the sparkline never shifts between renders. */
export function sparkSeries(seed: string, n = 14): number[] {
  let acc = Array.from(seed).reduce((a, c) => a + c.charCodeAt(0), 17)
  return Array.from({ length: n }, (_, i) => {
    acc = (acc * 1103515245 + 12345 + i) % 2147483647
    return 25 + (acc % 70)
  })
}

/* ------------------------------------------------------------------ */
/* ITSM change-ticket bridge (Jira & ServiceNow)                      */
/* ------------------------------------------------------------------ */

/**
 * Seeded bridge configuration matching the server's `DefaultITSMSettings` plus
 * a populated ticket mirror, so the hub and the compliance filter both render a
 * complete, realistic picture on a cold start.
 *
 * Enforcement defaults to `warn` — not `required` — because the correlation
 * needs a populated mirror before it can produce meaningful verdicts, and
 * turning on a hard control before any tickets have synced would flag every
 * production change in the fleet on day one.
 */
export const FALLBACK_ITSM_SETTINGS: ITSMSettingsView = {
  jira: {
    url: 'https://acme.atlassian.net',
    project: 'OPS',
    username: 'svc-statetrack@acme.example',
    enabled: true,
    last_sync_at: hoursAgo(0, 22),
    last_sync_ok: true,
    last_sync_count: 18,
  },
  servicenow: {
    url: 'https://acme.service-now.com',
    project: 'change_request',
    username: 'statetrack.integration',
    enabled: true,
    last_sync_at: hoursAgo(1, 5),
    last_sync_ok: true,
    last_sync_count: 42,
  },
  enforcement: 'warn',
  window_grace_minutes: 15,
  min_level: 1,
  exempt_actors: ['config-management', 'terraform', 'state-sync'],
  jira_token_set: true,
  servicenow_token_set: true,
  enforcements: ['off', 'warn', 'required'],
  kinds: ['jira', 'servicenow', 'manual'],
  modes: [
    {
      value: 'off',
      label: 'Off',
      help: 'Record changes only. No compliance verdict is attached and nothing is flagged.',
    },
    {
      value: 'warn',
      label: 'Warn (recommended)',
      help: "Attach an 'Unapproved Change' badge to Level 1 changes with no approved ticket. Nothing is blocked.",
    },
    {
      value: 'required',
      label: 'Required',
      help: 'Flag and alert on every Level 1 change without an approved ticket. Use once your ticket mirror is populated.',
    },
  ],
  unapproved_count: 2,
}

/**
 * Seeded ticket mirror. Windows are anchored to the seeded timeline's own
 * change times, so the correlation in this preview produces the same verdicts
 * the server would: one covered production change, one window that has closed,
 * and one ticket that exists but was never approved.
 */
export const FALLBACK_CHANGE_TICKETS: ChangeTicket[] = [
  {
    id: mockId('chg', 1),
    kind: 'servicenow',
    ref: 'CHG-1042',
    status: 'approved',
    status_label: 'Approved',
    authorized: true,
    summary: 'Raise nginx upstream timeout and rotate the backing DB credential',
    url: 'https://acme.service-now.com/change_request.do?sys_id=CHG-1042',
    hosts: ['prod-web-01'],
    environments: ['production'],
    paths: ['/etc/nginx/nginx.conf', '/k8s/prod-k8s-01/payments/configmaps/**'],
    window_start: hoursAgo(2),
    window_end: hoursAgo(-1),
    requested_by: 'a.chen@acme.example',
    created_at: hoursAgo(26),
    updated_at: hoursAgo(2),
    expired: false,
  },
  {
    id: mockId('chg', 2),
    kind: 'servicenow',
    ref: 'CHG-1108',
    status: 'in_progress',
    status_label: 'In Progress',
    authorized: true,
    summary: 'Roll RabbitMQ to 3.13.7 and apply the messaging namespace changes',
    url: 'https://acme.service-now.com/change_request.do?sys_id=CHG-1108',
    hosts: ['prod-k8s-01'],
    environments: ['production'],
    paths: ['/k8s/prod-k8s-01/messaging/**'],
    window_start: hoursAgo(6),
    window_end: hoursAgo(-2),
    requested_by: 'r.okafor@acme.example',
    created_at: hoursAgo(48),
    updated_at: hoursAgo(1, 30),
    expired: false,
  },
  {
    id: mockId('chg', 3),
    kind: 'jira',
    ref: 'OPS-8813',
    status: 'approved',
    status_label: 'Approved',
    authorized: true,
    summary: 'Scheduled Postgres minor upgrade maintenance window',
    url: 'https://acme.atlassian.net/browse/OPS-8813',
    hosts: ['prod-db-01'],
    environments: ['production'],
    paths: ['postgresql-16'],
    // Deliberately closed: this is the "window expired" case the review queue
    // exists to surface, and the one a reviewer must extend rather than
    // re-raise.
    window_start: hoursAgo(30),
    window_end: hoursAgo(26),
    requested_by: 'a.chen@acme.example',
    created_at: hoursAgo(72),
    updated_at: hoursAgo(26),
    expired: true,
  },
  {
    id: mockId('chg', 4),
    kind: 'jira',
    ref: 'OPS-9042',
    status: 'requested',
    status_label: 'Pending Approval',
    authorized: false,
    summary: 'Enable debug logging on the application registry hive',
    url: 'https://acme.atlassian.net/browse/OPS-9042',
    hosts: ['win-app-01', 'win-app-02'],
    environments: ['production'],
    paths: ['HKLM\\Software\\Company\\App\\*'],
    window_start: hoursAgo(12),
    window_end: hoursAgo(-12),
    requested_by: 'jdoe@acme.example',
    created_at: hoursAgo(12),
    updated_at: hoursAgo(12),
    expired: false,
  },
  {
    id: mockId('chg', 5),
    kind: 'manual',
    ref: 'CHG-0987',
    status: 'rejected',
    status_label: 'Rejected',
    authorized: false,
    summary: 'Proposed wildcard certificate swap on the staging ingress',
    hosts: ['prod-k8s-01'],
    environments: ['staging'],
    paths: ['/k8s/prod-k8s-01/staging/**'],
    window_start: hoursAgo(96),
    window_end: hoursAgo(90),
    requested_by: 'deploy-bot@acme.example',
    created_at: hoursAgo(120),
    updated_at: hoursAgo(96),
    expired: true,
  },
]

/**
 * Applies the same verdict table the server's correlation uses, so the offline
 * preview cannot disagree with a live deployment.
 *
 * The mapping is deliberately the *shape* of the server's decision, not a
 * re-implementation of it: metadata citation, then host+environment scope, then
 * window, then the unauthorised fallback. Deriving an `unapproved` verdict here
 * that the server would call `approved` is exactly the kind of drift that makes
 * a compliance preview worse than none.
 */
export function fallbackComplianceEvents(
  filters: { compliance?: Compliance | ''; host_id?: string; impact_level?: number } = {},
): ComplianceEvent[] {
  const tickets = FALLBACK_CHANGE_TICKETS
  const now = Date.now()

  const verdictFor = (e: Event): { compliance: Compliance; ticket?: ChangeTicket; reason: string } => {
    if (e.impact_level !== 1) {
      return { compliance: 'not_required', reason: 'Change tickets are required for Level 1 critical changes only.' }
    }

    // An explicit citation is the strongest evidence, and is reported even when
    // the cited ticket is unauthorised — "somebody edited production citing a
    // change that was refused" is the finding worth surfacing.
    const cited = (e.metadata?.change_ticket ?? '').trim().toUpperCase()
    if (cited) {
      const t = tickets.find((x) => x.ref.toUpperCase() === cited)
      if (t) {
        return t.authorized
          ? { compliance: 'approved', ticket: t, reason: `${t.ref} (${t.status_label}) is authorised and covers this change.` }
          : {
              compliance: 'unapproved',
              ticket: t,
              reason: `${t.ref} is ${t.status_label.toLowerCase()}, not approved; this change is not authorised by it.`,
            }
      }
      return { compliance: 'unapproved', reason: `This change cites ${cited}, which is not a known change ticket.` }
    }

    const hostEnv = environmentOf(e.hostname ?? '')
    const scoped = tickets.filter(
      (t) =>
        (!t.hosts?.length || t.hosts.includes(e.hostname ?? '')) &&
        (!t.environments?.length || t.environments.includes(hostEnv)) &&
        (!t.paths?.length || t.paths.some((p) => globMatches(p, e.path_or_key))),
    )
    const at = new Date(e.occurred_at).getTime()
    const inWindow = scoped.find(
      (t) =>
        t.authorized &&
        (!t.window_start || at >= new Date(t.window_start).getTime() - 15 * 60_000) &&
        (!t.window_end || at <= new Date(t.window_end).getTime() + 15 * 60_000),
    )
    if (inWindow) {
      return {
        compliance: 'approved',
        ticket: inWindow,
        reason: `Covered by ${inWindow.ref} (${inWindow.status_label}).`,
      }
    }
    const expired = scoped.find((t) => t.authorized && t.window_end && new Date(t.window_end).getTime() < now)
    if (expired) {
      return {
        compliance: 'expired',
        ticket: expired,
        reason: `${expired.ref} covers this target but its window closed.`,
      }
    }
    const unauthorised = scoped.find((t) => !t.authorized)
    if (unauthorised) {
      return {
        compliance: 'unapproved',
        ticket: unauthorised,
        reason: `${unauthorised.ref} covers this target but is ${unauthorised.status_label.toLowerCase()}.`,
      }
    }
    return { compliance: 'unapproved', reason: 'No approved change ticket covers this host at this time.' }
  }

  return FALLBACK_EVENTS.filter(
    (e) =>
      (!filters.host_id || e.host_id === filters.host_id) &&
      (!filters.impact_level || e.impact_level === filters.impact_level),
  ).map((e) => {
    const verdict = verdictFor(e)
    return {
      ...e,
      compliance: verdict.compliance,
      compliance_reason: verdict.reason,
      ticket_ref: verdict.ticket?.ref,
      ticket_status: verdict.ticket?.status_label,
    }
  }).filter((e) => !filters.compliance || e.compliance === filters.compliance)
}

/** Derives a logical tier from a hostname, token-wise.
 *
 * "preprod-web-01" must not read as production on the "prod" inside "preprod",
 * which is the same near-miss the agent's risk tiering guards against. */
function environmentOf(hostname: string): string {
  for (const tok of hostname.toLowerCase().split(/[^a-z0-9]+/)) {
    if (tok === 'prod' || tok === 'production' || tok === 'live') return 'production'
    if (tok === 'preprod' || tok === 'stag' || tok === 'stage' || tok === 'staging') return 'staging'
    if (tok === 'dev' || tok === 'develop' || tok === 'development') return 'development'
    if (tok === 'test' || tok === 'testing' || tok === 'qa' || tok === 'uat') return 'test'
  }
  return 'unknown'
}

/** Segment-aware glob match mirroring the server's `**` / `*` semantics, with
 * Windows separators folded onto `/` so a registry scope works too. */
function globMatches(pattern: string, path: string): boolean {
  if (!pattern) return false
  if (!pattern.includes('*') && !pattern.includes('?')) {
    return pattern.toLowerCase() === path.toLowerCase()
  }
  const fold = (s: string) => s.replace(/\\/g, '/')
  const segs = (s: string) => fold(s).split('/')
  const pat = segs(pattern)
  const parts = segs(path)

  const matchSeg = (p: string, s: string): boolean => {
    if (!p.includes('*') && !p.includes('?')) return p.toLowerCase() === s.toLowerCase()
    let pi = 0
    let si = 0
    let star = -1
    let mark = 0
    while (si < s.length) {
      if (pi < p.length && (p[pi] === '?' || p[pi].toLowerCase() === s[si].toLowerCase())) {
        pi++
        si++
      } else if (pi < p.length && p[pi] === '*') {
        star = pi
        mark = si
        pi++
      } else if (star >= 0) {
        pi = star + 1
        mark++
        si = mark
      } else {
        return false
      }
    }
    while (pi < p.length && p[pi] === '*') pi++
    return pi === p.length
  }

  const walk = (pi: number, si: number): boolean => {
    if (pi === pat.length) return si === parts.length
    if (pat[pi] === '**') {
      for (let i = si; i <= parts.length; i++) {
        if (walk(pi + 1, i)) return true
      }
      return false
    }
    if (si === parts.length || !matchSeg(pat[pi], parts[si])) return false
    return walk(pi + 1, si + 1)
  }

  return walk(0, 0)
}

/* ------------------------------------------------------------------ */
/* Pluggable AI provider gateway                                      */
/* ------------------------------------------------------------------ */

/**
 * Seeded gateway configuration matching the server's `ai.DefaultSettings` plus
 * the hub's derived fields (effective endpoint/model, credential presence), so
 * the AI card renders a complete, realistic form when the API is unreachable.
 *
 * The default is the deterministic engine, enabled: that is the only honest
 * default for a product that must work air-gapped, and it mirrors exactly what
 * a fresh deployment stores so a preview is indistinguishable from a real one.
 */
export const FALLBACK_AI_SETTINGS: AISettingsResponse = {
  provider: 'deterministic',
  endpoint: '',
  model: '',
  api_version: '',
  enabled: true,
  temperature: 0.1,
  max_tokens: 700,
  timeout_seconds: 20,
  last_test_ok: false,
  last_test_at: hoursAgo(0, 3),
  providers: ['deterministic', 'ollama', 'azure_openai', 'openai', 'anthropic'],
  api_key_set: false,
  needs_network: false,
  effective_endpoint: 'No network calls — derived from the event locally',
  effective_model: 'heuristic-remediation-v1',
}
