/**
 * Provisioned integration assets and the copy/download affordances the
 * Integrations hub puts on every card.
 *
 * The files themselves live in `integrations/` at the repo root — beside the
 * READMEs that document them, which is where an operator looks for them in a
 * checkout. The dev server serves them under `/integration-assets/`, and
 * `dev.ps1 web-build` copies them into `web/public` for a production bundle, so
 * the path below is stable in both modes and there is only ever one source of
 * truth on disk.
 */
import { useQuery } from '@tanstack/react-query'

/** Where the console fetches the provisioned files from. */
export const ASSET_BASE = '/integration-assets'

export interface IntegrationAsset {
  /** Stable key, also the download filename stem. */
  id: string
  label: string
  /** Path relative to ASSET_BASE. */
  path: string
  /** Shown on the download button and in the copy confirmation. */
  filename: string
  /** One-line description of what the file is for. */
  description: string
  /** Language tag used for syntax-neutral code blocks. */
  language: 'json' | 'yaml' | 'python'
}

export const INTEGRATION_ASSETS: Record<string, IntegrationAsset> = {
  grafanaDashboard: {
    id: 'grafana-dashboard',
    label: 'Overview dashboard',
    path: '/grafana/statetrack-overview-dashboard.json',
    filename: 'statetrack-overview-dashboard.json',
    description: 'StateTrack – Change Impact: KPI grid, telemetry hero with L1/L2 flags, breakdown and recent-changes tables.',
    language: 'json',
  },
  prometheusAlerts: {
    id: 'prometheus-alerts',
    label: 'Alerting rules',
    path: '/prometheus/prometheus_alerts.yml',
    filename: 'prometheus_alerts.yml',
    description: 'Alert rules for agent offline, critical-change spikes and change storms.',
    language: 'yaml',
  },
  checkmkPlugin: {
    id: 'checkmk-plugin',
    label: 'Checkmk check plugin',
    path: '/checkmk/check_statetrack.py',
    filename: 'check_statetrack.py',
    description: 'Zero-dependency Python check supporting --mode local and --mode nagios.',
    language: 'python',
  },
  zabbixTemplate: {
    id: 'zabbix-template',
    label: 'Zabbix template',
    path: '/zabbix/zabbix_template_statetrack.yaml',
    filename: 'zabbix_template_statetrack.yaml',
    description: 'Zabbix 6.4/7.0 template: one HTTP Agent master item with dependent items.',
    language: 'yaml',
  },
}

export function assetUrl(asset: IntegrationAsset): string {
  return `${ASSET_BASE}${asset.path}`
}

/**
 * Fetches a provisioned asset's text. Cached indefinitely by TanStack Query:
 * these are build artifacts, not live data, so refetching them on every mount
 * would be pure noise.
 */
export function useIntegrationAsset(asset: IntegrationAsset | null) {
  return useQuery({
    queryKey: ['integration-asset', asset?.id ?? ''],
    enabled: !!asset,
    staleTime: Infinity,
    retry: 1,
    queryFn: async (): Promise<string> => {
      const res = await fetch(assetUrl(asset as IntegrationAsset))
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
      return res.text()
    },
  })
}

/**
 * Copies text to the clipboard. Re-exported from the shared helper so existing
 * Integrations call sites keep their import path while the console has exactly
 * one clipboard implementation.
 */
export { copyText } from './clipboard'

/** Triggers a browser download of `text` under `filename`. */
export function downloadText(filename: string, text: string, mime = 'text/plain'): void {
  const blob = new Blob([text], { type: `${mime};charset=utf-8` })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  // Revoke on the next tick: revoking synchronously can race the download in
  // some browsers, and leaking the object URL would hold the blob in memory.
  window.setTimeout(() => URL.revokeObjectURL(url), 0)
}
