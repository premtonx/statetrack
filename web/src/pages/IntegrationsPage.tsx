import { useState } from 'react'
import { Activity, Bot, Server, Users } from 'lucide-react'
import PageHeader from '../components/ui/PageHeader'
import Card from '../components/ui/Card'
import StatusPill from '../components/ui/StatusPill'
import { Tabs, type TabItem } from '../components/ui/controls'
import ObservabilityTab from '../components/Integrations/ObservabilityTab'
import InfrastructureTab from '../components/Integrations/InfrastructureTab'
import ChatOpsTab from '../components/Integrations/ChatOpsTab'
import ITSMTab from '../components/Integrations/ITSMTab'
import AIMcpTab from '../components/Integrations/AIMcpTab'
import {
  useAIIntegration,
  useGrafanaIntegration,
  useHostList,
  useITSMIntegration,
  useWebhookChannels,
} from '../api/hooks'

type HubTab = 'observability' | 'infrastructure' | 'chatops' | 'ai'

const TABS: TabItem<HubTab>[] = [
  { id: 'observability', label: 'Observability' },
  { id: 'infrastructure', label: 'Infrastructure Monitors' },
  { id: 'chatops', label: 'ChatOps, Paging & SIEM' },
  { id: 'ai', label: 'AI & MCP Server' },
]

/**
 * The Enterprise Integrations Hub.
 *
 * One page owns every external connection: Grafana & Prometheus (push/pull),
 * Checkmk & Zabbix (poller), the ChatOps/SIEM channels plus the ITSM
 * change-ticket bridge, and the AI provider gateway with its MCP server.
 * Previously Grafana lived on its own page and Settings carried placeholder
 * duplicates of the rest, which meant an operator had to guess where a given
 * integration lived.
 *
 * The header summarises live state per category so the answer to "is anything
 * misconfigured?" is visible without opening a tab — the tabs are for
 * configuring, not for discovering a problem. Nothing here is an AI widget:
 * the analyzer is reached from the Inspector drawer, and the MCP server is for
 * external clients, which is what keeps the main dashboard clean.
 */
export default function IntegrationsPage() {
  const [tab, setTab] = useState<HubTab>('observability')

  // One cheap query per category, reused by the header summary. These are the
  // same queries the tabs run, so they are served from the cache rather than
  // costing an extra request.
  const grafana = useGrafanaIntegration()
  const channels = useWebhookChannels()
  const itsm = useITSMIntegration()
  const ai = useAIIntegration()
  const { total, online } = useHostList()

  const reachable = grafana.testResult?.ok ?? grafana.settings?.last_test_ok ?? false
  const enabledChannels = (channels.channels ?? []).filter((c) => c.enabled).length
  const failing = (channels.deliveries ?? []).some((d) => !d.success)
  // The ITSM badge reports the control's output, not its configuration: an
  // operator glancing at the hub should see whether anything is being flagged,
  // which is the only question that matters about this integration.
  const itsmSyncs = [itsm.settings?.jira, itsm.settings?.servicenow].filter(
    (c) => c?.enabled,
  ).length
  const unapproved = itsm.settings?.unapproved_count ?? 0
  // The AI badge names the engine and whether it is live; a model that is down
  // silently degrades to the offline heuristics, so "which engine is active" is
  // the fact worth surfacing at the hub level.
  const aiEngine = ai.settings?.provider ?? 'deterministic'
  const aiVerified = ai.testResult?.ok ?? ai.settings?.last_test_ok ?? false

  return (
    <div className="h-full overflow-y-auto">
      <PageHeader
        title="Integrations"
        subtitle="Connect StateTrack to your observability stack, monitoring pollers, ChatOps tooling, change management and AI providers."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <StatusPill tone={reachable ? 'green' : 'slate'} dot>
              Grafana {reachable ? 'connected' : 'not verified'}
            </StatusPill>
            <StatusPill tone={online > 0 ? 'green' : 'slate'} dot>
              {online}/{total} agents
            </StatusPill>
            <StatusPill tone={enabledChannels > 0 ? 'blue' : 'slate'} dot>
              {enabledChannels} channel{enabledChannels === 1 ? '' : 's'} on
            </StatusPill>
            <StatusPill tone={unapproved > 0 ? 'red' : itsmSyncs > 0 ? 'green' : 'slate'} dot>
              {unapproved > 0
                ? `${unapproved} unapproved change${unapproved === 1 ? '' : 's'}`
                : itsmSyncs > 0
                  ? 'Change control active'
                  : 'Change control off'}
            </StatusPill>
            <StatusPill
              tone={aiEngine === 'deterministic' ? 'slate' : aiVerified ? 'purple' : 'amber'}
              dot
            >
              {aiEngine === 'deterministic'
                ? 'AI: offline heuristics'
                : `AI: ${aiEngine}${aiVerified ? '' : ' (unverified)'}`}
            </StatusPill>
            {failing ? (
              <StatusPill tone="red" dot>
                Delivery failing
              </StatusPill>
            ) : null}
          </div>
        }
      />

      <div className="space-y-5 p-4 sm:p-6">
        <Card flush>
          <div className="px-4 pt-3">
            <Tabs tabs={TABS} active={tab} onChange={setTab} />
          </div>
          <div className="px-4 pb-1 pt-3">
            <p className="flex items-center gap-2 text-xs text-slate-500">
              {tab === 'observability' ? (
                <>
                  <Activity className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                  Push change annotations into Grafana and let Prometheus scrape StateTrack's
                  metrics endpoint.
                </>
              ) : tab === 'infrastructure' ? (
                <>
                  <Server className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                  Poll StateTrack from Checkmk or Zabbix using the unified host summary endpoint.
                </>
              ) : tab === 'chatops' ? (
                <>
                  <Users className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                  Deliver changes to your team's channels, forward them to your SIEM, and correlate
                  them against approved ITIL change requests.
                </>
              ) : (
                <>
                  <Bot className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                  Choose the engine behind the Inspector's Analyze &amp; Rollback, and connect
                  Cursor or Claude Desktop to the MCP server.
                </>
              )}
            </p>
          </div>
        </Card>

        {tab === 'observability' ? <ObservabilityTab /> : null}
        {tab === 'infrastructure' ? <InfrastructureTab /> : null}
        {tab === 'chatops' ? (
          <div className="space-y-6">
            <ChatOpsTab />
            {/* The ITSM bridge lives with the other outbound integrations rather
                than on a tab of its own: it is configured once, like the rest of
                this page, and its verdicts were already the hub header's job to
                surface. */}
            <div className="border-t border-slate-200 pt-5">
              <ITSMTab />
            </div>
          </div>
        ) : null}
        {tab === 'ai' ? <AIMcpTab /> : null}
      </div>
    </div>
  )
}
