import { useCallback, useMemo, type ReactNode } from 'react'
import { useHostList, useTimelineLive } from '../../api/hooks'
import { navigate, eventUrl, viewUrl, settingsUrl, type EventTab, type View } from '../../lib/router'
import { ConsoleContext, type ConsoleContextValue } from '../../lib/consoleContext'

/**
 * Owns the cross-page console state: the universal search query, the live
 * WebSocket status, the host inventory used by KPI counts, and inspector
 * drawer navigation. Kept in its own module so Fast Refresh treats it as a
 * single, well-defined component boundary.
 */
export default function ConsoleProvider({
  search,
  view,
  hostId,
  setHostId,
  children,
}: {
  search: string
  view: View
  hostId: string
  setHostId: (id: string) => void
  children: ReactNode
}) {
  const liveStatus = useTimelineLive()
  const { hosts, online: onlineCount, isLoading } = useHostList()

  const openEvent = useCallback(
    (id: string, from?: View, tab?: EventTab) => navigate(eventUrl(id, from ?? view, tab)),
    [view],
  )
  const closeEvent = useCallback(() => navigate(viewUrl(view)), [view])

  /**
   * Page navigation. A Settings deep link carries its tab, so an empty-state CTA
   * can open the Agents tab directly instead of dropping the operator on the
   * General form to hunt for the install command.
   */
  const goTo = useCallback(
    (v: View, options?: { settingsTab?: 'general' | 'security' | 'agents' | 'audit' }) => {
      navigate(v === 'settings' && options?.settingsTab ? settingsUrl(options.settingsTab) : viewUrl(v))
    },
    [],
  )

  const hostName = useCallback(
    (id: string) => hosts.find((h) => h.id === id)?.hostname ?? id.slice(0, 8),
    [hosts],
  )

  const value = useMemo<ConsoleContextValue>(
    () => ({
      search,
      liveStatus,
      openEvent,
      closeEvent,
      view,
      hosts,
      hostsLoading: isLoading,
      onlineCount,
      hostId,
      setHostId,
      hostName,
      goTo,
    }),
    [
      search,
      liveStatus,
      openEvent,
      closeEvent,
      view,
      hosts,
      isLoading,
      onlineCount,
      hostId,
      setHostId,
      hostName,
      goTo,
    ],
  )

  return <ConsoleContext.Provider value={value}>{children}</ConsoleContext.Provider>
}
