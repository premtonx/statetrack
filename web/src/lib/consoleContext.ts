import { createContext, useContext } from 'react'
import type { LiveStatus } from '../api/hooks'
import type { EventTab, View } from './router'
import type { Host } from '../types'

/**
 * Cross-page console state: the universal search query, the live WebSocket
 * status, the host inventory behind the KPI counts, and inspector navigation.
 *
 * The context object and its hook live here (a plain, component-free module)
 * so that the provider component in `components/Layout/ConsoleProvider.tsx`
 * has an unambiguous React Fast Refresh boundary.
 */
export interface ConsoleContextValue {
  /** Debounced universal search text (consumed by list pages). */
  search: string
  liveStatus: LiveStatus
  /**
   * Opens the Monaco inspector drawer for an event, keeping the current page.
   * Pass `tab` to land directly on a pane (e.g. 'diff' for a `</> Diff` action).
   */
  openEvent: (id: string, view?: View, tab?: EventTab) => void
  closeEvent: () => void
  view: View
  hosts: Host[]
  hostsLoading: boolean
  onlineCount: number
  /** Selected host filter shared by the timeline and dashboard. */
  hostId: string
  setHostId: (id: string) => void
  hostName: (id: string) => string
  /**
   * Navigate to a page. Pass `{ settingsTab }` to land on a specific Settings
   * tab (the onboarding empty states use this to open agent setup directly).
   */
  goTo: (view: View, options?: { settingsTab?: 'general' | 'security' | 'agents' | 'audit' }) => void
}

export const ConsoleContext = createContext<ConsoleContextValue | null>(null)

export function useConsole(): ConsoleContextValue {
  const ctx = useContext(ConsoleContext)
  if (!ctx) {
    throw new Error('useConsole must be used inside <ConsoleProvider>')
  }
  return ctx
}
