import {
  Activity,
  BarChart3,
  GitCompare,
  LayoutDashboard,
  Plug,
  Server,
  Settings as SettingsIcon,
} from 'lucide-react'
import type { View } from './router'

export interface NavItem {
  id: View
  label: string
  icon: typeof LayoutDashboard
}

/**
 * The seven-page console navigation, shared by the sidebar drawer and the
 * top bar breadcrumb. Kept in a component-free module so the sidebar keeps a
 * clean React Fast Refresh boundary.
 */
export const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'timeline', label: 'Timeline', icon: Activity },
  { id: 'servers', label: 'Servers', icon: Server },
  { id: 'drift', label: 'Drift Matrix', icon: GitCompare },
  { id: 'integrations', label: 'Integrations', icon: Plug },
  { id: 'reports', label: 'Reports', icon: BarChart3 },
  { id: 'settings', label: 'Settings', icon: SettingsIcon },
]
