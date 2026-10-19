/**
 * The console's authorization posture, derived once from `GET /api/v1/auth/me`
 * and shared by every surface that renders a mutating control.
 *
 * Why a context rather than calling `useAuthMe()` at each control: the read-only
 * decision has to be identical in the header banner, the Settings forms, and the
 * one-off buttons scattered across pages. Re-deriving it per component would let
 * two of them disagree — a button that looks enabled while the server rejects it
 * is exactly the confusion this suite exists to remove.
 *
 * `canWrite` is the *server's* predicate (`AuthUser.can_write`), not a
 * re-implementation of it in TypeScript, so the UI cannot offer an affordance
 * the API would 403.
 */
import { createContext, useContext, useMemo, type ReactNode } from 'react'
import { useAuthMe, useSwitchRole, ROLE_LABELS } from '../api/hooks'
import type { AuthMeResponse, AuthUser, Role } from '../types'

export interface AuthState {
  /** The authenticated principal, or null while loading / when signed out. */
  user: AuthUser | null
  /** Full /auth/me payload (SSO posture, scopes, demo mode). */
  me: AuthMeResponse | null
  isLoading: boolean
  isError: boolean
  /** True when the server would accept a mutating request from this principal. */
  canWrite: boolean
  /** True while acting as the read-only compliance auditor. */
  readOnly: boolean
  /** The granted role, which differs from `user.role` while demo-acting as less. */
  realRole: Role | null
  /** True when acting in a lesser role than the grant, so a banner is warranted. */
  actingAsLesserRole: boolean
  /** True when the console is in dev/demo mode with an automatic session. */
  demoMode: boolean
  devAutoLogin: boolean
  /** Switches the effective role (demo affordance; no-op outside demo mode). */
  setRole: (role: Role) => void
  isSwitchingRole: boolean
  roleLabel: (role: Role | null | undefined) => string
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const me = useAuthMe()
  const switchRole = useSwitchRole()

  const value = useMemo<AuthState>(() => {
    const data = me.data ?? null
    const user = data?.authenticated ? data.user : null
    const realRole = (data?.real_role as Role | undefined) ?? user?.role ?? null
    return {
      user,
      me: data,
      isLoading: me.isLoading,
      isError: me.isError,
      // Absent data is not permission: while the posture is unknown the console
      // renders as read-only, which is the safe default and avoids a flash of
      // enabled buttons on load.
      canWrite: user?.can_write ?? false,
      readOnly: data ? data.read_only : true,
      realRole,
      actingAsLesserRole: Boolean(
        data?.authenticated && realRole && user && realRole !== user.role,
      ),
      demoMode: data?.demo_mode ?? false,
      devAutoLogin: data?.dev_autologin ?? false,
      setRole: (role: Role) => switchRole.mutate(role),
      isSwitchingRole: switchRole.isPending,
      roleLabel: (role) => (role ? ROLE_LABELS[role] ?? role : ''),
    }
  }, [me.data, me.isLoading, me.isError, switchRole])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used inside <AuthProvider>')
  }
  return ctx
}

/**
 * Convenience flag for mutating controls: `const readOnly = useReadOnly()`.
 * Named for the question the call site is actually asking.
 */
export function useReadOnly(): boolean {
  return !useAuth().canWrite
}
