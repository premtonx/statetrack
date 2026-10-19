import { useState, type FormEvent } from 'react'
import { KeyRound, Loader2, Lock, ShieldCheck } from 'lucide-react'
import { Button, Field, TextInput } from '../ui/controls'
import { useLogin } from '../../api/hooks'
import { cn } from '../../lib/utils'

/**
 * Sign-in gate for a deployment that is not in demo mode.
 *
 * Production has no auto-login (that switch is `STATETRACK_DEV_AUTOLOGIN`,
 * defaulted from demo mode), so without this screen a fresh container would show
 * a console where every panel answered 401 and every button was disabled. The
 * screen is the difference between "authenticated by design" and "unusable".
 *
 * The second factor is a second step rather than an always-visible field: the
 * server answers 428 with `totp_required` only after the password checks out, so
 * revealing the field then is both accurate and avoids telling an anonymous
 * visitor which accounts have 2FA.
 */
export default function LoginPage({ sso }: { sso?: { enabled: boolean; provider: string } }) {
  const login = useLogin()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [needsCode, setNeedsCode] = useState(false)

  const error = login.error instanceof Error ? login.error.message : ''
  // The 428 from /auth/login is the only path that asks for a code.
  const totpPrompt = needsCode || /two-factor/i.test(error)

  function submit(e: FormEvent) {
    e.preventDefault()
    login.mutate(
      { email: email.trim(), password, totpCode: totpPrompt ? code.trim() : undefined },
      {
        onError: (err) => {
          if (/two-factor/i.test(err instanceof Error ? err.message : '')) setNeedsCode(true)
        },
      },
    )
  }

  return (
    <div className="flex min-h-full items-center justify-center bg-slate-50 px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-2 text-center">
          <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-blue-600 text-white shadow-sm">
            <ShieldCheck className="h-5 w-5" />
          </span>
          <h1 className="text-lg font-semibold text-slate-900">Sign in to StateTrack</h1>
          <p className="text-xs text-slate-500">
            Infrastructure change intelligence for this fleet.
          </p>
        </div>

        <form
          onSubmit={submit}
          className="space-y-4 rounded-xl border border-slate-200/80 bg-white p-5 shadow-xs"
        >
          <Field label="Email" htmlFor="login-email">
            <TextInput
              id="login-email"
              type="email"
              autoComplete="username"
              autoFocus
              required
              placeholder="admin@localhost"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </Field>

          <Field label="Password" htmlFor="login-password">
            <TextInput
              id="login-password"
              type="password"
              autoComplete="current-password"
              required
              icon={<Lock className="h-3.5 w-3.5" />}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </Field>

          {totpPrompt ? (
            <Field
              label="Two-factor code"
              htmlFor="login-totp"
              hint="6-digit code from your authenticator app."
            >
              <TextInput
                id="login-totp"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                required
                icon={<KeyRound className="h-3.5 w-3.5" />}
                className="font-mono tracking-[0.3em]"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
              />
            </Field>
          ) : null}

          {error ? (
            <p
              role="alert"
              className={cn(
                'rounded-lg border px-3 py-2 text-xs leading-5',
                'border-red-200 bg-red-50 text-red-700',
              )}
            >
              {error}
            </p>
          ) : null}

          <Button
            type="submit"
            variant="primary"
            className="w-full"
            disabled={login.isPending}
            icon={
              login.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Lock className="h-3.5 w-3.5" />
              )
            }
          >
            {login.isPending ? 'Signing in…' : 'Sign in'}
          </Button>

          {sso?.enabled ? (
            <p className="text-center text-xs text-slate-500">
              Single sign-on is configured for this organization ({sso.provider}). If password
              sign-in is disabled, continue with your identity provider.
            </p>
          ) : null}
        </form>

        <p className="mt-4 px-1 text-center text-[11px] leading-5 text-slate-400">
          A fresh install creates its first administrator on boot and prints the generated password
          once: <code className="font-mono">docker compose logs statetrack | grep administrator</code>
        </p>
      </div>
    </div>
  )
}
