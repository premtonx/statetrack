import { useState } from 'react'
import { CheckCircle2, Loader2, ShieldCheck, ShieldOff, Smartphone, TriangleAlert, XCircle } from 'lucide-react'
import Card, { CardHeader } from '../ui/Card'
import StatusPill from '../ui/StatusPill'
import Modal from '../ui/Modal'
import QRCode from '../ui/QRCode'
import { Button, Field, TextInput } from '../ui/controls'
import { copyText } from '../../lib/clipboard'
import { useAuth, useReadOnly } from '../../lib/authContext'
import { useSetupTOTP, useVerifyTOTP } from '../../api/hooks'

/**
 * Two-factor authentication (TOTP) for the signed-in console identity.
 *
 * Enrollment is a two-step handshake because the alternative locks people out:
 * `setup` stores a candidate secret but leaves the factor disabled, and only a
 * verified 6-digit code flips it on. Disabling requires a valid current code for
 * the same reason — a stolen session must not be able to remove the factor.
 */
export default function TwoFactorCard() {
  const auth = useAuth()
  const readOnly = useReadOnly()
  const setup = useSetupTOTP()
  const verify = useVerifyTOTP()

  const [modal, setModal] = useState<'enroll' | 'disable' | null>(null)
  const [code, setCode] = useState('')
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const user = auth.user
  const enabled = user?.totp_enabled ?? false
  const enrollment = setup.data ?? null

  const closeModal = () => {
    setModal(null)
    setCode('')
    setError(null)
  }

  const openDisable = () => {
    setCode('')
    setError(null)
    setModal('disable')
  }

  const startEnrollment = () => {
    setError(null)
    setup.mutate(undefined, {
      onSuccess: () => {
        setCode('')
        setError(null)
        setModal('enroll')
      },
      onError: (err: unknown) =>
        setError(err instanceof Error ? err.message : 'Could not start enrollment'),
    })
  }

  const submitCode = (disable: boolean) => {
    setError(null)
    verify.mutate(
      { code: code.trim(), disable },
      {
        onSuccess: () => closeModal(),
        onError: (err: unknown) =>
          setError(err instanceof Error ? err.message : 'That code was not accepted'),
      },
    )
  }

  const codeValid = /^\d{6}$/.test(code.trim())

  const CodeInput = ({ id }: { id: string }) => (
    <TextInput
      id={id}
      value={code}
      autoFocus
      onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
      placeholder="000000"
      inputMode="numeric"
      autoComplete="one-time-code"
      className="w-40 text-center font-mono text-lg tracking-[0.4em]"
    />
  )

  return (
    <>
      <Card>
        <CardHeader
          title="Two-Factor Authentication (TOTP)"
          subtitle="Protect console access with an authenticator app"
          icon={<Smartphone className="h-4 w-4" />}
          actions={
            enabled ? (
              <StatusPill tone="green" dot>
                2FA Enabled
              </StatusPill>
            ) : (
              <StatusPill tone="amber" dot>
                2FA Off
              </StatusPill>
            )
          }
        />

        <div className="mt-4 space-y-4">
          <div className="rounded-lg border border-slate-200 bg-slate-50/60 px-3 py-2.5">
            <p className="text-xs text-slate-600">
              {enabled
                ? 'A one-time code from your authenticator app is required at every sign-in.'
                : 'Add a second factor. Standard RFC 6238 TOTP — works with Google Authenticator, 1Password, Authy and Microsoft Authenticator.'}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {enabled ? (
              <Button
                disabled={readOnly}
                onClick={openDisable}
                icon={<ShieldOff className="h-4 w-4" />}
              >
                Disable 2FA
              </Button>
            ) : (
              <Button
                variant="primary"
                disabled={readOnly || setup.isPending}
                onClick={startEnrollment}
                icon={
                  setup.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <ShieldCheck className="h-4 w-4" />
                  )
                }
              >
                {setup.isPending ? 'Preparing…' : 'Enable 2FA'}
              </Button>
            )}
            {user?.auth_provider === 'oidc' ? (
              <span className="text-xs text-slate-500">
                This account signs in through SSO; 2FA is enforced by the identity provider.
              </span>
            ) : null}
          </div>

          {error && !modal ? (
            <div className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
              <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>{error}</span>
            </div>
          ) : null}
        </div>
      </Card>

      {/* Enrollment: QR + manual key, then the verification code. */}
      <Modal
        open={modal === 'enroll'}
        onClose={closeModal}
        size="md"
        title="Set up two-factor authentication"
        description="Scan the code with your authenticator app, then enter the 6-digit code it shows."
      >
        <div className="space-y-4">
          <div className="flex flex-col items-center gap-3 sm:flex-row sm:items-start">
            <div className="shrink-0 rounded-lg border border-slate-200 bg-white p-2">
              {enrollment?.otpauth_uri ? (
                <QRCode value={enrollment.otpauth_uri} size={148} />
              ) : (
                <div className="flex h-[148px] w-[148px] items-center justify-center rounded bg-slate-50 text-xs text-slate-400">
                  Generating…
                </div>
              )}
            </div>
            <div className="min-w-0 flex-1 space-y-2">
              <p className="text-xs text-slate-600">Can't scan? Enter this setup key manually:</p>
              <div className="flex items-center gap-2">
                <TextInput
                  readOnly
                  value={enrollment?.secret ?? ''}
                  className="font-mono text-xs tracking-wide"
                  wrapperClassName="flex-1"
                  aria-label="TOTP setup key"
                />
                <Button
                  onClick={async () => {
                    if (!enrollment?.secret) return
                    setCopied(await copyText(enrollment.secret))
                    window.setTimeout(() => setCopied(false), 1500)
                  }}
                  disabled={!enrollment?.secret}
                >
                  {copied ? 'Copied' : 'Copy'}
                </Button>
              </div>
              <p className="text-[11px] text-slate-400">
                {enrollment
                  ? `${enrollment.issuer} · ${enrollment.algorithm} · ${enrollment.digits} digits · ${enrollment.period}s period`
                  : 'Preparing enrollment…'}
              </p>
            </div>
          </div>

          <Field label="Verification code" htmlFor="totp-enroll-code">
            <CodeInput id="totp-enroll-code" />
          </Field>

          {error ? (
            <div className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
              <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>{error}</span>
            </div>
          ) : (
            <div className="flex items-start gap-2 rounded-lg border border-slate-200 bg-slate-50/60 px-3 py-2 text-xs text-slate-500">
              <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>
                The factor is only activated once a code is verified, so you cannot lock yourself out.
              </span>
            </div>
          )}
        </div>

        <div className="mt-4 flex items-center justify-end gap-2 border-t border-slate-200 pt-3">
          <Button onClick={closeModal}>Cancel</Button>
          <Button
            variant="primary"
            disabled={!codeValid || verify.isPending}
            onClick={() => submitCode(false)}
            icon={
              verify.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <CheckCircle2 className="h-4 w-4" />
              )
            }
          >
            {verify.isPending ? 'Verifying…' : 'Verify & enable'}
          </Button>
        </div>
      </Modal>

      {/* Disabling requires a current code, so the modal collects one. */}
      <Modal
        open={modal === 'disable'}
        onClose={closeModal}
        size="sm"
        title="Disable two-factor authentication"
        description="Enter a current 6-digit code to confirm. Without it, a stolen session could remove your second factor."
      >
        <div className="space-y-3">
          <Field label="Current code" htmlFor="totp-disable-code">
            <CodeInput id="totp-disable-code" />
          </Field>
          {error ? (
            <div className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
              <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>{error}</span>
            </div>
          ) : null}
        </div>

        <div className="mt-4 flex items-center justify-end gap-2 border-t border-slate-200 pt-3">
          <Button onClick={closeModal}>Cancel</Button>
          <Button
            variant="danger"
            disabled={!codeValid || verify.isPending}
            onClick={() => submitCode(true)}
            icon={verify.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : undefined}
          >
            {verify.isPending ? 'Disabling…' : 'Disable 2FA'}
          </Button>
        </div>
      </Modal>
    </>
  )
}
