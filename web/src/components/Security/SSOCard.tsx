import { useEffect, useState } from 'react'
import {
  BadgeCheck,
  ExternalLink,
  KeyRound,
  Loader2,
  Save,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react'
import Card, { CardHeader } from '../ui/Card'
import StatusPill from '../ui/StatusPill'
import { Button, Field, Select, TextInput, Toggle } from '../ui/controls'
import { useReadOnly } from '../../lib/authContext'
import { useSaveSSO, useSSOConfig } from '../../api/hooks'
import { ROLE_OPTIONS, SSO_PROVIDERS, type Role, type SSOProvider } from '../../types'
import { formatDateTime } from '../../lib/utils'

/**
 * Enterprise single sign-on (OIDC) configuration.
 *
 * The form is a faithful mirror of the server's write contract: the client
 * secret is write-only (the server returns only whether one is stored), so
 * leaving the field blank keeps the stored value rather than clearing it. That
 * matters because the alternative — round-tripping the secret to render it —
 * would mean the console holds a credential it never needs.
 */
export default function SSOCard() {
  const readOnly = useReadOnly()
  const { data, isLoading, isError } = useSSOConfig()
  const { mutate, isPending, saveError } = useSaveSSO()

  const [provider, setProvider] = useState<SSOProvider>('microsoft_entra')
  const [issuer, setIssuer] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [domain, setDomain] = useState('')
  const [autoRole, setAutoRole] = useState<Role>('auditor')
  const [requireSso, setRequireSso] = useState(false)
  const [enabled, setEnabled] = useState(false)

  // Seed the form from the server's copy whenever it changes, so a save
  // round-trip does not leave the form holding stale values.
  useEffect(() => {
    if (!data) return
    setProvider(data.provider)
    setIssuer(data.issuer_url ?? '')
    setClientId(data.client_id ?? '')
    setDomain(data.enforced_domain ?? '')
    setAutoRole(data.auto_provision_role ?? 'auditor')
    setRequireSso(data.require_sso)
    setEnabled(data.enabled)
    setClientSecret('')
  }, [data])

  const spec = SSO_PROVIDERS.find((p) => p.id === provider) ?? SSO_PROVIDERS[0]
  // Enabling or requiring SSO without an issuer + client id is what the server
  // rejects, so the button is disabled with the same reason rather than letting
  // the operator discover it from a 400.
  const incomplete = enabled && (!issuer.trim() || !clientId.trim())

  const handleSave = () => {
    mutate({
      provider,
      issuer_url: issuer.trim(),
      client_id: clientId.trim(),
      enforced_domain: domain.trim(),
      auto_provision_role: autoRole,
      require_sso: requireSso,
      enabled,
      // Omitted when blank: an absent field keeps the stored secret.
      ...(clientSecret.trim() ? { client_secret: clientSecret.trim() } : {}),
    })
    setClientSecret('')
  }

  return (
    <Card>
      <CardHeader
        title="Single Sign-On (OIDC)"
        subtitle="Federate console access with your identity provider"
        icon={<KeyRound className="h-4 w-4" />}
        actions={
          data?.enabled ? (
            <StatusPill tone="green" dot>
              Enabled
            </StatusPill>
          ) : (
            <StatusPill tone="slate" dot>
              Disabled
            </StatusPill>
          )
        }
      />

      <div className="mt-4 space-y-4">
        <Field label="Identity Provider" htmlFor="sso-provider">
          <Select
            id="sso-provider"
            value={provider}
            disabled={readOnly}
            onChange={(e) => setProvider(e.target.value as SSOProvider)}
          >
            {SSO_PROVIDERS.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </Select>
        </Field>

        <Field
          label="Issuer URL"
          hint={spec.issuerHint}
          htmlFor="sso-issuer"
        >
          <TextInput
            id="sso-issuer"
            value={issuer}
            disabled={readOnly}
            onChange={(e) => setIssuer(e.target.value)}
            placeholder={spec.issuerHint}
            className="font-mono text-xs"
          />
        </Field>

        <Field label="Client ID" htmlFor="sso-client-id">
          <TextInput
            id="sso-client-id"
            value={clientId}
            disabled={readOnly}
            onChange={(e) => setClientId(e.target.value)}
            placeholder="00000000-0000-0000-0000-000000000000"
            className="font-mono text-xs"
          />
        </Field>

        <Field
          label="Client Secret"
          hint={
            data?.client_secret_set
              ? 'A secret is stored. Leave blank to keep it; type a new value to rotate.'
              : 'Write-only: the server never returns a stored secret.'
          }
          htmlFor="sso-client-secret"
        >
          <div className="flex items-center gap-2">
            <TextInput
              id="sso-client-secret"
              type="password"
              value={clientSecret}
              disabled={readOnly}
              onChange={(e) => setClientSecret(e.target.value)}
              placeholder={data?.client_secret_set ? '•••••••••••• (stored)' : 'Enter client secret'}
              className="font-mono text-xs"
              wrapperClassName="flex-1"
            />
            {data?.client_secret_set ? (
              <StatusPill tone="green">
                <BadgeCheck className="h-3 w-3" /> Stored
              </StatusPill>
            ) : null}
          </div>
        </Field>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field
            label="Enforced Domain"
            hint="Optional: restrict sign-in to this email domain."
            htmlFor="sso-domain"
          >
            <TextInput
              id="sso-domain"
              value={domain}
              disabled={readOnly}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="acme.com"
              className="font-mono text-xs"
            />
          </Field>

          <Field
            label="Auto-provision Role"
            hint="Granted to a first-time SSO sign-in."
            htmlFor="sso-role"
          >
            <Select
              id="sso-role"
              value={autoRole}
              disabled={readOnly}
              onChange={(e) => setAutoRole(e.target.value as Role)}
            >
              {ROLE_OPTIONS.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.label}
                </option>
              ))}
            </Select>
          </Field>
        </div>

        <div className="divide-y divide-slate-100 border-t border-slate-100 pt-1">
          <Toggle
            checked={enabled}
            onChange={setEnabled}
            disabled={readOnly}
            label="Enable SSO sign-in"
            description="Offer the identity provider on the login screen."
          />
          <Toggle
            checked={requireSso}
            onChange={setRequireSso}
            disabled={readOnly}
            label="Require SSO"
            description="Disable local password sign-in for every user in the organization."
          />
        </div>

        {requireSso ? (
          <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
            <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>
              Requiring SSO turns off the password path. Confirm the issuer and client ID are
              correct before saving, or you will be locked out of this console.
            </span>
          </div>
        ) : null}

        {isError ? (
          <div className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
            <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>Could not load the SSO configuration.</span>
          </div>
        ) : null}

        <div className="flex flex-wrap items-center gap-3 border-t border-slate-100 pt-4">
          <Button
            variant="primary"
            disabled={readOnly || isPending || isLoading || incomplete}
            onClick={handleSave}
            icon={isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
          >
            {isPending ? 'Saving…' : 'Save SSO configuration'}
          </Button>
          {incomplete ? (
            <span className="text-xs text-amber-700">Issuer URL and Client ID are required to enable SSO.</span>
          ) : saveError ? (
            <span className="text-xs text-red-700">{saveError}</span>
          ) : data?.updated_at ? (
            <span className="flex items-center gap-1.5 text-xs text-slate-500">
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-600" />
              Last updated {formatDateTime(data.updated_at)}
            </span>
          ) : (
            <span className="flex items-center gap-1.5 text-xs text-slate-500">
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-600" />
              Client secret stored encrypted at rest
            </span>
          )}
        </div>

        <p className="flex items-center gap-1.5 text-[11px] text-slate-400">
          <ExternalLink className="h-3 w-3" />
          Discovery is read from the issuer's <span className="font-mono">/.well-known/openid-configuration</span>.
        </p>
      </div>
    </Card>
  )
}
