# Security Policy

StateTrack is a change-intelligence and audit platform: it observes
configuration, identity and service state across a fleet, and its output is used
as a compliance record. A security defect here is therefore serious in two
directions — it can expose the environment it watches, and it can undermine the
integrity of the trail it produces. We take both seriously.

---

## Reporting a vulnerability

**Please do not open a public GitHub issue, discussion or pull request for a
security vulnerability.** A public report tells an attacker what to look for
before a fix exists.

Report privately by email to:

```
premtonx@gmail.com
```

If you prefer, request a private channel and we will open a private security
advisory on the repository to coordinate there.

Please include as much of the following as you can:

- A description of the issue and the impact you believe it has.
- The component and version affected (`statetrack-agent`, `statetrack-server`,
  `statetrack-mcp`, or the web console), and the commit or tag.
- Reproduction steps, or a proof of concept. A minimal reproduction is worth
  more than a long description.
- Any suggested remediation, if you have one.
- Whether you intend to disclose publicly, and on what timeline.

Do **not** include live credentials, customer data, or data from systems you do
not own or have written permission to test.

### What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement of your report | within 2 business days |
| Initial assessment and severity classification | within 5 business days |
| Fix or mitigation plan communicated | within 10 business days |
| Public disclosure | coordinated with you, after a fix ships |

We will credit you in the release notes and advisory unless you ask us not to.

---

## Scope

### In scope

- The agent (`agent/`), the server (`server/`), the MCP binaries
  (`server/cmd/statetrack-mcp`), the shared libraries (`pkg/`), the web console
  (`web/`), and the deployment manifests (`deploy/`).
- The security properties the design claims, in particular:
  - **Edge secret scrubbing** — a credential that reaches StateTrack storage,
    the API, an integration payload, an AI provider, an MCP client or an
    exported post-mortem in recoverable form is a vulnerability. See
    [§ Secret scrubber](README.md#7-secret-scrubber).
  - **Read-only observation** — a collector or discovery probe that can mutate
    the host, registry, service, cluster or file it observes is a vulnerability.
  - **Zero-secret guarantee for AI** — the analysis gateway must never receive
    or reconstruct a raw credential. See
    [§ AI provider gateway](README.md#11-ai-provider-gateway).
  - **Authentication and authorization** — bypassing RBAC, a scope check
    (`read:summary`, `read:annotations`, `read:mcp`, `admin:write`), org scoping,
    session signing, or the audit trail is a vulnerability.
  - **Credential storage** — a stored password, API key or enrollment token that
    can be recovered in usable form from the database is a vulnerability.
- Elevation of privilege, authentication bypass, remote code execution, SQL or
  command injection, SSRF, path traversal, deserialization issues, and
  information disclosure.

### Out of scope

- Findings that require a compromised host, a local administrator, or a
  malicious agent binary that has already been installed with root/system
  privileges. The agent is a privileged component by design; its trust boundary
  is documented in [§ Install an agent](README.md#2-install-an-agent).
- The bundled development stack (Postgres, SeaweedFS, Grafana) running with its
  default demo credentials (`admin`/`admin`, `statetrack`/`statetrack`). These
  are development-only and documented as such.
- `STATETRACK_DEMO_MODE`, `STATETRACK_AUTH_DISABLED` and
  `STATETRACK_DEV_AUTOLOGIN` when they are explicitly enabled. They are
  deliberate, loudly-named switches and are never appropriate for production;
  using them in production is a deployment misconfiguration, not a product
  vulnerability.
- Missing hardening headers or best-practice suggestions with no demonstrated
  impact.
- Denial of service achieved by exceeding documented resource limits (the
  agent's 200 MB spool, the change-storm breaker threshold) through legitimate
  configuration.
- Automated scanner output with no proof of exploitability.

---

## Hardening checklist for operators

The following are the settings a production deployment should set. They are
described in the [README](README.md#3-configuration-agentyaml--targeted-watchers).

- [ ] Set `STATETRACK_SESSION_SECRET` to a strong random value. Without it the
      server generates a per-boot key, so console sessions do not survive a
      restart and multiple replicas do not share sessions.
- [ ] Leave `STATETRACK_DEMO_MODE`, `STATETRACK_AUTH_DISABLED` and
      `STATETRACK_DEV_AUTOLOGIN` **unset**.
- [ ] Leave `STATETRACK_ALLOW_ANONYMOUS_DATASOURCE` unset outside demo mode.
- [ ] Replace the seeded demo users, API keys and enrollment tokens. They exist
      so a first run is not an empty shell and are created by migration
      `006_enterprise_security.sql`.
- [ ] Give every credential the **narrowest scope** it needs: a Checkmk/Zabbix
      poller needs `read:summary`, an MCP client needs `read:mcp`, a Grafana
      bridge needs `read:annotations`. Never hand a poller `admin:write`.
- [ ] Enforce TLS and mTLS for agent ingestion (`ca_file`/`cert_file`/`key_file`),
      and terminate TLS in front of the HTTP API.
- [ ] Review the Kubernetes RBAC in
      [`deploy/k8s/rbac.yaml`](deploy/k8s/rbac.yaml). The default is a
      cluster-wide read of ConfigMaps and **Secrets**; if that is not acceptable,
      switch to the commented namespace-scoped `Role` instead.
- [ ] Do not point the AI gateway at a provider that does not meet your
      data-handling requirements; the hub states the residency per provider.
      The built-in offline heuristics transmit nothing.
- [ ] Export the control-plane audit trail to your SIEM, and alert on
      `apikey.created`, `sso.updated` and `agent.revoked`.

---

## What the product already guarantees

These are properties the code is written to preserve. A change that weakens one
of them is a defect, even if it is not otherwise exploitable.

- **Secrets never leave the host in cleartext.** The agent scrubs diffs at the
  edge with a per-host salted hash, replacing each value with
  `[REDACTED:sha256:<8 hex>]` while preserving line structure. The same secret
  maps to the same stub, so a reviewer can see *that* a credential changed
  without seeing the credential. See
  [§ Secret scrubber](README.md#7-secret-scrubber).
- **The AI gateway is a pure function of the already-scrubbed event.** There is
  no field for a raw credential and no code path that could fetch one, so the
  guarantee is structural rather than a promise.
- **The AI gateway always returns an answer.** A model that is down or
  mis-configured degrades to the deterministic engine, and the response names
  the engine that answered, so a heuristic is never mistaken for a model's
  judgement.
- **The MCP server is not a second data path.** The stdio proxy forwards to a
  `statetrack-server`, so every tool call runs through the same RBAC, org scoping
  and audit rules as the hosted API. A desktop client's config file never holds a
  database DSN.
- **Credentials are stored unrecoverable.** Passwords are PBKDF2-HMAC-SHA256;
  API keys and enrollment tokens are stored as hashes. The console-facing secret
  is shown exactly once and cannot be retrieved afterwards.
- **The audit trail is append-only by convention and by grant.** The application
  only ever inserts; the console only reads.
- **Observation is read-only.** Every discovery probe and the Kubernetes
  collector only issue reads; there is no `create`, `update`, `patch` or
  `delete` in the RBAC or the client.
- **The control-plane endpoints are authorization-checked per route.** Reads
  use a read guard, mutations go through RBAC *and* write the audit row on
  success, and the Grafana datasource endpoints are the only ones reachable by a
  scoped key (or anonymously in demo mode).

---

## Supported versions

StateTrack is under active development. Security fixes land on `main` and are
shipped in the next patch release of the current minor line.

| Version | Supported |
| --- | --- |
| `v0.1.x` | **Yes** — current release line, security fixes |
| `main` | **Yes** — development branch, fixes land here first |
| older tags | **No** — no backports before `v0.1.0` |

If you are running a build from before `v0.1.0`, upgrade before reporting: the
first public release includes the edge secret scrubber, per-route authorization
and the hashed credential storage this policy describes.

## Acknowledgements

We are glad to credit reporters who follow this policy, unless they prefer to
remain anonymous.
