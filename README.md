# Master Security Agent

Master Security Agent is a discovery-first cybersecurity research agent. Version 0.4 turns the v0.3 prototype into a modular, evidence-driven assessment engine for explicitly supplied HTTP(S) targets.

## v0.4 capabilities

- Safe Windows OS and browser metadata discovery
- DNS and HTTP(S) inspection
- Bounded GET requests with timeout, response-size, and redirect limits
- Redirect-chain capture
- TLS metadata observation where available
- Security-header observation for HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and X-Frame-Options
- Safe cookie-attribute observation without storing cookie names or values
- Public HTML form metadata inspection without storing field values
- Evidence-only authentication-surface analysis for login forms, OAuth/OIDC-like redirects, SAML-like redirects, and HTTP authentication challenges
- Deterministic module registry and fault-isolated scan engine
- Structured evidence, findings, module results, and scan sessions
- Interactive shell with the new `scan <url>` command
- JSON scan reports
- pytest regression suite and GitHub Actions test workflow

## Safety boundary

The default engine is observation-only. It does not collect or submit credentials, cookies, tokens, request bodies, or authentication requests. It does not perform password testing, password cracking, credential stuffing, login automation, token harvesting, exploitation, persistence, destructive actions, or address-range scanning.

Network inspection is limited to an explicitly supplied HTTP or HTTPS target and bounded unauthenticated GET observations. Authentication-related conclusions are evidence labels, not proof of an internal implementation.

Credential-compromise or active-exploitation experiments belong only in controlled systems that we own or are explicitly authorized to test.

## Install on Windows

```powershell
cd E:\masterkey-security-agent
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
pytest -q
```

## Run the shell

```powershell
python -m masterkey_agent.shell
```

Example:

```text
MK> scan https://example.com/
Scan session: <session-id>
Target: https://example.com/
Modules: 3
Evidence: <count>
Findings: <count>
Errors: 0
```

The built-in modules currently include:

```text
network_discovery
    ↓
auth_surface
security_controls
```

The network observation is collected once and provided to downstream modules. New modules can be registered without changing the engine's execution loop.

## JSON reports

After a scan, use:

```text
MK> report reports\example-scan.json
```

The report contains:

```json
{
  "agent_version": "0.4.0",
  "session": {},
  "target": {},
  "modules": [],
  "evidence": [],
  "findings": [],
  "errors": [],
  "warnings": []
}
```

Sensitive values such as cookie values and public form `value=` attributes are not retained by the observation models.

## Development workflow

```powershell
git pull origin main
pytest -q
python -m masterkey_agent.shell
```

For local changes:

```powershell
git status
git add .
git commit -m "Describe the change"
git push origin main
```

The repository also contains the approved v0.4 design and implementation plan under `docs/superpowers/`.

## Future direction

The stable scan-session, module, evidence, and finding interfaces are intended to support later authorized lab-tool adapters, richer platform discovery, packaging, and eventually a portable/bootable USB environment. Those future layers are not part of v0.4 yet.
