# Master Security Agent

Master Security Agent is a discovery-first cybersecurity research agent. Version 0.5 extends the modular, evidence-driven assessment engine for explicitly supplied HTTP(S) targets with richer TLS, public HTML, authentication-surface, security-control, and reporting intelligence.

## v0.5 capabilities

- Safe Windows OS and browser metadata discovery
- DNS and HTTP(S) inspection
- Bounded unauthenticated GET requests with timeout, response-size, redirect, and policy limits
- Redirect-chain and transport metadata capture
- TLS/certificate subject, issuer, SAN, validity, protocol, and cipher observations
- Security-header observations for HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Frame-Options, and CSP frame-ancestors
- Cookie-attribute observation without storing cookie names or values
- Public HTML title, safe meta, form-field metadata, public-link, script, and stylesheet inspection
- Authentication-surface correlation across forms, titles, public links, redirects, and `WWW-Authenticate`
- Evidence-backed descriptive findings with confidence and remediation guidance
- Deterministic evidence de-duplication helpers and serialized URL redaction
- Interactive shell plus non-interactive `masterkey-agent scan`
- JSON and Markdown scan reports
- Fault-isolated module execution and Python 3.11–3.14 CI

## Safety boundary

The default engine is observation-only. It does not collect or submit credentials, cookies, tokens, request bodies, or authentication requests. It does not perform password testing, password cracking, credential stuffing, login automation, token harvesting, exploitation, persistence, destructive actions, endpoint brute force, or address-range scanning.

Network inspection is limited to an explicitly supplied HTTP or HTTPS target and bounded unauthenticated GET observations. Public HTML links and forms are metadata only; discovered links are never fetched automatically and forms are never submitted. Authentication-related conclusions are evidence labels, not proof of an internal implementation.

Credential-compromise or active-exploitation experiments belong only in controlled systems that we own or are explicitly authorized to test.

## Install on Windows

```powershell
cd E:\masterkey-security-agent
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
pytest -q
```

## Run the interactive shell

```powershell
python -m masterkey_agent.shell
```

Example:

```text
MK> scan https://example.com/
Scan session: <session-id>
Target: https://example.com/
Modules: 4
Evidence: <count>
Findings: <count>
Errors: 0
```

## Run a non-interactive safe scan

```powershell
masterkey-agent scan https://example.com/ --profile safe --output reports\example-scan.json
masterkey-agent scan https://example.com/ --profile safe --output reports\example-scan.md
```

The equivalent module invocation is:

```powershell
python -m masterkey_agent scan https://example.com/ --profile safe --output reports\example-scan.json
```

`safe` is the only v0.5 scan profile. The CLI intentionally does not expose credential, cookie, request-body, password, brute-force, or exploitation options.

## Reports

JSON and Markdown reports are generated from the same scan session. Markdown includes target, policy, module state, evidence, findings, errors, warnings, timestamps, and the observation-only scope statement.

Sensitive values such as cookie values, form `value=` attributes, URL query strings, and fragments from extracted page links are not retained in the report data.

## Development workflow

```powershell
git status
pytest -q
python -m masterkey_agent.shell
```

The repository contains the approved v0.5 design and implementation plan under `docs/superpowers/`.

## Architecture

```text
Explicit Target
      ↓
 Target Policy
      ↓
 Network Observation
      ├── transport / DNS / redirects
      ├── TLS intelligence
      └── public HTML snapshot
              ↓
      ┌───────┴────────┐
      ↓                ↓
 auth_surface   security_controls
      └───────┬────────┘
              ↓
      Evidence / Findings
              ↓
        JSON / Markdown
```

New modules are registered through the module registry without changing the engine's module execution loop.

## Future direction

The stable scan-session, module, evidence, and finding interfaces are intended to support later authorized lab-tool adapters, richer platform discovery, packaging, AI-assisted analysis, and eventually a portable/bootable USB environment. Those future layers are not part of v0.5.
