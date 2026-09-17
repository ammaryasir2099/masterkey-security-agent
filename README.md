# Master Security Agent

Master Security Agent is a discovery-first cybersecurity research agent. Version **0.5.0** turns the earlier prototype into a modular, evidence-driven assessment engine for one explicitly supplied HTTP(S) target.

## v0.5 capabilities

- Safe Windows OS and browser metadata discovery
- DNS, HTTP(S), redirect, content-type, and bounded response inspection
- TLS version/cipher/certificate metadata observation where available
- Security-control observations for HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and X-Frame-Options
- Safe cookie-attribute analysis without retaining cookie names or values
- CORS response metadata observation without sending preflight or custom requests
- Public HTML form/page metadata analysis without storing input values or response bodies
- Passive authentication-surface indicators for login, SSO, OAuth/OIDC-like, SAML-like, identity-provider-like, and HTTP auth challenge signals
- Dedicated passive web-metadata analysis module over the already collected HTML snapshot
- Deterministic evidence/finding correlation and stable result ordering
- Bounded concurrent analysis with a configurable worker limit and scan time budget
- Fault isolation so one analysis module can fail without aborting unrelated modules
- Evidence-backed findings with severity, confidence, recommendations, and evidence references
- Interactive shell with `scan`, `modules`, and `version` commands
- JSON and Markdown scan reports
- pytest regression suite, package build validation, and GitHub Actions CI

## Safety boundary

The default engine is observation-only. It does not collect or submit credentials, cookies, tokens, request bodies, or authentication requests. It does not perform password testing, password cracking, credential stuffing, login automation, token harvesting, exploitation, persistence, destructive actions, endpoint wordlist discovery, or address-range scanning.

Network collection is limited to one explicitly supplied HTTP or HTTPS target and bounded unauthenticated GET observations. Analysis modules do not make network requests; they consume the sanitized observation produced by the network layer.

Authentication-related conclusions are evidence labels, not proof of an internal implementation. Missing controls and CORS conditions are reported as configuration observations, not confirmed exploitability.

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

Examples:

```text
MK> version
Master Security Agent 0.5.0

MK> modules
Registered modules:
  - auth_surface
  - security_controls
  - web_metadata

MK> scan https://example.com/
Scan session: <session-id>
Target: https://example.com/
Elapsed: <seconds>s
Modules: 4
Evidence: <count>
Findings: <count>
Errors: 0
Warnings: 0

MK> scan https://example.com/ --output reports\example-scan.md --format markdown
```

The network phase runs once. The built-in analysis modules consume that shared observation and are executed within the configured analysis-worker budget.

## Reporting

Write the latest scan using the report command:

```text
MK> report reports\example-scan.json
MK> report reports\example-scan.md
```

The writer also supports explicit format selection from code:

```python
write_scan_report("reports/example.json", session, format="json")
write_scan_report("reports/example.md", session, format="markdown")
```

JSON reports contain:

```json
{
  "agent_version": "0.5.0",
  "session": {},
  "target": {},
  "modules": [],
  "evidence": [],
  "findings": [],
  "errors": [],
  "warnings": []
}
```

Report URLs are normalized to remove query strings and fragments. Cookie values, cookie names, form values, authorization headers, request bodies, and response bodies are not retained in reports.

## Built-in modules

```text
network_discovery
    |
    +--> auth_surface
    +--> security_controls
    +--> web_metadata
    |
    +--> correlation
    |
    +--> JSON / Markdown report
```

`web_metadata` is analysis-only: it never fetches discovered scripts, stylesheets, forms, canonical links, or authentication URLs.

## Development and CI

Run the full local test suite:

```powershell
python -m pip install -e ".[test]"
pytest -q
python -m pip wheel . --no-deps -w dist
```

GitHub Actions runs the test suite on Python 3.11–3.14, performs a narrow Ruff syntax/undefined-name gate, builds a wheel, and provides a manually triggered bounded scan/report workflow for explicitly supplied public HTTP(S) targets.

The repository's approved design and implementation plan are under `docs/superpowers/`.

## Future direction

The stable scan-session, module, evidence, and finding interfaces are intended to support later authorized lab-tool adapters, richer platform discovery, packaging, and eventually a portable/bootable USB environment. Those capabilities remain outside the default observation-only engine.
