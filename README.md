# Master Security Agent

A discovery-first cybersecurity research agent. v0.3 focuses on local environment discovery and unauthenticated network/authentication-surface mapping.

## Safety boundary

The discovery modules do not collect or submit credentials, cookies, tokens, or authentication requests. Network inspection is limited to public metadata and unauthenticated HTTP(S) observations.

## v0.3 capabilities

- Safe Windows OS and browser metadata discovery
- DNS and HTTP(S) inspection
- Redirect-chain capture
- Security-header inspection
- Public HTML form and authentication-indicator inspection
- Evidence-based authentication mapping and confidence
- Interactive shell and JSON reports

## Development

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
pytest -q
python -m masterkey_agent.shell
```

The project is designed to grow into independent modules and a later bootable-USB builder. Credential-compromise experiments belong in controlled systems that we own or are explicitly authorized to test.
