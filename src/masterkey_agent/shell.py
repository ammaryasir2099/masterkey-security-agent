"""Interactive command shell for the discovery agent."""
from __future__ import annotations
import shlex
from typing import Any
from masterkey_agent.authmap.mapper import build_auth_map
from masterkey_agent.discovery.local import collect_system_info, detect_browsers
from masterkey_agent.discovery.network import inspect_url
from masterkey_agent.report import write_report

_HELP="""Commands:
  help                         Show this help.
  local                        Collect safe local OS/browser metadata.
  inspect <url>                Inspect URL/network metadata without credentials.
  map <url>                    Inspect URL and build an evidence-based auth map.
  discover <url>               Run network inspection and summarize auth evidence.
  inspect-auth <url>           Show authentication evidence and confidence.
  inspect-redirects <url>      Show observed public redirect destinations.
  inspect-headers <url>        Show safe response headers.
  inspect-public-html <url>    Show public HTML title/form metadata only.
  report <path>                Write the current state as JSON.
  exit                         Quit.
"""

def dispatch(command: str,state: dict[str,Any])->str:
    parts=shlex.split(command)
    if not parts:return ""
    action=parts[0].lower()
    if action=="help":return _HELP.strip()
    if action in {"exit","quit"}:return "__EXIT__"
    if action=="local" and len(parts)==1:
        info=collect_system_info(); browsers=detect_browsers(); state["local"]=info.to_dict()|{"browsers":[b.to_dict() for b in browsers]}
        return f"OS: {info.os_name} {info.release}\nHostname: {info.hostname}\nBrowsers detected: {len(browsers)}"
    if action=="report" and len(parts)==2: write_report(parts[1],state); return f"Report written: {parts[1]}"
    if len(parts)==2 and action in {"inspect","map","discover","inspect-auth","inspect-redirects","inspect-headers","inspect-public-html"}:
        observation=inspect_url(parts[1]); state["network"]=observation.to_dict()
        if action=="inspect": return f"URL: {observation.url}\nStatus: {observation.status_code if observation.status_code is not None else 'unavailable'}\nError: {observation.error or 'none'}\nResolved: {', '.join(observation.resolved_addresses) or 'none'}\nRedirects: {len(observation.redirects)}"
        if action in {"map","discover"}:
            m=build_auth_map(observation); state["auth_map"]=m.to_dict(); return f"Transport evidence: {', '.join(m.transport_evidence) or 'none'}\nAuthentication confidence: {m.authentication_confidence}\nAuthentication evidence: {', '.join(m.authentication_evidence) or 'none'}\nSecurity controls: {', '.join(m.security_controls) or 'none'}"
        if action=="inspect-auth":
            m=build_auth_map(observation); state["auth_map"]=m.to_dict(); return f"Authentication confidence: {m.authentication_confidence}\nAuthentication evidence: {', '.join(m.authentication_evidence) or 'none'}\nCandidate protocols: {', '.join([p for p in m.protocols if p != 'HTTPS/TLS']) or 'none'}"
        if action=="inspect-redirects": return "Redirects:\n"+"\n".join(f"  {x}" for x in observation.redirects) if observation.redirects else "Redirects: none"
        if action=="inspect-headers":
            lines=[f"{k}: {v}" for k,v in sorted(observation.headers.items())]; return "Headers:\n"+"\n".join(lines) if lines else "Headers: none"
        html=observation.public_html
        if html is None:return "Public HTML: none"
        return f"Title: {html.title or 'none'}\nForms: {len(html.forms)}\n"+"\n".join(f"  FORM {i}: method={f.method} action={f.action or 'same-document'} fields="+",".join(f"{x.name or '<unnamed>'}:{x.type or 'text'}"+(f":autocomplete={x.autocomplete}" if x.autocomplete else "") for x in f.fields) for i,f in enumerate(html.forms,1))
    return "Unknown command or arguments. Type 'help'."

def main():
    print("Master Security Agent 0.3 — discovery mode"); print("No credentials are collected or submitted. Type 'help' for commands."); state={}
    while True:
        try: command=input("MK> ")
        except (EOFError,KeyboardInterrupt): print(); break
        result=dispatch(command,state)
        if result=="__EXIT__":break
        if result:print(result)

if __name__=="__main__":main()
