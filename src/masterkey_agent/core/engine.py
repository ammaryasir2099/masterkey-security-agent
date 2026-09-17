"""Orchestration for the v0.4 observation-only assessment engine."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from masterkey_agent.discovery.authsurface import AuthSurfaceModule
from masterkey_agent.discovery.network import inspect_url
from masterkey_agent.discovery.security import SecurityControlsModule
from masterkey_agent.discovery.tls import TLSIntelligenceModule
from masterkey_agent.models import NetworkObservation

from .models import Evidence, Finding, ModuleResult, ScanSession
from .registry import ModuleRegistry
from .target import Target, TargetPolicy, normalize_target, validate_target


def build_default_registry() -> ModuleRegistry:
    registry = ModuleRegistry()
    registry.register(AuthSurfaceModule())
    registry.register(SecurityControlsModule())
    registry.register(TLSIntelligenceModule())
    return registry


class ScanEngine:
    def __init__(
        self,
        registry: ModuleRegistry,
        policy: TargetPolicy | None = None,
        agent_version: str = "0.4.0",
    ) -> None:
        self.registry = registry
        self.policy = policy or TargetPolicy()
        self.agent_version = agent_version

    def scan(self, target_input: str) -> ScanSession:
        target = normalize_target(target_input)
        validate_target(target, self.policy)
        started = datetime.now(timezone.utc)
        session = ScanSession(
            session_id=str(uuid4()),
            agent_version=self.agent_version,
            started_at=started,
            target={
                "original_input": target.original_input,
                "url": target.url,
                "scheme": target.scheme,
                "hostname": target.hostname,
                "port": target.port,
                "path": target.path,
            },
            policy={
                "timeout_seconds": self.policy.timeout_seconds,
                "max_response_bytes": self.policy.max_response_bytes,
                "max_redirects": self.policy.max_redirects,
                "allow_http": self.policy.allow_http,
                "allow_https": self.policy.allow_https,
            },
        )

        try:
            observation = inspect_url(
                target.url,
                timeout=self.policy.timeout_seconds,
                max_bytes=self.policy.max_response_bytes,
                max_redirects=self.policy.max_redirects,
            )
        except Exception as exc:
            observation = NetworkObservation(
                url=target.url,
                scheme=target.scheme,
                host=target.hostname,
                error=str(exc),
            )

        self._record_network_result(session, target, observation)

        context: dict[str, Any] = {"network": observation}
        for module in self.registry.modules():
            try:
                result = module.run(target, context)
            except Exception as exc:  # defensive isolation for third-party/future modules
                result = ModuleResult(module.name, False, error=str(exc))
                session.errors.append(
                    {
                        "module": module.name,
                        "stage": "run",
                        "message": str(exc),
                    }
                )

            session.modules.append(result)
            session.evidence.extend(result.evidence)
            session.findings.extend(result.findings)
            if result.error:
                session.errors.append(
                    {
                        "module": module.name,
                        "stage": "result",
                        "message": result.error,
                    }
                )

        session.ended_at = datetime.now(timezone.utc)
        return session

    @staticmethod
    def _record_network_result(
        session: ScanSession,
        target: Target,
        observation: NetworkObservation,
    ) -> None:
        evidence: list[Evidence] = []
        findings: list[Finding] = []

        if observation.scheme == "https":
            evidence.append(
                Evidence(
                    "network-https-1",
                    "network_discovery",
                    "transport.https",
                    "HTTPS/TLS target observed",
                    target.url,
                )
            )
        if observation.status_code is not None:
            evidence.append(
                Evidence(
                    "network-status-1",
                    "network_discovery",
                    "transport.http_status",
                    str(observation.status_code),
                    target.url,
                )
            )
        if observation.redirects:
            evidence.append(
                Evidence(
                    "network-redirects-1",
                    "network_discovery",
                    "transport.redirect_chain",
                    f"{len(observation.redirects)} redirect(s) observed",
                    target.url,
                    {"count": len(observation.redirects)},
                )
            )
        if observation.error:
            session.errors.append(
                {
                    "module": "network_discovery",
                    "stage": "inspect",
                    "message": observation.error,
                }
            )

        result = ModuleResult(
            "network_discovery",
            observation.error is None,
            evidence=evidence,
            observations={
                "status_code": observation.status_code,
                "redirects": list(observation.redirects),
                "resolved_addresses": list(observation.resolved_addresses),
                "content_type": observation.content_type,
                "tls_available": observation.tls is not None,
            },
            findings=findings,
            error=observation.error,
        )
        session.modules.append(result)
        session.evidence.extend(evidence)
        session.findings.extend(findings)
