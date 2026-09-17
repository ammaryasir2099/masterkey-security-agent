"""Bounded orchestration for the observation-only assessment engine."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timezone
from time import monotonic
from typing import Any
from uuid import uuid4

from masterkey_agent.discovery.authsurface import AuthSurfaceModule
from masterkey_agent.discovery.network import inspect_url
from masterkey_agent.discovery.security import SecurityControlsModule
from masterkey_agent.discovery.webmeta import WebMetadataModule
from masterkey_agent.models import NetworkObservation

from .correlation import correlate_results
from .models import Evidence, Finding, ModuleResult, ScanSession
from .registry import DiscoveryModule, ModuleRegistry
from .target import Target, TargetPolicy, normalize_target, validate_target


def build_default_registry() -> ModuleRegistry:
    registry = ModuleRegistry()
    registry.register(AuthSurfaceModule())
    registry.register(SecurityControlsModule())
    registry.register(WebMetadataModule())
    return registry


class ScanEngine:
    def __init__(
        self,
        registry: ModuleRegistry,
        policy: TargetPolicy | None = None,
        agent_version: str = "0.5.0",
    ) -> None:
        self.registry = registry
        self.policy = policy or TargetPolicy()
        self.policy.validate()
        self.agent_version = agent_version

    def _run_modules(
        self,
        target: Target,
        context: dict[str, Any],
        modules: tuple[DiscoveryModule, ...],
        policy: TargetPolicy,
        *,
        deadline: float | None = None,
    ) -> list[ModuleResult]:
        def execute(module: DiscoveryModule) -> ModuleResult:
            try:
                return module.run(target, dict(context))
            except Exception as exc:
                return ModuleResult(module=module.name, success=False, error=str(exc))

        pool = ThreadPoolExecutor(
            max_workers=policy.max_workers,
            thread_name_prefix="mkscan",
        )
        futures = [pool.submit(execute, module) for module in modules]
        results: list[ModuleResult] = []
        try:
            for module, future in zip(modules, futures):
                timeout = policy.max_scan_seconds
                if deadline is not None:
                    timeout = max(0.0, deadline - monotonic())
                try:
                    results.append(future.result(timeout=timeout))
                except FutureTimeoutError:
                    future.cancel()
                    results.append(
                        ModuleResult(
                            module=module.name,
                            success=False,
                            error="module execution exceeded scan time budget",
                        )
                    )
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        return results

    def scan(self, target_input: str) -> ScanSession:
        target = normalize_target(target_input)
        validate_target(target, self.policy)
        started = datetime.now(timezone.utc)
        deadline = monotonic() + self.policy.max_scan_seconds
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
                "max_scan_seconds": self.policy.max_scan_seconds,
                "max_workers": self.policy.max_workers,
            },
        )

        observation = self._collect_network(target, deadline)
        self._record_network_result(session, target, observation)

        modules = self.registry.modules()
        analysis_results = self._run_modules(
            target,
            {"network": observation},
            modules,
            self.policy,
            deadline=deadline,
        )
        session.modules.extend(analysis_results)

        for result in analysis_results:
            if not result.success and result.error:
                session.errors.append(
                    {"module": result.module, "stage": "run", "message": result.error}
                )

        correlated_evidence, correlated_findings = correlate_results(analysis_results)
        session.evidence.extend(correlated_evidence)
        session.findings.extend(correlated_findings)

        elapsed = monotonic() - (deadline - self.policy.max_scan_seconds)
        if elapsed > self.policy.max_scan_seconds:
            session.warnings.append("scan time budget was exceeded while collecting network metadata")

        session.ended_at = datetime.now(timezone.utc)
        return session

    def _collect_network(self, target: Target, deadline: float) -> NetworkObservation:
        try:
            remaining = max(0.1, deadline - monotonic())
            timeout = min(self.policy.timeout_seconds, remaining)
            if timeout <= 0:
                raise TimeoutError("scan time budget exhausted before network inspection")
            return inspect_url(
                target.url,
                timeout=timeout,
                max_bytes=self.policy.max_response_bytes,
                max_redirects=self.policy.max_redirects,
            )
        except Exception as exc:
            return NetworkObservation(
                url=target.url,
                scheme=target.scheme,
                host=target.hostname,
                error=str(exc),
            )

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
                    id="network-https-1",
                    source_module="network_discovery",
                    evidence_type="transport.https",
                    value="HTTPS/TLS target observed",
                    target_url=target.url,
                )
            )
        if observation.status_code is not None:
            evidence.append(
                Evidence(
                    id="network-status-1",
                    source_module="network_discovery",
                    evidence_type="transport.http_status",
                    value=str(observation.status_code),
                    target_url=target.url,
                )
            )
        if observation.redirects:
            evidence.append(
                Evidence(
                    id="network-redirects-1",
                    source_module="network_discovery",
                    evidence_type="transport.redirect_chain",
                    value=f"{len(observation.redirects)} redirect(s) observed",
                    target_url=target.url,
                    metadata={"count": len(observation.redirects)},
                )
            )
        if observation.cors:
            evidence.append(
                Evidence(
                    id="network-cors-1",
                    source_module="network_discovery",
                    evidence_type="transport.cors_metadata",
                    value="CORS response metadata observed",
                    target_url=target.url,
                    metadata={"keys": sorted(observation.cors)},
                )
            )
        if observation.response_size_limited:
            evidence.append(
                Evidence(
                    id="network-size-limit-1",
                    source_module="network_discovery",
                    evidence_type="transport.response_size_limited",
                    value="Response body exceeded the configured inspection limit",
                    target_url=target.url,
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
            module="network_discovery",
            success=observation.error is None,
            evidence=evidence,
            observations={
                "status_code": observation.status_code,
                "redirects": list(observation.redirects),
                "resolved_addresses": list(observation.resolved_addresses),
                "content_type": observation.content_type,
                "tls_available": observation.tls is not None,
                "cors": dict(observation.cors),
                "response_size_limited": observation.response_size_limited,
            },
            findings=findings,
            error=observation.error,
        )
        session.modules.append(result)
        session.evidence.extend(evidence)
        session.findings.extend(findings)
