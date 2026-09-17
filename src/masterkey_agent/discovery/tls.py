"""Bounded TLS and certificate intelligence for the supplied HTTPS target."""
from __future__ import annotations

import ssl
from datetime import datetime, timezone
from typing import Any

from masterkey_agent.core.models import Evidence, Finding, ModuleResult
from masterkey_agent.core.target import Target
from masterkey_agent.models import NetworkObservation


def _flatten_name(value: Any) -> list[str]:
    flattened: list[str] = []
    for relative_name in value or ():
        for attribute in relative_name or ():
            if isinstance(attribute, (tuple, list)) and len(attribute) >= 2:
                flattened.append(f"{attribute[0]}={attribute[1]}")
    return flattened


def _normalize_san(value: Any) -> list[str]:
    names: list[str] = []
    for entry in value or ():
        if isinstance(entry, (tuple, list)) and len(entry) >= 2:
            kind, item = str(entry[0]), str(entry[1])
            if kind.upper() in {"DNS", "IP ADDRESS"}:
                names.append(item)
    return names


def _parse_cert_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def normalize_tls_metadata(
    metadata: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Normalize standard-library certificate metadata into safe observations."""
    normalized: dict[str, Any] = {
        "version": metadata.get("version"),
        "cipher": metadata.get("cipher"),
        "subject": _flatten_name(metadata.get("subject")),
        "issuer": _flatten_name(metadata.get("issuer")),
        "san": _normalize_san(metadata.get("subjectAltName")),
        "not_before": metadata.get("not_before"),
        "not_after": metadata.get("not_after"),
    }

    current = now or datetime.now(timezone.utc)
    not_before = _parse_cert_time(metadata.get("not_before"))
    not_after = _parse_cert_time(metadata.get("not_after"))
    if not_before and current < not_before:
        normalized["validity_state"] = "not_yet_valid"
    elif not_after and current > not_after:
        normalized["validity_state"] = "expired"
    elif not_before or not_after:
        normalized["validity_state"] = "valid"
    else:
        normalized["validity_state"] = "unknown"
    return normalized


class TLSIntelligenceModule:
    name = "tls_intelligence"

    def run(self, target: Target, context: dict[str, Any]) -> ModuleResult:
        observation: NetworkObservation | None = context.get("network")
        if observation is None:
            return ModuleResult(self.name, False, error="network observation missing")

        if target.scheme != "https":
            return ModuleResult(
                self.name,
                True,
                observations={"available": False, "reason": "target is not HTTPS"},
            )

        metadata = observation.tls
        if not metadata:
            return ModuleResult(
                self.name,
                True,
                observations={"available": False, "reason": "TLS metadata unavailable"},
            )

        normalized = normalize_tls_metadata(metadata)
        evidence: list[Evidence] = []

        for key, evidence_type, description in (
            ("version", "tls.version", "Negotiated TLS protocol version observed"),
            ("cipher", "tls.cipher", "Negotiated TLS cipher observed"),
        ):
            if normalized.get(key):
                evidence.append(Evidence(
                    f"tls-{key}-1", self.name, evidence_type, str(normalized[key]), target.url
                ))

        for key, evidence_type, description in (
            ("subject", "tls.subject", "Certificate subject observed"),
            ("issuer", "tls.issuer", "Certificate issuer observed"),
            ("san", "tls.san", "Certificate subject alternative names observed"),
        ):
            values = normalized.get(key) or []
            if values:
                evidence.append(Evidence(
                    f"tls-{key}-1", self.name, evidence_type, ", ".join(values), target.url
                ))

        validity = normalized.get("validity_state")
        if validity != "unknown":
            evidence.append(Evidence(
                "tls-validity-1",
                self.name,
                "tls.validity",
                validity,
                target.url,
                {
                    "not_before": normalized.get("not_before"),
                    "not_after": normalized.get("not_after"),
                },
            ))

        findings: list[Finding] = []
        if validity in {"expired", "not_yet_valid"}:
            findings.append(
                Finding(
                    id="finding-tls-certificate-validity",
                    title=f"TLS certificate is {validity.replace('_', ' ')}",
                    severity="medium",
                    category="transport",
                    summary="The observed certificate validity period does not include the inspection time.",
                    evidence_refs=["tls-validity-1"],
                    recommendation="Review certificate issuance and deployment so the active certificate is valid for the service lifecycle.",
                    confidence="high",
                )
            )

        return ModuleResult(
            self.name,
            True,
            evidence=evidence,
            observations={"available": True, **normalized},
            findings=findings,
        )
