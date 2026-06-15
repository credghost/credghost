"""JSON output matching the documented schema."""

from __future__ import annotations

import json

from credghost import __version__
from credghost.models.nhi import ScanResult


def build_payload(result: ScanResult) -> dict:
    return {
        "meta": {
            "scan_id": result.scan_id,
            "scanned_at": result.scanned_at.isoformat(),
            "provider": result.provider,
            "account": result.account,
            "tool_version": __version__,
            "scan_duration_seconds": result.scan_duration_seconds,
        },
        "summary": {
            "total_nhis": result.total_nhis,
            "orphaned": result.orphaned,
            "stale": result.stale,
            "never_used": result.never_used,
            "over_privileged": result.over_privileged,
            "by_risk": result.by_risk(),
        },
        "identities": [i.to_dict() for i in result.identities],
        "errors": result.errors,
        "warnings": result.warnings,
    }


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(build_payload(result), indent=indent)


def write_json(result: ScanResult, path: str, indent: int = 2) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(to_json(result, indent=indent))


def load_scan(path: str) -> ScanResult:
    """Reconstruct a :class:`ScanResult` from a saved JSON scan file."""
    from datetime import datetime

    from credghost.models.nhi import NHIIdentity, RiskLevel

    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    meta = data.get("meta", {})

    def _dt(value):
        return datetime.fromisoformat(value) if value else None

    identities = []
    for raw in data.get("identities", []):
        identities.append(
            NHIIdentity(
                id=raw["id"],
                name=raw["name"],
                nhi_type=_safe_type(raw.get("type")),
                provider=raw.get("provider", meta.get("provider", "aws")),
                account=raw.get("account", meta.get("account", "")),
                created_at=_dt(raw.get("created_at")),
                last_used_at=_dt(raw.get("last_used_at")),
                expires_at=_dt(raw.get("expires_at")),
                owner=raw.get("owner"),
                created_by=raw.get("created_by"),
                purpose=raw.get("purpose"),
                granted_permissions=raw.get("granted_permissions", []),
                used_permissions=raw.get("used_permissions", []),
                unused_permissions=raw.get("unused_permissions", []),
                risk_level=RiskLevel(raw.get("risk_level", "info")),
                risk_reasons=raw.get("risk_reasons", []),
                blast_radius=raw.get("blast_radius", "low"),
            )
        )

    scanned = meta.get("scanned_at")
    return ScanResult(
        scan_id=meta.get("scan_id", ""),
        scanned_at=datetime.fromisoformat(scanned) if scanned else datetime.now(),
        provider=meta.get("provider", "aws"),
        account=meta.get("account", ""),
        total_nhis=len(identities),
        identities=identities,
        errors=data.get("errors", []),
        warnings=data.get("warnings", []),
        scan_duration_seconds=meta.get("scan_duration_seconds", 0.0),
    )


def _safe_type(value):
    from credghost.models.nhi import NHIType

    try:
        return NHIType(value)
    except (ValueError, TypeError):
        return NHIType.UNKNOWN
