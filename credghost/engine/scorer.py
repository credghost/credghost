"""Risk scoring.

Assigns a :class:`RiskLevel` and human-readable reasons to each NHI based on
ownership, staleness, over-privilege and blast radius. Implements the rules from
the build spec, with explicit precedence so the highest applicable level wins.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from credghost.models.nhi import NHIIdentity, RiskLevel

# Services whose permissions imply a large blast radius if compromised.
HIGH_RISK_SERVICES = ["iam", "s3", "kms", "secretsmanager", "ec2", "rds"]

NEVER_USED_CRITICAL_DAYS = 180


def _now() -> datetime:
    return datetime.now(timezone.utc)


def compute_blast_radius(nhi: NHIIdentity) -> str:
    """Blast radius from the high-risk services the grants touch."""
    touched = {
        svc
        for perm in nhi.granted_permissions
        for svc in HIGH_RISK_SERVICES
        if svc in perm.lower()
    }
    # Wildcard grants (`*`) are maximally dangerous.
    if any(p == "*" or p.endswith(":*") and "iam" in p.lower() for p in nhi.granted_permissions):
        return "critical"
    if "*" in nhi.granted_permissions:
        return "critical"
    if len(touched) > 3:
        return "high"
    if len(touched) >= 2:
        return "medium"
    return "low"


def score_nhi(nhi: NHIIdentity, stale_threshold_days: int = 90) -> NHIIdentity:
    reasons: list[str] = []
    triggered: list[RiskLevel] = []

    nhi.blast_radius = compute_blast_radius(nhi)
    now = _now()

    days_since = nhi.days_since_last_use

    # ---- CRITICAL conditions ------------------------------------------------
    if nhi.owner is None and nhi.blast_radius in ("high", "critical"):
        reasons.append("Orphaned identity with high blast radius")
        triggered.append(RiskLevel.CRITICAL)

    if nhi.never_used and nhi.created_at is not None:
        age = now - _aware(nhi.created_at)
        if age > timedelta(days=NEVER_USED_CRITICAL_DAYS):
            reasons.append(f"Never used, exists for {NEVER_USED_CRITICAL_DAYS}+ days")
            triggered.append(RiskLevel.CRITICAL)

    # ---- HIGH conditions ----------------------------------------------------
    if days_since is not None and days_since > stale_threshold_days:
        reasons.append(f"Unused for {days_since} days")
        triggered.append(RiskLevel.HIGH)

    if nhi.is_over_privileged:
        reasons.append(
            f"{len(nhi.unused_permissions)} permissions granted but never used"
        )
        triggered.append(RiskLevel.HIGH)

    if nhi.owner is None:
        reasons.append("No owner assigned — orphaned")
        triggered.append(RiskLevel.HIGH)

    # Access Analyzer corroboration, if present.
    if nhi.raw.get("access_analyzer_findings"):
        reasons.append("Access Analyzer flagged unused access")
        triggered.append(RiskLevel.HIGH)

    # ---- MEDIUM conditions --------------------------------------------------
    if nhi.expires_at is None:
        reasons.append("Credential never expires")
        triggered.append(RiskLevel.MEDIUM)

    if nhi.purpose is None:
        reasons.append("No description or purpose defined")
        triggered.append(RiskLevel.MEDIUM)

    if nhi.last_used_unknown:
        reasons.append("Last-used unknown (CloudTrail unavailable)")
        triggered.append(RiskLevel.MEDIUM)

    # ---- Resolve final level ------------------------------------------------
    if triggered:
        nhi.risk_level = max(triggered, key=lambda r: r.rank)
    else:
        # Nothing triggered: recently used & clean -> INFO, otherwise LOW.
        if days_since is not None and days_since <= 30:
            nhi.risk_level = RiskLevel.INFO
        else:
            nhi.risk_level = RiskLevel.LOW

    nhi.risk_reasons = reasons
    return nhi


def score_all(
    identities: list[NHIIdentity], stale_threshold_days: int = 90
) -> list[NHIIdentity]:
    return [score_nhi(i, stale_threshold_days) for i in identities]


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
