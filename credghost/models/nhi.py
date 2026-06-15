"""Core NHI (non-human identity) data models.

Every identity found — regardless of provider — maps onto :class:`NHIIdentity`.
Build everything else to populate this model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class RiskLevel(Enum):
    CRITICAL = "critical"  # Orphaned + high permissions, never expires
    HIGH = "high"  # Stale >90 days, over-privileged
    MEDIUM = "medium"  # Stale >30 days OR no owner
    LOW = "low"  # Active, owned, scoped appropriately
    INFO = "info"  # Active, used recently, looks clean

    @property
    def rank(self) -> int:
        """Numeric severity ordering — higher is worse."""
        return {
            RiskLevel.INFO: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }[self]


class NHIType(Enum):
    SERVICE_ACCOUNT = "service_account"
    API_KEY = "api_key"
    IAM_ROLE = "iam_role"
    IAM_USER = "iam_user"
    OAUTH_GRANT = "oauth_grant"
    AGENT_CREDENTIAL = "agent_credential"
    ACCESS_KEY = "access_key"
    UNKNOWN = "unknown"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class NHIIdentity:
    # Identity basics
    id: str  # Unique internal ID (provider:account:name)
    name: str  # Display name (e.g. "splunk-service-account")
    nhi_type: NHIType
    provider: str  # "aws", "github", "okta" etc.
    account: str  # AWS account ID, org name etc.

    # Lifecycle
    created_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None  # None = never expires

    # Ownership
    owner: Optional[str] = None  # Username/email of human owner. None = orphaned
    created_by: Optional[str] = None  # Who created it
    purpose: Optional[str] = None  # Description if any exists

    # Permissions
    granted_permissions: list[str] = field(default_factory=list)
    used_permissions: list[str] = field(default_factory=list)
    unused_permissions: list[str] = field(default_factory=list)

    # Risk
    risk_level: RiskLevel = RiskLevel.INFO
    risk_reasons: list[str] = field(default_factory=list)
    blast_radius: str = "low"  # "low" / "medium" / "high" / "critical"

    # When last-used data is genuinely unknown (e.g. CloudTrail off) rather than
    # confirmed "never used". Keeps us from over-flagging.
    last_used_unknown: bool = False

    # Raw data
    raw: dict = field(default_factory=dict)  # Original API response for reference

    @property
    def days_since_last_use(self) -> Optional[int]:
        if self.last_used_at is None:
            return None
        return (_utcnow() - _ensure_aware(self.last_used_at)).days

    @property
    def is_orphaned(self) -> bool:
        return self.owner is None

    @property
    def is_over_privileged(self) -> bool:
        if not self.unused_permissions:
            return False
        if self.used_permissions:
            # We observed usage: flag when granted access dwarfs what's used.
            return len(self.unused_permissions) > len(self.used_permissions) * 2
        # No observed usage (e.g. service-last-accessed unavailable). Only call
        # it over-privileged when the grant is genuinely broad — a wildcard or
        # several unused permissions — so a single narrowly-scoped permission we
        # simply lack usage data for isn't a false positive.
        if any(p == "*" or p.endswith(":*") for p in self.unused_permissions):
            return True
        return len(self.unused_permissions) >= 3

    @property
    def never_used(self) -> bool:
        return self.last_used_at is None and not self.last_used_unknown

    def last_used_display(self) -> str:
        if self.last_used_unknown:
            return "Unknown"
        days = self.days_since_last_use
        if days is None:
            return "Never"
        if days == 0:
            return "Today"
        return f"{days} days ago"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.nhi_type.value,
            "provider": self.provider,
            "account": self.account,
            "created_at": _iso(self.created_at),
            "last_used_at": _iso(self.last_used_at),
            "expires_at": _iso(self.expires_at),
            "owner": self.owner,
            "created_by": self.created_by,
            "purpose": self.purpose,
            "risk_level": self.risk_level.value,
            "risk_reasons": self.risk_reasons,
            "blast_radius": self.blast_radius,
            "granted_permissions": self.granted_permissions,
            "used_permissions": self.used_permissions,
            "unused_permissions": self.unused_permissions,
        }


@dataclass
class ScanResult:
    scan_id: str
    scanned_at: datetime
    provider: str
    account: str
    total_nhis: int
    identities: list[NHIIdentity]
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    # --- Derived summary counters -------------------------------------------------
    @property
    def orphaned(self) -> int:
        return sum(1 for i in self.identities if i.is_orphaned)

    @property
    def stale(self) -> int:
        return sum(
            1
            for i in self.identities
            if (i.days_since_last_use or 0) > 90 and not i.last_used_unknown
        )

    @property
    def never_used(self) -> int:
        return sum(1 for i in self.identities if i.never_used)

    @property
    def over_privileged(self) -> int:
        return sum(1 for i in self.identities if i.is_over_privileged)

    def by_risk(self) -> dict[str, int]:
        counts = {level.value: 0 for level in RiskLevel}
        for i in self.identities:
            counts[i.risk_level.value] += 1
        return counts

    def identities_by_level(self, level: RiskLevel) -> list[NHIIdentity]:
        return [i for i in self.identities if i.risk_level == level]


def _ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return _ensure_aware(dt).isoformat()
