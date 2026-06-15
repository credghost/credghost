"""Risk scorer unit tests — pure logic, no AWS."""

from datetime import datetime, timedelta, timezone

import pytest

from credghost.engine.scorer import compute_blast_radius, score_nhi
from credghost.models.nhi import NHIIdentity, NHIType, RiskLevel


def _now():
    return datetime.now(timezone.utc)


def make_nhi(**kwargs) -> NHIIdentity:
    base = dict(
        id="aws:1:role:test",
        name="test",
        nhi_type=NHIType.IAM_ROLE,
        provider="aws",
        account="1",
        owner="owner@example.com",
        purpose="defined",
        expires_at=_now() + timedelta(days=30),
        last_used_at=_now() - timedelta(days=1),
        created_at=_now() - timedelta(days=10),
    )
    base.update(kwargs)
    return NHIIdentity(**base)


def test_orphaned_high_blast_radius_is_critical():
    nhi = make_nhi(
        owner=None,
        granted_permissions=["iam:*", "s3:*", "kms:Decrypt", "ec2:RunInstances"],
    )
    score_nhi(nhi)
    assert nhi.risk_level == RiskLevel.CRITICAL
    assert any("blast radius" in r.lower() for r in nhi.risk_reasons)


def test_never_used_over_180_days_is_critical():
    nhi = make_nhi(
        last_used_at=None,
        created_at=_now() - timedelta(days=200),
        granted_permissions=["logs:PutLogEvents"],
    )
    score_nhi(nhi)
    assert nhi.risk_level == RiskLevel.CRITICAL


def test_stale_beyond_threshold_is_high():
    nhi = make_nhi(last_used_at=_now() - timedelta(days=120))
    score_nhi(nhi, stale_threshold_days=90)
    assert nhi.risk_level >= RiskLevel.HIGH if False else nhi.risk_level == RiskLevel.HIGH
    assert any("Unused for" in r for r in nhi.risk_reasons)


def test_over_privileged_is_high():
    nhi = make_nhi(
        used_permissions=["s3:GetObject"],
        unused_permissions=["s3:Put", "s3:Delete", "s3:List"],
    )
    score_nhi(nhi)
    assert nhi.risk_level == RiskLevel.HIGH


def test_no_owner_is_at_least_high():
    nhi = make_nhi(owner=None, granted_permissions=["logs:PutLogEvents"])
    score_nhi(nhi)
    assert nhi.risk_level.rank >= RiskLevel.HIGH.rank


def test_never_expires_is_medium():
    nhi = make_nhi(expires_at=None, granted_permissions=["logs:PutLogEvents"])
    score_nhi(nhi)
    assert nhi.risk_level == RiskLevel.MEDIUM
    assert "Credential never expires" in nhi.risk_reasons


def test_clean_recent_identity_is_info():
    nhi = make_nhi(
        granted_permissions=["logs:PutLogEvents"],
        used_permissions=["logs:PutLogEvents"],
        last_used_at=_now() - timedelta(days=2),
    )
    score_nhi(nhi)
    assert nhi.risk_level == RiskLevel.INFO


def test_blast_radius_wildcard_is_critical():
    nhi = make_nhi(granted_permissions=["*"])
    assert compute_blast_radius(nhi) == "critical"


def test_blast_radius_many_risky_services_is_high():
    nhi = make_nhi(
        granted_permissions=["iam:ListUsers", "s3:GetObject", "kms:Decrypt", "rds:DescribeDBInstances"]
    )
    assert compute_blast_radius(nhi) == "high"


def test_last_used_unknown_does_not_count_as_never_used():
    nhi = make_nhi(last_used_at=None, last_used_unknown=True)
    assert nhi.never_used is False
    score_nhi(nhi)
    assert "Last-used unknown (CloudTrail unavailable)" in nhi.risk_reasons
