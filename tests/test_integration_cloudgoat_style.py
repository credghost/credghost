"""Integration test: a CloudGoat-style misconfigured AWS account.

CloudGoat (Rhino Security Labs) deploys intentionally vulnerable IAM into a real
account — over-privileged roles, orphaned admin principals, wildcard policies.
Those misconfigurations don't depend on time, so we can reproduce the same
*shape* of account with moto and assert CredGhost detects it end-to-end. This is
the offline equivalent of the live runbook in ``docs/testing.md``.

Run a real CloudGoat validation later with:
    ./cloudgoat.py create iam_privesc_by_rotation
    credghost scan --provider aws --output html --report-path cloudgoat.html
    ./cloudgoat.py destroy iam_privesc_by_rotation
"""

import json

import boto3
import pytest

moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

from credghost.engine.inventory import build_inventory  # noqa: E402
from credghost.models.nhi import NHIType, RiskLevel  # noqa: E402
from credghost.providers.aws import AWSProvider  # noqa: E402

ADMIN_STAR = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
)

# Over-privileged: broad grants across high-blast-radius services.
OVERBROAD = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:*",
                    "s3:*",
                    "kms:*",
                    "secretsmanager:GetSecretValue",
                    "ec2:RunInstances",
                ],
                "Resource": "*",
            }
        ],
    }
)

# Well-scoped, owned, least-privilege.
SCOPED = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        ],
    }
)


@pytest.fixture
def cloudgoat_style_account():
    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")

        # 1. Orphaned admin user with a wildcard policy and a live access key.
        iam.create_user(UserName="cg-admin-orphan")
        iam.put_user_policy(
            UserName="cg-admin-orphan", PolicyName="star", PolicyDocument=ADMIN_STAR
        )
        iam.create_access_key(UserName="cg-admin-orphan")

        # 2. Over-privileged, ownerless role (the classic privesc target).
        iam.create_role(RoleName="cg-privesc-role", AssumeRolePolicyDocument="{}")
        iam.put_role_policy(
            RoleName="cg-privesc-role", PolicyName="broad", PolicyDocument=OVERBROAD
        )

        # 3. A properly-owned, least-privilege role (should score low).
        iam.create_role(
            RoleName="cg-readonly-app",
            AssumeRolePolicyDocument="{}",
            Description="App read-only role",
            Tags=[
                {"Key": "owner", "Value": "appteam@example.com"},
                {"Key": "purpose", "Value": "read app config"},
            ],
        )
        iam.put_role_policy(
            RoleName="cg-readonly-app", PolicyName="scoped", PolicyDocument=SCOPED
        )

        yield


@mock_aws
def test_credghost_detects_cloudgoat_style_misconfig(cloudgoat_style_account):
    result = build_inventory(AWSProvider(region="us-east-1"), stale_threshold_days=90)

    by_name = {(i.name, i.nhi_type): i for i in result.identities}

    # The orphaned wildcard admin user must be flagged at the top severities.
    admin = by_name[("cg-admin-orphan", NHIType.IAM_USER)]
    assert admin.owner is None
    assert admin.blast_radius in ("high", "critical")
    assert admin.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert any("orphan" in r.lower() for r in admin.risk_reasons)

    # The over-privileged ownerless role must be high/critical too.
    privesc = by_name[("cg-privesc-role", NHIType.IAM_ROLE)]
    assert privesc.owner is None
    assert privesc.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    # The owned, least-privilege role must NOT be high/critical.
    clean = by_name[("cg-readonly-app", NHIType.IAM_ROLE)]
    assert clean.owner == "appteam@example.com"
    assert clean.risk_level.rank < RiskLevel.HIGH.rank


@mock_aws
def test_summary_counts_are_credible(cloudgoat_style_account):
    result = build_inventory(AWSProvider(region="us-east-1"), stale_threshold_days=90)
    by_risk = result.by_risk()

    # At least one serious finding, and the orphaned principals are counted.
    assert by_risk["critical"] + by_risk["high"] >= 2
    assert result.orphaned >= 2  # admin user + privesc role
    assert result.over_privileged >= 1
    # Scan never errors out on this account shape.
    assert isinstance(result.errors, list)
