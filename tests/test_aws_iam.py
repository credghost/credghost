"""AWS IAM provider tests using moto to mock AWS."""

import boto3
import pytest

moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

from credghost.models.nhi import NHIType  # noqa: E402


ADMIN_POLICY = """{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": ["s3:*", "iam:PassRole", "kms:Decrypt"], "Resource": "*"}]
}"""


@pytest.fixture
def aws_account():
    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")

        # A user with an inline admin-ish policy and an access key.
        iam.create_user(UserName="svc-legacy-backup")
        iam.put_user_policy(
            UserName="svc-legacy-backup",
            PolicyName="inline-admin",
            PolicyDocument=ADMIN_POLICY,
        )
        iam.create_access_key(UserName="svc-legacy-backup")

        # A user that is owned via tags.
        iam.create_user(
            UserName="owned-user",
            Tags=[
                {"Key": "owner", "Value": "alice@example.com"},
                {"Key": "purpose", "Value": "nightly etl"},
            ],
        )

        # A customer role we should keep.
        iam.create_role(
            RoleName="deploy-prod-2021",
            AssumeRolePolicyDocument="{}",
            Description="prod deploy",
        )
        iam.put_role_policy(
            RoleName="deploy-prod-2021",
            PolicyName="inline",
            PolicyDocument=ADMIN_POLICY,
        )

        yield


def _collect():
    from credghost.providers.aws import AWSProvider

    provider = AWSProvider(region="us-east-1")
    return provider.collect()


@mock_aws
def test_collect_returns_users_roles_and_keys(aws_account):
    result = _collect()
    names = {i.name for i in result.identities}
    types = {i.nhi_type for i in result.identities}

    assert "svc-legacy-backup" in names
    assert "owned-user" in names
    assert "deploy-prod-2021" in names
    assert NHIType.IAM_USER in types
    assert NHIType.IAM_ROLE in types
    assert NHIType.ACCESS_KEY in types


@mock_aws
def test_owner_and_purpose_from_tags(aws_account):
    result = _collect()
    owned = next(i for i in result.identities if i.name == "owned-user")
    assert owned.owner == "alice@example.com"
    assert owned.purpose == "nightly etl"


@mock_aws
def test_orphaned_user_has_no_owner(aws_account):
    result = _collect()
    legacy = next(
        i
        for i in result.identities
        if i.name == "svc-legacy-backup" and i.nhi_type == NHIType.IAM_USER
    )
    assert legacy.owner is None
    assert any("s3" in p.lower() for p in legacy.granted_permissions)


@mock_aws
def test_service_linked_roles_filtered_out(aws_account):
    # moto won't create /aws-service-role/ roles here, but the list should not
    # contain any such path.
    result = _collect()
    for i in result.identities:
        if i.nhi_type == NHIType.IAM_ROLE:
            assert (
                not i.raw.get("role", {})
                .get("Path", "/")
                .startswith("/aws-service-role/")
            )


@mock_aws
def test_does_not_crash_without_access_analyzer(aws_account):
    # No analyzer configured -> warnings recorded, scan continues.
    result = _collect()
    assert result.identities  # still produced identities
    assert isinstance(result.warnings, list)


@mock_aws
def test_full_inventory_scores_risk(aws_account):
    from credghost.engine.inventory import build_inventory
    from credghost.providers.aws import AWSProvider

    result = build_inventory(AWSProvider(region="us-east-1"), stale_threshold_days=90)
    assert result.total_nhis >= 4
    # Every identity must have a risk level assigned.
    assert all(i.risk_level is not None for i in result.identities)
    # The orphaned admin user should not be low/info.
    legacy = next(
        i
        for i in result.identities
        if i.name == "svc-legacy-backup" and i.nhi_type == NHIType.IAM_USER
    )
    assert legacy.risk_level.value in ("medium", "high", "critical")
