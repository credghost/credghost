"""Demo provider — realistic synthetic NHI data, no AWS account required.

Powers `credghost demo`. Dates are stored *relative to now* (e.g. "created
1600 days ago") so the dataset always looks like a messy, aged organisation no
matter when you run it. Useful for screenshots, sales demos, and dogfounding the
risk engine without touching a real cloud.

Nothing here calls AWS. The identities are unscored on the way out — the normal
risk scorer runs over them exactly like a real scan, so the demo report is
produced by the same code path a customer sees.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from credghost.models.nhi import NHIIdentity, NHIType
from credghost.providers.base import BaseProvider, ProviderResult

DEMO_ACCOUNT = "123456789012"


def _ago(days: float | None) -> datetime | None:
    if days is None:
        return None
    return datetime.now(timezone.utc) - timedelta(days=days)


def _ahead(days: float | None) -> datetime | None:
    if days is None:
        return None
    return datetime.now(timezone.utc) + timedelta(days=days)


# Each row: (name, type, created_days_ago, last_used_days_ago|None,
#            expires_in_days|None, owner|None, purpose|None, granted, used)
# unused permissions are derived as granted - used by the provider.
_FIXTURE = [
    # ------------------------------------------------------------- CRITICAL-ish
    (
        "svc-legacy-backup", NHIType.IAM_USER, 1620, None, None, None, None,
        ["s3:*", "iam:PassRole", "kms:Decrypt", "kms:Encrypt", "ec2:RunInstances", "ec2:TerminateInstances"],
        [],
    ),
    (
        "deploy-prod-2021", NHIType.IAM_ROLE, 1450, None, None, None, None,
        ["iam:*", "sts:AssumeRole", "s3:GetObject"],
        [],
    ),
    (
        "AKIAIOSFODNN7EXAMPLE", NHIType.ACCESS_KEY, 1200, 410, None, None, None,
        ["s3:GetObject", "s3:PutObject", "iam:CreateUser", "kms:Decrypt", "secretsmanager:GetSecretValue"],
        ["s3:GetObject"],
    ),
    # ------------------------------------------------------------------- HIGH-ish
    (
        "ci-pipeline-old", NHIType.ACCESS_KEY, 980, 312, None, "john@acme.io", None,
        ["s3:*", "ec2:*", "iam:PassRole", "ecr:*", "logs:*"],
        ["ecr:GetAuthorizationToken", "logs:PutLogEvents"],
    ),
    (
        "terraform-runner", NHIType.IAM_ROLE, 720, 140, None, "platform@acme.io", "Terraform CI applies",
        ["ec2:*", "rds:*", "s3:*", "iam:CreateRole", "kms:CreateKey", "route53:*"],
        ["ec2:DescribeInstances", "s3:GetObject"],
    ),
    (
        "old-jenkins-key", NHIType.ACCESS_KEY, 1100, 205, None, None, None,
        ["s3:GetObject", "s3:PutObject", "ec2:DescribeInstances"],
        ["s3:GetObject"],
    ),
    (
        "s3-migration-2022", NHIType.IAM_ROLE, 860, 190, None, None, "One-off 2022 bucket migration",
        ["s3:*", "kms:Decrypt", "ec2:CreateSnapshot"],
        [],
    ),
    (
        "datadog-integration", NHIType.IAM_ROLE, 540, 95, None, "observability@acme.io", "Datadog AWS integration",
        ["cloudwatch:*", "ec2:Describe*", "rds:Describe*", "s3:GetBucketTagging", "tag:GetResources", "support:*"],
        ["cloudwatch:GetMetricData", "ec2:DescribeInstances"],
    ),
    # ------------------------------------------------------------------ MEDIUM-ish
    (
        "github-actions-oidc", NHIType.IAM_ROLE, 300, 1, None, "devex@acme.io", "GitHub Actions deploy via OIDC",
        ["s3:PutObject", "cloudfront:CreateInvalidation"],
        ["s3:PutObject", "cloudfront:CreateInvalidation"],
    ),
    (
        "lambda-image-processor", NHIType.IAM_ROLE, 260, 0, None, "media@acme.io", "Resizes uploaded images",
        ["s3:GetObject", "s3:PutObject", "logs:PutLogEvents"],
        ["s3:GetObject", "s3:PutObject", "logs:PutLogEvents"],
    ),
    (
        "rds-snapshot-exporter", NHIType.IAM_ROLE, 410, 3, None, "data@acme.io", "Nightly RDS snapshot export",
        ["rds:CreateDBSnapshot", "rds:DescribeDBSnapshots", "s3:PutObject"],
        ["rds:CreateDBSnapshot", "s3:PutObject"],
    ),
    (
        "svc-prometheus", NHIType.IAM_USER, 480, 2, None, "sre@acme.io", "Prometheus CloudWatch exporter",
        ["cloudwatch:GetMetricData", "cloudwatch:ListMetrics", "ec2:DescribeTags"],
        ["cloudwatch:GetMetricData", "cloudwatch:ListMetrics"],
    ),
    (
        "ecs-task-web", NHIType.IAM_ROLE, 220, 0, None, "web@acme.io", "Web service task role",
        ["secretsmanager:GetSecretValue", "logs:PutLogEvents", "dynamodb:GetItem", "dynamodb:PutItem"],
        ["secretsmanager:GetSecretValue", "logs:PutLogEvents", "dynamodb:GetItem", "dynamodb:PutItem"],
    ),
    (
        "backup-vault-role", NHIType.IAM_ROLE, 350, 5, None, "infra@acme.io", "AWS Backup vault access",
        ["backup:*", "s3:GetObject"],
        ["backup:StartBackupJob"],
    ),
    (
        "svc-mailer", NHIType.IAM_USER, 600, 4, None, "growth@acme.io", "Transactional email via SES",
        ["ses:SendEmail", "ses:SendRawEmail"],
        ["ses:SendEmail"],
    ),
    (
        "athena-reporter", NHIType.IAM_ROLE, 290, 8, None, "analytics@acme.io", "Scheduled Athena reports",
        ["athena:*", "glue:GetTable", "s3:GetObject", "s3:PutObject"],
        ["athena:StartQueryExecution", "s3:GetObject"],
    ),
    # ------------------------------------------------------------------- LOW / INFO
    # Modern, short-lived, well-scoped credentials with owners + purpose + expiry.
    (
        "vault-agent-token", NHIType.AGENT_CREDENTIAL, 30, 0, 0.04, "platform@acme.io", "HashiCorp Vault agent",
        ["secretsmanager:GetSecretValue"],
        ["secretsmanager:GetSecretValue"],
    ),
    (
        "okta-scim-oauth", NHIType.OAUTH_GRANT, 120, 0, 14, "it@acme.io", "Okta SCIM provisioning grant",
        ["sso:ListInstances"],
        ["sso:ListInstances"],
    ),
    (
        "claude-agent-readonly", NHIType.AGENT_CREDENTIAL, 12, 0, 0.5, "ai@acme.io", "Read-only LLM agent session",
        ["s3:GetObject", "dynamodb:GetItem"],
        ["s3:GetObject", "dynamodb:GetItem"],
    ),
    (
        "svc-feature-flags", NHIType.SERVICE_ACCOUNT, 95, 1, 30, "product@acme.io", "Feature flag service",
        ["appconfig:GetConfiguration"],
        ["appconfig:GetConfiguration"],
    ),
    (
        "ci-preview-deployer", NHIType.IAM_ROLE, 60, 0, 7, "devex@acme.io", "Ephemeral PR preview deploys",
        ["s3:PutObject", "cloudfront:CreateInvalidation"],
        ["s3:PutObject", "cloudfront:CreateInvalidation"],
    ),
]


class DemoProvider(BaseProvider):
    """Returns the synthetic fixture as unscored identities."""

    name = "demo"

    def account_id(self) -> str:
        return DEMO_ACCOUNT

    def collect(self, progress_callback=None) -> ProviderResult:
        identities: list[NHIIdentity] = []
        for (
            name, nhi_type, created_days, last_used_days, expires_days,
            owner, purpose, granted, used,
        ) in _FIXTURE:
            unused = [p for p in granted if p not in used]
            identities.append(
                NHIIdentity(
                    id=f"aws:{DEMO_ACCOUNT}:{nhi_type.value}:{name}",
                    name=name,
                    nhi_type=nhi_type,
                    provider="demo",
                    account=DEMO_ACCOUNT,
                    created_at=_ago(created_days),
                    last_used_at=_ago(last_used_days),
                    expires_at=_ahead(expires_days),
                    owner=owner,
                    purpose=purpose,
                    granted_permissions=sorted(granted),
                    used_permissions=sorted(used),
                    unused_permissions=sorted(unused),
                )
            )

        if progress_callback:
            progress_callback("users", sum(1 for i in identities if i.nhi_type in (NHIType.IAM_USER, NHIType.SERVICE_ACCOUNT)))
            progress_callback("roles", sum(1 for i in identities if i.nhi_type == NHIType.IAM_ROLE))
            progress_callback("analyzer", None)
            progress_callback("cloudtrail", None)

        return ProviderResult(
            provider=self.name,
            account=DEMO_ACCOUNT,
            identities=identities,
            errors=[],
            warnings=[
                "DEMO MODE — synthetic data. No AWS account was contacted.",
            ],
        )
