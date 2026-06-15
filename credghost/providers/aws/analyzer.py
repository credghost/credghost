"""AWS IAM Access Analyzer — unused-access findings.

Maps UNUSED_ACCESS findings back to the IAM identities collected elsewhere so we
can confirm over-privilege and stale credentials. If no analyzer is configured,
we warn and skip gracefully.
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from credghost.providers.aws.client import (
    error_code,
    is_access_denied,
    with_backoff,
)


class AccessAnalyzerCollector:
    def __init__(self, analyzer_client, errors: list[str], warnings: list[str]):
        self.client = analyzer_client
        self.errors = errors
        self.warnings = warnings

    @with_backoff()
    def list_analyzer_arns(self) -> list[str]:
        arns: list[str] = []
        try:
            paginator = self.client.get_paginator("list_analyzers")
            for page in paginator.paginate():
                for analyzer in page.get("analyzers", []):
                    # Unused-access findings come from ACCOUNT_UNUSED_ACCESS type
                    # analyzers, but we accept any and filter findings by type.
                    arns.append(analyzer["arn"])
        except ClientError as exc:
            if is_access_denied(exc):
                self.errors.append(
                    "AccessDenied calling access-analyzer:ListAnalyzers — skipped"
                )
            else:
                # Region/SDK doesn't support Access Analyzer, etc. — never crash.
                self.warnings.append(
                    f"Access Analyzer unavailable ({error_code(exc)}) — skipped"
                )
            return []
        except Exception:  # pragma: no cover - defensive, never crash the scan
            self.warnings.append("Access Analyzer unavailable — skipped")
            return []
        return arns

    @with_backoff()
    def unused_access_findings(self, analyzer_arn: str) -> list[dict]:
        """Return UNUSED_ACCESS findings for one analyzer.

        Each finding is normalised to ``{"resource": str, "finding": dict}``.
        """
        findings: list[dict] = []
        try:
            paginator = self.client.get_paginator("list_findings_v2")
            pages = paginator.paginate(
                analyzerArn=analyzer_arn,
                filter={"findingType": {"eq": ["UnusedAccess"]}},
            )
            for page in pages:
                findings.extend(page.get("findings", []))
        except ClientError as exc:
            code = error_code(exc)
            if is_access_denied(exc):
                self.errors.append(
                    "AccessDenied calling access-analyzer:ListFindingsV2 — skipped"
                )
                return []
            # Older regions / SDKs may not support v2 filters.
            self.warnings.append(
                f"Access Analyzer findings unavailable ({code}) — skipped"
            )
            return []
        return findings

    def collect_unused_by_resource(self) -> dict[str, list[dict]]:
        """Aggregate unused-access findings keyed by resource ARN/id."""
        arns = self.list_analyzer_arns()
        if not arns:
            self.warnings.append(
                "No IAM Access Analyzer configured — unused-access correlation "
                "skipped. Enable it with `aws accessanalyzer create-analyzer "
                "--type ACCOUNT_UNUSED_ACCESS`."
            )
            return {}

        by_resource: dict[str, list[dict]] = {}
        for arn in arns:
            for finding in self.unused_access_findings(arn):
                resource = finding.get("resource") or finding.get("resourceArn") or ""
                by_resource.setdefault(resource, []).append(finding)
        return by_resource
