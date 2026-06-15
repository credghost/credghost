"""AWS IAM data collection.

Each step from the build spec is a separate function/method:

* Step 1 — generate & pull the credential report
* Step 2 — list IAM users (+ access keys, key last-used, attached policies)
* Step 3 — list IAM roles (+ attached policies, service-last-accessed)

All calls degrade gracefully: a missing permission records an error and the
scan continues. Nothing here mutates AWS state.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

from botocore.exceptions import ClientError

from credghost.providers.aws.client import (
    error_code,
    is_access_denied,
    with_backoff,
)

# Path prefix for AWS-managed service-linked roles — we filter these OUT.
_AWS_SERVICE_ROLE_PREFIX = "/aws-service-role/"

# Max seconds to poll an async IAM job (last-accessed / credential report).
_POLL_TIMEOUT = 20
_POLL_INTERVAL = 1.0


class IAMCollector:
    """Pulls users, roles and policy permissions from one account."""

    def __init__(self, iam_client, errors: list[str], warnings: list[str]):
        self.iam = iam_client
        self.errors = errors
        self.warnings = warnings
        # Cache managed-policy documents so we don't re-fetch shared policies.
        self._policy_doc_cache: dict[str, list[str]] = {}

    # ------------------------------------------------------------------ helpers
    def _record_denied(self, call: str) -> None:
        self.errors.append(f"AccessDenied calling {call} — skipped, scan continued")

    # --------------------------------------------------- Step 1: credential report
    @with_backoff()
    def credential_report(self) -> list[dict]:
        """Generate (if needed) and parse the IAM credential report CSV.

        Returns one dict per row keyed by the CSV column headers.
        """
        try:
            # GenerateCredentialReport is async; poll until it stops reporting
            # STARTED. GetCredentialReport raises ReportNotPresent until ready.
            deadline = time.time() + _POLL_TIMEOUT
            while True:
                self.iam.generate_credential_report()
                try:
                    report = self.iam.get_credential_report()
                    break
                except ClientError as exc:
                    code = error_code(exc)
                    if code in ("ReportNotPresent", "ReportInProgress", "ReportExpired"):
                        if time.time() > deadline:
                            self.warnings.append(
                                "Credential report not ready in time — skipped"
                            )
                            return []
                        time.sleep(_POLL_INTERVAL)
                        continue
                    raise
        except ClientError as exc:
            if is_access_denied(exc):
                self._record_denied("iam:GetCredentialReport")
                return []
            raise

        return _parse_credential_report_csv(report["Content"])

    # ------------------------------------------------------- Step 2: list users
    @with_backoff()
    def list_users(self) -> list[dict]:
        users: list[dict] = []
        try:
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                users.extend(page.get("Users", []))
        except ClientError as exc:
            if is_access_denied(exc):
                self._record_denied("iam:ListUsers")
                return []
            raise
        return users

    @with_backoff()
    def access_keys_for_user(self, user_name: str) -> list[dict]:
        """Return access keys with their last-used metadata merged in."""
        keys: list[dict] = []
        try:
            paginator = self.iam.get_paginator("list_access_keys")
            for page in paginator.paginate(UserName=user_name):
                for key in page.get("AccessKeyMetadata", []):
                    key["LastUsed"] = self._access_key_last_used(key["AccessKeyId"])
                    keys.append(key)
        except ClientError as exc:
            if is_access_denied(exc):
                self._record_denied(f"iam:ListAccessKeys for {user_name}")
                return []
            raise
        return keys

    def _access_key_last_used(self, key_id: str) -> Optional[dict]:
        try:
            resp = self.iam.get_access_key_last_used(AccessKeyId=key_id)
            return resp.get("AccessKeyLastUsed")
        except ClientError as exc:
            if is_access_denied(exc):
                self._record_denied("iam:GetAccessKeyLastUsed")
                return None
            raise

    @with_backoff()
    def user_tags(self, user_name: str) -> list[dict]:
        try:
            resp = self.iam.list_user_tags(UserName=user_name)
            return resp.get("Tags", [])
        except ClientError as exc:
            if is_access_denied(exc):
                self._record_denied("iam:ListUserTags")
                return []
            raise
        except Exception:  # pragma: no cover - endpoint gaps; never crash
            return []

    @with_backoff()
    def role_tags(self, role_name: str) -> list[dict]:
        try:
            resp = self.iam.list_role_tags(RoleName=role_name)
            return resp.get("Tags", [])
        except ClientError as exc:
            if is_access_denied(exc):
                self._record_denied("iam:ListRoleTags")
                return []
            raise
        except Exception:  # pragma: no cover - endpoint gaps; never crash
            return []

    # ------------------------------------------------------- Step 3: list roles
    @with_backoff()
    def list_roles(self, include_service_roles: bool = False) -> list[dict]:
        roles: list[dict] = []
        try:
            paginator = self.iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    path = role.get("Path", "/")
                    if not include_service_roles and path.startswith(
                        _AWS_SERVICE_ROLE_PREFIX
                    ):
                        continue
                    roles.append(role)
        except ClientError as exc:
            if is_access_denied(exc):
                self._record_denied("iam:ListRoles")
                return []
            raise
        return roles

    # --------------------------------------------------------- policy expansion
    def user_permissions(self, user_name: str) -> list[str]:
        actions: set[str] = set()
        actions.update(self._attached_user_policy_actions(user_name))
        actions.update(self._inline_user_policy_actions(user_name))
        return sorted(actions)

    def role_permissions(self, role_name: str) -> list[str]:
        actions: set[str] = set()
        actions.update(self._attached_role_policy_actions(role_name))
        actions.update(self._inline_role_policy_actions(role_name))
        return sorted(actions)

    def _attached_user_policy_actions(self, user_name: str) -> set[str]:
        actions: set[str] = set()
        try:
            paginator = self.iam.get_paginator("list_attached_user_policies")
            for page in paginator.paginate(UserName=user_name):
                for pol in page.get("AttachedPolicies", []):
                    actions.update(self._managed_policy_actions(pol["PolicyArn"]))
        except ClientError as exc:
            if is_access_denied(exc):
                self._record_denied("iam:ListAttachedUserPolicies")
            else:
                raise
        return actions

    def _inline_user_policy_actions(self, user_name: str) -> set[str]:
        actions: set[str] = set()
        try:
            paginator = self.iam.get_paginator("list_user_policies")
            for page in paginator.paginate(UserName=user_name):
                for name in page.get("PolicyNames", []):
                    doc = self.iam.get_user_policy(
                        UserName=user_name, PolicyName=name
                    ).get("PolicyDocument")
                    actions.update(_actions_from_document(doc))
        except ClientError as exc:
            if is_access_denied(exc):
                self._record_denied("iam:ListUserPolicies")
            else:
                raise
        return actions

    def _attached_role_policy_actions(self, role_name: str) -> set[str]:
        actions: set[str] = set()
        try:
            paginator = self.iam.get_paginator("list_attached_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                for pol in page.get("AttachedPolicies", []):
                    actions.update(self._managed_policy_actions(pol["PolicyArn"]))
        except ClientError as exc:
            if is_access_denied(exc):
                self._record_denied("iam:ListAttachedRolePolicies")
            else:
                raise
        return actions

    def _inline_role_policy_actions(self, role_name: str) -> set[str]:
        actions: set[str] = set()
        try:
            paginator = self.iam.get_paginator("list_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                for name in page.get("PolicyNames", []):
                    doc = self.iam.get_role_policy(
                        RoleName=role_name, PolicyName=name
                    ).get("PolicyDocument")
                    actions.update(_actions_from_document(doc))
        except ClientError as exc:
            if is_access_denied(exc):
                self._record_denied("iam:ListRolePolicies")
            else:
                raise
        return actions

    @with_backoff()
    def _managed_policy_actions(self, policy_arn: str) -> list[str]:
        if policy_arn in self._policy_doc_cache:
            return self._policy_doc_cache[policy_arn]
        actions: set[str] = set()
        try:
            meta = self.iam.get_policy(PolicyArn=policy_arn)["Policy"]
            version_id = meta["DefaultVersionId"]
            doc = self.iam.get_policy_version(
                PolicyArn=policy_arn, VersionId=version_id
            )["PolicyVersion"]["Document"]
            actions.update(_actions_from_document(doc))
        except ClientError as exc:
            if is_access_denied(exc):
                self._record_denied("iam:GetPolicy/GetPolicyVersion")
            else:
                raise
        result = sorted(actions)
        self._policy_doc_cache[policy_arn] = result
        return result

    # --------------------------------------------- service-last-accessed (usage)
    def service_last_accessed(self, arn: str) -> dict[str, Optional[datetime]]:
        """Return ``{service_namespace: last_authenticated_datetime|None}``.

        Used to estimate which granted permissions were actually exercised.
        """
        try:
            job = self.iam.generate_service_last_accessed_details(Arn=arn)
            job_id = job["JobId"]
        except ClientError as exc:
            if is_access_denied(exc):
                self._record_denied("iam:GenerateServiceLastAccessedDetails")
                return {}
            raise
        except Exception:  # pragma: no cover - SDK/endpoint gaps; never crash
            msg = "Service-last-accessed unavailable — usage estimation skipped"
            if msg not in self.warnings:
                self.warnings.append(msg)
            return {}

        deadline = time.time() + _POLL_TIMEOUT
        services: dict[str, Optional[datetime]] = {}
        while True:
            try:
                resp = self.iam.get_service_last_accessed_details(JobId=job_id)
            except ClientError as exc:
                if is_access_denied(exc):
                    self._record_denied("iam:GetServiceLastAccessedDetails")
                    return {}
                raise
            status = resp.get("JobStatus")
            if status == "COMPLETED":
                for svc in resp.get("ServicesLastAccessed", []):
                    services[svc["ServiceNamespace"]] = svc.get("LastAuthenticated")
                return services
            if status == "FAILED":
                self.warnings.append(f"Service-last-accessed job failed for {arn}")
                return {}
            if time.time() > deadline:
                self.warnings.append(
                    f"Service-last-accessed timed out for {arn} — usage incomplete"
                )
                return services
            time.sleep(_POLL_INTERVAL)


# --------------------------------------------------------------------- parsing


def _parse_credential_report_csv(content: bytes) -> list[dict]:
    import csv
    import io

    text = content.decode("utf-8") if isinstance(content, bytes) else content
    reader = csv.DictReader(io.StringIO(text))
    return list(reader)


def _actions_from_document(doc) -> set[str]:
    """Extract Allow action strings from a policy document.

    Policy documents may arrive as dicts (boto3 decodes them) or URL-encoded
    JSON strings. Statements and actions can each be a string or a list.
    """
    import json
    from urllib.parse import unquote

    if doc is None:
        return set()
    if isinstance(doc, str):
        try:
            doc = json.loads(unquote(doc))
        except (ValueError, TypeError):
            return set()

    actions: set[str] = set()
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        acts = stmt.get("Action", [])
        if isinstance(acts, str):
            acts = [acts]
        actions.update(acts)
    return actions


def parse_iso(value) -> Optional[datetime]:
    """Best-effort parse of credential-report timestamp strings."""
    if value in (None, "", "N/A", "no_information", "not_supported"):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    from dateutil import parser as date_parser

    try:
        dt = date_parser.parse(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
