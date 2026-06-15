"""AWS provider — orchestrates IAM, Access Analyzer and CloudTrail collection
and maps everything onto the unified :class:`NHIIdentity` model.

Read-only. Degrades gracefully on every missing permission.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional

from credghost.models.nhi import NHIIdentity, NHIType
from credghost.providers.aws.analyzer import AccessAnalyzerCollector
from credghost.providers.aws.client import (
    CredentialsMissing,
    build_session,
    make_client,
    verify_credentials,
)
from credghost.providers.aws.credentials import CloudTrailEnricher
from credghost.providers.aws.iam import IAMCollector, parse_iso
from credghost.providers.base import BaseProvider, ProviderResult

ProgressCB = Optional[Callable[[str, Optional[int]], None]]


class AWSProvider(BaseProvider):
    name = "aws"

    def __init__(
        self,
        profile: str | None = None,
        region: str | None = None,
        account_id: str | None = None,
    ):
        self._profile = profile
        self._region = region
        self._account_override = account_id
        self._session = build_session(profile=profile, region=region)
        self._account = account_id

    def account_id(self) -> str:
        if self._account is None:
            self._account = verify_credentials(self._session)
        return self._account

    # ------------------------------------------------------------------ collect
    def collect(self, progress_callback: ProgressCB = None) -> ProviderResult:
        errors: list[str] = []
        warnings: list[str] = []

        # Resolve account first — fail loudly only if credentials are absent.
        try:
            account = self.account_id()
        except CredentialsMissing:
            raise

        iam = IAMCollector(make_client(self._session, "iam"), errors, warnings)
        analyzer = AccessAnalyzerCollector(
            make_client(self._session, "accessanalyzer"), errors, warnings
        )
        cloudtrail = CloudTrailEnricher(
            make_client(self._session, "cloudtrail"), errors, warnings
        )

        identities: list[NHIIdentity] = []

        # Step 1 — credential report (indexed by user for enrichment).
        cred_rows = {row.get("user"): row for row in iam.credential_report()}

        # Step 4 (pre-fetched) — Access Analyzer unused-access findings.
        unused_by_resource = analyzer.collect_unused_by_resource()

        # Step 5 (pre-fetched) — CloudTrail assume-role recency.
        ct_recency = cloudtrail.assume_role_recency()
        cloudtrail_available = bool(ct_recency) or not any(
            "CloudTrail not" in w for w in warnings
        )

        # Step 2 — users + access keys.
        users = iam.list_users()
        _notify(progress_callback, "users", len(users))
        for user in users:
            identities.extend(
                self._map_user(user, iam, cred_rows, account)
            )

        # Step 3 — roles.
        roles = iam.list_roles()
        _notify(progress_callback, "roles", len(roles))
        for role in roles:
            identities.append(
                self._map_role(role, iam, ct_recency, cloudtrail_available, account)
            )

        _notify(progress_callback, "analyzer", None)
        _notify(progress_callback, "cloudtrail", None)

        return ProviderResult(
            provider=self.name,
            account=account,
            identities=identities,
            errors=errors,
            warnings=warnings,
        )

    # --------------------------------------------------------------- user mapping
    def _map_user(
        self,
        user: dict,
        iam: IAMCollector,
        cred_rows: dict,
        account: str,
    ) -> list[NHIIdentity]:
        name = user["UserName"]
        granted = iam.user_permissions(name)
        used_services = _used_services(iam.service_last_accessed(user["Arn"]))
        used, unused = _split_permissions(granted, used_services)

        tags = user.get("Tags") or iam.user_tags(name)
        owner, purpose = _owner_and_purpose(tags)
        cred = cred_rows.get(name, {})

        last_used = _user_last_used(user, cred)

        user_identity = NHIIdentity(
            id=f"aws:{account}:user:{name}",
            name=name,
            nhi_type=NHIType.IAM_USER,
            provider="aws",
            account=account,
            created_at=_as_dt(user.get("CreateDate")),
            last_used_at=last_used,
            expires_at=None,  # IAM users never expire
            owner=owner,
            created_by=None,
            purpose=purpose,
            granted_permissions=granted,
            used_permissions=used,
            unused_permissions=unused,
            raw={"user": _jsonable(user), "credential_report": cred},
        )
        results = [user_identity]

        # Each access key becomes its own NHI (matches the spec's API-key rows).
        for key in iam.access_keys_for_user(name):
            key_id = key["AccessKeyId"]
            last = key.get("LastUsed") or {}
            results.append(
                NHIIdentity(
                    id=f"aws:{account}:access_key:{key_id}",
                    name=key_id,
                    nhi_type=NHIType.ACCESS_KEY,
                    provider="aws",
                    account=account,
                    created_at=_as_dt(key.get("CreateDate")),
                    last_used_at=_as_dt(last.get("LastUsedDate")),
                    expires_at=None,
                    owner=owner or name,
                    purpose=purpose,
                    granted_permissions=granted,
                    used_permissions=used,
                    unused_permissions=unused,
                    raw={"access_key": _jsonable(key)},
                )
            )
        return results

    # --------------------------------------------------------------- role mapping
    def _map_role(
        self,
        role: dict,
        iam: IAMCollector,
        ct_recency: dict,
        cloudtrail_available: bool,
        account: str,
    ) -> NHIIdentity:
        name = role["RoleName"]
        granted = iam.role_permissions(name)
        svc_accessed = iam.service_last_accessed(role["Arn"])
        used_services = _used_services(svc_accessed)
        used, unused = _split_permissions(granted, used_services)

        tags = role.get("Tags") or iam.role_tags(name)
        owner, purpose = _owner_and_purpose(tags)
        if not purpose and role.get("Description"):
            purpose = role["Description"]

        last_used = _role_last_used(role, svc_accessed, ct_recency)
        last_used_unknown = last_used is None and not cloudtrail_available

        return NHIIdentity(
            id=f"aws:{account}:role:{name}",
            name=name,
            nhi_type=NHIType.IAM_ROLE,
            provider="aws",
            account=account,
            created_at=_as_dt(role.get("CreateDate")),
            last_used_at=last_used,
            expires_at=None,  # IAM roles never expire
            owner=owner,
            purpose=purpose,
            granted_permissions=granted,
            used_permissions=used,
            unused_permissions=unused,
            last_used_unknown=last_used_unknown,
            raw={"role": _jsonable(role)},
        )


# ----------------------------------------------------------------------- helpers


def _notify(cb: ProgressCB, stage: str, total: Optional[int]) -> None:
    if cb is not None:
        cb(stage, total)


def _owner_and_purpose(tags: list[dict]) -> tuple[Optional[str], Optional[str]]:
    owner = None
    purpose = None
    for tag in tags or []:
        key = (tag.get("Key") or "").lower()
        val = tag.get("Value")
        if key in ("owner", "owner-email", "team", "contact"):
            owner = owner or val
        if key in ("purpose", "description", "use-case"):
            purpose = purpose or val
    return owner, purpose


def _used_services(svc_accessed: dict) -> set[str]:
    return {svc for svc, last in svc_accessed.items() if last is not None}


def _split_permissions(
    granted: list[str], used_services: set[str]
) -> tuple[list[str], list[str]]:
    """Approximate used vs unused permissions at service-namespace granularity."""
    used: list[str] = []
    unused: list[str] = []
    for action in granted:
        service = action.split(":", 1)[0].lower() if ":" in action else action.lower()
        # "*" grants everything — count as used only if anything was accessed.
        if action == "*":
            (used if used_services else unused).append(action)
        elif service in used_services:
            used.append(action)
        else:
            unused.append(action)
    return used, unused


def _user_last_used(user: dict, cred: dict) -> Optional[datetime]:
    candidates: list[datetime] = []
    pwd = _as_dt(user.get("PasswordLastUsed"))
    if pwd:
        candidates.append(pwd)
    for col in (
        "password_last_used",
        "access_key_1_last_used_date",
        "access_key_2_last_used_date",
    ):
        dt = parse_iso(cred.get(col))
        if dt:
            candidates.append(dt)
    return max(candidates) if candidates else None


def _role_last_used(role: dict, svc_accessed: dict, ct_recency: dict) -> Optional[datetime]:
    candidates: list[datetime] = []
    role_last = role.get("RoleLastUsed", {}).get("LastUsedDate")
    if role_last:
        candidates.append(_as_dt(role_last))
    for last in svc_accessed.values():
        if last is not None:
            candidates.append(_as_dt(last))
    ct = ct_recency.get(role["RoleName"])
    if ct:
        candidates.append(_as_dt(ct))
    candidates = [c for c in candidates if c is not None]
    return max(candidates) if candidates else None


def _as_dt(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return parse_iso(value)


def _jsonable(obj):
    """Make a boto3 response safe to embed in JSON (datetimes -> ISO)."""
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj
