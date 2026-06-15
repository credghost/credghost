"""CloudTrail enrichment (Step 5) — best-effort role-assumption recency.

If CloudTrail is unavailable we log a warning, skip, and the caller marks
affected NHIs as ``last_used_unknown`` rather than ``never used``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from credghost.providers.aws.client import is_access_denied, with_backoff


class CloudTrailEnricher:
    def __init__(self, cloudtrail_client, errors: list[str], warnings: list[str]):
        self.client = cloudtrail_client
        self.errors = errors
        self.warnings = warnings

    @with_backoff()
    def assume_role_recency(self, days: int = 90) -> dict[str, datetime]:
        """Return ``{role_name_or_arn: most_recent_assume_time}``.

        Best effort: scans AssumeRole events in the window. Returns an empty dict
        (and records a warning) if CloudTrail is disabled or denied.
        """
        start = datetime.now(timezone.utc) - timedelta(days=days)
        end = datetime.now(timezone.utc)
        recency: dict[str, datetime] = {}

        try:
            paginator = self.client.get_paginator("lookup_events")
            pages = paginator.paginate(
                LookupAttributes=[
                    {"AttributeKey": "EventName", "AttributeValue": "AssumeRole"}
                ],
                StartTime=start,
                EndTime=end,
            )
            for page in pages:
                for event in page.get("Events", []):
                    self._record_event(event, recency)
        except ClientError as exc:
            if is_access_denied(exc):
                self.warnings.append(
                    "CloudTrail not accessible — data-event analysis skipped. "
                    "Affected identities marked last-used-unknown."
                )
            else:
                self.warnings.append(
                    "CloudTrail not enabled — data-event analysis skipped. "
                    "Affected identities marked last-used-unknown."
                )
            return {}
        except Exception:  # pragma: no cover - defensive, never crash the scan
            self.warnings.append("CloudTrail enrichment failed — skipped.")
            return {}

        return recency

    @staticmethod
    def _record_event(event: dict, recency: dict[str, datetime]) -> None:
        event_time = event.get("EventTime")
        if not isinstance(event_time, datetime):
            return
        for resource in event.get("Resources", []):
            if resource.get("ResourceType") == "AWS::IAM::Role":
                name = resource.get("ResourceName", "")
                key = name.split("/")[-1] if name else name
                if key and (key not in recency or event_time > recency[key]):
                    recency[key] = event_time
