"""Inventory engine — drives a provider, correlates findings, scores risk and
returns a :class:`ScanResult`.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

from credghost.engine.correlator import apply_unused_access_findings
from credghost.engine.scorer import score_all
from credghost.models.nhi import ScanResult
from credghost.providers.base import BaseProvider


def build_inventory(
    provider: BaseProvider,
    stale_threshold_days: int = 90,
    score: bool = True,
    progress_callback=None,
) -> ScanResult:
    """Run a provider end-to-end and produce a scored :class:`ScanResult`.

    Set ``score=False`` for the raw inventory command (no risk scoring).
    """
    start = time.monotonic()
    result = provider.collect(progress_callback=progress_callback)

    # Fold Access Analyzer findings the provider stored on raw payloads.
    # (Provider already attaches them; correlator is the cross-provider hook.)
    unused = {}
    for identity in result.identities:
        for finding in identity.raw.get("access_analyzer_findings", []):
            unused.setdefault(identity.id, []).append(finding)
    apply_unused_access_findings(result.identities, {})

    if score:
        score_all(result.identities, stale_threshold_days)

    duration = time.monotonic() - start

    return ScanResult(
        scan_id=str(uuid.uuid4()),
        scanned_at=datetime.now(timezone.utc),
        provider=result.provider,
        account=result.account,
        total_nhis=len(result.identities),
        identities=result.identities,
        errors=result.errors,
        warnings=result.warnings,
        scan_duration_seconds=round(duration, 2),
    )
