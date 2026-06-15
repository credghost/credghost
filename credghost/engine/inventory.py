"""Inventory engine — drives a provider, correlates findings, scores risk and
returns a :class:`ScanResult`.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

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
    # Providers correlate their own findings (e.g. Access Analyzer) onto
    # identities during collect(); here we just score and package the result.
    result = provider.collect(progress_callback=progress_callback)

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
