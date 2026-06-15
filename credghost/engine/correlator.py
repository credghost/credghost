"""Cross-system correlation.

Phase 1 has a single provider (AWS), so correlation is light: fold Access
Analyzer unused-access findings into the matching identities. The interface is
built to extend across providers in Phase 2.
"""

from __future__ import annotations

from credghost.models.nhi import NHIIdentity


def apply_unused_access_findings(
    identities: list[NHIIdentity], unused_by_resource: dict[str, list[dict]]
) -> None:
    """Annotate identities that have UNUSED_ACCESS findings.

    Findings are keyed by resource ARN; we match on the identity name appearing
    in the resource string (roles/users). Recorded as a risk reason hint stored
    on the raw payload so the scorer can pick it up.
    """
    if not unused_by_resource:
        return
    for identity in identities:
        for resource, findings in unused_by_resource.items():
            if identity.name and identity.name in (resource or ""):
                identity.raw.setdefault("access_analyzer_findings", []).extend(findings)
