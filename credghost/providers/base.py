"""Abstract base provider class.

A provider is responsible for talking to one cloud/SaaS system and returning a
list of :class:`~credghost.models.nhi.NHIIdentity` objects plus any errors and
warnings encountered along the way. Providers must be read-only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from credghost.models.nhi import NHIIdentity


@dataclass
class ProviderResult:
    """Raw collection output before risk scoring is applied."""

    provider: str
    account: str
    identities: list[NHIIdentity] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class BaseProvider(ABC):
    """Every provider implements ``collect()`` and resolves an account id."""

    name: str = "base"

    @abstractmethod
    def collect(self, progress_callback=None) -> ProviderResult:
        """Collect every NHI from the provider. Must never raise on partial
        failure — degrade gracefully and record the problem in ``errors``/
        ``warnings``.

        ``progress_callback`` (optional) is called as
        ``progress_callback(stage: str, total: int | None)`` so the CLI can
        render progress bars.
        """
        raise NotImplementedError

    @abstractmethod
    def account_id(self) -> str:
        """Return the account / org identifier being scanned."""
        raise NotImplementedError
