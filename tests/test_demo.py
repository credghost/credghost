"""Demo provider tests — no AWS, deterministic-ish distribution."""

from credghost.engine.inventory import build_inventory
from credghost.models.nhi import RiskLevel
from credghost.providers.demo import DemoProvider


def test_demo_produces_a_realistic_spread():
    result = build_inventory(DemoProvider(), stale_threshold_days=90)
    by_risk = result.by_risk()

    # Every risk band should be represented so screenshots look real.
    assert by_risk["critical"] >= 1
    assert by_risk["high"] >= 1
    assert by_risk["medium"] >= 1
    assert by_risk["low"] + by_risk["info"] >= 1

    # Summary counters are sane.
    assert result.total_nhis == len(result.identities)
    assert result.orphaned >= 1
    assert result.over_privileged >= 1
    assert result.never_used >= 1


def test_demo_is_offline_and_self_labelled():
    result = build_inventory(DemoProvider(), stale_threshold_days=90)
    assert any("DEMO MODE" in w for w in result.warnings)
    assert result.provider == "demo"
    assert result.errors == []


def test_demo_short_lived_creds_are_low_risk():
    result = build_inventory(DemoProvider(), stale_threshold_days=90)
    agent = next(i for i in result.identities if i.name == "vault-agent-token")
    assert agent.risk_level in (RiskLevel.INFO, RiskLevel.LOW)
