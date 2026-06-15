"""Config loading/saving for ~/.credghost/config.json.

Stores saved provider profiles so users don't repeat flags. Pure file I/O — no
secrets are stored (AWS credentials always come from the standard chain).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CONFIG_DIR = Path.home() / ".credghost"
CONFIG_PATH = CONFIG_DIR / "config.json"

DEFAULTS: dict[str, Any] = {
    "stale_after": 90,
    "profiles": {},  # name -> {provider, profile, region, stale_after, account_id}
}


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        return dict(DEFAULTS)
    try:
        data = json.loads(CONFIG_PATH.read_text())
    except (ValueError, OSError):
        return dict(DEFAULTS)
    merged = dict(DEFAULTS)
    merged.update(data)
    return merged


def save_config(config: dict) -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2))
    return CONFIG_PATH


def set_profile(
    name: str,
    provider: str,
    profile: str | None = None,
    region: str | None = None,
    stale_after: int = 90,
    account_id: str | None = None,
) -> Path:
    config = load_config()
    config.setdefault("profiles", {})[name] = {
        "provider": provider,
        "profile": profile,
        "region": region,
        "stale_after": stale_after,
        "account_id": account_id,
    }
    return save_config(config)


def get_profile(name: str) -> dict | None:
    return load_config().get("profiles", {}).get(name)


def policy_json_path() -> Path:
    """Path to the bundled read-only IAM policy JSON."""
    return Path(__file__).parent / "providers" / "aws" / "iam-policy.json"
