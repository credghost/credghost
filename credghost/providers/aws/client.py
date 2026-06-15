"""AWS session / client helpers with retry and graceful auth handling."""

from __future__ import annotations

import time
from functools import wraps

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError

# boto3's built-in adaptive retries plus our own wrapper on top.
_BOTO_CONFIG = Config(retries={"max_attempts": 3, "mode": "adaptive"})

# Error codes we treat as "permission missing" — log and continue, never crash.
ACCESS_DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
}

# Error codes that mean "throttled" — back off and retry.
THROTTLE_CODES = {
    "Throttling",
    "ThrottlingException",
    "ThrottledException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
}


class CredentialsMissing(Exception):
    """Raised when no usable AWS credentials are found."""


def build_session(
    profile: str | None = None, region: str | None = None
) -> boto3.Session:
    """Build a boto3 session from existing credentials (env, ~/.aws, IAM role)."""
    try:
        if profile:
            return boto3.Session(profile_name=profile, region_name=region)
        return boto3.Session(region_name=region)
    except Exception as exc:  # pragma: no cover - profile resolution errors
        raise CredentialsMissing(str(exc)) from exc


def make_client(session: boto3.Session, service: str):
    return session.client(service, config=_BOTO_CONFIG)


def is_access_denied(exc: Exception) -> bool:
    return (
        isinstance(exc, ClientError)
        and exc.response.get("Error", {}).get("Code") in ACCESS_DENIED_CODES
    )


def error_code(exc: Exception) -> str | None:
    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code")
    return None


def with_backoff(max_retries: int = 3, base_delay: float = 1.0):
    """Decorator: exponential backoff on throttling errors (max 3 retries)."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            attempt = 0
            while True:
                try:
                    return fn(*args, **kwargs)
                except ClientError as exc:
                    code = error_code(exc)
                    if code in THROTTLE_CODES and attempt < max_retries:
                        time.sleep(base_delay * (2**attempt))
                        attempt += 1
                        continue
                    raise

        return wrapper

    return decorator


def verify_credentials(session: boto3.Session) -> str:
    """Confirm credentials resolve and return the account id."""
    try:
        sts = session.client("sts", config=_BOTO_CONFIG)
        return sts.get_caller_identity()["Account"]
    except NoCredentialsError as exc:
        raise CredentialsMissing(
            "No AWS credentials found. Configure them via environment variables, "
            "`aws configure`, or an attached IAM role. "
            "See https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html"
        ) from exc
    except ClientError as exc:
        raise CredentialsMissing(
            f"AWS credentials present but rejected: {error_code(exc)}"
        ) from exc
