# AWS Provider

The AWS provider is the only provider shipped in Phase 1. It is **read-only** and
authenticates using the standard AWS credential chain (environment variables,
`~/.aws/credentials`, SSO, or an attached IAM role) — CredGhost never asks for
or stores credentials.

## What it collects

| Step | AWS API calls | Produces |
|------|---------------|----------|
| 1. Credential report | `GenerateCredentialReport`, `GetCredentialReport` | Per-user password & access-key last-used, MFA status |
| 2. IAM users | `ListUsers`, `ListAccessKeys`, `GetAccessKeyLastUsed`, `ListAttachedUserPolicies`, `ListUserPolicies` | One NHI per user + one per access key |
| 3. IAM roles | `ListRoles`, `ListAttachedRolePolicies`, `ListRolePolicies`, `GenerateServiceLastAccessedDetails`, `GetServiceLastAccessedDetails` | One NHI per customer role (service-linked roles filtered out) |
| 4. Access Analyzer | `ListAnalyzers`, `ListFindingsV2` | Unused-access findings correlated to identities |
| 5. CloudTrail (best effort) | `LookupEvents` | Recent `AssumeRole` activity for roles |

Service-linked roles (path beginning `/aws-service-role/`) are filtered out — they
are managed by AWS, not by you.

## Required IAM policy

Run `credghost configure --provider aws --show-policy` or see
[`../../credghost/providers/aws/iam-policy.json`](../../credghost/providers/aws/iam-policy.json).

## Graceful degradation

- **Missing permission** → the failing call is logged in `errors`; the scan continues.
- **Access Analyzer not configured** → warning emitted with the command to enable it; correlation skipped.
- **CloudTrail unavailable** → warning emitted; affected roles are marked
  *last-used-unknown* rather than *never used*.
- **Throttling** → exponential backoff, up to 3 retries.

## Over-privilege estimation

Granted permissions are extracted from attached managed policies and inline
policies. Usage is approximated from IAM *service-last-accessed* data at
service-namespace granularity: a granted action whose service was never
authenticated is counted as **unused**.
