# 👻 CredGhost

**Find every ghost key in your cloud.**

CredGhost is a read-only command-line tool that connects to your cloud account and produces a complete inventory and risk report of every *non-human identity* (NHI) you have — service accounts, API keys, IAM roles, access keys, and agent credentials. Think of it like a building security audit: it walks every door, tells you which keys still work, which ones nobody remembers cutting, and which open far more rooms than they should. Nothing is changed, nothing is unlocked — you just finally get the full list.

It answers four questions that no existing tool answers cleanly:

1. **What NHI credentials exist?** A full inventory across your account.
2. **Should they still exist?** Stale, orphaned, and ownerless detection.
3. **Are they over-privileged?** Granted permissions vs. permissions actually used.
4. **Can you prove revocation?** An evidence trail your auditors can read.

CredGhost is **read-only**, runs in **under 5 minutes**, and **nothing leaves your environment**.

---

## Install

```bash
pip install credghost
```

(Requires Python 3.11+.)

---

## Quick start

```bash
# 1. Make sure you have AWS credentials available (env vars, `aws configure`, or an IAM role)
aws sts get-caller-identity

# 2. See how bad your problem is in ~30 seconds
credghost check --provider aws

# 3. Run a full scan and generate an audit-ready HTML report
credghost scan --provider aws --output html --report-path credghost-report.html
```

That's it — zero infrastructure, no agent, no new credentials.

### No AWS account? Try the demo

See exactly what a report looks like against a realistic, messy organisation —
without touching any cloud:

```bash
credghost demo                       # full report in your terminal
credghost demo --output html --report-path demo.html   # audit-ready HTML
```

The demo uses built-in synthetic data and never contacts AWS.

---

## Required AWS permissions

CredGhost only needs **read-only** access. Print the exact IAM policy with:

```bash
credghost configure --provider aws --show-policy
```

The policy is also bundled at [`credghost/providers/aws/iam-policy.json`](credghost/providers/aws/iam-policy.json). Attach it to the user or role CredGhost runs as.

> One-click CloudFormation stack: _coming soon_ — `https://console.aws.amazon.com/cloudformation/...` _(placeholder)_

---

## Output examples

**Quick check**

```
CredGhost — Quick Check
━━━━━━━━━━━━━━━━━━━━━━━━

AWS Account: 123456789012

  Total NHIs found:          247
  Orphaned (no owner):        89  ← 36%
  Stale (>90 days unused):    61  ← 25%
  Over-privileged:           143  ← 58%

  🔴 Critical 12   🟠 High 44   🟡 Medium 91   🟢 Low 100
```

**Full scan** — Rich terminal tables of CRITICAL / HIGH / MEDIUM findings, plus recommended actions.

**HTML report** — _screenshot placeholder_ — a self-contained, print-to-PDF audit report with risk charts and expandable per-identity permission detail.

---

## What it detects

- Orphaned identities with no owner
- Stale credentials unused beyond your threshold (default 90 days)
- Identities that have **never** been used
- Over-privileged identities (granted ≫ used permissions)
- High-blast-radius access (IAM, S3, KMS, Secrets Manager, EC2, RDS)
- Credentials that never expire
- Unused-access findings corroborated by IAM Access Analyzer

---

## What it does **not** do

- ❌ **No write operations.** CredGhost never modifies, disables, or deletes anything.
- ❌ **No data leaves your environment.** All reads are live API calls; output is a local file or your terminal.
- ❌ **No agent installed.** Nothing is deployed into your account.

---

## Roadmap

- **Phase 2 (hosted tier):** continuous monitoring, additional providers (Okta, GitHub, Azure, GCP), agent-credential discovery, and remediation workflows.

---

## Contributing

Contributions welcome! Open an issue or PR. Set up a dev environment with:

```bash
pip install -e ".[dev]"
pytest
```

Run `ruff` and `black` before submitting.

---

## License

MIT © CredGhost contributors. See [LICENSE](LICENSE).
