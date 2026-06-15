# Testing CredGhost against realistic data

You don't always have a production-grade AWS account to scan. Here are three
ways to exercise CredGhost, from zero-setup to fully realistic.

## 1. Built-in demo (no AWS account)

```bash
credghost demo
credghost demo --output html --report-path demo.html
```

Uses a synthetic, *relatively-dated* organisation (orphaned keys, stale roles,
over-privileged CI runners, plus well-scoped modern credentials). Dates are
stored relative to "now", so the dataset always looks aged. Best for
screenshots, sales demos, and exercising the risk engine offline.

**Limitation:** it's synthetic, so it proves the *engine*, not your AWS
integration.

## 2. CloudGoat — realistic *misconfiguration* in a real account

[CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) deploys
intentionally vulnerable, over-privileged IAM into a throwaway AWS account via
Terraform. Over-privilege and orphaning don't depend on time, so this is the
best way to validate real detections cheaply.

```bash
# In a sandbox/free-tier AWS account — NOT production
git clone https://github.com/RhinoSecurityLabs/cloudgoat
cd cloudgoat && pip install -r requirements.txt
./cloudgoat.py create iam_privesc_by_rotation   # or any scenario

# Then scan it
credghost scan --provider aws --output html --report-path cloudgoat.html

# Always tear it down to avoid charges
./cloudgoat.py destroy iam_privesc_by_rotation
```

Other deliberately-vulnerable labs that work the same way: **AWSGoat**,
**sadcloud**, **flaws.cloud**.

**Limitation:** freshly-created resources have recent `CreateDate`s, so
staleness ("unused for 800 days") still won't trigger — see below.

## 3. The staleness caveat

You **cannot backdate** `CreateDate` or last-used timestamps in AWS. A
freshly-built test account always looks young, so time-based detections (stale,
"never used in N days") can only be exercised with the demo dataset (option 1)
or against a genuinely old real account. Over-privilege, orphaning, blast
radius, and never-expiring detections work fine on any account.
