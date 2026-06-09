# ELDEN RING Live Demo Metrics

Generated: 2026-06-09 15:30 KST

## Executive Summary

The current live evidence is strongest when presented as a **repeatability and exploit-prevention result**, not as a broad multi-site benchmark.

- Tested live target sites: **1**
- Successfully remediated live sites: **1**
- Site-level remediation success rate: **100%**
- Certified scenario in this run: **SQL Injection / CWE-89**
- Core SQLi validation checks: **30 / 30 passed**
- Valid-login regression checks: **10 / 10 passed**
- Internal post-patch SQLi replay checks: **10 / 10 blocked**
- Public URL SQLi exploit attempts: **10 / 10 did not exploit successfully**

## Best Presentation Wording

> In the live demo environment, ELDEN RING successfully remediated the tested target site against SQL Injection. Across 30 repeated verification checks, valid user login continued to work, internal SQLi replay was blocked, and public replay attempts did not produce a successful exploit.

This avoids overstating the result as a large multi-site benchmark while still giving the audience a quantitative outcome.

## Site-Level Result

| Target site | Certified scenario | Initial exploit | LLM patch | Phase 3 validation | Deployment | Post-patch result |
| --- | --- | --- | --- | --- | --- | --- |
| `target-app` / `http://34.136.94.175` | SQL Injection / CWE-89 | Succeeded | Claude Code generated patch | Exploit, regression, SLO passed | Success | Internal replay blocked; public replay did not exploit |

## Repeated Validation Matrix

| Validation axis | Trials | Passed | Success rate | Evidence |
| --- | ---: | ---: | ---: | --- |
| Valid login regression | 10 | 10 | 100% | `demo/demo1234` stayed successful |
| SQLi replay block, internal compose network | 10 | 10 | 100% | Monitor confirmed patched state and replay blocked |
| SQLi replay, public URL exploit prevention | 10 | 10 | 100% | No attempt returned successful admin login |
| End-to-end remediation cycle | 1 | 1 | 100% | Runtime -> Claude patch -> Phase 3 -> deploy -> replay blocked |

## Evidence Snapshot

| Evidence | Value |
| --- | --- |
| Successful remediation incident | `evt-manual-b48201a7` |
| Secure Coding job | `sc-job-ccb903672ad3` |
| Patch ID | `patch-ee8776ddf067` |
| LLM provider | `claude_code` |
| Candidate image | `ghcr.io/mjsec-mju/elden-target-app:real-latest` |
| Phase 3 verdict | `exploit=PASSED`, `regression=PASSED`, `slo=PASSED` |
| Deploy result | `deploy success replay=blocked` |
| Current target state | `patched` |
| Internal SQLi replay | blocked, `HTTP 401`, `status=fail` |
| Later replay event | `blocked=true`, `requires_patch=false` |

## Current Scope Boundary

| Probe | Current result | Interpretation |
| --- | --- | --- |
| SQL Injection / CWE-89 | Success | Certified for this live run |
| Reflected XSS / CWE-79 | Not certified in this metrics snapshot | Should be run as a separate remediation cycle before claiming coverage |
| Path Traversal / CWE-22 | Not certified in this metrics snapshot | Should be run as a separate remediation cycle before claiming coverage |

## Interpretation

The latest complete run demonstrates the intended closed loop:

1. The vulnerable target accepted a SQL Injection payload.
2. Runtime Defense produced a CWE-89 remediation context.
3. Secure Coding invoked Claude Code and patched `login_handler`.
4. Recovery Assurance passed exploit, regression, and SLO checks.
5. The patched image was deployed.
6. Repeated replay checks confirmed that SQLi no longer produced a successful exploit.

The result should be presented as **one live target site, one certified vulnerability class, 30 repeated verification checks, 100% SQLi exploit-prevention success**.

## How To Upgrade This Into A Multi-Site Statistic

To honestly claim "N sites succeeded", repeat the same workflow for each target URL and add one row per target:

1. Roll back or deploy the target in a vulnerable baseline state.
2. Confirm exploit success before remediation.
3. Trigger ELDEN RING remediation.
4. Require Phase 3 exploit/regression/SLO to pass.
5. Deploy the patched target.
6. Run repeated replay checks and count the site only if replay is blocked.
