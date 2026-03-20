# Secret Scanning in Restricted Environments: Vexil, Gitleaks, and TruffleHog Without Network Verification

## The question this document answers

You are evaluating secret scanners for an environment where outbound network
calls are forbidden or impossible. Which tool fits?

This is a different question from "which secret scanner is best." It excludes
GitGuardian (SaaS-only), GitHub Advanced Security (requires GitHub.com), and
TruffleHog's primary value proposition (live API verification). What remains
is a narrower field: tools that operate purely on static text.

Trivy is also excluded from this comparison. Trivy is a comprehensive
vulnerability and misconfiguration platform — its secret scanning is a
secondary feature within a larger ecosystem. Comparing Vexil to Trivy on
secret detection metrics is a category error. The relevant comparison is
between dedicated static secret scanners operating under the same constraint:
no outbound access.

---

## The three tools

|  | Gitleaks | TruffleHog (offline) | Vexil |
|---|---|---|---|
| **Primary design** | Fast, configurable regex scanner | Verification-first; degrades offline | Entropy-gated, air-gap native |
| **False positive model** | Allow-list / suppress via config | Verified = confirmed; unverified = noise | Mathematical gate; no lists required |
| **Offline precision** | Regex only | Collapses to regex | Entropy + structural validation |
| **Credential-class secrets** | Regex | Regex | Separate class; no entropy gate applied |
| **Compliance output** | None | None | ISO27001, NIS2, DORA, IEC62443 |
| **Git history scan** | Yes (`--no-git` inverts) | Yes | Yes (`--git-aware`) |
| **Static binary** | Yes | No (Python / container) | Yes |
| **External dependencies** | None | Python runtime or Docker | None |

---

## What each tool does well

**Gitleaks** is fast, widely deployed, and has extensive pattern coverage
(150+ patterns). In environments that can tolerate false positives managed
via `.gitleaks.toml`, it works well. The limitation is that precision depends
entirely on the quality of ignore configuration — there is no mathematical
model for distinguishing real secrets from placeholders. Every `your_api_key_here`
that matches a pattern requires a manual rule to suppress.

**TruffleHog** in connected environments is the most precise scanner
available. Live API verification means a "verified" finding is confirmed
active — not just a pattern match. In offline environments, verification
is disabled and all results return as `unverified`. The tool still runs,
but the feature that makes it precise does not exist. What remains is pattern
matching — functionally equivalent to a less configurable Gitleaks.

**Vexil** applies Shannon entropy as a mathematical gate before raising a
finding. `your_api_key_here` is discarded without configuration because its
entropy (~2.1 bits/char) is below the threshold for CSPRNG output. The
credential bifurcation — treating passwords and LDAP bind credentials
separately from generated tokens — addresses the structural limitation of
applying entropy uniformly to human-chosen strings. Compliance output
(ISO27001, NIS2, DORA, IEC62443 control references, blast radius,
offline-executable remediation steps) is generated deterministically from
each finding, requiring no network access.

---

## The honest trade-off

Vexil has fewer patterns than Gitleaks. This is deliberate. Each Vexil
pattern is validated against empirical entropy data to confirm the
false-positive model holds for that pattern class. Adding patterns without
that validation would undermine the mathematical guarantee that is Vexil's
primary differentiator.

The bet Vexil makes: in regulated environments, alert fatigue from
false positives is more operationally damaging than missing an obscure
credential type. A scanner that cries wolf on placeholder strings trains
developers to ignore findings. Eighteen high-confidence patterns with
no noise is a different product from 150 patterns requiring constant
ignore-list maintenance.

If your environment is connected, pattern breadth matters, and you can
maintain a `.gitleaks.toml`, Gitleaks is likely the right tool. If you
are in an air-gapped zone — OT/ICS, classified network, financial pipeline
with egress restrictions — where you cannot maintain ignore-lists and need
compliance-mapped output for audit cycles, Vexil is built for that
constraint.

If you need to confirm whether a found secret is currently active and
your environment has outbound access, TruffleHog's verified findings are
the highest-confidence signal available. Do not use TruffleHog in
air-gapped environments expecting that precision to carry over.

---

## What none of these tools cover

Gitleaks, TruffleHog, and Vexil all operate on the same threat: a developer
accidentally committing a credential into source control.

None of them detect:
- Secrets injected via a compromised build dependency
- Adversary activity in a pipeline that is already compromised
- Credentials exfiltrated from process memory or environment variables at runtime
- Supply chain intrusions like SolarWinds or 3CX, where the attack surface
  was the build system — not the source files

The detection surface for those scenarios is build system behaviour,
network telemetry, and binary integrity verification. A scanner that reads
text files is not the right instrument for those problems, regardless of
which one you choose.
