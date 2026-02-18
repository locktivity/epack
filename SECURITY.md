# Security Policy

## Reporting a Vulnerability

Do not open public issues for suspected vulnerabilities.

Report vulnerabilities to:

**security@locktivity.com**

Please include:
- Description of the vulnerability
- Steps to reproduce
- Affected commit/version
- Potential impact and attacker prerequisites
- Minimal proof-of-concept, logs, or payloads when possible

## Response Timeline

- Initial triage acknowledgement: within 48 hours
- Severity assessment: within 7 days
- Remediation target:
  - Critical: 7 days
  - High: 30 days
  - Medium/Low: next planned release or documented risk acceptance

## Scope

This policy covers:
- CLI and library code in this repository
- Pack integrity/signature verification logic
- Collector dependency resolution, binary sync, lockfile handling, and runner behavior
- Unsafe-defaults, trust-boundary bypasses, path traversal, command execution, and secret leakage bugs

## Out of Scope

- Vulnerabilities in third-party dependencies with no exploitable path in epack itself
- Reports without actionable reproduction details
- Social engineering, phishing, or physical access attacks
- Denial-of-service requiring unrealistic resources or privileged local access

## Safe Harbor

If you follow this policy in good faith, we will not pursue legal action for your research.
Testing must:

- Avoid privacy violations and data destruction
- Avoid service disruption
- Use only accounts/systems you own or have explicit permission to test

## Disclosure

We follow coordinated disclosure.

- Do not publish details until a fix or mitigation is available.
- We may request an embargo period to protect users.
- After release, we will credit researchers who want attribution.

## Recognition

We appreciate security reports that are specific, reproducible, and adversarially validated.
