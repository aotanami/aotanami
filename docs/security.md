---
title: Security Policy
---

# Security Policy

## Reporting a Vulnerability

The Zelyo Operator team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

**Please do NOT report security vulnerabilities through public GitHub issues.**

### How to Report

Send an email to **[security@zelyo.ai](mailto:security@zelyo.ai)** with the following details:

- **Description** of the vulnerability
- **Steps to reproduce** (proof of concept if possible)
- **Impact assessment** — what an attacker could achieve
- **Affected versions** (if known)

### What to Expect

| Step | Timeline |
|---|---|
| Acknowledgment | Within **48 hours** |
| Initial assessment | Within **5 business days** |
| Fix timeline communicated | Within **10 business days** |
| Security advisory published | Upon fix release |

### Scope

The following are in scope:

- Zelyo Operator binary and container images
- Helm chart and Kubernetes manifests
- Dashboard and REST API
- CRD validation and webhook logic
- LLM integration and API key handling

### Out of Scope

- Third-party dependencies (report upstream, but let us know)
- Issues in Kubernetes itself
- Social engineering attacks

## Supported Versions

| Version | Supported |
|---|---|
| Latest release | ✅ |
| Previous minor | ✅ (security fixes only) |
| Older versions | ❌ |

## Security Best Practices

When deploying Zelyo Operator:

1. **Store API keys in Kubernetes Secrets** — never in ConfigMaps or environment variables directly
2. **Use network policies** to restrict Zelyo Operator's egress to only required endpoints
3. **Enable RBAC** — Zelyo Operator uses read-only cluster access by design
4. **Verify image signatures** using Cosign before deployment
5. **Review SBOMs** attached to each release for supply chain transparency

## Acknowledgments

We gratefully acknowledge security researchers who help keep Zelyo Operator and its users safe. With your permission, we will acknowledge your contribution in our security advisories.
