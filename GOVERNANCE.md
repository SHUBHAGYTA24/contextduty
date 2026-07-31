# Governance

This document describes how ContextDuty is governed, who holds privileged
access, and the roles and responsibilities within the project.

## Project members and roles

ContextDuty is currently maintained by a single maintainer. Roles are defined
so they can scale as the project grows.

| Role | Current holder | Responsibilities |
|---|---|---|
| **Maintainer / Lead** | Shubhagyta Swaraj Jayswal ([@SHUBHAGYTA24](https://github.com/SHUBHAGYTA24)) | Overall direction, final review and merge authority, releases, security response, and administration of all sensitive resources below. |
| **Contributors** | Community (via pull requests) | Propose changes via PRs under the [CLA](CLA.md) and [CONTRIBUTING](CONTRIBUTING.md). No standing privileged access. |
| **Security contact** | Shubhagyta Swaraj Jayswal | Receives and triages vulnerability reports per [SECURITY.md](SECURITY.md). |

## Members with access to sensitive resources

The following resources are access-controlled. Access is limited to the
maintainer(s) listed above and is protected by two-factor authentication.

| Resource | Who has access | Protection |
|---|---|---|
| GitHub repository (admin) | Maintainer | GitHub 2FA required |
| `main` branch | No direct write (all changes via PR) | Branch protection; PR required |
| PyPI project `contextduty` | Maintainer | 2FA; OIDC trusted publishing (no long-lived token in CI) |
| Release signing | GitHub Actions (keyless, per-run OIDC) | Sigstore; no stored private key |
| Hugging Face Space (demo) | Maintainer | HF account credentials |

New maintainers are added only by the current maintainer, with the lowest
privilege required for their role, and must have 2FA enabled.

## Decision making

- Routine changes (bug fixes, docs, detectors) are merged by the maintainer
  after review and passing CI.
- Significant changes (architecture, licensing, security-relevant behavior) are
  discussed publicly in a GitHub Issue or Pull Request before merge.
- The maintainer holds final decision authority until a broader governance
  structure is warranted by project growth.

## Becoming a maintainer

Contributors who demonstrate sustained, high-quality contributions and good
judgment may be invited to become maintainers. This document will be updated to
reflect any change in membership.

## Changes to this document

Governance changes are made via pull request to this file and take effect when
merged.
