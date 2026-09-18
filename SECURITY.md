# Security policy

## This project’s purpose

CivicBaseline helps operators **find misconfigurations and missing baseline practices**. It must not become an attack toolkit. Pull requests that add exploits, credential-spraying, protocol fuzzing against live devices, or active PLC scanning will be rejected.

## Supported versions

The `main` branch and the latest tagged release are supported for security fixes.

## Reporting a vulnerability in CivicBaseline

If you find a flaw in the CLI, parsers, or report generator (path traversal when reading evidence, unsafe YAML, SSRF when fetching KEV, and similar):

1. **Do not** open a public issue with exploit details.
2. Email the maintainers listed in the latest release notes, or open a **private** GitHub security advisory.
3. Allow 90 days for a fix before public disclosure, unless the issue is already being exploited.

We will acknowledge within 5 business days.

## Using KEV and vulnerability data

The optional KEV matching feature only compares **identifiers** (CVE IDs) from an SBOM or local cache. CivicBaseline never ships exploit instructions. Keep KEV caches on a system that is allowed to reach `cisa.gov`, or vendor the JSON offline.

## Supply chain of this tool

Releases should be tagged, generate an SBOM for CivicBaseline itself, and (when maintainers enable it) be signed with Sigstore. See `docs/en/release-and-signing.md`.
