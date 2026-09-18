# Signed releases and SBOM of this tool

CivicBaseline should meet the same supply-chain bar it asks of operators.

## Every tagged release

1. `git tag v0.1.x` and push tags.
2. GitHub Actions workflow `.github/workflows/release.yml` runs `scripts/release_artifacts.py`, which writes:
   - `impact-snapshot.json` (pack coverage)
   - `civicbaseline.cdx.json` (stub CycloneDX of this CLI)
3. Attach those files to the GitHub Release.
4. Prefer generating a full SBOM with [Syft](https://github.com/anchore/syft) or cdxgen when the release is public:

```bash
syft . -o cyclonedx-json=dist/civicbaseline.cdx.json
```

## Sigstore (maintainers)

When publishing to GitHub Releases, sign the sdist/wheel and the SBOM:

```bash
cosign sign-blob dist/civicbaseline.cdx.json --output-signature dist/civicbaseline.cdx.json.sig
```

Use the `id-token: write` permission already present on the release workflow. Document verification in the release notes:

```bash
cosign verify-blob dist/civicbaseline.cdx.json --signature dist/civicbaseline.cdx.json.sig
```

Exact OIDC flags depend on the GitHub / Sigstore flow in use at release time; do not commit long-lived signing keys.

## SLSA-oriented notes

- Builds happen in GitHub Actions, not on a laptop.
- Dependencies are pinned in spirit by publishing the SBOM next to the tag.
- Provenance can be added later with `slsa-github-generator`; it is not required for v0.1.0.

## Operator verification

Tell operators to prefer tagged releases over random commits, and to read [ACCEPTABLE_USE.md](../../ACCEPTABLE_USE.md) before pointing the tool at their evidence directory.
