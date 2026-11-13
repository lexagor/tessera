# Supply-Chain Security

**Status:** image signing, CodeQL, Scorecard, SBOM, provenance, and digest pinning are configured.
GitHub Actions must be enabled for the new workflows before they appear in branch protection.
Branch protection is currently a recommended follow-up; see the internal security assessment.

## Controls

| Control | Implementation |
|---|---|
| Immutable deployment | Live `TESSERA_*_IMAGE` values point to `@sha256:...` digests |
| Build provenance | Buildx provenance + SBOM enabled in `images.yml` |
| Image signature | Keyless cosign OIDC signature for every published image digest |
| Signature verification | `infra/scripts/verify-images.sh <release-manifest.json>` |
| SBOM | `.github/workflows/sbom.yml` and buildx SBOM |
| Static analysis | CodeQL `security-and-quality` for JavaScript/TypeScript |
| Repository posture | OpenSSF Scorecard SARIF upload |
| Dependency review | `dependency-review-action` on pull requests |
| Rust/npm audits | `cargo-audit`, `cargo-deny`, `pnpm audit --prod` |
| Action pinning | Every workflow action is pinned to a commit SHA |
| Release record | `infra/releases/<commit>.json` with digests, migrations, checks |

## Verify a release

```bash
cosign verify \
  --certificate-identity 'https://github.com/lexagor/tessera/.github/workflows/images.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/lexagor/tessera-api@sha256:...
```

Or verify every image in a release manifest:

```bash
infra/scripts/verify-images.sh infra/releases/2989db82.json
```

Cosign can also inspect the transparency log and SBOM attestations. Do not deploy an unsigned
digest or a digest whose signature identity is not the expected repository/workflow/ref.

## Limits

- A valid signature proves which workflow built the image, not that the code is vulnerability-free.
- Keyless signing depends on GitHub OIDC and the public transparency log.
- Scorecard is a posture signal, not a compliance certification.
- The `828c8b9f` live API/portal/site digests were signed by the keyless workflow; verify the
  signatures before the next deploy and after every image update.
