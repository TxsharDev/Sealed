# Quick Start

## Install

```bash
pip install alia-sealed
```

## Seal your first package

```bash
sealed install requests
```

That's it. Sealed just:
1. Resolved every dependency (urllib3, certifi, idna, charset-normalizer)
2. Downloaded source for each from PyPI
3. Scanned for dangerous patterns
4. Measured your build environment
5. Built each from source
6. Signed provenance chains with Ed25519
7. Checked trust policy
8. Installed verified artifacts

## Verify what you have

```bash
sealed audit
```

Shows every sealed package with its attestation method.

## Check trust

```bash
sealed trust requests
```

Shows your dependency tree with trust scores. Highlights the weakest link.

## What just happened under the hood

Every package now has three files in `~/.sealed/store/<package>-<version>/`:

- `seal.json` - Ed25519 signature over the provenance chain
- `chain.json` - 5-step provenance record (environment, audit, source, toolchain, build)
- `<package>.whl` - The artifact you installed

The seal binds source to binary. If anything was tampered with at any step, verification fails.
