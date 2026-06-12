# How It Works

## The Pipeline

```
PyPI Registry
    |
    v
[1] Environment Attestation
    Measure: Python binary, pip, OS, CPU, compiler, env vars
    TPM: extend PCR, get hardware quote
    |
    v
[2] Source Audit
    Pattern scan: shell injection, deserialization, dynamic imports
    Setup.py: install-time code execution
    CVE check: pip-audit integration
    |
    v
[3] Source Verification
    Download sdist, SHA-256 verify against PyPI (fail-closed)
    Extract with path traversal protection
    |
    v
[4] Toolchain Capture
    Hash the Python interpreter binary
    |
    v
[5] Build
    pip wheel --no-deps --no-binary :all:
    Record source hash -> artifact hash
    |
    v
[6] Sign
    Ed25519 over chain hash (covers all 5 steps + environment)
    |
    v
[7] Policy Check
    Signature valid? Key pinned? Key revoked? Attestation ok? Enough signers?
    |
    v
[8] Install
    pip install <verified artifact>
```

## The Chain Hash

```
H = SHA-256(package_name:version || env_canonical || R1 || R2 || ... || Rn)
```

The environment is hashed into the chain. If someone swaps the environment metadata after signing, the hash changes, the signature fails. Same for any record.

## What Gets Signed

The Ed25519 signature covers `H_chain`. That single hash covers everything: package identity, environment fingerprint, all 5 provenance records. One bit changed anywhere = signature invalid.

## What Gets Stored

```
~/.sealed/
  key.ed25519           Signing key (encrypted or OS keychain)
  registry.db           SQLite: seals, key pins, revocations
  transparency.db       Append-only hash-chained log
  policy.json           Trust policy config
  store/
    requests-2.32.3/
      seal.json
      chain.json
      requests-2.32.3-py3-none-any.whl
```
