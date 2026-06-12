# Architecture

## Overview

Sealed is a ten-module Python library with a CLI entry point. The modules form a pipeline: attest, fetch, build, record, sign, verify, resolve, store, enforce.

```
 PyPI Registry
      |
      v
 [resolver.py]   DependencyResolver
      |            - Resolves transitive dependencies via pip
      |            - Topological sort (deps before dependents)
      v
 [attestation.py]  SoftwareAttestor / TPMAttestor
      |              - Measures: Python, pip, OS, CPU, compiler, env vars
      |              - TPM: PCR values + hardware quote (when available)
      v
 [source.py]  SourceFetcher
      |         - Downloads sdist from PyPI (rejects wheels)
      |         - SHA-256 fail-closed verification against PyPI digest
      |         - Extracts with path traversal protection (tar + zip)
      v
 [builder.py]  IsolatedBuilder
      |          - Builds wheel from source (pip wheel --no-binary :all:)
      |          - Records: env attestation + source hash + toolchain hash + artifact hash
      |          - Produces ProvenanceChain
      v
 [chain.py]  ProvenanceChain
      |        - Ordered list of ProvenanceRecords
      |        - BuildEnvironment fingerprint
      |        - chain_hash covers: package identity + environment + all records
      v
 [seal.py]  SealAuthority
      |       - Ed25519 key generation and persistence
      |       - Signs chain_hash, producing a Seal
      v
 [verify.py]  SealVerifier
      |         - Checks: stored hash, signature, trusted keys, artifact hash, chain links
      v
 [policy.py]  PolicyEngine
      |         - Checks: signature, TOFU pin, revocation, attestation level, multi-party
      v
 [registry.py]  SealRegistry
      |           - SQLite store for seals, chains, key pins, revocations
      |           - Export/import for team sharing
      v
 [cli.py]  CLI
             - install: resolve deps + build + attest + seal + verify + policy + install
             - build, verify, inspect, audit, keygen, registry, policy
```

## Data Flow: `sealed install requests`

```
1. _ensure_key()
   Check ~/.sealed/key.ed25519, generate if missing

2. DependencyResolver.resolve("requests")
   pip install --dry-run --report (file-based, avoids Windows encoding issues)
   Returns: [certifi, charset-normalizer, idna, urllib3, requests] (topo order)

3. For each package in order:

   a. SoftwareAttestor.attest() / TPMAttestor.attest()
      Measures 7 components, produces Attestation with digest

   b. SourceFetcher.fetch(package, version)
      GET PyPI JSON API, find sdist, download, SHA-256 verify (fail-closed)
      Extract with filter="data" (tar) or path traversal check (zip)

   c. IsolatedBuilder.build(source_dir, archive_hash, name, version)
      Record environment_attestation, source_verify, toolchain_capture, build

   d. SealAuthority.seal(chain)
      Ed25519 sign chain_hash

   e. SealVerifier.verify(seal_path, artifact, chain_path)
      Check stored hash, signature, artifact hash, chain links

   f. PolicyEngine.evaluate(seal, chain, attestation_method)
      Check signature, TOFU pin, revocation, attestation, multi-party

   g. SealRegistry.store(seal, chain, attestation_method)

4. pip install <all verified artifacts> --force-reinstall --no-deps
```

## File Storage

```
~/.sealed/
  key.ed25519              Ed25519 private key (hex)
  registry.db              SQLite database (seals, pins, revocations)
  policy.json              Trust policy config (optional)
  store/
    requests-2.32.3/
      seal.json            Seal (signature + metadata)
      chain.json           Full provenance chain
      requests-2.32.3-py3-none-any.whl
    certifi-2024.8.30/
      seal.json
      chain.json
      certifi-2024.8.30-py3-none-any.whl
```

## Provenance Chain Format

```json
{
  "package_name": "requests",
  "package_version": "2.32.3",
  "environment": {
    "python_version": "3.12.9 ...",
    "platform": "Windows-11-...",
    "architecture": "AMD64",
    "hostname": "dev-machine"
  },
  "records": [
    {"step": "environment_attestation", "input_hash": "...", "output_hash": "...",
     "metadata": {"method": "software", "measurements": {...}}},
    {"step": "source_verify", "input_hash": "archive_hash", "output_hash": "dir_hash"},
    {"step": "toolchain_capture", "input_hash": "python_hash", "output_hash": "python_hash"},
    {"step": "build", "input_hash": "dir_hash", "output_hash": "artifact_hash"}
  ],
  "chain_hash": "..."
}
```

## Verification Checks (in order)

1. **Chain integrity**: Recompute chain_hash from records, compare to stored hash
2. **Signature**: Verify Ed25519 signature over chain_hash
3. **Trusted keys** (optional): Check seal's public key is in the trusted set
4. **Artifact hash**: SHA-256 of artifact file matches build record's output_hash
5. **Chain links**: Build step's input_hash matches source_verify step's output_hash

## Policy Checks (in order)

1. **Signature**: Ed25519 verification
2. **Key pin (TOFU)**: First use pins, mismatch blocks
3. **Revocation**: Revoked keys rejected
4. **Attestation level**: Method must be in required list
5. **Multi-party**: Enough unique signers in registry

All checks must pass. Any failure = package rejected.
