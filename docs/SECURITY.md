# Security Model

## What Sealed Proves

Sealed v0.1 provides source-to-binary provenance for Python packages. When you run `sealed install <package>`, the system proves:

1. **Source authenticity.** The source archive was downloaded from PyPI and its SHA-256 hash matches PyPI's registry. If the download was tampered with in transit, the hash check fails. No hash from PyPI = no download (fail-closed).

2. **Environment attestation.** The build machine's state is measured: Python binary hash, pip version, OS kernel, CPU architecture, compiler versions, build-affecting environment variables. When TPM 2.0 hardware is available, boot PCR values are recorded and a hardware quote is obtained.

3. **Build provenance.** The binary artifact was built from that specific source, using a specific Python interpreter, on a measured machine. The environment fingerprint is hashed into the chain.

4. **Chain integrity.** Nobody modified any record in the provenance chain after it was signed. The Ed25519 signature covers the full chain hash, which includes every record, the environment, and the package identity.

5. **Artifact binding.** The artifact file on disk matches the hash recorded at build time. If the binary was modified after building (disk corruption, malware, MITM), verification fails.

6. **Key continuity.** TOFU key pinning detects signing key changes. If a package was previously signed by key A and a new seal uses key B, the install is blocked.

7. **Multi-party agreement.** When configured, multiple independent signers must verify a package before it is accepted.

## What Sealed Does NOT Prove

1. **Source code safety.** Sealed verifies the binary came from the source. It does not verify the source is safe. If the source contains a backdoor, Sealed will faithfully build and seal it.

2. **Full build environment integrity (without TPM).** Software attestation measures the environment but cannot prove it was not compromised. TPM attestation binds measurements to hardware.

3. **Reproducibility.** Two machines building the same package produce different chain hashes (different environments, timestamps). Sealed is a provenance system, not a reproducibility system.

4. **Key security.** The signing key is stored as a hex file on disk (`~/.sealed/key.ed25519`). It is not encrypted, not passphrase-protected, and not stored in a hardware security module.

## Threat Model

### Protected Against

| Threat | Mechanism |
|--------|-----------|
| PyPI mirror tampering | SHA-256 fail-closed verification |
| Download MITM | Hash check catches modified bytes |
| Post-build binary modification | Artifact hash in chain |
| Dependency confusion | Build from source catches unexpected code at build time |
| Chain tampering | Ed25519 signature over full chain hash detects any modification |
| Cross-package seal replay | Package name and version are hashed into the chain |
| Version replay | Different versions produce different chain hashes |
| Key compromise detection | TOFU pinning alerts on key change |
| Single point of trust | Multi-party N-of-M verification |
| Build env change detection | Environment attestation measurements in chain |

### NOT Protected Against

| Threat | Why | Planned Fix |
|--------|-----|-------------|
| Compromised build machine (no TPM) | Attacker controls key + build + chain | TPM attestation (available now when hardware exists) |
| Malicious source code | Sealed does not audit code | Out of scope (use code review tools) |
| Stolen signing key (use) | Key is plaintext on disk | HSM/keychain integration (future) |
| Compromised PyPI registry | If PyPI serves malicious source with correct hashes | Multi-source verification (future) |

## Key Management

The signing key is auto-generated on first use and stored at `~/.sealed/key.ed25519`. This is a 32-byte Ed25519 private key encoded as 64 hex characters.

**Recommendations:**
- Set file permissions to owner-only: `chmod 600 ~/.sealed/key.ed25519`
- Back up the key securely if you plan to share seals with others
- Generate separate keys for separate machines
- Never pass private key files to `--trusted-keys` (the CLI warns and rejects this)

## TOFU Key Pinning

Trust-on-first-use works like SSH `known_hosts`:

1. First time you see package X signed by key K, K is pinned to X
2. Next install of X: if signed by K, accepted. If signed by different key, blocked.
3. Manual override: `sealed registry revoke --key <old-key>` then re-pin

Key pins are stored in the SQLite registry and can be exported/imported for team sharing.

## Multi-Party Verification

Configure `sealed policy set --min-signatures N` to require N independent signers. Each team member builds and seals independently. Their seals are collected via `sealed registry export/import`. The policy engine counts unique signing keys before accepting a package.

## Reporting Vulnerabilities

If you find a security issue, email txshar@proton.me with details. Do not open a public issue for security vulnerabilities.
