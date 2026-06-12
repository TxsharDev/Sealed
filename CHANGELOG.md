# Changelog

## v0.1.0 (2026-06-11)

Initial release. Full-stack supply chain attestation in one command.

**Core Pipeline:**
- `sealed install <package>`: resolve deps, build each from source, audit, attest, seal, verify, policy check, install
- `sealed build <package>`: build and seal without installing
- `sealed verify`: verify a sealed artifact (signature + chain + artifact hash + chain links)
- `sealed inspect`: print seal or chain contents
- `sealed audit`: list all sealed packages with attestation method
- `sealed reproduce <package>`: build twice and compare for reproducibility

**5-Step Provenance Chain:**
- Environment attestation: Python, pip, OS, CPU, compiler, env vars, TPM PCRs
- Source audit: pattern scan (dangerous calls), setup.py analysis, CVE check (pip-audit)
- Source verification: SHA-256 fail-closed against PyPI registry
- Toolchain capture: Python interpreter hash
- Build: source dir hash to artifact hash

**Environment Attestation:**
- Software attestation: 7 measured components hashed into chain
- TPM 2.0 attestation: PCR values + hardware quote (when tpm2-tools available)

**Source Code Safety:**
- Pattern scanner: detects dangerous calls in source before building
- Setup.py analyzer: detects install-time code execution
- CVE check: pip-audit integration (when installed)
- Audit results recorded in provenance chain as `source_audit` step

**Encrypted Key Storage:**
- PBKDF2 key derivation (100K iterations) + NaCl SecretBox encryption
- Passphrase-protected keys via `sealed keygen --passphrase`
- Auto-prompts on first use (interactive terminals)
- chmod 600 on Unix, backwards compatible with plaintext keys

**Reproducibility Verification:**
- `sealed reproduce <package>`: builds twice from same source, compares
- Wheel diff: file-by-file content comparison
- Normalized comparison: strips RECORD/timestamps, checks content identity
- Reports exact differences when builds diverge

**Recursive Dependency Sealing:**
- Topological dependency resolution via `pip install --dry-run --report`
- All transitive dependencies sealed, not just top-level
- Skip already-sealed packages in local store
- `--no-deps` flag for single-package mode

**Shared Registry:**
- SQLite-backed seal and chain storage
- Export/import seals with signature verification on import
- Export/import key pins
- Query by package, version, or signing key

**Trust-on-First-Use (TOFU) Key Pinning:**
- Auto-pin signing key on first encounter
- Key pinning deferred until ALL policy checks pass (prevents pin poisoning)
- Key mismatch detection and rejection
- Manual key pinning and revocation with reason tracking

**Multi-Party Verification:**
- Configurable `min_signatures` policy
- Multiple independent signers stored per package-version
- N-of-M verification

**Trust Policy Engine:**
- `sealed policy show/set/reset` CLI
- Configurable: min signatures, TOFU toggle, pin enforcement, attestation requirements
- Policy evaluated on every install

**Security Hardening:**
- Python 3.10+ compatible tarfile extraction (manual path check on <3.12, filter="data" on 3.12+)
- Zip path traversal protection
- Symlink skipping in directory hashing
- Specific exception handling in crypto verification
- Private key rejection in trusted-key CLI
- Seal.from_dict filters unknown keys (prevents crash on extra fields)
- Registry close on all exit paths (no resource leaks)

**Testing:**
- 213 tests, 3 skipped (Windows symlinks)
- Coverage: chain, seal, verify, attestation, source audit, keystore, reproducibility, registry, key pinning, revocation, multi-party, policy, dependency resolution, edge cases, integration
