# CLI Reference

## sealed install

Build from source, seal, verify, and install a package with all dependencies.

```bash
sealed install <package> [--version VERSION] [--no-deps]
```

| Flag | Description |
|------|-------------|
| `--version, -v` | Install specific version |
| `--no-deps` | Skip transitive dependency sealing |

## sealed build

Build and seal without installing.

```bash
sealed build <package> [--version VERSION]
```

## sealed verify

Verify a sealed artifact.

```bash
sealed verify <seal.json> [--artifact FILE] [--chain FILE] [--trusted-keys FILE...]
```

| Flag | Description |
|------|-------------|
| `--artifact, -a` | Artifact file to verify hash |
| `--chain, -c` | Chain JSON file |
| `--trusted-keys, -t` | Public key files (.pub) |

## sealed inspect

Print contents of a seal or chain file.

```bash
sealed inspect <seal.json or chain.json>
```

## sealed audit

List all sealed packages with attestation method.

```bash
sealed audit
```

## sealed keygen

Generate a new Ed25519 signing key.

```bash
sealed keygen [--output FILE] [--force] [--passphrase]
```

| Flag | Description |
|------|-------------|
| `--output, -o` | Key file path (default: ~/.sealed/key.ed25519) |
| `--force, -f` | Overwrite existing key |
| `--passphrase, -p` | Encrypt with passphrase |

## sealed reproduce

Check if a package builds reproducibly.

```bash
sealed reproduce <package> [--version VERSION]
```

Builds twice from the same source, compares outputs raw and normalized.

## sealed sandbox

Behavioral analysis: import a package in an isolated process and monitor activity.

```bash
sealed sandbox <package> [--version VERSION] [--timeout SECONDS]
```

| Flag | Description |
|------|-------------|
| `--timeout, -t` | Timeout in seconds (default: 30) |

## sealed consensus

Build N times independently, check for majority agreement.

```bash
sealed consensus <package> [--version VERSION] [--num-builds N] [--threshold FLOAT]
```

| Flag | Description |
|------|-------------|
| `--num-builds, -n` | Number of builds (default: 3) |
| `--threshold` | Agreement threshold 0.0-1.0 (default: 0.67) |

## sealed watchdog

Runtime integrity verification.

```bash
sealed watchdog check [--package NAME]
sealed watchdog list
```

| Action | Description |
|--------|-------------|
| `check` | Verify installed files against snapshots |
| `list` | List all snapshots |

## sealed trust

Trust graph with weak-link analysis.

```bash
sealed trust <package> [--version VERSION] [--json]
```

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |

## sealed registry

Registry operations for team sharing.

```bash
sealed registry export [-o FILE]
sealed registry import [-i FILE]
sealed registry pins
sealed registry export-pins [-o FILE]
sealed registry import-pins [-i FILE]
sealed registry revoke --key KEY [--reason TEXT]
```

## sealed policy

Trust policy configuration.

```bash
sealed policy show
sealed policy set [--min-signatures N] [--tofu true/false] [--enforce-pins true/false] [--require-attestation METHOD...]
sealed policy reset
```
