# Team Setup

## The Problem

Alice seals her deps. Bob installs the same packages but gets different binaries. Neither knows if the other's build was compromised. They need shared verification.

## Step 1: Everyone Installs Sealed

```bash
pip install alia-sealed
```

First run generates a signing key. Each team member has their own key.

## Step 2: Seal Your Dependencies

Each team member seals independently:

```bash
sealed install requests flask sqlalchemy
```

## Step 3: Share Seals

```bash
# Export your seals
sealed registry export -o my-seals.json

# Share via git, Slack, internal tool
# Import teammate's seals
sealed registry import -i alice-seals.json
sealed registry import -i bob-seals.json
```

Import verifies Ed25519 signatures before accepting. Forged seals are rejected.

## Step 4: Set Policy

Require multiple signers:

```bash
sealed policy set --min-signatures 2
```

Now a package needs seals from at least 2 different keys before it's accepted.

## Step 5: Pin Keys

Keys are auto-pinned on first use (TOFU). If a key changes, the install is blocked.

Share key pins across the team:

```bash
sealed registry export-pins -o team-pins.json
# Teammates import
sealed registry import-pins -i team-pins.json
```

## Step 6: Lockfile

Commit a lockfile to your repo:

```bash
# After sealing, create lockfile
python -c "
from sealed import Lockfile, LockEntry, SealRegistry
from pathlib import Path

with SealRegistry() as reg:
    lf = Lockfile()
    for pkg in reg.list_packages():
        entries = reg.lookup(pkg['package'], pkg['version'])
        if entries:
            e = entries[0]
            lf.add(LockEntry(
                pkg['package'], pkg['version'],
                e.chain.chain_hash(), e.seal.chain_hash,
                e.seal.public_key,
            ))
    lf.save(Path('sealed.lock'))
"
```

Check `sealed.lock` into version control.

## Key Rotation

If someone leaves the team or a key is compromised:

```bash
# Revoke the old key
sealed registry revoke --key <hex-public-key> --reason "employee departure"

# Generate new key for the replacement
sealed keygen --force --passphrase

# Re-seal everything
sealed install requests flask sqlalchemy

# Export new seals and pins
sealed registry export -o updated-seals.json
sealed registry export-pins -o updated-pins.json
```
