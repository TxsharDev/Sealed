# Use Cases

## 1. Solo Developer - "I want to know my deps are clean"

You're building a web app. You install 30 packages. Any one of them could be compromised. You want proof that what you installed matches the published source.

```bash
pip install alia-sealed
sealed install flask
```

Done. Flask and all its deps are built from source, attested, sealed, verified. Check what you have:

```bash
sealed audit
sealed trust flask
```

The trust graph shows every dependency with a score. If something looks wrong, you see it.

## 2. Team Lead - "Everyone should install the same thing"

You sealed your deps. You want your team to verify against the same seals.

```bash
# You: export your seals
sealed registry export -o team-seals.json

# Share team-seals.json via git, Slack, whatever

# Teammate: import and verify
sealed registry import -i team-seals.json
```

Now both of you have the same seals. If a package was rebuilt differently on their machine, they know.

For version pinning:

```python
from sealed import Lockfile, LockEntry

lf = Lockfile()
lf.add(LockEntry("flask", "3.1.0", artifact_hash, chain_hash, public_key))
lf.save(Path("sealed.lock"))

# Commit sealed.lock to your repo
# Teammates verify against it
```

## 3. Security Team - "We need multi-party verification"

No single person should be the only one who sealed a package. Require 3 independent signers:

```bash
sealed policy set --min-signatures 3
```

Each team member seals independently:

```bash
# Alice
sealed build requests
sealed registry export -o alice-seals.json

# Bob
sealed build requests
sealed registry export -o bob-seals.json

# Charlie
sealed build requests
sealed registry export -o charlie-seals.json
```

Import all:

```bash
sealed registry import -i alice-seals.json
sealed registry import -i bob-seals.json
sealed registry import -i charlie-seals.json
```

Now `sealed install requests` sees 3 unique signers and accepts.

## 4. CI/CD - "Seal in CI, verify in prod"

`.github/workflows/seal.yml`:

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"
- run: pip install alia-sealed
- run: sealed keygen --force
- run: |
    sealed build requests
    sealed build flask
    sealed audit
- uses: actions/upload-artifact@v4
  with:
    name: sealed-attestations
    path: ~/.sealed/store/
```

Download the attestations in your deploy step. Verify before running.

## 5. Open Source Maintainer - "Prove my release is clean"

You publish a library. You want users to verify the PyPI release matches your source:

```bash
sealed build my-library --version 1.0.0
sealed inspect ~/.sealed/store/my-library-1.0.0/chain.json
```

Publish `seal.json` and `chain.json` alongside your release. Users verify:

```bash
sealed verify my-library-1.0.0.seal.json \
  --artifact my_library-1.0.0-py3-none-any.whl \
  --chain my-library-1.0.0.chain.json
```

## 6. Security Researcher - "Is this package safe to import?"

You found a suspicious package. Before installing, scan it:

```bash
sealed sandbox suspicious-package
```

The sandbox imports it in an isolated process and monitors:
- Network connections (blocked and logged)
- Process spawning (blocked and logged)
- Sensitive file reads (.ssh, .aws, .env)
- Secret env var access (tokens, passwords)

If it tries to phone home or read your credentials, you know before it touches your system.

## 7. Paranoid Mode - "Build it 3 times, prove it's the same"

```bash
sealed consensus requests --num-builds 3
```

Builds the same source 3 times independently. If 2/3 produce the same output, you know the build is deterministic. If they diverge, something is off.

## 8. Incident Response - "Was my package tampered with after install?"

```bash
sealed watchdog check
```

Compares every installed file against its snapshot hash. If malware modified a `.py` file after installation, you see it:

```
INTEGRITY VIOLATIONS (1):
  requests/adapters.py: expected a1b2c3..., got f4e5d6...
```

## 9. Compliance - "Show me the audit trail"

The transparency log records every seal, revocation, and key pin:

```python
from sealed import TransparencyLog

with TransparencyLog() as log:
    history = log.get_history(package="requests")
    for entry in history:
        print(f"{entry.action}: {entry.package_name} {entry.package_version}")

    # Verify the log itself hasn't been tampered with
    valid, errors = log.verify_chain()
    assert valid
```

## 10. Key Compromise Recovery

Your signing key was stolen. Revoke it:

```bash
sealed registry revoke --key <hex-public-key> --reason "key compromised"
```

All future verifications against that key fail. Generate a new key:

```bash
sealed keygen --force --passphrase
```

Re-seal your packages:

```bash
sealed install requests  # rebuilds and re-seals with new key
```

Export new key pins to your team:

```bash
sealed registry export-pins -o new-pins.json
```
