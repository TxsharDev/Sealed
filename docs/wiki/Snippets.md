# Code Snippets

Copy-paste Python examples for common operations.

## Seal and Verify a Package

```python
from sealed import SourceFetcher, IsolatedBuilder, SealAuthority, SealVerifier
from pathlib import Path

# Fetch source
fetcher = SourceFetcher()
source = fetcher.fetch("requests", "2.32.3")

# Build from source
builder = IsolatedBuilder()
result = builder.build(
    source.source_dir, source.archive_hash,
    source.package, source.version,
)

# Sign the chain
auth = SealAuthority()
seal = auth.seal(result.chain)

# Save
seal.save(Path("seal.json"))
Path("chain.json").write_text(result.chain.to_json())

# Verify
verifier = SealVerifier()
vr = verifier.verify(Path("seal.json"), result.artifact, Path("chain.json"))
print(f"Valid: {vr.ok}")
```

## Source Audit Before Building

```python
from sealed.audit_source import SourceAuditor

auditor = SourceAuditor()
result = auditor.audit(source_dir, "package-name", "1.0.0")

if not result.safe:
    print("UNSAFE - findings:")
    for f in result.findings:
        print(f"  [{f.severity}] {f.message} ({f.file}:{f.line})")
else:
    print("Source passed safety scan")
```

## Behavioral Sandbox

```python
from sealed import BehavioralSandbox

sandbox = BehavioralSandbox(timeout=30)
result = sandbox.analyze("suspicious-package", "1.0.0")

if not result.safe:
    for b in result.behaviors:
        if b.severity in ("critical", "high"):
            print(f"[{b.severity}] {b.type}: {b.details}")
```

## Trust Graph

```python
from sealed import TrustGraphBuilder, SealRegistry

with SealRegistry() as reg:
    builder = TrustGraphBuilder(registry=reg)
    graph = builder.build("flask", "3.1.0")

    print(graph.render_text())
    print(f"Weakest link: {graph.weakest_link.name}")
    print(f"Average trust: {graph.average_trust:.0%}")
```

## Registry Export/Import

```python
from sealed import SealRegistry

# Export
with SealRegistry() as reg:
    seals_json = reg.export_seals(["requests", "flask"])
    Path("team-seals.json").write_text(seals_json)

    pins_json = reg.export_pins()
    Path("team-pins.json").write_text(pins_json)

# Import (on another machine)
with SealRegistry() as reg:
    count = reg.import_seals(Path("team-seals.json").read_text())
    print(f"Imported {count} seals")
```

## Policy Engine

```python
from sealed import PolicyEngine, PolicyConfig, SealRegistry

with SealRegistry() as reg:
    config = PolicyConfig(
        min_signatures=2,
        tofu_enabled=True,
        enforce_pins=True,
        require_attestation=["software"],
    )
    engine = PolicyEngine(config, reg)

    result = engine.evaluate(seal, chain, attestation_method="software")
    if result.accepted:
        print("Policy passed")
    else:
        for err in result.errors:
            print(f"Rejected: {err}")
```

## Transparency Log

```python
from sealed.transparency import TransparencyLog

with TransparencyLog() as log:
    # Record a seal
    log.append("seal", "requests", "2.32.3", chain_hash, public_key)

    # Verify chain integrity
    valid, errors = log.verify_chain()

    # Detect equivocation
    alerts = log.detect_equivocation()
    for alert in alerts:
        print(f"WARNING: {alert.package} {alert.version} has "
              f"{len(alert.chain_hashes)} different builds")
```

## Lockfile

```python
from sealed import Lockfile, LockEntry
from pathlib import Path

# Create lockfile
lf = Lockfile()
lf.add(LockEntry(
    name="requests",
    version="2.32.3",
    artifact_hash="abc123...",
    chain_hash="def456...",
    public_key="key_hex...",
))
lf.save(Path("sealed.lock"))

# Verify against lockfile
lf = Lockfile.load(Path("sealed.lock"))
check = lf.check("requests", "2.32.3", "abc123...")
if check.ok:
    print("Matches lockfile")
elif check.status == "version_mismatch":
    print(f"Wrong version: {check.message}")
elif check.status == "hash_mismatch":
    print(f"Artifact changed: {check.message}")
```

## Consensus Build

```python
from sealed import ConsensusBuilder

builder = ConsensusBuilder(num_builds=3, threshold=0.67)
result = builder.build("six", "1.17.0")

if result.consensus_reached:
    print(f"Consensus: {result.agreement_count}/{result.total_builds}")
    print(f"Hash: {result.consensus_hash}")
else:
    print("No consensus - builds diverged")
    for b in result.builds:
        print(f"  Build {b.build_id}: {b.normalized_hash[:16]}...")
```

## Runtime Watchdog

```python
from sealed import IntegrityWatchdog
from pathlib import Path

wd = IntegrityWatchdog()

# Take snapshot after install
wd.snapshot("requests", "2.32.3", Path("/path/to/requests"))

# Check later
violations = wd.check("requests")
if violations:
    for v in violations:
        print(f"TAMPERED: {v.file}")
else:
    print("All files intact")
```

## Encrypted Key Management

```python
from sealed.keystore import Keystore
from pathlib import Path

ks = Keystore(Path("my-key.sealed"))

# Generate with passphrase
key = ks.generate(passphrase="strong-passphrase")
print(f"Public key: {key.verify_key.encode().hex()}")

# Load (prompts for passphrase interactively)
key = ks.load()

# Change passphrase
ks.change_passphrase("old-pass", "new-pass")

# Remove encryption
ks.change_passphrase("pass", None)
```

## Multi-Ecosystem

```python
from sealed.ecosystem import get_adapter

# pip
pip = get_adapter("pip")
source = pip.fetch("requests", "2.32.3")
artifact = pip.build(source)

# npm (requires npm installed)
npm = get_adapter("npm")
source = npm.fetch("lodash", "4.17.21")

# cargo (requires cargo installed)
cargo = get_adapter("cargo")
source = cargo.fetch("serde", "1.0.200")
```
