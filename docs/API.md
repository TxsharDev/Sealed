# API Reference

Sealed works as a CLI tool or as a Python library.

## CLI

### `sealed install <package>`

Build from source, seal, verify, and install a package with all its dependencies.

```bash
sealed install requests
sealed install flask --version 3.1.0
sealed install numpy --no-deps
```

Options:
- `--version, -v`: Install a specific version
- `--no-deps`: Skip dependency sealing (single package only)

### `sealed build <package>`

Build and seal without installing.

```bash
sealed build numpy
sealed build scipy --version 1.14.0
```

### `sealed verify <seal.json>`

Verify a sealed artifact.

```bash
sealed verify ~/.sealed/store/requests-2.32.3/seal.json
sealed verify seal.json --artifact pkg.whl --chain chain.json
sealed verify seal.json --trusted-keys team.pub
```

Options:
- `--artifact, -a`: Path to artifact file (verifies hash)
- `--chain, -c`: Path to chain file (default: `<seal>.chain.json`)
- `--trusted-keys, -t`: One or more `.pub` key files

### `sealed inspect <file>`

Print contents of a seal or chain file.

```bash
sealed inspect ~/.sealed/store/requests-2.32.3/seal.json
sealed inspect ~/.sealed/store/requests-2.32.3/chain.json
```

### `sealed audit`

List all sealed packages with attestation method.

### `sealed keygen`

Generate a new Ed25519 signing key.

```bash
sealed keygen
sealed keygen --output custom.key --force
```

### `sealed registry <action>`

Registry operations for team sharing.

```bash
sealed registry export -o seals.json
sealed registry import -i seals.json
sealed registry pins
sealed registry export-pins -o pins.json
sealed registry import-pins -i pins.json
sealed registry revoke --key <hex-pubkey> --reason "compromised"
```

### `sealed policy <action>`

Trust policy configuration.

```bash
sealed policy show
sealed policy set --min-signatures 2
sealed policy set --tofu false
sealed policy set --require-attestation tpm2
sealed policy reset
```

## Python Library

### ProvenanceChain

```python
from sealed import ProvenanceChain

chain = ProvenanceChain(package_name="mylib", package_version="1.0")
chain.add("source_verify", input_hash="abc", output_hash="def", url="https://...")
chain.add("build", input_hash="def", output_hash="ghi")

chain_hash = chain.chain_hash()
json_str = chain.to_json()

# Deserialize (returns chain + stored hash for integrity check)
restored, stored_hash = ProvenanceChain.from_json(json_str)
assert restored.verify_integrity(stored_hash)
```

### SealAuthority

```python
from sealed import SealAuthority

authority = SealAuthority()
authority.save_key(Path("my.key"))
authority = SealAuthority.from_key_file(Path("my.key"))

seal = authority.seal(chain)
SealAuthority.verify_seal(seal, chain)  # raises SealError on failure
```

### SealVerifier

```python
from sealed import SealVerifier

verifier = SealVerifier()
verifier.add_trusted_key("hex_public_key")

result = verifier.verify(seal_path, artifact_path, chain_path)
if result.ok:
    print(f"Verified: {result.package_name} {result.package_version}")
```

### Attestation

```python
from sealed import create_attestation, SoftwareAttestor

att = create_attestation()  # uses TPM if available, else software
print(att.method)           # "software" or "tpm2"
print(att.digest())         # SHA-256 over all measurements
print(att.measurements)     # dict of named hashes
```

### SealRegistry

```python
from sealed import SealRegistry

with SealRegistry() as reg:
    reg.store(seal, chain, attestation_method="software")
    entries = reg.lookup("requests", "2.32.3")
    reg.pin_key("requests", public_key_hex)
    pin = reg.check_pin("requests", some_key)
    exported = reg.export_seals()
```

### PolicyEngine

```python
from sealed import PolicyEngine, PolicyConfig, SealRegistry

registry = SealRegistry()
config = PolicyConfig(min_signatures=2, tofu_enabled=True)
engine = PolicyEngine(config, registry)

result = engine.evaluate(seal, chain, attestation_method="software")
if result.accepted:
    print("Policy passed")
else:
    print(result.errors)
```

### DependencyResolver

```python
from sealed import DependencyResolver

resolver = DependencyResolver()
deps = resolver.resolve("requests", "2.32.3")
for dep in deps:
    print(f"{dep.name}=={dep.version}")
# Output (topological order):
#   certifi==2024.8.30
#   charset_normalizer==3.4.2
#   idna==3.10
#   urllib3==2.4.0
#   requests==2.32.3
```
