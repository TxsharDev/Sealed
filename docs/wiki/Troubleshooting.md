# Troubleshooting

## Build fails: "no compiler found"

Packages with C extensions (numpy, scipy, lxml) need a C compiler.

**Linux:**
```bash
sudo apt install build-essential python3-dev
```

**macOS:**
```bash
xcode-select --install
```

**Windows:**
Install Visual Studio Build Tools with "C++ build tools" workload.

**Workaround:** Use `--no-deps` and only seal pure Python packages:
```bash
sealed install flask --no-deps
```

## "Key is encrypted. Provide passphrase"

Your key was created with a passphrase. Set the passphrase interactively or pass it via env:

```bash
sealed install requests  # prompts for passphrase
```

To remove the passphrase:
```python
from sealed.keystore import Keystore
from pathlib import Path
ks = Keystore(Path.home() / ".sealed" / "key.ed25519")
ks.change_passphrase("old-passphrase", None)
```

## "No source distribution for <package>"

Some packages only publish wheels (pre-built binaries) on PyPI. Sealed requires source.

Check if a source distribution exists:
```bash
pip download <package> --no-binary :all: --no-deps -d /tmp/check
```

If this fails, the package has no sdist. You cannot seal it.

## "KEY PIN MISMATCH"

The package was previously signed by a different key. This could mean:
- Key rotation (legitimate)
- Key compromise (attack)

To investigate:
```bash
sealed registry pins
```

To accept the new key (after verifying it's legitimate):
```bash
sealed registry revoke --key <old-key> --reason "key rotation"
sealed install <package>  # will pin the new key
```

## "Only N signatures, need M"

Your policy requires more signers than are available. Either:

1. Get more team members to seal the package
2. Lower the requirement: `sealed policy set --min-signatures 1`

## Slow builds

C extension packages take time. This is inherent to building from source.

**Tips:**
- Seal once, cache forever. Already-sealed packages are skipped.
- Use `--no-deps` for quick single-package sealing.
- Run in CI where build time doesn't block your workflow.

## SQLite locked

If two `sealed install` commands run simultaneously:

```
sqlite3.OperationalError: database is locked
```

Wait for the first to finish, or use separate registries:

```bash
SEALED_HOME=/tmp/sealed-alt sealed install <package>
```

## Windows: "charmap codec can't encode"

Set UTF-8 mode:

```bash
set PYTHONUTF8=1
sealed install requests
```

Or permanently in PowerShell:

```powershell
[Environment]::SetEnvironmentVariable("PYTHONUTF8", "1", "User")
```
