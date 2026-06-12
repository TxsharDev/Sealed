# CI/CD Integration

## GitHub Actions

### Basic: Seal and Upload

```yaml
name: Seal Dependencies
on: [push]

jobs:
  seal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install alia-sealed

      - name: Seal all dependencies
        run: |
          sealed keygen --force
          sealed install requests flask sqlalchemy
          sealed audit

      - uses: actions/upload-artifact@v4
        with:
          name: sealed-attestations
          path: ~/.sealed/store/
```

### Verify Before Deploy

```yaml
name: Deploy
on:
  workflow_dispatch:

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: sealed-attestations
          path: ~/.sealed/store/

      - run: pip install alia-sealed
      - run: sealed audit
      - run: sealed watchdog check
```

### Reusable Workflow

Use the included workflow:

```yaml
jobs:
  seal:
    uses: TxsharDev/Sealed/.github/workflows/sealed-action.yml@main
    with:
      packages: "requests flask numpy"
      python-version: "3.12"
```

## Exit Codes

All `sealed` commands return proper exit codes:

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Failure (verification failed, policy rejected, build error) |

Use in CI:

```bash
sealed verify seal.json --artifact pkg.whl || exit 1
```

## Machine-Readable Output

Trust graph as JSON:

```bash
sealed trust requests --json > trust.json
```

Registry export as JSON:

```bash
sealed registry export -o seals.json
```

Lockfile as JSON:

```bash
cat sealed.lock  # already JSON
```
