"""CLI: sealed install / build / verify / inspect / audit / keygen / registry / policy."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from sealed.chain import ProvenanceChain
from sealed.seal import SealAuthority, Seal
from sealed.source import SourceFetcher, SourceFetchError
from sealed.builder import IsolatedBuilder
from sealed.verify import SealVerifier
from sealed.registry import SealRegistry
from sealed.resolver import DependencyResolver
from sealed.policy import PolicyEngine, PolicyConfig
from sealed.keystore import Keystore
from sealed.reproduce import ReproducibilityChecker
from sealed.transparency import TransparencyLog

SEAL_DIR = Path.home() / ".sealed"
KEY_FILE = SEAL_DIR / "key.ed25519"
STORE_DIR = SEAL_DIR / "store"
POLICY_FILE = SEAL_DIR / "policy.json"


def _ensure_key() -> SealAuthority:
    """Auto-generate a signing key on first use.

    Priority: OS keychain > encrypted file > plaintext file.
    """
    from sealed.os_keychain import OSKeychain, KeychainError

    SEAL_DIR.mkdir(parents=True, exist_ok=True)
    STORE_DIR.mkdir(parents=True, exist_ok=True)

    # Try OS keychain first
    if OSKeychain.available():
        try:
            key = OSKeychain.load()
            return SealAuthority(key)
        except KeychainError:
            pass  # Not stored yet, fall through

    # Try file-based key
    ks = Keystore(KEY_FILE)
    if KEY_FILE.exists():
        key = ks.load()
        return SealAuthority(key)

    # Generate new key
    import getpass
    from nacl.signing import SigningKey

    key = SigningKey.generate()

    # Store in OS keychain if available
    if OSKeychain.available():
        try:
            OSKeychain.store(key)
            print(f"  Signing key stored in OS keychain")
            print(f"  Public key: {key.verify_key.encode().hex()}")
            print()
            return SealAuthority(key)
        except KeychainError:
            pass  # Fall through to file

    # File-based: prompt for passphrase
    passphrase = None
    if sys.stdin.isatty():
        passphrase = getpass.getpass("Set key passphrase (empty for no encryption): ")
        if not passphrase:
            passphrase = None

    ks.save(key, passphrase=passphrase)
    print(f"  Generated signing key: {KEY_FILE}")
    print(f"  Public key: {key.verify_key.encode().hex()}")
    if passphrase:
        print(f"  Encrypted with passphrase")
    print()
    return SealAuthority(key)


def _get_registry() -> SealRegistry:
    return SealRegistry()


def _get_transparency_log() -> TransparencyLog:
    return TransparencyLog()


def _get_policy() -> tuple[PolicyEngine, SealRegistry]:
    registry = _get_registry()
    if POLICY_FILE.exists():
        config = PolicyConfig.load(POLICY_FILE)
    else:
        config = PolicyConfig()
    engine = PolicyEngine(config, registry)
    return engine, registry


def _build_and_seal_single(package: str, version: str,
                           authority: SealAuthority) -> tuple[Path, Path, Path, str]:
    """Build and seal one package. Returns (artifact, seal_path, chain_path, attestation_method)."""
    fetcher = SourceFetcher()
    source = fetcher.fetch(package, version)

    builder = IsolatedBuilder()
    result = builder.build(
        source.source_dir, source.archive_hash,
        source.package, source.version,
    )

    seal = authority.seal(result.chain)
    pkg_dir = STORE_DIR / f"{source.package}-{source.version}"
    pkg_dir.mkdir(parents=True, exist_ok=True)

    seal_path = pkg_dir / "seal.json"
    chain_path = pkg_dir / "chain.json"
    artifact_dest = pkg_dir / result.artifact.name

    seal.save(seal_path)
    chain_path.write_text(result.chain.to_json())
    shutil.copy2(result.artifact, artifact_dest)

    return artifact_dest, seal_path, chain_path, result.attestation.method


def cmd_install(args: argparse.Namespace) -> int:
    """Resolve deps, build each from source, seal, verify, install."""
    package = args.package
    version = getattr(args, "version", None)
    recursive = not getattr(args, "no_deps", False)

    print(f"sealed install {package}")
    print()

    authority = _ensure_key()
    policy_engine, registry = _get_policy()
    verifier = SealVerifier()
    tlog = _get_transparency_log()

    if recursive:
        print("  Resolving dependencies...")
        try:
            resolver = DependencyResolver()
            deps = resolver.resolve(package, version)
            print(f"  Found {len(deps)} packages to seal:")
            for dep in deps:
                print(f"    {dep.name}=={dep.version}")
            print()
        except Exception as e:
            print(f"  Dependency resolution failed: {e}")
            print("  Falling back to single package mode.")
            deps = None
    else:
        deps = None

    # Build list: either resolved deps or just the single package
    if deps:
        build_list = [(d.name, d.version) for d in deps]
    else:
        build_list = [(package, version)]

    installed = []
    failed = []

    for pkg_name, pkg_version in build_list:
        print(f"  [{pkg_name} {pkg_version or 'latest'}]")

        # Check if already sealed in store
        if pkg_version:
            existing = STORE_DIR / f"{pkg_name}-{pkg_version}"
            if existing.exists() and (existing / "seal.json").exists():
                print(f"    Already sealed, skipping build.")
                artifacts = [f for f in existing.iterdir()
                             if f.suffix == ".whl" or f.name.endswith(".tar.gz")]
                if artifacts:
                    installed.append((pkg_name, artifacts[0]))
                    continue

        try:
            artifact, seal_path, chain_path, attest_method = _build_and_seal_single(
                pkg_name, pkg_version, authority,
            )
            print(f"    Built and sealed ({attest_method} attestation)")
        except SourceFetchError as e:
            print(f"    SKIP: {e}")
            failed.append(pkg_name)
            continue
        except Exception as e:
            print(f"    FAILED: {e}")
            failed.append(pkg_name)
            continue

        # Verify
        result = verifier.verify(seal_path, artifact, chain_path)
        if not result.ok:
            print(f"    SEAL BROKEN:")
            for err in result.errors:
                print(f"      {err}")
            failed.append(pkg_name)
            continue

        # Policy check
        seal = Seal.load(seal_path)
        chain, _ = ProvenanceChain.from_json(chain_path.read_text())
        policy_result = policy_engine.evaluate(seal, chain, attest_method)

        if not policy_result.accepted:
            print(f"    POLICY REJECTED:")
            for err in policy_result.errors:
                print(f"      {err}")
            failed.append(pkg_name)
            continue

        for warning in policy_result.warnings:
            print(f"    WARNING: {warning}")

        # Store in registry and transparency log
        registry.store(seal, chain, attest_method)
        tlog.append("seal", seal.package_name, seal.package_version,
                     seal.chain_hash, seal.public_key)

        print(f"    VERIFIED ({result.chain_length} steps)")
        installed.append((pkg_name, artifact))

    # Install all verified artifacts
    if installed:
        print(f"\n  Installing {len(installed)} verified packages...")
        ret = subprocess.run(
            [sys.executable, "-m", "pip", "install"] +
            [str(a) for _, a in installed] +
            ["--force-reinstall", "--quiet", "--no-deps"],
            capture_output=True, text=True,
        )
        if ret.returncode != 0:
            print(f"  pip install failed: {ret.stderr}")
            registry.close()
            tlog.close()
            return 1

    registry.close()
    tlog.close()

    print(f"\n  Done. {len(installed)} sealed, {len(failed)} failed.")
    if failed:
        print(f"  Failed: {', '.join(failed)}")
    return 1 if failed and not installed else 0


def cmd_build(args: argparse.Namespace) -> int:
    """Build and seal without installing."""
    authority = _ensure_key()
    registry = _get_registry()

    try:
        artifact, seal_path, chain_path, attest_method = _build_and_seal_single(
            args.package, args.version, authority,
        )
    except Exception as e:
        print(f"FAILED: {e}")
        return 1

    seal = Seal.load(seal_path)
    chain, _ = ProvenanceChain.from_json(chain_path.read_text())
    registry.store(seal, chain, attest_method)
    tlog = _get_transparency_log()
    tlog.append("seal", seal.package_name, seal.package_version,
                seal.chain_hash, seal.public_key)
    tlog.close()
    registry.close()

    print(f"  Sealed ({attest_method} attestation).")
    print(f"  Seal:     {seal_path}")
    print(f"  Chain:    {chain_path}")
    print(f"  Artifact: {artifact}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a sealed artifact."""
    seal_path = Path(args.seal)
    artifact_path = Path(args.artifact) if args.artifact else None
    chain_path = Path(args.chain) if args.chain else None

    verifier = SealVerifier()

    if args.trusted_keys:
        for key_file in args.trusted_keys:
            key = Path(key_file).read_text().strip()
            # Ed25519 public keys are 64 hex chars (32 bytes)
            # Accept any 64-char hex string as a public key
            if len(key) == 64:
                try:
                    int(key, 16)  # validate hex
                    verifier.add_trusted_key(key)
                except ValueError:
                    print(f"Invalid hex in key file: {key_file}")
                    return 1
            else:
                print(f"Invalid key format in {key_file} (expected 64 hex chars)")
                return 1

    result = verifier.verify(seal_path, artifact_path, chain_path)

    if result.ok:
        print(f"VERIFIED: {result.package_name} {result.package_version}")
        print(f"  Chain: {result.chain_length} steps")
        return 0
    else:
        print(f"FAILED: {result.package_name} {result.package_version}")
        for err in result.errors:
            print(f"  {err}")
        return 1


def cmd_inspect(args: argparse.Namespace) -> int:
    """Inspect a seal or chain file."""
    path = Path(args.file)
    data = json.loads(path.read_text())

    if "signature" in data:
        print(f"Seal: {data['package_name']} {data['package_version']}")
        print(f"  Chain hash:  {data['chain_hash'][:32]}...")
        print(f"  Public key:  {data['public_key'][:32]}...")
        print(f"  Signature:   {data['signature'][:32]}...")
    elif "records" in data:
        print(f"Chain: {data['package_name']} {data['package_version']}")
        print(f"  Hash: {data['chain_hash'][:32]}...")
        print(f"  Steps: {len(data['records'])}")
        for i, rec in enumerate(data["records"]):
            step = rec["step"]
            if step == "environment_attestation":
                method = rec.get("metadata", {}).get("method", "?")
                print(f"    [{i}] {step} ({method})")
            else:
                print(f"    [{i}] {step}: {rec['input_hash'][:12]}... -> {rec['output_hash'][:12]}...")
    else:
        print(json.dumps(data, indent=2))
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Show all sealed packages."""
    registry = _get_registry()
    packages = registry.list_packages()
    registry.close()

    if not packages:
        print("No sealed packages. Run 'sealed install <package>' to get started.")
        return 0

    print(f"Sealed packages ({len(packages)}):\n")
    for pkg in packages:
        print(f"  {pkg['package']}=={pkg['version']}  "
              f"key={pkg['public_key']}  "
              f"attestation={pkg['attestation']}")
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    """Generate a new Ed25519 signing key."""
    output = Path(args.output)
    if output.exists() and not args.force:
        print(f"Key exists: {output}")
        print("Use --force to overwrite.")
        return 1

    import getpass
    passphrase = None
    if args.passphrase:
        passphrase = getpass.getpass("Key passphrase: ")
    elif sys.stdin.isatty():
        passphrase = getpass.getpass("Set key passphrase (empty for none): ")
        if not passphrase:
            passphrase = None

    ks = Keystore(output)
    key = ks.generate(passphrase=passphrase)
    print(f"Key: {output}")
    print(f"Public key: {key.verify_key.encode().hex()}")
    if passphrase:
        print("Encrypted with passphrase")
    return 0


def cmd_reproduce(args: argparse.Namespace) -> int:
    """Check if a package builds reproducibly."""
    checker = ReproducibilityChecker()
    print(f"Checking reproducibility: {args.package}")
    print("  Building twice from same source...")

    try:
        result = checker.check(args.package, args.version)
    except Exception as e:
        print(f"  FAILED: {e}")
        return 1

    if result.reproducible:
        print(f"  REPRODUCIBLE: {result.package} {result.version}")
        print(f"  Both builds: {result.build1_hash[:16]}...")
    elif result.normalized_match:
        print(f"  NORMALIZED MATCH: {result.package} {result.version}")
        print(f"  Raw hashes differ (timestamps/RECORD), but content is identical")
        print(f"  Build 1: {result.build1_hash[:16]}...")
        print(f"  Build 2: {result.build2_hash[:16]}...")
    else:
        print(f"  NOT REPRODUCIBLE: {result.package} {result.version}")
        print(f"  Build 1: {result.build1_hash[:16]}...")
        print(f"  Build 2: {result.build2_hash[:16]}...")
        if result.differences:
            print(f"  Differences:")
            for diff in result.differences:
                print(f"    {diff}")
    return 0


def cmd_sandbox(args: argparse.Namespace) -> int:
    """Run behavioral analysis on a package."""
    from sealed.sandbox import BehavioralSandbox

    print(f"Behavioral analysis: {args.package}")
    print("  Importing in isolated subprocess with monitors...")

    sandbox = BehavioralSandbox(timeout=args.timeout)
    result = sandbox.analyze(args.package, args.version or "latest")

    if result.safe:
        print(f"\n  SAFE: No dangerous behaviors detected")
    else:
        print(f"\n  UNSAFE: Dangerous behaviors detected")

    if result.timeout:
        print(f"  TIMEOUT: Package took >{args.timeout}s to import")

    for b in result.behaviors:
        if b.severity in ("critical", "high"):
            print(f"  [{b.severity.upper()}] {b.type}: {b.details}")
        elif b.severity != "info":
            print(f"  [{b.severity}] {b.type}")

    if result.error:
        print(f"  Error: {result.error}")

    return 0 if result.safe else 1


def cmd_consensus(args: argparse.Namespace) -> int:
    """Run consensus build verification."""
    from sealed.consensus import ConsensusBuilder

    print(f"Consensus build: {args.package} (n={args.num_builds})")

    builder = ConsensusBuilder(
        num_builds=args.num_builds,
        threshold=args.threshold,
    )
    try:
        result = builder.build(args.package, args.version)
    except Exception as e:
        print(f"  FAILED: {e}")
        return 1

    if result.consensus_reached:
        print(f"\n  CONSENSUS: {result.agreement_count}/{result.total_builds} builds agree")
        print(f"  Hash: {result.consensus_hash[:16]}...")
    else:
        print(f"\n  NO CONSENSUS: only {result.agreement_count}/{result.total_builds} agree")
        for b in result.builds:
            status = "OK" if b.success else f"FAIL: {b.error}"
            print(f"    Build {b.build_id}: {b.normalized_hash[:16] if b.normalized_hash else '?'}... {status}")

    return 0 if result.consensus_reached else 1


def cmd_watchdog(args: argparse.Namespace) -> int:
    """Runtime integrity checks."""
    from sealed.watchdog import IntegrityWatchdog

    watchdog = IntegrityWatchdog()
    action = args.action

    if action == "check":
        violations = watchdog.check(args.package)
        if not violations:
            print("No integrity violations detected.")
            return 0
        print(f"INTEGRITY VIOLATIONS ({len(violations)}):")
        for v in violations:
            print(f"  {v.package}/{v.file}: expected {v.expected_hash[:12]}..., got {v.actual_hash[:12]}...")
        return 1

    elif action == "list":
        snaps = watchdog.list_snapshots()
        if not snaps:
            print("No snapshots. Snapshots are created during sealed install.")
            return 0
        for s in snaps:
            print(f"  {s['package']}=={s['version']} ({s['file_count']} files)")

    return 0


def cmd_trust(args: argparse.Namespace) -> int:
    """Show trust graph for a package."""
    from sealed.trust_graph import TrustGraphBuilder

    registry = _get_registry()
    builder = TrustGraphBuilder(registry=registry)

    try:
        graph = builder.build(args.package, args.version)
    except Exception as e:
        print(f"Failed to build trust graph: {e}")
        registry.close()
        return 1

    if args.json:
        print(json.dumps(graph.to_dict(), indent=2))
    else:
        print(graph.render_text())

    registry.close()
    return 0


def cmd_registry(args: argparse.Namespace) -> int:
    """Registry operations: export, import, list pins."""
    registry = _get_registry()
    action = args.action

    if action == "export":
        data = registry.export_seals()
        if args.output:
            Path(args.output).write_text(data)
            print(f"Exported to {args.output}")
        else:
            print(data)

    elif action == "import":
        if not args.input:
            print("Provide --input file to import")
            return 1
        data = Path(args.input).read_text()
        count = registry.import_seals(data)
        print(f"Imported {count} seals")

    elif action == "pins":
        packages = set()
        for pkg in registry.list_packages():
            packages.add(pkg["package"])
        for pkg_name in sorted(packages):
            pins = registry.get_pins(pkg_name)
            if pins:
                print(f"{pkg_name}:")
                for pin in pins:
                    print(f"  {pin['public_key'][:32]}... ({pin['pin_type']})")

    elif action == "export-pins":
        data = registry.export_pins()
        if args.output:
            Path(args.output).write_text(data)
            print(f"Exported pins to {args.output}")
        else:
            print(data)

    elif action == "import-pins":
        if not args.input:
            print("Provide --input file to import")
            return 1
        data = Path(args.input).read_text()
        count = registry.import_pins(data)
        print(f"Imported {count} key pins")

    elif action == "revoke":
        if not args.key:
            print("Provide --key to revoke")
            return 1
        registry.revoke_key(args.key, args.reason or "")
        print(f"Revoked key {args.key[:16]}...")

    else:
        print(f"Unknown registry action: {action}")
        return 1

    registry.close()
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    """View or set trust policy."""
    if args.action == "show":
        if POLICY_FILE.exists():
            config = PolicyConfig.load(POLICY_FILE)
        else:
            config = PolicyConfig()
        print(json.dumps(config.to_dict(), indent=2))

    elif args.action == "set":
        if POLICY_FILE.exists():
            config = PolicyConfig.load(POLICY_FILE)
        else:
            config = PolicyConfig()

        if args.min_signatures is not None:
            config.min_signatures = args.min_signatures
        if args.tofu is not None:
            config.tofu_enabled = args.tofu
        if args.enforce_pins is not None:
            config.enforce_pins = args.enforce_pins
        if args.require_attestation:
            config.require_attestation = args.require_attestation

        POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
        config.save(POLICY_FILE)
        print("Policy updated:")
        print(json.dumps(config.to_dict(), indent=2))

    elif args.action == "reset":
        if POLICY_FILE.exists():
            POLICY_FILE.unlink()
        print("Policy reset to defaults.")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="sealed",
        description="Tamper with the binary. The seal breaks.",
    )
    sub = parser.add_subparsers(dest="command")

    # install
    p_install = sub.add_parser("install", help="Build from source, seal, verify, install (with deps)")
    p_install.add_argument("package", help="Package name (PyPI)")
    p_install.add_argument("--version", "-v", help="Specific version")
    p_install.add_argument("--no-deps", action="store_true", help="Don't seal dependencies")

    # build
    p_build = sub.add_parser("build", help="Build and seal without installing")
    p_build.add_argument("package", help="Package name (PyPI)")
    p_build.add_argument("--version", "-v", help="Specific version")

    # verify
    p_verify = sub.add_parser("verify", help="Verify a sealed artifact")
    p_verify.add_argument("seal", help="Seal JSON file")
    p_verify.add_argument("--artifact", "-a", help="Artifact to verify")
    p_verify.add_argument("--chain", "-c", help="Chain JSON file")
    p_verify.add_argument("--trusted-keys", "-t", nargs="+", help="Trusted .pub key files")

    # inspect
    p_inspect = sub.add_parser("inspect", help="Inspect a seal or chain")
    p_inspect.add_argument("file", help="Seal or chain JSON file")

    # audit
    sub.add_parser("audit", help="Show all sealed packages")

    # keygen
    p_keygen = sub.add_parser("keygen", help="Generate signing key")
    p_keygen.add_argument("--output", "-o", default=str(KEY_FILE), help="Output key file")
    p_keygen.add_argument("--force", "-f", action="store_true", help="Overwrite existing")
    p_keygen.add_argument("--passphrase", "-p", action="store_true", help="Encrypt with passphrase")

    # reproduce
    p_repro = sub.add_parser("reproduce", help="Check if a package builds reproducibly")
    p_repro.add_argument("package", help="Package name (PyPI)")
    p_repro.add_argument("--version", "-v", help="Specific version")

    # sandbox
    p_sand = sub.add_parser("sandbox", help="Behavioral analysis: monitor what a package does at import")
    p_sand.add_argument("package", help="Package name")
    p_sand.add_argument("--version", "-v", help="Specific version")
    p_sand.add_argument("--timeout", "-t", type=int, default=30, help="Timeout in seconds")

    # consensus
    p_cons = sub.add_parser("consensus", help="Build N times independently, check agreement")
    p_cons.add_argument("package", help="Package name (PyPI)")
    p_cons.add_argument("--version", "-v", help="Specific version")
    p_cons.add_argument("--num-builds", "-n", type=int, default=3, help="Number of builds")
    p_cons.add_argument("--threshold", type=float, default=0.67, help="Agreement threshold")

    # watchdog
    p_watch = sub.add_parser("watchdog", help="Runtime integrity verification")
    p_watch.add_argument("action", choices=["check", "list"])
    p_watch.add_argument("--package", "-p", help="Check specific package only")

    # trust
    p_trust = sub.add_parser("trust", help="Show trust graph for a package and its deps")
    p_trust.add_argument("package", help="Package name")
    p_trust.add_argument("--version", "-v", help="Specific version")
    p_trust.add_argument("--json", action="store_true", help="Output as JSON")

    # registry
    p_reg = sub.add_parser("registry", help="Registry operations")
    p_reg.add_argument("action", choices=[
        "export", "import", "pins", "export-pins", "import-pins", "revoke",
    ])
    p_reg.add_argument("--output", "-o", help="Output file")
    p_reg.add_argument("--input", "-i", help="Input file")
    p_reg.add_argument("--key", help="Public key (hex) for revocation")
    p_reg.add_argument("--reason", help="Revocation reason")

    # policy
    p_pol = sub.add_parser("policy", help="Trust policy configuration")
    p_pol.add_argument("action", choices=["show", "set", "reset"])
    p_pol.add_argument("--min-signatures", type=int, help="Minimum signers required")
    p_pol.add_argument("--tofu", type=lambda x: x.lower() == "true", help="Enable TOFU (true/false)")
    p_pol.add_argument("--enforce-pins", type=lambda x: x.lower() == "true", help="Enforce key pins (true/false)")
    p_pol.add_argument("--require-attestation", nargs="+", help="Required attestation methods")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    commands = {
        "install": cmd_install,
        "build": cmd_build,
        "verify": cmd_verify,
        "inspect": cmd_inspect,
        "audit": cmd_audit,
        "keygen": cmd_keygen,
        "reproduce": cmd_reproduce,
        "sandbox": cmd_sandbox,
        "consensus": cmd_consensus,
        "watchdog": cmd_watchdog,
        "trust": cmd_trust,
        "registry": cmd_registry,
        "policy": cmd_policy,
    }
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
