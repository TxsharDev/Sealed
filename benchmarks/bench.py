"""Sealed benchmarks: measure real performance of every core operation.

Produces bench_results.json with timing data for:
- Directory hashing (Sealed vs raw hashlib)
- Attestation creation
- Seal creation (Ed25519 signing)
- Seal verification (Ed25519 + chain integrity)
- Lockfile generation and integrity check
- Sandbox policy evaluation
- Scale test: 10, 100, 1000 files
"""

import hashlib
import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

# Add the project root to sys.path so we can import sealed
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sealed.chain import (
    ProvenanceChain,
    ProvenanceRecord,
    BuildEnvironment,
    _hash_file,
    _hash_bytes,
    _hash_directory,
)
from sealed.seal import Seal, SealAuthority
from sealed.verify import SealVerifier, VerifyResult
from sealed.lockfile import Lockfile, LockEntry
from sealed.attestation import SoftwareAttestor, Attestation
from sealed.sandbox import SandboxResult, SandboxBehavior
from sealed.policy import PolicyConfig, PolicyEngine, PolicyResult
from sealed.registry import SealRegistry


def timed(fn, iterations=100):
    """Run fn iterations times, return (mean_ms, stdev_ms, min_ms, max_ms)."""
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000)
    return {
        "mean_ms": round(statistics.mean(times), 4),
        "stdev_ms": round(statistics.stdev(times) if len(times) > 1 else 0, 4),
        "min_ms": round(min(times), 4),
        "max_ms": round(max(times), 4),
        "iterations": iterations,
    }


def create_test_dir(num_files, file_size_bytes=4096):
    """Create a temp directory with num_files files of file_size_bytes each."""
    tmpdir = tempfile.mkdtemp(prefix=f"sealed_bench_{num_files}_")
    data = os.urandom(file_size_bytes)
    for i in range(num_files):
        subdir = Path(tmpdir) / f"pkg_{i // 50}"
        subdir.mkdir(exist_ok=True)
        (subdir / f"file_{i}.py").write_bytes(data)
    return Path(tmpdir)


def raw_hashlib_directory(path: Path):
    """Baseline: hash a directory with raw hashlib, same algorithm as Sealed."""
    h = hashlib.sha256()
    for p in sorted(path.rglob("*")):
        if p.is_symlink():
            continue
        if p.is_file():
            rel = p.relative_to(path).as_posix()
            h.update(rel.encode())
            fh = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 16), b""):
                    fh.update(chunk)
            h.update(fh.hexdigest().encode())
    return h.hexdigest()


def make_chain(pkg="bench-pkg", ver="1.0.0"):
    """Build a realistic provenance chain for benchmarking."""
    chain = ProvenanceChain(package_name=pkg, package_version=ver)
    chain.add("environment_attestation",
              _hash_bytes(b"env_input"), _hash_bytes(b"env_output"),
              method="software")
    chain.add("source_verify",
              _hash_bytes(b"archive"), _hash_bytes(b"source_dir"))
    chain.add("toolchain_capture",
              _hash_bytes(b"python_bin"), _hash_bytes(b"python_bin"))
    chain.add("build",
              _hash_bytes(b"source_dir"), _hash_bytes(b"artifact"))
    return chain


def bench_directory_hashing():
    """Benchmark: Sealed _hash_directory vs raw hashlib on 100-file dir."""
    print("  [1/7] Directory hashing...")
    d = create_test_dir(100)
    try:
        sealed_result = timed(lambda: _hash_directory(d), iterations=50)
        raw_result = timed(lambda: raw_hashlib_directory(d), iterations=50)
        overhead_pct = round(
            (sealed_result["mean_ms"] / raw_result["mean_ms"] - 1) * 100, 2
        )
        return {
            "sealed_hash_directory": sealed_result,
            "raw_hashlib_directory": raw_result,
            "overhead_percent": overhead_pct,
            "num_files": 100,
            "file_size_bytes": 4096,
        }
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


def bench_attestation():
    """Benchmark: SoftwareAttestor.attest() -- measures build environment."""
    print("  [2/7] Attestation creation...")
    attestor = SoftwareAttestor()
    # Warm up (first call may be slow due to pip version check)
    attestor.attest()
    result = timed(lambda: attestor.attest(), iterations=10)
    return {"software_attestation": result}


def bench_seal_creation():
    """Benchmark: create a Seal (Ed25519 key gen + sign)."""
    print("  [3/7] Seal creation...")
    chain = make_chain()

    # Key generation (one-time cost)
    keygen_result = timed(lambda: SealAuthority(), iterations=100)

    # Signing with pre-existing key
    authority = SealAuthority()
    sign_result = timed(lambda: authority.seal(chain), iterations=500)

    return {
        "keygen_ed25519": keygen_result,
        "seal_sign": sign_result,
    }


def bench_seal_verification():
    """Benchmark: verify a Seal (Ed25519 verify + chain hash recompute)."""
    print("  [4/7] Seal verification...")
    chain = make_chain()
    authority = SealAuthority()
    seal = authority.seal(chain)

    # Verification (signature + chain hash)
    verify_result = timed(
        lambda: SealAuthority.verify_seal(seal, chain), iterations=500
    )

    # Full verifier (JSON round-trip + all checks)
    seal_json = seal.to_json()
    chain_json = chain.to_json()
    verifier = SealVerifier(trusted_keys=[authority.public_key])
    full_result = timed(
        lambda: verifier.verify_json(seal_json, chain_json), iterations=200
    )

    return {
        "seal_verify_signature": verify_result,
        "full_verify_json": full_result,
    }


def bench_lockfile():
    """Benchmark: lockfile generation, serialization, integrity check."""
    print("  [5/7] Lockfile operations...")

    def make_lockfile(n):
        lf = Lockfile()
        for i in range(n):
            lf.add(LockEntry(
                name=f"package-{i}",
                version=f"1.{i}.0",
                artifact_hash=_hash_bytes(f"artifact_{i}".encode()),
                chain_hash=_hash_bytes(f"chain_{i}".encode()),
                public_key=_hash_bytes(f"key_{i}".encode()),
            ))
        return lf

    # 10 packages
    lf10 = make_lockfile(10)
    gen10 = timed(lambda: make_lockfile(10), iterations=200)
    ser10 = timed(lambda: lf10.to_json(), iterations=500)
    integ10 = timed(lambda: lf10.verify_integrity(), iterations=500)

    # 100 packages
    lf100 = make_lockfile(100)
    gen100 = timed(lambda: make_lockfile(100), iterations=50)
    ser100 = timed(lambda: lf100.to_json(), iterations=100)
    integ100 = timed(lambda: lf100.verify_integrity(), iterations=100)

    # Check operation
    check_result = timed(
        lambda: lf100.check("package-50", "1.50.0",
                            _hash_bytes(b"artifact_50")),
        iterations=1000,
    )

    return {
        "generate_10_packages": gen10,
        "serialize_10_packages": ser10,
        "integrity_check_10_packages": integ10,
        "generate_100_packages": gen100,
        "serialize_100_packages": ser100,
        "integrity_check_100_packages": integ100,
        "single_package_check": check_result,
    }


def bench_policy_evaluation():
    """Benchmark: PolicyEngine.evaluate() with all checks."""
    print("  [6/7] Policy evaluation...")
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "bench_registry.db"
        registry = SealRegistry(db_path=db_path)

        chain = make_chain()
        authority = SealAuthority()
        seal = authority.seal(chain)

        # Store seal in registry for multi-party checks
        registry.store(seal, chain, "software")

        config = PolicyConfig(
            min_signatures=1,
            require_attestation=["software"],
            tofu_enabled=True,
            check_revocations=True,
            enforce_pins=True,
        )
        engine = PolicyEngine(config, registry)

        # First evaluation (TOFU pin)
        engine.evaluate(seal, chain, "software")

        # Subsequent evaluations (pin exists)
        result = timed(
            lambda: engine.evaluate(seal, chain, "software"),
            iterations=200,
        )

        registry.close()
        return {"policy_evaluate_full": result}


def bench_scale():
    """Benchmark: directory hashing at different file counts."""
    print("  [7/7] Scale test (10, 100, 1000 files)...")
    import shutil
    results = {}
    for n in [10, 100, 1000]:
        d = create_test_dir(n)
        try:
            iters = max(5, 100 // (n // 10))
            r = timed(lambda d=d: _hash_directory(d), iterations=iters)
            results[f"hash_{n}_files"] = r
            results[f"hash_{n}_files"]["total_bytes"] = n * 4096
        finally:
            shutil.rmtree(d, ignore_errors=True)

    # Chain hash scaling: chains with 4, 20, 100 records
    for n_records in [4, 20, 100]:
        chain = ProvenanceChain(package_name="scale-pkg", package_version="1.0.0")
        for i in range(n_records):
            chain.add(f"step_{i}",
                      _hash_bytes(f"in_{i}".encode()),
                      _hash_bytes(f"out_{i}".encode()))
        r = timed(lambda c=chain: c.chain_hash(), iterations=500)
        results[f"chain_hash_{n_records}_records"] = r

    return results


def main():
    print("Sealed Benchmarks")
    print("=" * 50)

    results = {
        "metadata": {
            "python_version": sys.version,
            "platform": sys.platform,
            "timestamp": time.time(),
        }
    }

    results["directory_hashing"] = bench_directory_hashing()
    results["attestation"] = bench_attestation()
    results["seal_creation"] = bench_seal_creation()
    results["seal_verification"] = bench_seal_verification()
    results["lockfile"] = bench_lockfile()
    results["policy_evaluation"] = bench_policy_evaluation()
    results["scale"] = bench_scale()

    # Save results
    out_path = Path(__file__).parent / "bench_results.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nResults saved to {out_path}")

    # Print summary
    print("\n--- Summary ---")
    print(f"Dir hash (100 files):  {results['directory_hashing']['sealed_hash_directory']['mean_ms']:.2f} ms")
    print(f"Raw hashlib (100 files): {results['directory_hashing']['raw_hashlib_directory']['mean_ms']:.2f} ms")
    print(f"Overhead: {results['directory_hashing']['overhead_percent']:.1f}%")
    print(f"Attestation:           {results['attestation']['software_attestation']['mean_ms']:.2f} ms")
    print(f"Ed25519 keygen:        {results['seal_creation']['keygen_ed25519']['mean_ms']:.2f} ms")
    print(f"Seal sign:             {results['seal_creation']['seal_sign']['mean_ms']:.2f} ms")
    print(f"Seal verify (sig):     {results['seal_verification']['seal_verify_signature']['mean_ms']:.2f} ms")
    print(f"Full verify (JSON):    {results['seal_verification']['full_verify_json']['mean_ms']:.2f} ms")
    print(f"Lockfile gen (100):    {results['lockfile']['generate_100_packages']['mean_ms']:.2f} ms")
    print(f"Lockfile integrity:    {results['lockfile']['integrity_check_100_packages']['mean_ms']:.2f} ms")
    print(f"Policy evaluate:       {results['policy_evaluation']['policy_evaluate_full']['mean_ms']:.2f} ms")
    print(f"Hash 10 files:         {results['scale']['hash_10_files']['mean_ms']:.2f} ms")
    print(f"Hash 100 files:        {results['scale']['hash_100_files']['mean_ms']:.2f} ms")
    print(f"Hash 1000 files:       {results['scale']['hash_1000_files']['mean_ms']:.2f} ms")


if __name__ == "__main__":
    main()
