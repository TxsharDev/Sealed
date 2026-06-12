"""Tests for runtime integrity watchdog."""

import pytest
from pathlib import Path

from sealed.watchdog import IntegrityWatchdog, WatchdogSnapshot, IntegrityViolation


class TestIntegrityWatchdog:
    def test_snapshot_and_check_clean(self, tmp_path):
        # Create a fake installed package
        pkg_dir = tmp_path / "mypackage"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("x = 1\n")
        (pkg_dir / "main.py").write_text("def hello(): pass\n")

        watchdog = IntegrityWatchdog(snapshot_dir=tmp_path / "snapshots")
        snap = watchdog.snapshot("mypackage", "1.0", pkg_dir)
        assert len(snap.file_hashes) == 2

        # Check: should be clean
        violations = watchdog.check("mypackage")
        assert violations == []

    def test_detects_modified_file(self, tmp_path):
        pkg_dir = tmp_path / "mypackage"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("x = 1\n")

        watchdog = IntegrityWatchdog(snapshot_dir=tmp_path / "snapshots")
        watchdog.snapshot("mypackage", "1.0", pkg_dir)

        # Tamper: modify the file
        (pkg_dir / "__init__.py").write_text("x = 2  # TAMPERED\n")

        violations = watchdog.check("mypackage")
        assert len(violations) == 1
        assert violations[0].package == "mypackage"
        assert "__init__.py" in violations[0].file

    def test_detects_deleted_file(self, tmp_path):
        pkg_dir = tmp_path / "mypackage"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("x = 1\n")
        (pkg_dir / "main.py").write_text("y = 2\n")

        watchdog = IntegrityWatchdog(snapshot_dir=tmp_path / "snapshots")
        watchdog.snapshot("mypackage", "1.0", pkg_dir)

        # Delete a file
        (pkg_dir / "main.py").unlink()

        violations = watchdog.check("mypackage")
        assert len(violations) == 1
        assert violations[0].actual_hash == "FILE_DELETED"

    def test_check_all_packages(self, tmp_path):
        pkg1 = tmp_path / "pkg1"
        pkg1.mkdir()
        (pkg1 / "a.py").write_text("a\n")

        pkg2 = tmp_path / "pkg2"
        pkg2.mkdir()
        (pkg2 / "b.py").write_text("b\n")

        watchdog = IntegrityWatchdog(snapshot_dir=tmp_path / "snapshots")
        watchdog.snapshot("pkg1", "1.0", pkg1)
        watchdog.snapshot("pkg2", "1.0", pkg2)

        # Tamper with pkg2
        (pkg2 / "b.py").write_text("TAMPERED\n")

        violations = watchdog.check()  # check all
        assert len(violations) == 1
        assert violations[0].package == "pkg2"

    def test_list_snapshots(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "a.py").write_text("x\n")

        watchdog = IntegrityWatchdog(snapshot_dir=tmp_path / "snapshots")
        watchdog.snapshot("pkg", "1.0", pkg)

        snaps = watchdog.list_snapshots()
        assert len(snaps) == 1
        assert snaps[0]["package"] == "pkg"


class TestWatchdogSnapshot:
    def test_json_roundtrip(self):
        snap = WatchdogSnapshot(
            package="test", version="1.0",
            install_path="/tmp/test",
            file_hashes={"a.py": "abc123", "b.py": "def456"},
        )
        j = snap.to_json()
        restored = WatchdogSnapshot.from_json(j)
        assert restored.package == "test"
        assert restored.file_hashes == snap.file_hashes


class TestIntegrityViolation:
    def test_to_dict(self):
        v = IntegrityViolation(
            package="pkg", file="main.py",
            expected_hash="aaa", actual_hash="bbb",
        )
        d = v.to_dict()
        assert d["package"] == "pkg"
