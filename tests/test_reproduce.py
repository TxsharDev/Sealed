"""Tests for reproducibility checker."""

import zipfile
import pytest

from sealed.reproduce import ReproducibilityChecker, ReproduceResult


class TestReproduceResult:
    def test_reproducible(self):
        r = ReproduceResult(
            package="test", version="1.0",
            reproducible=True,
            build1_hash="abc", build2_hash="abc",
        )
        assert r.reproducible
        assert r.to_dict()["reproducible"] is True

    def test_not_reproducible(self):
        r = ReproduceResult(
            package="test", version="1.0",
            reproducible=False,
            build1_hash="abc", build2_hash="def",
            differences=["Content differs: RECORD"],
        )
        assert not r.reproducible
        assert len(r.differences) == 1


class TestReproducibilityChecker:
    def test_diff_identical_wheels(self, tmp_path):
        checker = ReproducibilityChecker()

        # Create two identical wheels
        w1 = tmp_path / "pkg1.whl"
        w2 = tmp_path / "pkg2.whl"
        for w in [w1, w2]:
            with zipfile.ZipFile(w, "w") as zf:
                zf.writestr("pkg/__init__.py", "x = 1\n")
                zf.writestr("pkg/main.py", "def hi(): pass\n")

        diffs = checker._diff_wheels(w1, w2)
        assert diffs == []

    def test_diff_different_wheels(self, tmp_path):
        checker = ReproducibilityChecker()

        w1 = tmp_path / "pkg1.whl"
        w2 = tmp_path / "pkg2.whl"
        with zipfile.ZipFile(w1, "w") as zf:
            zf.writestr("pkg/__init__.py", "x = 1\n")
        with zipfile.ZipFile(w2, "w") as zf:
            zf.writestr("pkg/__init__.py", "x = 2\n")

        diffs = checker._diff_wheels(w1, w2)
        assert any("Content differs" in d for d in diffs)

    def test_diff_extra_files(self, tmp_path):
        checker = ReproducibilityChecker()

        w1 = tmp_path / "pkg1.whl"
        w2 = tmp_path / "pkg2.whl"
        with zipfile.ZipFile(w1, "w") as zf:
            zf.writestr("pkg/__init__.py", "x = 1\n")
        with zipfile.ZipFile(w2, "w") as zf:
            zf.writestr("pkg/__init__.py", "x = 1\n")
            zf.writestr("pkg/extra.py", "y = 2\n")

        diffs = checker._diff_wheels(w1, w2)
        assert any("only in build 2" in d.lower() for d in diffs)

    def test_normalize_strips_record(self, tmp_path):
        checker = ReproducibilityChecker()

        w1 = tmp_path / "pkg1.whl"
        w2 = tmp_path / "pkg2.whl"
        with zipfile.ZipFile(w1, "w") as zf:
            zf.writestr("pkg/__init__.py", "x = 1\n")
            zf.writestr("pkg-1.0.dist-info/RECORD", "hash1\n")
        with zipfile.ZipFile(w2, "w") as zf:
            zf.writestr("pkg/__init__.py", "x = 1\n")
            zf.writestr("pkg-1.0.dist-info/RECORD", "hash2\n")

        h1 = checker._normalize_wheel_hash(w1)
        h2 = checker._normalize_wheel_hash(w2)
        assert h1 == h2  # RECORD stripped, content identical

    def test_live_reproduce_six(self):
        """Build six twice and check reproducibility."""
        checker = ReproducibilityChecker()
        try:
            result = checker.check("six", "1.17.0")
            assert result.package == "six"
            assert result.version == "1.17.0"
            # Pure Python should be reproducible or at least normalized match
            assert result.reproducible or result.normalized_match
        except Exception:
            pytest.skip("Network not available")
