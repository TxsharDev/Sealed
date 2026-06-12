"""Tests for transparency log."""

import pytest

from sealed.transparency import TransparencyLog, LogEntry, EquivocationAlert


class TestTransparencyLog:
    def test_append_and_verify(self, tmp_path):
        with TransparencyLog(tmp_path / "test.db") as log:
            log.append("seal", "pkg", "1.0", "chain_abc", "key_123")
            log.append("seal", "pkg", "2.0", "chain_def", "key_123")

            valid, errors = log.verify_chain()
            assert valid
            assert errors == []

    def test_chain_links(self, tmp_path):
        with TransparencyLog(tmp_path / "test.db") as log:
            e1 = log.append("seal", "a", "1.0", "h1", "k1")
            e2 = log.append("seal", "b", "1.0", "h2", "k2")

            assert e1.prev_hash == TransparencyLog.GENESIS_HASH
            assert e2.prev_hash == e1.entry_hash

    def test_tamper_detected(self, tmp_path):
        db_path = tmp_path / "test.db"
        with TransparencyLog(db_path) as log:
            log.append("seal", "pkg", "1.0", "h1", "k1")
            log.append("seal", "pkg", "2.0", "h2", "k2")

        # Tamper: modify an entry's chain_hash
        import sqlite3
        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE log_entries SET chain_hash='TAMPERED' WHERE sequence=1")
        conn.commit()
        conn.close()

        with TransparencyLog(db_path) as log:
            valid, errors = log.verify_chain()
            assert not valid
            assert len(errors) >= 1

    def test_detect_equivocation(self, tmp_path):
        with TransparencyLog(tmp_path / "test.db") as log:
            # Same package-version, different chain hashes = equivocation
            log.append("seal", "pkg", "1.0", "hash_A", "key_1")
            log.append("seal", "pkg", "1.0", "hash_B", "key_2")

            alerts = log.detect_equivocation()
            assert len(alerts) == 1
            assert alerts[0].package == "pkg"
            assert len(alerts[0].chain_hashes) == 2

    def test_no_equivocation_same_hash(self, tmp_path):
        with TransparencyLog(tmp_path / "test.db") as log:
            log.append("seal", "pkg", "1.0", "same_hash", "key_1")
            log.append("seal", "pkg", "1.0", "same_hash", "key_2")

            alerts = log.detect_equivocation()
            assert len(alerts) == 0

    def test_get_history(self, tmp_path):
        with TransparencyLog(tmp_path / "test.db") as log:
            log.append("seal", "a", "1.0", "h1", "k1")
            log.append("seal", "b", "1.0", "h2", "k2")
            log.append("revoke", "a", "1.0", "", "k1")

            all_entries = log.get_history()
            assert len(all_entries) == 3

            pkg_entries = log.get_history(package="a")
            assert len(pkg_entries) == 2

    def test_export_log(self, tmp_path):
        import json
        with TransparencyLog(tmp_path / "test.db") as log:
            log.append("seal", "pkg", "1.0", "h1", "k1")
            exported = log.export_log()
            data = json.loads(exported)
            assert data["version"] == 1
            assert len(data["entries"]) == 1

    def test_size(self, tmp_path):
        with TransparencyLog(tmp_path / "test.db") as log:
            assert log.size() == 0
            log.append("seal", "a", "1.0", "h", "k")
            assert log.size() == 1

    def test_empty_log_verifies(self, tmp_path):
        with TransparencyLog(tmp_path / "test.db") as log:
            valid, errors = log.verify_chain()
            assert valid


class TestLogEntry:
    def test_to_dict(self):
        e = LogEntry(
            sequence=1, timestamp=1000.0, action="seal",
            package_name="pkg", package_version="1.0",
            chain_hash="abc", public_key="def",
            prev_hash="000", entry_hash="fff",
        )
        d = e.to_dict()
        assert d["action"] == "seal"
        assert d["sequence"] == 1

    def test_from_dict(self):
        d = {
            "sequence": 1, "timestamp": 1000.0, "action": "seal",
            "package_name": "pkg", "package_version": "1.0",
            "chain_hash": "abc", "public_key": "def",
            "prev_hash": "000", "entry_hash": "fff",
        }
        e = LogEntry.from_dict(d)
        assert e.package_name == "pkg"
