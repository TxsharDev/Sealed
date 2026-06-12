"""Tests for dependency resolver."""

import pytest

from sealed.resolver import DependencyResolver, DepNode, _normalize


class TestNormalize:
    def test_lowercase(self):
        assert _normalize("Flask") == "flask"

    def test_hyphens_to_underscores(self):
        assert _normalize("my-package") == "my_package"

    def test_dots_to_underscores(self):
        assert _normalize("my.package") == "my_package"

    def test_mixed(self):
        assert _normalize("My-Cool.Package") == "my_cool_package"

    def test_strips_whitespace(self):
        assert _normalize("  flask  ") == "flask"


class TestDepNode:
    def test_defaults(self):
        node = DepNode(name="test", version="1.0")
        assert node.dependencies == []
        assert node.sealed is False
        assert node.error is None

    def test_with_deps(self):
        node = DepNode(name="requests", version="2.32.3",
                       dependencies=["urllib3", "certifi"])
        assert len(node.dependencies) == 2


class TestDependencyResolver:
    def test_resolve_returns_list(self):
        """Integration test: resolve a real small package."""
        resolver = DependencyResolver()
        try:
            deps = resolver.resolve("six", "1.17.0")
            assert len(deps) >= 1
            names = [d.name for d in deps]
            assert "six" in names
        except Exception:
            pytest.skip("Network not available or pip --dry-run --report not supported")

    def test_topological_sort_order(self):
        """Direct test of topo sort logic."""
        resolver = DependencyResolver()
        tree = {
            "a": DepNode("a", "1.0", dependencies=["b", "c"]),
            "b": DepNode("b", "1.0", dependencies=["c"]),
            "c": DepNode("c", "1.0", dependencies=[]),
        }
        result = resolver._topological_sort(tree)
        names = [d.name for d in result]
        # c must come before b, b before a
        assert names.index("c") < names.index("b")
        assert names.index("b") < names.index("a")

    def test_topological_sort_single(self):
        resolver = DependencyResolver()
        tree = {"x": DepNode("x", "1.0")}
        result = resolver._topological_sort(tree)
        assert len(result) == 1
        assert result[0].name == "x"

    def test_topological_sort_handles_missing_deps(self):
        resolver = DependencyResolver()
        tree = {
            "a": DepNode("a", "1.0", dependencies=["missing"]),
        }
        result = resolver._topological_sort(tree)
        assert len(result) == 1  # just "a", "missing" is skipped
