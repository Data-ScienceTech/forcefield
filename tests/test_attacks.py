"""Tests for the attack catalog."""

import pytest
from forcefield.attacks import CATALOG, CATEGORIES, get_catalog, get_by_category


class TestAttackCatalog:
    def test_catalog_has_entries(self):
        assert len(CATALOG) >= 100

    def test_catalog_categories_all_present(self):
        cats_in_catalog = {a.category for a in CATALOG}
        for cat_key in CATEGORIES:
            assert cat_key in cats_in_catalog, f"Category {cat_key} has no attacks"

    def test_get_catalog_returns_copy(self):
        cat = get_catalog()
        assert len(cat) == len(CATALOG)
        cat.pop()
        assert len(get_catalog()) == len(CATALOG)

    def test_get_by_category(self):
        injections = get_by_category("prompt_injection_basic")
        assert len(injections) >= 10
        assert all(a.category == "prompt_injection_basic" for a in injections)

    def test_all_attacks_have_required_fields(self):
        for a in CATALOG:
            assert a.id
            assert a.category
            assert a.severity in ("low", "medium", "high")
            assert a.prompt
            assert len(a.prompt) > 10
