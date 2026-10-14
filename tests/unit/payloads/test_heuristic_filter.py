"""MiFID transaction references have no fixed format, so they are heuristic."""
from evadex.core.result import CATEGORY_TYPES, CategoryType, PayloadCategory
from evadex.payloads.builtins import HEURISTIC_CATEGORIES, get_payloads


def test_mifid_is_heuristic_in_both_places():
    # CATEGORY_TYPES labels the category; HEURISTIC_CATEGORIES is what the
    # default payload filter actually reads.
    assert CATEGORY_TYPES[PayloadCategory.MIFID_TX_ID] == CategoryType.HEURISTIC
    assert PayloadCategory.MIFID_TX_ID in HEURISTIC_CATEGORIES


def test_mifid_runs_only_when_heuristics_are_asked_for():
    cats = {PayloadCategory.MIFID_TX_ID}
    assert get_payloads(cats) == []
    assert get_payloads(cats, include_heuristic=True)
