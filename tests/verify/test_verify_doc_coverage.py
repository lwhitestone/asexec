"""Doc coverage: every numbered requirement in docs/VERIFICATION.md has a failing-case test.

Reads the numbered *Passes when all* items of each `` ### `<test>` `` section (and the
numbered items of `## Counting rule`), and the ``test_<name>__{pass,fail}__<N>_...`` names
of this suite (see conftest.py). Black-box: it checks the suite against the doc, never
against the verifier's code.
"""

import ast
import re
from pathlib import Path

from asexec.verifier import TEST_CATALOG

HERE = Path(__file__).parent
DOC = HERE.parents[1] / "docs" / "VERIFICATION.md"

_TEST_NAME = re.compile(
    r"^test_(?P<name>[A-Za-z_]+?)__(?P<kind>pass|fail)__(?P<item>\d+|all|vacuous)_?"
)
_ITEM = re.compile(r"^(\d+)\. ")


def _doc_items() -> dict[str, set[int]]:
    """``{test name: {item numbers}}`` from the doc's numbered requirement lists."""
    items: dict[str, set[int]] = {}
    section = None
    listing = False
    for line in DOC.read_text().splitlines():
        heading = re.match(r"^### `(\w+)`$", line)
        if heading:
            section, listing = heading.group(1), False
            items[section] = set()
        elif line == "## Counting rule":
            section, listing = "counting_rule", True
            items[section] = set()
        elif line.startswith("## "):
            section, listing = None, False
        elif section and line.startswith("**Passes when all**"):
            listing = True
        elif section and listing:
            numbered = _ITEM.match(line)
            if numbered:
                items[section].add(int(numbered.group(1)))
            elif line and not line.startswith(" ") and items[section]:
                listing = False  # the list ended
    return items


def _suite_tests() -> list[tuple[str, str, str]]:
    """``(name, kind, item)`` for every structured test name in this suite."""
    found = []
    for path in sorted(HERE.glob("test_verify_*.py")):
        for node in ast.parse(path.read_text()).body:
            if isinstance(node, ast.FunctionDef):
                m = _TEST_NAME.match(node.name)
                if m:
                    found.append((m["name"], m["kind"], m["item"]))
    return found


DOC_ITEMS = _doc_items()
SUITE = _suite_tests()


def test_doc_coverage__doc_lists_every_catalog_test():
    assert set(TEST_CATALOG) == set(DOC_ITEMS) - {"counting_rule"}
    assert all(DOC_ITEMS.values()), "a section with no numbered items was parsed"


def test_doc_coverage__every_numbered_item_has_a_fail_test():
    covered = {(name, int(item)) for name, kind, item in SUITE if kind == "fail" and item.isdigit()}
    wanted = {(name, n) for name, ns in DOC_ITEMS.items() for n in ns}
    assert sorted(wanted - covered) == []


def test_doc_coverage__every_numbered_test_names_a_doc_item():
    named = {(name, int(item)) for name, _kind, item in SUITE if item.isdigit()}
    wanted = {(name, n) for name, ns in DOC_ITEMS.items() for n in ns}
    assert sorted(named - wanted) == []


def test_doc_coverage__every_catalog_test_has_pass_all_and_vacuous_fail():
    for name in TEST_CATALOG:
        assert (name, "pass", "all") in SUITE, name
        assert (name, "fail", "vacuous") in SUITE, name
