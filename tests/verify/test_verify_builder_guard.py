"""Guard: the production writer and the raw verify data must not drift apart.

The verify suite never uses the writer, so nothing else would notice if the writer
started producing manifests the suite no longer resembles. A schema change updates
``tests/manifest_data.py`` first; these tests then fail until the writer matches.
"""

import json

import manifest_data as d
import pytest

from asexec import manifest
from asexec.verifier import verify_paths

TESTS = ["BDR", "chain", "content", "floor", "keyconsist"]
ALL_PASS = "asexec-verify/1 BDR=PASS chain=PASS content=PASS floor=PASS keyconsist=PASS"


def _built(raw):
    """What the writer builds from the same inputs as the raw body."""
    args = {k: raw[k] for k in ("due", "declaration", "subject", "hash_alg", "notes") if k in raw}
    if "anchor" in raw:
        args["floor"] = raw["anchor"]["floor"]
    if raw["phase"] == "prereg":
        return manifest.build_prereg(raw["target"], **args)
    return manifest.build_postreg(raw["target"], fulfills=raw["fulfills"], **args)


PREREG_WITH_FLOOR = d.with_field(d.PREREG, "anchor.floor", d.FLOOR)
POSTREG_TO_IT = d.with_field(d.POSTREG, "fulfills", d.ref(PREREG_WITH_FLOOR))


@pytest.mark.parametrize(
    "raw", [d.PREREG, d.POSTREG, PREREG_WITH_FLOOR], ids=["prereg", "postreg", "prereg-floor"]
)
def test_guard__writer_builds_the_raw_body_and_envelope(raw):
    assert _built(raw) == raw
    assert manifest.sign(_built(raw), *d.TEST_KEY) == d.sign(raw)


def test_guard__writer_output_and_raw_data_verify_alike(tmp_path):
    for rel, text in d.ARTIFACTS.items():
        (tmp_path / "artifacts" / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "artifacts" / rel).write_text(text)
    codes = []
    for source in ("writer", "raw"):
        paths = []
        for name, raw in (("pre", PREREG_WITH_FLOOR), ("post", POSTREG_TO_IT)):
            env = manifest.sign(_built(raw), *d.TEST_KEY) if source == "writer" else d.sign(raw)
            path = tmp_path / f"{source}-{name}.json"
            path.write_text(json.dumps(env))
            paths.append(str(path))
        codes.append(verify_paths(paths, TESTS, str(tmp_path / "artifacts"))["code"])
    assert codes == [ALL_PASS, ALL_PASS]
