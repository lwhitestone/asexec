"""Shared scenario builder for the ``asexec verify`` test suite.

Test organization (mirrors docs/VERIFICATION.md)
------------------------------------------------
One file per catalog test, plus one per cross-cutting section of the doc::

    test_verify_bdr.py               ## BDR
    test_verify_ceiling.py           ## ceiling
    test_verify_chain.py             ## chain
    test_verify_content.py           ## content
    test_verify_floor.py             ## floor
    test_verify_keyconsist.py        ## keyconsist
    test_verify_counting_rule.py     ## Counting rule
    test_verify_commitment_states.py ## Commitment states
    test_verify_run_rules.py         ## Conventions (Result, Code, Run rules)
    test_verify_doc_coverage.py      every numbered item above has a fail test

Within a catalog-test file the tests appear in this order, and are named::

    test_<TEST>__pass__all                 every "Passes when all" item holds
    test_<TEST>__pass__<N>_<slug>          an item's optional branch ("if present")
    test_<TEST>__fail__<N>_<slug>          only item N is violated, the rest hold
    test_<TEST>__fail__vacuous_<slug>      nothing to examine (Run rules, (*))

``<N>`` is the item number in that test's *Passes when all* list in the doc, and
every docstring starts with ``<TEST> #<N>:`` followed by the item's wording. A
``fail`` test builds the all-passing scenario, breaks exactly one item (as far as
the items allow: where one item cannot be broken without another, the test says
so), and asserts the whole code, so ``BDR=PASS`` also shows the rest still holds.
Several documented failure modes of one item share a parametrized test.

Tests are black-box: they build inputs, run ``verify_paths``, and assert what the doc
defines (verdicts, the code, documented reasons). Invalid inputs are written as the
doc's dotted property paths (``scenario.set(name, "payload.anchor.floor.round", "1000")``),
never through the verifier's own models.

Cross-cutting files use ``test_counting_rule__...``, ``test_state__<state>__...``,
``test_due__...`` and, in run rules, ``test_tests_arg__``, ``test_code__``, ``test_run__``
and ``test_never_raises__``.

The ``scenario`` fixture is a signed commitment: one prereg and three chained
postregs, all by one key, whose subjects match ``scenario.artifacts``. Floor and
ceiling are opt-in (``with_floor`` / ``with_ceiling``): a floor costs about one
second of BLS math each time ``verify_paths`` runs.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest

from asexec import drand, hashing, keys, manifest
from asexec.canonical import signing_input
from asexec.errors import ManifestError
from asexec.verifier import verify_paths

TARGET = {"kind": "api", "provider": "anthropic", "model_id": "m", "endpoint": ""}
DUE = "2099-01-01T00:00:00Z"

# Real quicknet round 1000 (fetched once; verification is offline).
REAL_FLOOR = {
    "floor_type": "drand",
    "chain_hash": drand.QUICKNET_HASH,
    "round": 1000,
    "signature": (
        "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125"
        "e342b73a8dd2bacbe47e4b6b63ed5e39"
    ),
    "randomness": "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd",
}

WITNESS_ID = "synthetic"
_AUTO = object()
_UNSET = object()


@dataclass
class _Spec:
    kind: str  # "prereg" | "postreg"
    subject: list[dict]  # digests taken when declared, before a test alters artifacts
    fulfills: str | None = None  # a spec name, or a literal "sha-256:<hex>" ref
    prev: str | None = None  # a spec name, or a literal "sha-256:<hex>" ref
    floor: bool = False
    mutations: list[Callable[[dict], None]] = field(default_factory=list)


class Scenario:
    """A signed commitment on disk, with knobs to break exactly one thing.

    Specs are declarative (``fulfills``/``prev`` name other specs), and refs are
    derived at write time, so mutating one body keeps every link consistent
    unless a test deliberately overrides the link.
    """

    def __init__(self, tmp_path, make_server, ceiling_for):
        self.ceiling_for = ceiling_for
        self.manifest_dir = tmp_path / "manifests"
        self.manifest_dir.mkdir()
        self.artifacts = tmp_path / "artifacts"
        (self.artifacts / "harness").mkdir(parents=True)
        (self.artifacts / "harness" / "eval.py").write_text("def run():\n    return 42\n")
        for i in range(3):
            (self.artifacts / f"transcript{i}.txt").write_text(f"run {i}: score=0.{i}\n")
        self.outside = tmp_path / "outside.txt"  # a real file beyond --artifacts
        self.outside.write_text("secret\n")

        self.key = keys.generate()
        self.server_pub, self.sign_response = make_server()
        self.servers = {WITNESS_ID: {"pubkey": self.server_pub}}  # the pinned witnesses

        self.specs: dict[str, _Spec] = {}
        self.signers: dict[str, tuple[bytes, bytes]] = {}
        self.ceilings: dict[str, Any] = {}  # name -> _AUTO | callable(nonce_hex) -> dict
        self.post_sign: dict[str, list[Callable[[dict], None]]] = {}
        self.missing: list[str] = []  # names handed to verify without a file behind them
        self.raw: dict[str, str | bytes] = {}  # extra files written verbatim
        self.dropped: set[str] = set()  # specs derived from but not written
        self._bodies: dict[str, dict] = {}

        self.add_prereg("prereg")
        for i in range(3):
            self.add_postreg(
                f"postreg{i}",
                prev=f"postreg{i - 1}" if i else None,
                transcript=f"transcript{i}.txt",
            )

    # --- declaring manifests ------------------------------------------------ #
    def add_prereg(self, name: str) -> None:
        self.specs[name] = _Spec("prereg", self._subject(["harness"]))

    def add_postreg(
        self,
        name: str,
        fulfills: str = "prereg",
        prev: str | None = None,
        transcript: str = "transcript0.txt",
    ) -> None:
        subject = self._subject([transcript, "harness"])
        self.specs[name] = _Spec("postreg", subject, fulfills=fulfills, prev=prev)

    def with_floor(self, name: str = "prereg") -> None:
        self.specs[name].floor = True

    def with_ceiling(self, name: str = "prereg") -> None:
        self.ceilings[name] = _AUTO

    # --- breaking exactly one thing ----------------------------------------- #
    def mutate(self, name: str, fn: Callable[[dict], None]) -> None:
        """Edit a body before signing (links to later manifests follow the edit)."""
        self.specs[name].mutations.append(fn)

    def set(self, name: str, path: str, value: Any) -> None:
        """Set the property at a doc-style dotted ``path`` (from the envelope root).

        ``payload.*`` is edited before signing, so the junk is validly signed; any other
        root (``signature.*``, ``ceiling.*``) is edited after signing. Missing objects on
        the way are created; a numeric segment indexes an array.
        """
        self._edit(name, path, lambda parent, key: parent.__setitem__(key, value))

    def unset(self, name: str, path: str) -> None:
        """Remove the property at a doc-style dotted ``path`` (see ``set``)."""
        self._edit(name, path, lambda parent, key: parent.pop(key, None))

    def _edit(self, name: str, path: str, op: Callable[[Any, Any], None]) -> None:
        parts = [int(k) if k.isdigit() else k for k in path.split(".")]

        def apply(envelope: Any) -> None:
            obj = envelope
            for key in parts[:-1]:
                obj = obj[key] if isinstance(key, int) else obj.setdefault(key, {})
            op(obj, parts[-1])

        if parts[0] == "payload":
            self.mutate(name, lambda body: apply({"payload": body}))
        else:
            self.tamper(name, apply)

    def mutate_all(self, fn: Callable[[dict], None]) -> None:
        for name in self.specs:
            self.mutate(name, fn)

    def link(self, name: str, *, fulfills: Any = _UNSET, prev: Any = _UNSET) -> None:
        """Re-point a manifest at another spec name, a literal ref, or (prev only) None."""
        if fulfills is not _UNSET:
            self.specs[name].fulfills = fulfills
        if prev is not _UNSET:
            self.specs[name].prev = prev

    def sign_with(self, name: str, signer: tuple[bytes, bytes]) -> None:
        self.signers[name] = signer

    def tamper(self, name: str, fn: Callable[[dict], None]) -> None:
        """Edit the envelope after signing (the signature no longer matches)."""
        self.post_sign.setdefault(name, []).append(fn)

    def drop(self, name: str) -> None:
        """Do not provide this manifest to verify (others still link to it)."""
        self.dropped.add(name)

    def add_missing(self, name: str) -> None:
        """Hand verify a path that has no file (an unreadable input)."""
        self.missing.append(name)

    def add_raw(self, name: str, content: str | bytes) -> None:
        self.raw[name] = content

    def read(self, name: str) -> str:
        self.write()
        return (self.manifest_dir / f"{name}.json").read_text()

    def pin_server(self, pubkey: bytes) -> None:
        self.servers = {WITNESS_ID: {"pubkey": pubkey}}

    # --- building ------------------------------------------------------------ #
    def _subject(self, names: list[str]) -> list[dict]:
        return hashing.build_subject([str(self.artifacts / n) for n in names])

    def _link(self, target: str | None) -> str | None:
        if target is None or target.startswith("sha-256:"):
            return target
        return manifest.ref(self._body(target))

    def _body(self, name: str) -> dict:
        if name not in self._bodies:
            self._bodies[name] = self._build_body(name)
        return self._bodies[name]

    def _build_body(self, name: str) -> dict:
        spec = self.specs[name]
        common = {
            "due": DUE,
            "declaration": "all runs in full",
            "subject": copy.deepcopy(spec.subject),
            "notes": name,  # makes sibling bodies distinct, so their refs differ
        }
        if spec.floor:
            common["floor"] = copy.deepcopy(REAL_FLOOR)
        if spec.kind == "prereg":
            body = manifest.build_prereg(TARGET, **common)
        else:
            body = manifest.build_postreg(
                TARGET,
                fulfills=self._link(spec.fulfills),
                prev_hash=self._link(spec.prev),
                **common,
            )
        for fn in spec.mutations:
            fn(body)
        return body

    def write(self) -> list[str]:
        self._bodies = {}
        paths = []
        for name in self.specs:
            body = self._body(name)
            envelope = _sign(body, *self.signers.get(name, self.key))
            record = self.ceilings.get(name)
            if record is not None:
                nonce_hex = manifest.ref(body).split(":", 1)[-1]
                if record is _AUTO:
                    record = self.ceiling_for(
                        nonce_hex, WITNESS_ID, self.server_pub, self.sign_response
                    )
                else:
                    record = record(nonce_hex)
                manifest.attach_ceiling(envelope, record)
            for fn in self.post_sign.get(name, []):
                fn(envelope)
            path = self.manifest_dir / f"{name}.json"
            manifest.save(envelope, str(path))
            if name not in self.dropped:
                paths.append(str(path))
        for name, content in self.raw.items():
            path = self.manifest_dir / f"{name}.json"
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content)
            paths.append(str(path))
        paths.extend(str(self.manifest_dir / f"{name}.json") for name in self.missing)
        return paths

    # --- running verify ------------------------------------------------------ #
    def verify(self, *tests: str, artifacts: bool = True, now: float | None = None) -> dict:
        names = ["BDR", *[t for t in tests if t != "BDR"]]
        paths = self.write()
        return verify_paths(
            paths,
            names,
            artifacts_dir=str(self.artifacts) if artifacts else None,
            now=now,
            servers=self.servers,
        )

    def code(self, *tests: str, **kwargs) -> str:
        return self.verify(*tests, **kwargs)["code"]


def _sign(body: dict, priv: bytes, pub: bytes) -> dict:
    """Sign with the production writer; a junk body its signing gate refuses (e.g. a
    subject with a null hash_alg) is signed anyway, as anyone with a key could."""
    try:
        return manifest.sign(body, priv, pub)
    except ManifestError:
        sig = keys.sign(priv, signing_input(body))
        signature = {"alg": "ed25519", "keyid": keys.keyid_for(pub), "pubkey": pub.hex()}
        return {"payload": body, "signature": {**signature, "sig": sig.hex()}}


@pytest.fixture
def scenario(tmp_path, make_server, ceiling_for) -> Scenario:
    return Scenario(tmp_path, make_server, ceiling_for)
