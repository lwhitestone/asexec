#!/usr/bin/env bash
#
# release.sh — bump the version, tag, and push a release.
#
# Usage:
#   scripts/release.sh [--no-check] VERSION
#
# VERSION is X.Y.Z or a PEP 440 beta X.Y.ZbN, in normalized form (no leading
# zeros), so the tag, the version declarations and the built file names agree.
#
# Examples:
#   scripts/release.sh 0.4.0b1
#   scripts/release.sh 0.4.0
#   scripts/release.sh --no-check 0.4.1
#
# What it does:
#   1. Verifies the working tree is clean and on the main branch
#   2. Verifies src/asexec/__init__.py and pyproject.toml agree on the
#      current version, and that VERSION is new
#   3. Verifies tag vVERSION doesn't already exist locally or on origin
#   4. Updates both version declarations to VERSION, and sets the payloadType
#      the release writes (below)
#   5. Runs scripts/check.sh (lint + tests) unless --no-check is passed
#   6. Commits ("Release vVERSION"), creates an annotated tag, and pushes
#      both to origin
#
# The payloadType (docs/DEVELOPMENT.md, Releasing): the release commit rewrites
# the MANIFEST_PAYLOAD_TYPE literal in src/asexec/constants.py and its pinned
# literal in tests/test_constants.py. This script is the sanctioned way to
# change them. A beta writes application/vnd.asexec.X.Y.ZbN+json, under the
# FORMATS entry under development, which is keyed by the name
# MANIFEST_PAYLOAD_TYPE. A full release writes its line's format, from
# RELEASE_PAYLOAD_TYPES below, and a line with none is refused. The first full
# release of a line (X.Y.0) releases the entry under development: its key
# becomes the type's literal, which never changes after that. Main keeps the
# type the last release commit set until the next release commit.
#
# Pushing the tag triggers .github/workflows/publish.yml (CI → TestPyPI →
# smoke test → manual approval → PyPI → GitHub Release). The workflow
# rejects tags that are not on main, so this script refuses to run on any
# other branch. The script itself still does not build or upload anything.
# If anything fails before the release commit, every file it edits (the two
# version declarations, uv.lock and the two payloadType files) is restored.

set -euo pipefail

# Validate arguments.
SKIP_CHECK=false

if [[ $# -eq 2 && "$1" == "--no-check" ]]; then
    SKIP_CHECK=true
    VERSION="$2"
elif [[ $# -eq 1 ]]; then
    VERSION="$1"
else
    echo "Usage: $0 [--no-check] VERSION"
    echo "Example: $0 0.3.4"
    echo "Example: $0 --no-check 0.3.4"
    exit 2
fi

TAG="v$VERSION"

INIT_FILE="src/asexec/__init__.py"
PYPROJECT_FILE="pyproject.toml"
LOCK_FILE="uv.lock"
CONSTANTS_FILE="src/asexec/constants.py"
PINS_FILE="tests/test_constants.py"
CHECK_SCRIPT="scripts/check.sh"
REMOTE="origin"
CLEANUP_NEEDED=false

# Some systems (e.g. Debian/Ubuntu-based) only provide `python3`.
if command -v python >/dev/null 2>&1; then
    PYTHON="python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
else
    echo "Error: neither 'python' nor 'python3' found on PATH."
    exit 1
fi

cleanup() {
    if [[ "$CLEANUP_NEEDED" == true ]]; then
        git restore -- "$INIT_FILE" "$PYPROJECT_FILE" "$LOCK_FILE" \
            "$CONSTANTS_FILE" "$PINS_FILE"
    fi
}

trap cleanup EXIT

# Validate the version: X.Y.Z or X.Y.ZbN, with no leading zeros.
NUM="(0|[1-9][0-9]*)"
if [[ ! "$VERSION" =~ ^$NUM\.$NUM\.$NUM(b$NUM)?$ ]]; then
    echo "Error: version must look like X.Y.Z or X.Y.ZbN (a PEP 440 beta), with no leading zeros"
    exit 2
fi

# Require a clean working tree.
if [[ -n "$(git status --porcelain)" ]]; then
    echo "Error: working tree is not clean."
    echo
    git status --short
    exit 1
fi

# Require a branch checkout.
BRANCH="$(git branch --show-current)"

if [[ -z "$BRANCH" ]]; then
    echo "Error: HEAD is detached."
    exit 1
fi

if [[ "$BRANCH" != "main" ]]; then
    echo "Error: releases must be cut from main (currently on '$BRANCH')."
    echo "The publish workflow rejects tags that are not on main."
    exit 1
fi

# Verify the current versions agree.
INIT_VERSION="$(
    sed -nE 's/^__version__ = "([^"]+)"/\1/p' "$INIT_FILE"
)"

PROJECT_VERSION="$(
    sed -nE 's/^version = "([^"]+)"/\1/p' "$PYPROJECT_FILE"
)"

if [[ -z "$INIT_VERSION" || -z "$PROJECT_VERSION" ]]; then
    echo "Error: could not determine current version."
    exit 1
fi

if [[ "$INIT_VERSION" != "$PROJECT_VERSION" ]]; then
    echo "Error: version mismatch before release:"
    echo "  $INIT_FILE:       $INIT_VERSION"
    echo "  $PYPROJECT_FILE:  $PROJECT_VERSION"
    exit 1
fi

if [[ "$INIT_VERSION" == "$VERSION" ]]; then
    echo "Error: already at version $VERSION."
    exit 1
fi

echo "Current version: $INIT_VERSION"
echo "Release version: $VERSION"
echo "Branch:          $BRANCH"
echo "Tag:             $TAG"

# Verify the tag does not exist locally.
if git rev-parse --verify --quiet "refs/tags/$TAG" >/dev/null; then
    echo
    echo "Error: local Git tag $TAG already exists."
    exit 1
fi

# Verify the remote exists.
if ! git remote get-url "$REMOTE" >/dev/null 2>&1; then
    echo
    echo "Error: Git remote '$REMOTE' does not exist."
    exit 1
fi

# Verify the tag does not exist remotely.
if git ls-remote --exit-code --tags "$REMOTE" "refs/tags/$TAG" >/dev/null 2>&1; then
    echo
    echo "Error: remote Git tag $TAG already exists on $REMOTE."
    exit 1
fi

# Require the check script before modifying version files unless checks are explicitly skipped.
if [[ "$SKIP_CHECK" == false ]]; then
    if [[ ! -x "$CHECK_SCRIPT" ]]; then
        echo
        echo "Error: $CHECK_SCRIPT not found or not executable."
        echo "Run scripts/dev-setup.sh first, or use --no-check."
        exit 1
    fi
fi

# Restore the edited files if anything fails before the release commit.
CLEANUP_NEEDED=true

# Update the version declarations and the payloadType. Every edit is checked
# before any file is written.
echo
echo "Updating version declarations and payloadType..."

"$PYTHON" - "$VERSION" "$INIT_FILE" "$PYPROJECT_FILE" "$CONSTANTS_FILE" "$PINS_FILE" <<'PY'
import pathlib
import re
import sys

version, init_name, pyproject_name, constants_name, pins_name = sys.argv[1:]

# The payloadType each release line's full releases write. A full release of a
# line with no entry here is refused rather than guessed: add the line once its
# format is decided (docs/MULTIVERSION.md).
RELEASE_PAYLOAD_TYPES = {
    "0.4": "application/vnd.asexec.v1+json",
}

major, minor, patch, beta = re.fullmatch(
    r"([0-9]+)\.([0-9]+)\.([0-9]+)(b[0-9]+)?", version
).groups()
line = f"{major}.{minor}"

if beta:
    payload_type = f"application/vnd.asexec.{version}+json"
elif line in RELEASE_PAYLOAD_TYPES:
    payload_type = RELEASE_PAYLOAD_TYPES[line]
else:
    raise SystemExit(
        f"Error: no payloadType is set for full releases of {line}; add it to "
        "RELEASE_PAYLOAD_TYPES in scripts/release.sh"
    )

# The FORMATS entry under development is keyed by the name, a released one by
# its literal.
NAME_KEY = r"(?m)^    MANIFEST_PAYLOAD_TYPE: \{$"
literal_key = f'    "{payload_type}": {{'
LITERAL_KEY = "(?m)^" + re.escape(literal_key) + "$"

texts = {}


def text_of(filename):
    if filename not in texts:
        texts[filename] = pathlib.Path(filename).read_text()
    return texts[filename]


def rewrite(filename, pattern, replacement, what):
    updated, count = re.subn(pattern, lambda _: replacement, text_of(filename))
    if count != 1:
        raise SystemExit(
            f"Error: {filename}: expected exactly one {what}, found {count}"
        )
    texts[filename] = updated


def occurrences(filename, pattern):
    return len(re.findall(pattern, text_of(filename)))


rewrite(
    init_name,
    r'(?m)^__version__ = "[^"]+"$',
    f'__version__ = "{version}"',
    "version declaration",
)
rewrite(
    pyproject_name,
    r'(?m)^version = "[^"]+"$',
    f'version = "{version}"',
    "version declaration",
)
rewrite(
    constants_name,
    r'(?m)^MANIFEST_PAYLOAD_TYPE = "[^"]+"$',
    f'MANIFEST_PAYLOAD_TYPE = "{payload_type}"',
    "MANIFEST_PAYLOAD_TYPE literal",
)
rewrite(
    pins_name,
    r'(?m)^    assert constants\.MANIFEST_PAYLOAD_TYPE == "[^"]+"$',
    f'    assert constants.MANIFEST_PAYLOAD_TYPE == "{payload_type}"',
    "pinned MANIFEST_PAYLOAD_TYPE literal",
)

if beta:
    # A beta's type names the entry under development, so it must exist.
    if occurrences(constants_name, NAME_KEY) != 1:
        raise SystemExit(
            f"Error: {constants_name}: a beta writes the FORMATS entry under "
            "development, but there is not exactly one keyed by MANIFEST_PAYLOAD_TYPE"
        )
elif patch == "0":
    # The first full release of a line releases the entry under development.
    rewrite(
        constants_name,
        NAME_KEY,
        literal_key,
        "FORMATS entry keyed by MANIFEST_PAYLOAD_TYPE (the entry to release)",
    )
elif occurrences(constants_name, NAME_KEY) != 0 or (
    occurrences(constants_name, LITERAL_KEY) != 1
):
    # A later release of the line writes the format its X.Y.0 released, and no
    # entry under development may share that key.
    raise SystemExit(
        f"Error: {constants_name}: a {line} release writes the released "
        f"{payload_type} entry, which must be keyed by its literal, with no entry "
        "keyed by MANIFEST_PAYLOAD_TYPE"
    )

for filename, text in texts.items():
    pathlib.Path(filename).write_text(text)

print(f"payloadType: {payload_type}")
PY

# Show and validate the changes.
echo
echo "Release changes:"
git diff -- "$INIT_FILE" "$PYPROJECT_FILE" "$CONSTANTS_FILE" "$PINS_FILE"

# Run lint + tests unless explicitly skipped. This may also update uv.lock
# (e.g. via `uv sync`/`uv run` picking up the new project version).
if [[ "$SKIP_CHECK" == true ]]; then
    echo
    echo "WARNING: Checks skipped (--no-check)."
else
    echo
    echo "Running checks..."
    "$CHECK_SCRIPT"
fi

echo
echo "Checking Git diff..."
git diff --check

# Create the release commit. Include uv.lock only if checks touched it.
echo
echo "Creating release commit..."

git add "$INIT_FILE" "$PYPROJECT_FILE" "$CONSTANTS_FILE" "$PINS_FILE"

if [[ -n "$(git status --porcelain -- "$LOCK_FILE")" ]]; then
    echo "  (including updated $LOCK_FILE)"
    git add "$LOCK_FILE"
fi

git commit -m "Release $TAG"

# The release commit is now permanent; failures after this point leave it intact.
CLEANUP_NEEDED=false

RELEASE_COMMIT="$(git rev-parse HEAD)"

echo
echo "Release commit:"
echo "  $RELEASE_COMMIT"

# Create the annotated release tag.
echo
echo "Creating annotated tag $TAG..."

git tag -a "$TAG" -m "Release $TAG"

# Verify the tag points exactly at the release commit.
TAG_COMMIT="$(git rev-list -n 1 "$TAG")"

if [[ "$TAG_COMMIT" != "$RELEASE_COMMIT" ]]; then
    echo "Error: release tag does not point to the release commit."
    echo "  Release commit: $RELEASE_COMMIT"
    echo "  Tag commit:     $TAG_COMMIT"
    exit 1
fi

# Push the release commit and tag together.
echo
echo "Pushing release commit and tag..."

git push "$REMOTE" "$BRANCH" --follow-tags

# Verify the remote tag points at the release commit.
echo
echo "Verifying remote tag..."

REMOTE_TAG_COMMIT="$(
    git ls-remote "$REMOTE" "refs/tags/$TAG^{}" |
        awk '{print $1}'
)"

if [[ -z "$REMOTE_TAG_COMMIT" ]]; then
    echo "Error: could not verify remote tag $TAG."
    exit 1
fi

if [[ "$REMOTE_TAG_COMMIT" != "$RELEASE_COMMIT" ]]; then
    echo "Error: remote tag does not point at the release commit."
    echo "  Release commit: $RELEASE_COMMIT"
    echo "  Remote tag:     $REMOTE_TAG_COMMIT"
    exit 1
fi

echo
echo "Release complete:"
echo
echo "  Version: $VERSION"
echo "  Commit:  $RELEASE_COMMIT"
echo "  Tag:     $TAG"
echo "  Branch:  $BRANCH"
if [[ "$SKIP_CHECK" == true ]]; then
    echo "  Checks:  SKIPPED"
fi

# Derive the Actions URL from the remote (SSH or HTTPS form).
REMOTE_URL="$(git remote get-url "$REMOTE")"
REPO_PATH="$(
    sed -E 's#^(git@[^:]+:|ssh://git@[^/]+/|https?://[^/]+/)##; s#\.git$##' <<<"$REMOTE_URL"
)"
echo
echo "Publish workflow:"
echo "  https://github.com/$REPO_PATH/actions/workflows/publish.yml"
echo "The pypi environment will wait for approval after the TestPyPI smoke test."