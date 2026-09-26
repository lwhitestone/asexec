#!/usr/bin/env bash
#
# release.sh — bump the version, tag, and push a release.
#
# Usage:
#   scripts/release.sh [--no-check] VERSION
#
# Examples:
#   scripts/release.sh 0.3.4
#   scripts/release.sh --no-check 0.3.4
#
# What it does:
#   1. Verifies the working tree is clean and on a real branch
#   2. Verifies src/asexec/__init__.py and pyproject.toml agree on the
#      current version, and that VERSION is new
#   3. Verifies tag vVERSION doesn't already exist locally or on origin
#   4. Updates both version declarations to VERSION
#   5. Runs scripts/check.sh (lint + tests) unless --no-check is passed
#   6. Commits ("Release vVERSION"), creates an annotated tag, and pushes
#      both to origin
#
# This script only tags and pushes — it does not build or publish a
# package. If anything fails before the release commit, the version file
# edits are automatically reverted.

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
CHECK_SCRIPT="scripts/check.sh"
REMOTE="origin"
CLEANUP_NEEDED=false

cleanup() {
    if [[ "$CLEANUP_NEEDED" == true ]]; then
        git restore -- "$INIT_FILE" "$PYPROJECT_FILE"
    fi
}

trap cleanup EXIT

# Validate the version.
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: version must look like X.Y.Z"
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

# Restore version files if anything fails before the release commit.
CLEANUP_NEEDED=true

# Update the version declarations.
echo
echo "Updating version declarations..."

python - "$VERSION" "$INIT_FILE" "$PYPROJECT_FILE" <<'PY'
import pathlib
import re
import sys

version, init_name, pyproject_name = sys.argv[1:]

files = [
    (
        init_name,
        r'(?m)^(__version__ = ")[^"]+(")$',
    ),
    (
        pyproject_name,
        r'(?m)^(version = ")[^"]+(")$',
    ),
]

for filename, pattern in files:
    path = pathlib.Path(filename)
    text = path.read_text()

    updated, count = re.subn(
        pattern,
        rf'\g<1>{version}\g<2>',
        text,
    )

    if count != 1:
        raise SystemExit(
            f"{filename}: expected exactly one version declaration, "
            f"found {count}"
        )

    path.write_text(updated)
PY

# Show and validate the changes.
echo
echo "Version changes:"
git diff -- "$INIT_FILE" "$PYPROJECT_FILE"

# Run lint + tests unless explicitly skipped.
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

# Create the release commit.
echo
echo "Creating release commit..."

git add "$INIT_FILE" "$PYPROJECT_FILE"
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