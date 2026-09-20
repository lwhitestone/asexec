#!/usr/bin/env bash

set -euo pipefail

# Validate arguments.
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 VERSION"
    echo "Example: $0 0.3.4"
    exit 2
fi

VERSION="$1"
TAG="v$VERSION"

INIT_FILE="src/asexec/__init__.py"
PYPROJECT_FILE="pyproject.toml"

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
REMOTE="origin"

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

echo
echo "Running tests..."
python -m pytest

echo
echo "Checking Git diff..."
git diff --check

# Create the release commit.
echo
echo "Creating release commit..."

git add "$INIT_FILE" "$PYPROJECT_FILE"
git commit -m "Release $TAG"

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
echo
echo "The tag is the release boundary."
