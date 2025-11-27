#!/bin/bash
set -e

# Script to finalize cleanup: stage deletions and commit
# Run from repository root: bash scripts/finalize_cleanup.sh

echo "Staging all changes..."
 git add -A

# If nothing staged, inform the user
if git diff --cached --quiet; then
  echo "Nothing to commit (no staged changes)."
  git status --short
  exit 0
fi

COMMIT_MSG="Remove archived unreferenced/duplicate files"

echo "Committing with message: $COMMIT_MSG"
 git commit -m "$COMMIT_MSG"

echo "Commit created. Current repo status:"
 git status --short

echo "Done. If you want to permanently remove large files from history, use BFG or git filter-repo (manual step)."
