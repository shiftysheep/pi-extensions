#!/bin/sh
# Block direct commits to main; use feature branches.
# Mirrors the GitHub branch protection rule (PRs only) locally, so the
# habit is formed before hitting the server-side rejection.
branch=$(git rev-parse --abbrev-ref HEAD)
if [ "$branch" = "main" ]; then
  echo "✖ Direct commits to main are blocked." >&2
  echo "  Create a feature branch first: git switch -c <type>/<short-desc>" >&2
  exit 1
fi
