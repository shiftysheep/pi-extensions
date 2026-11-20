#!/usr/bin/env bash
# Run the advisor-triggering eval suite.
#
# This runs LIVE pi sessions with the advisor tool + mock provider. It is NOT
# part of `npm test` (unit tests); it is a separate eval that incurs NO real
# API charges (the advisor model is mocked).
#
# Usage: npm run eval:advisor
set -euo pipefail

cd "$(dirname "$0")/.."

# Run the eval test file with tsx (TypeScript support).
npx tsx --test test/advisor-wrapper/eval.test.ts