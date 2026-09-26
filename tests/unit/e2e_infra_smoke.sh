#!/usr/bin/env bash
# tests/unit/e2e_infra_smoke.sh — FORWARDER (temporary seam, not a test).
# The suite MOVED to tests/integration/e2e_infra_smoke.sh (heavy tier: daemon spawn /
# real artifact build — .tasks.md "Decouple Heavy Integration Work").
# This file exists ONLY because tests/run-e2e.sh (owned by the e2e lane)
# invokes `bash $TESTS/unit/e2e_infra_smoke.sh` for its pre-scenario self-test
# (run-e2e.sh lines 244/251/262). run-unit.sh excludes it by name, so the
# suite is not double-paid on the fast lane. DELETE this forwarder when
# run-e2e.sh is repointed at tests/integration/.
exec bash "$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)/../integration/e2e_infra_smoke.sh" "$@"
