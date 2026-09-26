#!/usr/bin/env bash
# tests/unit/swtpm_proxy_data_plane.sh — FORWARDER (temporary seam, not a test).
# The suite MOVED to tests/integration/swtpm_proxy_data_plane.sh (heavy tier: daemon spawn /
# real artifact build — .tasks.md "Decouple Heavy Integration Work").
# This file exists ONLY because tests/run-e2e.sh (owned by the e2e lane)
# invokes `bash $TESTS/unit/swtpm_proxy_data_plane.sh` for its pre-scenario self-test
# (run-e2e.sh lines 244/251/262). run-unit.sh excludes it by name, so the
# suite is not double-paid on the fast lane. DELETE this forwarder when
# run-e2e.sh is repointed at tests/integration/.
exec bash "$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)/../integration/swtpm_proxy_data_plane.sh" "$@"
