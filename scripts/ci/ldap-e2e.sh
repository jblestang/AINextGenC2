#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "Starting FMN OpenLDAP (docker compose)..."
docker compose -f docker-compose.ldap-ci.yml up -d --wait --build

export MIM_LDAP_PIP_CONFIG="$ROOT/config/fmn-ldap-pip-ci.toml"
export MIM_LDAP_BIND_PASSWORD=ci-ldap-admin

echo "Running live LDAP E2E tests..."
cargo test -p mim-policy --test live_ldap_e2e -- --ignored
cargo test -p mim-transport-http --test ldap_identity_e2e -- --ignored

echo "LDAP E2E passed."
