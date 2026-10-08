#!/bin/sh
# Shell test for validate-fleet-inputs.sh: good inputs pass; newline, comma, space, '=' and
# overlong values fail. Run in CI's lint stage.
set -u
here=$(dirname "$0")
failures=0
nl='
'
good() {
  FLEET_MODE=apply FLEET_TARGET_VERSION=0.5.0 FLEET_DEPLOYMENT_NAME=uaen-hosted-1 FLEET_NAMESPACE=manar \
    FLEET_DEPLOYMENT_ID=6d3c0d6e-8f0a-4b8e-9a4e-1f2a3b4c5d6e FLEET_UPGRADE_ID=0b4a9f3c-1d2e-4f5a-8b6c-7d8e9f0a1b2c "$@"
}
expect() { # $1 expected (pass|fail), $2 label, rest: env assignments
  want=$1 label=$2
  shift 2
  if good env "$@" sh "$here/validate-fleet-inputs.sh" 2>/dev/null; then got=pass; else got=fail; fi
  if [ "$got" != "$want" ]; then
    echo "FAIL: $label (expected $want, got $got)"
    failures=$((failures + 1))
  fi
}
long=$(printf '%065d' 0)
expect pass "valid inputs"
expect fail "newline then helm --set injection" "FLEET_TARGET_VERSION=v1.2.3${nl},image.repository=evil/img"
expect fail "comma in tag" "FLEET_TARGET_VERSION=1.0,image.repository=evil"
expect fail "space in tag" "FLEET_TARGET_VERSION=1.0 --set x=y"
expect fail "equals in tag" "FLEET_TARGET_VERSION=a=b"
expect fail "overlong tag" "FLEET_TARGET_VERSION=$long"
expect fail "empty tag" "FLEET_TARGET_VERSION="
expect fail "newline in namespace" "FLEET_NAMESPACE=manar${nl}kube-system"
expect fail "uppercase namespace" "FLEET_NAMESPACE=Manar"
expect fail "path traversal in deployment name" "FLEET_DEPLOYMENT_NAME=.."
expect fail "slash in deployment name" "FLEET_DEPLOYMENT_NAME=a/b"
expect fail "unknown mode" "FLEET_MODE=destroy"
expect fail "bad deployment id" "FLEET_DEPLOYMENT_ID=not-a-uuid"
expect fail "newline in upgrade id" "FLEET_UPGRADE_ID=0b4a9f3c-1d2e-4f5a-8b6c-7d8e9f0a1b2c${nl}x"
if [ "$failures" -ne 0 ]; then exit 1; fi
echo "validate-fleet-inputs: all cases pass"
