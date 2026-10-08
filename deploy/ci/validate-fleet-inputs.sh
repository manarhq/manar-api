#!/bin/sh
# Validates the variables manar-fleet passes to the deploy pipeline (ADR-0010). Each check sees
# the whole value (no per-line grep), so a newline, comma, space, '=' or any other character
# outside the allowed set is rejected, as is an empty or overlong value. Rejects, never sanitises.
# Usage: validate-fleet-inputs.sh  (reads FLEET_* from the environment; exit 1 on the first failure)

fail() {
  echo "invalid $1" >&2
  exit 1
}

# $1 name, $2 value, $3 max length; allowed: letters, digits, dot, underscore, dash.
check_token() {
  case "$2" in "" | *[!0-9A-Za-z._-]* | [._-]*) fail "$1" ;; esac
  [ "${#2}" -le "$3" ] || fail "$1"
}

check_namespace() {
  case "$1" in "" | *[!0-9a-z-]* | -* | *-) fail FLEET_NAMESPACE ;; esac
  [ "${#1}" -le 63 ] || fail FLEET_NAMESPACE
}

check_uuid() {
  case "$2" in "" | *[!0-9a-f-]*) fail "$1" ;; esac
  [ "${#2}" -eq 36 ] || fail "$1"
}

case "$FLEET_MODE" in dry-run | apply | rollback) ;; *) fail FLEET_MODE ;; esac
check_token FLEET_TARGET_VERSION "$FLEET_TARGET_VERSION" 64
check_token FLEET_DEPLOYMENT_NAME "$FLEET_DEPLOYMENT_NAME" 100
case "$FLEET_DEPLOYMENT_NAME" in *..*) fail FLEET_DEPLOYMENT_NAME ;; esac
check_namespace "$FLEET_NAMESPACE"
check_uuid FLEET_DEPLOYMENT_ID "$FLEET_DEPLOYMENT_ID"
check_uuid FLEET_UPGRADE_ID "$FLEET_UPGRADE_ID"
