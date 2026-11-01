#!/usr/bin/env bash
# Removes the containers ci-deps.sh started for this run. Usage: ci-deps-stop.sh unit|e2e
ids=$(docker ps -aq --filter "label=manar-ci=${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${1:?unit|e2e}")
[ -z "$ids" ] || docker rm -f -v $ids >/dev/null
