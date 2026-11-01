#!/usr/bin/env bash
# Starts the backing services a CI job needs as containers on random loopback host ports and
# exports their addresses to later steps via $GITHUB_ENV. Usage: ci-deps.sh unit|e2e
# Containers carry the label manar-ci=<run id>-<attempt>; ci-deps-stop.sh removes them.
# (Not `services:` because postgres and keycloak need a command, and kafka must advertise its
# own host port.)
set -euo pipefail
mode=${1:?unit|e2e}
label="manar-ci=${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${mode}"
pfx="manar-ci-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${mode}"
env_out() { echo "$1=$2" >>"$GITHUB_ENV"; }
freeport() { node -e 'const s=require("net").createServer().listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})'; }
hostport() { docker port "$1" "$2/tcp" | head -1 | sed 's/.*://'; }
run() { docker run -d --label "$label" "$@" >/dev/null; }
wait_tcp() { timeout "${3:-90}" bash -c "until exec 3<>/dev/tcp/127.0.0.1/$2 2>/dev/null; do sleep 1; done" || { echo "$1 did not open port $2"; docker logs "$pfx-$1" 2>&1 | tail -30 || true; exit 1; }; }

# Throwaway CI database: no fsync. Tenant provisioning (CREATE DATABASE plus every tenant
# migration) is fsync-bound and stalled past its 60 s hook timeout on a shared runner host.
run --name "$pfx-postgres" -p 127.0.0.1::5432 \
  -e POSTGRES_USER=manar -e POSTGRES_PASSWORD=manar -e POSTGRES_DB=manar_control \
  postgres:18.6-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873 \
  postgres -c fsync=off -c synchronous_commit=off -c full_page_writes=off
run --name "$pfx-redis" -p 127.0.0.1::6379 \
  redis:8.10-alpine@sha256:3811787313eba226a2ef38658c6ccb91cd5e110edc89c37767de373120a0e5a0
pg=$(hostport "$pfx-postgres" 5432)
rd=$(hostport "$pfx-redis" 6379)
env_out CONTROL_DATABASE_URL "postgresql://manar:manar@localhost:$pg/manar_control"
env_out TENANT_DB_BASE_URL "postgresql://manar:manar@localhost:$pg/postgres"
env_out POSTGRES_PORT "$pg"
env_out REDIS_URL "redis://localhost:$rd"
wait_tcp postgres "$pg"
wait_tcp redis "$rd"
until docker exec "$pfx-postgres" pg_isready -U manar >/dev/null 2>&1; do sleep 1; done
[ "$mode" = unit ] && exit 0

# Host network on free ports: the brokering specs make Keycloak call its own second realm at the
# same localhost:<port> address the tests use, which a bridged container cannot reach.
kc=$(freeport); kcm=$(freeport)
run --name "$pfx-keycloak" --network host -e KC_HTTP_PORT="$kc" -e KC_HTTP_MANAGEMENT_PORT="$kcm" \
  -e KC_HTTP_HOST=127.0.0.1 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin -e KC_HEALTH_ENABLED=true \
  quay.io/keycloak/keycloak:26.7.1@sha256:f1f1f01e472c8a78df40d8f2a49a925274eda4d3d80d5f6edbb5c880ee3c01c6 \
  start-dev
run --name "$pfx-openbao" -p 127.0.0.1::8200 \
  -e BAO_DEV_ROOT_TOKEN_ID=manar-dev-root-token -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  openbao/openbao:2.6.1@sha256:5b2486ab0fb90bbc788cc345b0a08616dfb375873ee8be5df3a2fd4d378a67e0 \
  server -dev
# Single-node KRaft broker, as in deploy/docker-compose.yml but with one listener. It must
# advertise the host port it is reached on, so the port is picked first and mapped 1:1.
kp=$(freeport)
run --name "$pfx-kafka" -p "127.0.0.1:$kp:$kp" \
  -e KAFKA_NODE_ID=1 -e KAFKA_PROCESS_ROLES=broker,controller \
  -e "KAFKA_LISTENERS=PLAINTEXT://:$kp,CONTROLLER://:9093" \
  -e "KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:$kp" \
  -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT \
  -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER -e KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
  -e KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
  -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 \
  -e KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS=0 \
  apache/kafka:4.3.1@sha256:77e3df9054047a88b520d0cc46e16696d3b22022e1d580aeccd2632df6532837
# path.data: the data directory default may be root-owned; /tmp is writable.
run --name "$pfx-opensearch" -p 127.0.0.1::9200 \
  -e DISABLE_SECURITY_PLUGIN=true -e "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m" \
  opensearchproject/opensearch:3.8.0@sha256:fafe3fc3587088674669235575aa166228c48bdb940294a8cdbbc1da75236a40 \
  opensearch -Ediscovery.type=single-node -Epath.data=/tmp/opensearch-data

ob=$(hostport "$pfx-openbao" 8200)
os=$(hostport "$pfx-opensearch" 9200)
env_out KEYCLOAK_BASE_URL "http://127.0.0.1:$kc"  # Keycloak binds IPv4 loopback only
env_out OPENBAO_ADDR "http://localhost:$ob"
env_out OPENSEARCH_NODE "http://localhost:$os"
env_out KAFKA_BROKERS "localhost:$kp"
# Keycloak start-dev takes several seconds; its management port serves /health/ready.
timeout 120 bash -c "until curl -fs http://127.0.0.1:$kcm/health/ready | grep -q '\"status\": \"UP\"'; do sleep 1; done" \
  || { docker logs "$pfx-keycloak" 2>&1 | tail -30; exit 1; }
timeout 60 bash -c "until curl -fs http://localhost:$ob/v1/sys/health >/dev/null; do sleep 1; done"
wait_tcp kafka "$kp"
timeout 120 bash -c "until curl -fs http://localhost:$os/_cluster/health >/dev/null; do sleep 2; done" \
  || { docker logs "$pfx-opensearch" 2>&1 | tail -30; exit 1; }
