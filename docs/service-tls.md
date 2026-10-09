# Transport security between services

What each hop uses today, the evidence for it, and what to set on-prem (Proxmox k3s) and in
Azure UAE North (AKS). Written 9 Oct 2026 against `main`. "Not verified" means nobody has run
that hop with TLS on and checked it; the code may support it.

Labels used below: **mTLS** (both sides present certificates), **TLS** (server certificate
only), **plaintext**.

## Summary

| Hop                                       | Today (default config)                                                | Supports                                                                                                 | Evidence                                                                                                                                                                                                                                                               |
| ----------------------------------------- | --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Browser to Traefik / ingress              | TLS (edge)                                                            | TLS                                                                                                      | Edge config lives in manar/manar-infra; not verified here                                                                                                                                                                                                              |
| Traefik to manar-web, manar-api :3000     | plaintext in-cluster                                                  | TLS if the ingress re-encrypts                                                                           | `deploy/helm/*/templates/service.yaml` expose plain HTTP; NetworkPolicy limits sources                                                                                                                                                                                 |
| manar-web BFF to manar-api                | plaintext in-cluster                                                  | TLS by setting an `https://` `MANAR_API_BASE_URL`                                                        | manar-web `lib/env.ts`, chart value `http://manar-api:3000`                                                                                                                                                                                                            |
| Agents to manar-api :3443                 | **mTLS**                                                              | mTLS                                                                                                     | `src/main.ts` (`requestCert: true`, `rejectUnauthorized: true`), `src/agent-mtls/agent-mtls.guard.ts`, `test/agent-identity.e2e-spec.ts` case 6 (foreign-CA certificate rejected)                                                                                      |
| manar-api / worker to manar-ai gRPC       | plaintext unless enabled                                              | **mTLS** with peer allow-list                                                                            | `src/ai-advisory/ai-advisory.config.ts` (`AI_ADVISORY_TLS_ENABLED`); manar-ai refuses plaintext in staging and production: `manar-ai/tests/config/test_security_settings.py::test_real_deployment_without_grpc_tls_fails_to_start`, `manar-ai/tests/grpc/test_mtls.py` |
| manar-api to PostgreSQL                   | plaintext unless the URL asks                                         | TLS via `sslmode` in `CONTROL_DATABASE_URL` / `TENANT_DB_BASE_URL` (`@prisma/adapter-pg`, node-postgres) | `src/database/control-prisma.service.ts`; not verified                                                                                                                                                                                                                 |
| manar-api to Valkey/Redis                 | **plaintext, no auth**                                                | TLS (`rediss://`) and ACL auth once manar-api!22 merges                                                  | see "Kafka, Redis, OpenSearch" below                                                                                                                                                                                                                                   |
| manar-api to Kafka                        | **plaintext, no auth**                                                | TLS and SASL once manar-api!22 merges                                                                    | same                                                                                                                                                                                                                                                                   |
| manar-api to OpenSearch                   | **plaintext, no auth**                                                | TLS and basic auth once manar-api!22 merges                                                              | same                                                                                                                                                                                                                                                                   |
| manar-api to OpenBao                      | plaintext (`http://` in chart values)                                 | TLS by an `https://` `OPENBAO_ADDR`; a private CA needs `NODE_EXTRA_CA_CERTS`                            | `src/openbao/openbao-kv.client.ts`, `openbao-pki.client.ts` use `fetch`; not verified                                                                                                                                                                                  |
| manar-api to Keycloak                     | plaintext (`http://` in chart values)                                 | TLS by an `https://` `KEYCLOAK_BASE_URL`                                                                 | not verified                                                                                                                                                                                                                                                           |
| manar-api to OpenFGA                      | plaintext (`http://` in chart values)                                 | TLS by an `https://` `OPENFGA_API_URL`                                                                   | not verified                                                                                                                                                                                                                                                           |
| manar-api / worker to Temporal            | **plaintext**, no TLS option                                          | none today                                                                                               | `src/temporal/temporal-client.service.ts` and `src/worker.main.ts` call `Connection.connect({ address })` with no `tls`                                                                                                                                                |
| manar-api to Microsoft Graph and Defender | TLS (public CA)                                                       | TLS                                                                                                      | fixed `https://` endpoints in `src/cli/commands/microsoft-register.command.ts`, `src/tools/microsoft-actions.ts`                                                                                                                                                       |
| manar-api to customer HTTP/MCP tools      | whatever the registered URL says                                      | TLS                                                                                                      | `src/common/ssrf/url-safety.ts` accepts `http:` and `https:`; `http:` is allowed, not verified that production refuses it                                                                                                                                              |
| manar-api to Ollama                       | plaintext (`http://` default)                                         | TLS by URL                                                                                               | `src/agent-runtime/llm-proxy.config.ts` (`LLM_OLLAMA_BASE_URL`)                                                                                                                                                                                                        |
| manar-api to Azure OpenAI, Core42         | TLS (the endpoints are `https://`)                                    | TLS                                                                                                      | `LLM_AZURE_OPENAI_ENDPOINT`; the schema accepts any URL, `https` is not enforced                                                                                                                                                                                       |
| manar-api to manar-fleet (heartbeats)     | whatever `FLEET_HEARTBEAT_URL` says; each heartbeat is Ed25519-signed | TLS                                                                                                      | `src/fleet-heartbeat/fleet-heartbeat.config.ts`; not verified                                                                                                                                                                                                          |
| manar-fleet to manar-api platform API     | through the ingress (TLS at the edge)                                 | TLS                                                                                                      | ADR-0010; not verified                                                                                                                                                                                                                                                 |

## Kafka, Redis, OpenSearch

On `main`, manar-api's Kafka, OpenSearch and Redis clients have no TLS, SASL or auth options.
In-cluster these links are plaintext and unauthenticated; only the NetworkPolicies (the app
charts' egress lists and the namespace default-deny in manar/manar-infra) keep other pods off
them. manar-api!22 (`feat/backing-service-tls`) adds TLS and credentials for all three
(`KAFKA_SSL`, `KAFKA_SSL_CA_FILE`, `KAFKA_SASL_*`, `REDIS_USERNAME`, `REDIS_PASSWORD`,
`REDIS_TLS_CA_FILE` with a `rediss://` URL, `OPENSEARCH_USERNAME`, `OPENSEARCH_PASSWORD`,
`OPENSEARCH_TLS_CA_FILE`). Once it merges, the clients support TLS and auth; the charts already
take the settings (`backingServiceTls` in both API charts' values). A live run against the
platform's Strimzi, Valkey and OpenSearch services with TLS on has not been done.

## On-prem (Proxmox k3s)

- **Certificates**: cert-manager with a ClusterIssuer backed by the OpenBao PKI (an
  intermediate separate from the agent CA, `pki-int`), so service certificates and the agent CA
  never share a signing key. Public hostnames: ACME (Let's Encrypt) or the customer's CA.
- **Edge**: Traefik terminates TLS 1.2+ for the console and API hostnames. The agent listener
  :3443 must not be terminated at the edge: use TCP passthrough (Traefik `IngressRouteTCP`
  with `tls.passthrough: true`) or a LoadBalancer Service, or client certificates never reach
  manar-api.
- **manar-ai**: issue `manar-api`, `manar-api-worker` and `manar-ai` certificates from the same
  issuer, mount them at `/etc/manar/tls`, set `AI_ADVISORY_TLS_ENABLED=true` and manar-ai's
  `ENVIRONMENT=production`.
- **PostgreSQL (CNPG)**: CNPG serves TLS by default; set `sslmode=verify-full` and mount the
  cluster CA (`manar-pg-ca`), with `NODE_EXTRA_CA_CERTS` for node-postgres. Not verified.
- **OpenBao, Keycloak, OpenFGA**: serve TLS from cert-manager certificates, switch the URLs to
  `https://`, and give the pods `NODE_EXTRA_CA_CERTS` pointing at the issuer CA.
- **Valkey, Kafka, OpenSearch**: after manar-api!22, enable TLS listeners on the operators,
  put the CA bundles in one Secret and set `backingServiceTls.caSecretName`.
- **Temporal**: needs a code change (pass `tls` to `Connection.connect` and
  `NativeConnection.connect`). Until then the frontend link stays plaintext behind the
  NetworkPolicies.

## Azure UAE North (AKS)

- **Edge**: Application Gateway for Containers or ingress-nginx with a Key Vault certificate
  (TLS 1.2+). The agent listener needs a TCP path that keeps the client certificate: an Azure
  Load Balancer Service on :3443 straight to manar-api, not an HTTP(S) listener.
- **Azure Database for PostgreSQL flexible server**: `require_secure_transport` is on by
  default; use `sslmode=verify-full` with the DigiCert/Microsoft root bundle.
- **Azure Cache for Redis**: disable the non-TLS port (6379) and use `rediss://` on 6380 with an
  access key or Entra auth (after manar-api!22).
- **Key Vault** holds the edge certificate and the service secrets; cert-manager with the OpenBao
  PKI (or a Key Vault-backed issuer) issues the in-cluster mTLS certificates for manar-ai.
- **Private endpoints** for PostgreSQL, Redis, Key Vault and Azure OpenAI, so the
  `external-https` egress rule can be narrowed to the private endpoint addresses.

## Gaps

1. Temporal has no TLS option in the client code (above).
2. Kafka, Redis and OpenSearch are plaintext and unauthenticated until manar-api!22 merges and
   the operators enable TLS.
3. No hop enforces `https` in config validation for production (OpenBao, Keycloak, OpenFGA,
   LLM upstreams, customer tool URLs, the fleet heartbeat URL). A production check that refuses
   `http://` for non-loopback hosts would close it.
4. Postgres TLS has not been run with `verify-full`.
