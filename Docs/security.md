# Security Architecture

This document describes CoyoteSense’s secure secret-management approach, suitable for both Docker Compose and Kubernetes deployments, and for all types of units.

---

## 1. Overview

- **No local persistence**: Secrets are never written to disk or environment variables.
- **On-demand HTTPS fetch**: Units retrieve plaintext only over an encrypted channel.
- **Embedded or external vault**: A lightweight in-cluster KeyVault service (or a proxy to an external vault) provides a uniform REST API.
- **TLS/mTLS everywhere**: All vault ↔ unit traffic is protected by TLS, with optional mutual authentication.
- **Short-lived tokens**: Units authenticate and receive bearer tokens with tight TTL and scoping.
- **Audit and rotation**: Vault logs every request; tokens and secret values can be rotated without code changes.

---

## 2. KeyVault Units

### 2.1 Embedded KeyVault  
- Deployed as a sidecar or standalone service in Compose or Kubernetes.  
- Holds one master key (injected via container secret or Kubernetes Secret).  
- Exposes:
  - `POST /v1/auth` → issues a short-lived token  
  - `GET  /v1/secret/:path` → returns decrypted secret  

### 2.2 External Vault Proxy  
- Implements the **same REST interface** as the embedded KeyVault.  
- Forwards requests to external services (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).  
- Translates authentication and caching, enabling gradual migration.

---

## 3. Authentication & Tokens

1. **Unit identity**  
   - Kubernetes: service account JWT and Vault’s Kubernetes auth method.  
   - Docker Compose / VMs: AppRole credentials or short-lived bootstrap token.

2. **Token issuance**  
   - A `POST /v1/auth` with unit-specific credentials returns a bearer token scoped to that unit’s permissions.  
   - Token TTL is short (e.g. 5–15 minutes) and renewals require re-authentication or token refresh.

3. **Token security**  
   - Tokens are stored **only in memory** within the unit process.  
   - On process exit or token expiry, the unit must re-authenticate.

---

## 4. Secret Fetching & Use

- **Fetch**:   
  ```shell
  curl -sk -X POST https://vault:8201/v1/auth -d '{"role":"cpp-unit"}' \
    | jq -r .auth.client_token \
    > /tmp/vault-token

  curl -sk -H "Authorization: Bearer $(cat /tmp/vault-token)" \
    https://vault:8201/v1/secret/db/password \
    | jq -r .data.value \
    > /dev/shm/db-password

- **In-memory only**:

  - Secrets are read into application variables directly.
  - No environment variable or disk file persists them beyond process memory.
  - Immediate zeroization:
  - After use, sensitive buffers are overwritten (e.g. with OPENSSL_cleanse) and memory freed.

## 5. Transport Security

- **TLS Encryption**  
  - All calls to `https://<vault-service>:8201` use TLS 1.2+ with strong cipher suites (e.g. AEAD AES-GCM).  
  - Certificates are issued by your organization’s internal CA or a trusted public CA.

- **Mutual TLS (mTLS) [Optional but Recommended]**  
  - Units present client certificates when connecting to the vault service.  
  - Vault service verifies the client cert against its trust store before issuing tokens or returning secrets.

- **Certificate Provisioning**  
  - **Docker Compose**: Inject via Docker secrets or environment variables mounted as files.  
  - **Kubernetes**: Store in `Secret` objects and mount into the pod.  
  - Certificates and private keys are never baked into container images or source code.

---

## 6. Network Segmentation

- **Isolated Internal Network**  
  - **Kubernetes**: Use `hostNetwork: true` or Network Policies to confine traffic to dedicated nodes and namespaces.  
  - **Docker Compose**: Create a user-defined network that is not published to the host’s external interfaces.

- **Unencrypted HFT Bus**  
  - The Redis event bus and actor messages run on the same isolated network and do **not** use TLS, eliminating cryptographic overhead in the hot path.

- **Vault Service Exposure**  
  - Vault runs on the same internal network but uses TLS for all connections.  
  - No vault ports are exposed outside the cluster or compose network.

---

## 7. Audit & Rotation

- **Audit Logging**  
  - Embedded vault or external vault proxy logs every authentication and secret access request.  
  - Logs include: timestamp, unit identity, requested path, and success/failure status.

- **Token & Secret Rotation**  
  - **Tokens**  
    - Short TTL (e.g. 5–15 minutes).  
    - Units must re-authenticate to obtain fresh tokens.  
  - **Secrets**  
    - Vault can rotate underlying secrets (e.g. database passwords) automatically.  
    - New values are encrypted with the master key; old ciphertexts become invalid.

- **Master Key Rotation**  
  - For the embedded vault, you can roll a new `MASTER_KEY` by:
    1. Generating a new key.  
    2. Updating the Kubernetes `Secret` or Docker secret.  
    3. Restarting the vault service (it re-encrypts stored secrets under the new key).
  - Rotation can be scripted and performed with zero downtime if you run two vault instances and migrate data.

---

## 8. Extensibility & Future Upgrades

- **Swappable Backends**  
  - Replace the embedded vault with a vault-proxy that implements the same `/v1/auth` and `/v1/secret` API against any external vault (HashiCorp, AWS, Azure, GCP).

- **HSM/KMS Integration**  
  - Modify the embedded vault unit to store its master key in an HSM or cloud KMS rather than an environment variable.

- **High Availability & Scalability**  
  - Run multiple replicas of the vault service behind a load balancer or Kubernetes `Service` for HA.  
  - Scale out to handle high-volume secret fetch patterns (e.g. if many units fetch secrets on restart).

- **Enhanced Policies**  
  - Implement fine-grained access controls (e.g. per-unit or per-environment policies) in the vault or proxy.  
  - Enforce least-privilege: units can read only the specific secret paths they require.

---

**This security model ensures that secrets are always protected in transit and at rest, while HFT-critical messaging remains as fast as possible on a segregated network.**  
