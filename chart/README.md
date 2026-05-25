# assessment — Helm chart

Deploys the Sales Cloud Assessment as a per-link-token-gated container with
a password-protected admin portal. Backed by CNPG Postgres in-cluster.

## Install

```bash
JWT_KEY=$(openssl rand -base64 32)
ADMIN_PW=$(openssl rand -hex 24)
ADMIN_TOKEN=$(openssl rand -hex 32)
IP_SALT=$(openssl rand -hex 16)

helm install assessment ./chart \
  --namespace assessment --create-namespace \
  --set secret.jwtPrivateKey="$JWT_KEY" \
  --set secret.adminPassword="$ADMIN_PW" \
  --set secret.adminToken="$ADMIN_TOKEN" \
  --set secret.ipSalt="$IP_SALT" \
  --set ingress.host=assessment.your.domain \
  --set publicUrl=https://assessment.your.domain
```

## Lock admin to corporate egress (recommended)

```bash
helm upgrade assessment ./chart --reuse-values \
  --set 'ingress.adminAllowCIDRs={203.0.113.0/24,198.51.100.42/32}'
```

## Without CNPG

`--set postgres.cnpg.enabled=false --set postgres.externalUrl=postgres://...`
