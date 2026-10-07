# app-qfield Kubernetes deploy

Images (GHCR):

- `ghcr.io/betabit-technologikal/app-qfield-backend`
- `ghcr.io/betabit-technologikal/app-qfield-frontend`

## One-time secrets

```bash
kubectl create namespace app-qfield --dry-run=client -o yaml | kubectl apply -f -

# Generate:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
#   openssl rand -base64 32

kubectl -n app-qfield create secret generic app-qfield-secrets \
  --from-literal=jwt_secret='CHANGE_ME' \
  --from-literal=encryption_key='CHANGE_ME' \
  --dry-run=client -o yaml | kubectl apply -f -
```

## Apply

```bash
kubectl apply -k deploy/k8s
kubectl -n app-qfield rollout status deploy/backend deploy/frontend
kubectl -n app-qfield port-forward svc/frontend 8080:80
# open http://127.0.0.1:8080  (or Ingress host qfield.holarchy.cloud)
```

Standalone admin bootstrap is enabled for smoke tests (`NEBULA_COMMANDER_STANDALONE_ADMIN_BOOTSTRAP=true`).
Turn that off and configure OIDC for any real deployment.
