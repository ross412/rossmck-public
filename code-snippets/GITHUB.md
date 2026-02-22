# GitHub Code

GitHub is used for code management as well as a CI/CD pipeline. Various scans and best practices have been implemented.

## Pipeline Security

1. Least privilege for pipeline, write only used where explicitly needed.

```
permissions:
  contents: read
  packages: write
  security-events: write
  id-token: write
  pull-requests: write
```

2. Concurrency control to prevent duplicate runs. If a new push arrives while a pipeline is running, the old run is cancelled.

```
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true
```

## SAST & Secrets

3. Secrets scanning with Gitleaks. Scans the full git history for JWTs, Fernet keys, OIDC secrets, Ed25519 seeds, and AWS credentials.

```
- name: Scan for secrets (Gitleaks)
  uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

4. Bandit SAST scans Python source for common security issues like hardcoded passwords, SQL injection, and unsafe deserialization.

```
- name: Bandit (SAST)
  run: |
    uv run bandit -r services -x tests -ll
```

5. Semgrep as a second SAST layer alongside Bandit. Runs JWT confusion, OWASP top 10, and secrets rulesets against the full codebase.

```
- name: Semgrep SAST
  run: |
    semgrep scan \
      --config p/python \
      --config p/jwt \
      --config p/owasp-top-ten \
      --config p/secrets \
      --error
```

## Container Security

6. All 6 services are built, scanned, and pushed in parallel using a matrix strategy. Trivy fails the build on any HIGH or CRITICAL findings.

```
strategy:
  fail-fast: false
  matrix:
    service:
      - signing-api
      - verification-api
      - identity-api
      - bucket-api
      - admin-api
      - frontend

...

- name: Trivy scan image (fail on HIGH/CRITICAL)
  uses: aquasecurity/trivy-action@0.24.0
  with:
    image-ref: ${{ steps.meta.outputs.image }}:${{ steps.meta.outputs.tag }}
    ignore-unfixed: true
    severity: "HIGH,CRITICAL"
    exit-code: "1"
```

7. Trivy also scans Kubernetes manifests for misconfigurations like missing securityContext or privilege escalation.

```
- name: Trivy IaC scan (k8s manifests)
  uses: aquasecurity/trivy-action@0.24.0
  with:
    scan-type: config
    scan-ref: k8s/
    severity: "HIGH,CRITICAL"
    exit-code: "1"
```

8. Cosign used to sign images to provide non-repudiation. SBOM generated with Syft for compliance.

```
- name: Sign container image (Cosign)
  run: |
    cosign sign --yes "${{ steps.meta.outputs.image }}:${{ steps.meta.outputs.tag }}"
    cosign sign --yes "${{ steps.meta.outputs.image }}:latest"

- name: Generate SBOM (syft)
  uses: anchore/sbom-action@v0
  with:
    image: ${{ steps.meta.outputs.image }}:${{ steps.meta.outputs.tag }}
    format: spdx-json
    output-file: sbom-${{ matrix.service }}.spdx.json
```

## DAST

9. OWASP ZAP runs a baseline scan against the frontend and API scans against the OpenAPI specs of identity-api and bucket-api. Fails the pipeline if any HIGH risk alerts are found.

```
- name: Run OWASP ZAP baseline scan (frontend)
  run: |
    docker run --rm --network host ... ghcr.io/zaproxy/zaproxy:stable \
      zap-baseline.py -t "${FRONTEND_URL}" ...

- name: Run OWASP ZAP API scan (identity-api)
  run: |
    docker run --rm --network host ... ghcr.io/zaproxy/zaproxy:stable \
      zap-api-scan.py -t "http://localhost:8003/openapi.json" -f openapi ...

- name: Fail if ZAP finds HIGH risk alerts
  run: |
    highs = sum(
      1 for site in data.get("site", [])
      for alert in site.get("alerts", [])
      if str(alert.get("riskcode","")) == "3"
    )
    if highs > 0:
      sys.exit(1)
```

## Deployment

10. Deploy via SSH to EC2. Runner IP is temporarily whitelisted on port 22 then revoked after deploy. Alembic DB migrations run before restarting services.

```
- name: Whitelist runner IP on port 22
  run: |
    RUNNER_IP=$(curl -s https://checkip.amazonaws.com)
    aws ec2 authorize-security-group-ingress \
      --group-id ${{ secrets.EC2_SG_ID }} \
      --protocol tcp --port 22 \
      --cidr ${RUNNER_IP}/32

- name: Deploy via SSH
  script: |
    cd ~/secure-doc-signing
    git pull origin main
    # Run Alembic DB migrations before restarting services
    DATABASE_URL="sqlite:////opt/v2-data/secureshare.db" python3 -m alembic upgrade head
    find k8s/ -name '*.yaml' ! -name '01-secrets.yaml' | sort | xargs -I{} kubectl apply -f {}
    kubectl rollout restart deployment/signing-api -n docs
    ...
    kubectl rollout status deployment/frontend -n docs --timeout=120s

- name: Revoke runner IP from port 22
  if: always()
  run: |
    aws ec2 revoke-security-group-ingress \
      --group-id ${{ secrets.EC2_SG_ID }} \
      --protocol tcp --port 22 \
      --cidr ${RUNNER_IP}/32
```
