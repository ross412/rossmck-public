# Ross Mckechnie - Tunnel Bucket v2.0

This project is a demo for a zero trust file transfer service. Users are able to upload, sign and download files with cryptographic evidence under a zero trust architecture. Users can sign up through OIDC (OpenID Connect) with google and enable MFA for further security. Services communicate using mTLS in a service mesh managed by Istio and SPIFFE. FastAPI serves the APIs with hardening, providing protection against common API attacks. The project is run on AWS using Kubernetes to manage Dockerfiles. GitHub Actions control the CI/CD pipeline providing SAST and DAST as well as automated deployments to EC2.

[Demo Site](https://api.rossmck.dev/)

## TECH STACK

- Python (FastAPI, PyTest)
- Istio
- Docker
- Kubernetes
- Terraform
- PostgreSQL
- Argon2id
- OpenID Connect
- TOTP MFA

## Key Concepts

- Zero Trust
- Cryptography
- Infrastructure as Code
- Security Automation & Testing
- Secrets Management 
- CI/CD Security 
- Vulnerability Management & SBOM

## DATA FLOW DIAGRAM

```mermaid
graph TD

    subgraph Entire[" "]

        User("User Browser")

        CF("Cloudflare<br/>DDoS Protection<br/>TLS Termination Layer 1")

        subgraph AWS["AWS Cloud"]

            subgraph K8s["Kubernetes Cluster"]

                subgraph Istio["Istio Service Mesh"]

                    Gateway("Istio Gateway<br/>TLS Layer 2")

                    Frontend("Frontend / nginx<br/>Port 8080")

                    subgraph Services["API Microservices"]

                        direction LR

                        IdentityAPI("Identity API<br/>OIDC, MFA, Keys<br/>Port 8003")

                        BucketAPI("Bucket API<br/>Encrypted Storage<br/>Port 8000")

                        SignAPI("Signing API<br/>Port 8001")

                        VerifyAPI("Verification API<br/>Port 8002")

                        AdminAPI("Admin API<br/>Dashboard<br/>Port 8005")

                    end

                end

                subgraph Data["Data Layer"]

                    direction LR

                    DB("PostgreSQL<br/>Users, Keys, Metadata<br/>Audit Chain")

                    Storage("Encrypted File<br/>Storage")

                end

            end

        end

        OIDC("OIDC Provider<br/>Google")

    end

    User -->|HTTPS| CF

    CF -->|HTTPS| Gateway

    Gateway -->|Route| Frontend

    Frontend -->|Proxy| IdentityAPI

    Frontend -->|Proxy| BucketAPI

    Frontend -->|Proxy| SignAPI

    Frontend -->|Proxy| VerifyAPI

    Frontend -->|Proxy| AdminAPI

    IdentityAPI -->|SQL| DB

    BucketAPI -->|SQL| DB

    SignAPI -->|SQL| DB

    VerifyAPI -->|SQL| DB

    AdminAPI -->|SQL| DB

    BucketAPI -->|I/O| Storage

    BucketAPI -->|mTLS| SignAPI

    BucketAPI -->|mTLS| VerifyAPI

    IdentityAPI -->|OIDC| OIDC

    style Entire fill:#0f172a,color:#e2e8f0,stroke:#be123c,stroke-width:4px

    style AWS fill:#0f172a,color:#e2e8f0,stroke:#be123c,stroke-width:3px

    style K8s fill:#0f172a,color:#e2e8f0,stroke:#be123c,stroke-width:3px

    style Istio fill:#0f172a,color:#e2e8f0,stroke:#be123c,stroke-width:3px

    style Services fill:#0f172a,color:#e2e8f0,stroke:#be123c,stroke-width:3px

    style Data fill:#0f172a,color:#e2e8f0,stroke:#be123c,stroke-width:3px

    style CF fill:#ef5350,color:#ffffff

    style Gateway fill:#f97316,color:#ffffff

    style Frontend fill:#ea580c,color:#ffffff

    style IdentityAPI fill:#66bb6a,color:#ffffff

    style BucketAPI fill:#66bb6a,color:#ffffff

    style SignAPI fill:#66bb6a,color:#ffffff

    style VerifyAPI fill:#66bb6a,color:#ffffff

    style AdminAPI fill:#66bb6a,color:#ffffff

    style DB fill:#42a5f5,color:#ffffff

    style Storage fill:#ab47bc,color:#ffffff

    style OIDC fill:#78909c,color:#ffffff
```

## Code snippets

[API Code](code-snippets/API.md)
[Docker Code](code-snippets/DOCKER.md)
[GitHub Code](code-snippets/GITHUB.md)
[Istio Code](code-snippets/ISTIO.md)
[Terraform Code](code-snippets/TERRAFORM.md)
