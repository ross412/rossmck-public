# Istio Code

Istio is used for routing between services inside a service mesh. It is also integrated with SPIFFE IDs for identity based access control between services.

## mTLS & Identity

1. Strict mTLS across the full namespace. All pod to pod traffic must use mTLS, no plaintext allowed.

```
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: strict-mtls
  namespace: docs
spec:
  mtls:
    mode: STRICT
```

2. Each service gets its own ServiceAccount for fine grained SPIFFE identity. Authorization policies reference these to control which services can talk to each other.

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: signing-sa
  namespace: docs
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: identity-sa
  namespace: docs
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: bucket-sa
  namespace: docs
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-sa
  namespace: docs
...
```

## Authorization Policies

3. Signing API restricted to internal service accounts only. Only bucket API and identity API can call /sign. Health checks are open for probes.

```
spec:
  selector:
    matchLabels:
      app: signing-api
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/docs/sa/bucket-sa"
              - "cluster.local/ns/docs/sa/identity-sa"
      to:
        - operation:
            methods: ["POST"]
            paths: ["/sign"]
    - to:
        - operation:
            methods: ["GET"]
            paths: ["/health", "/health/*"]
```

4. Identity API allows access from multiple sources. The ingress gateway handles external OIDC callbacks, frontend proxies auth requests, and bucket API does internal user lookups.

```
spec:
  selector:
    matchLabels:
      app: identity-api
  action: ALLOW
  rules:
    # External requests via nginx
    - from:
        - source:
            principals:
              - "cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"
    # Frontend proxied API calls
    - from:
        - source:
            principals:
              - "cluster.local/ns/docs/sa/frontend-sa"
    # Internal user lookups from bucket-api
    - from:
        - source:
            principals:
              - "cluster.local/ns/docs/sa/bucket-sa"
```

## Routing

5. TLS termination at the Istio gateway using a Kubernetes secret for the certificate.

```
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: api-gateway
  namespace: docs
spec:
  selector:
    istio: ingressgateway
  servers:
    - port:
        number: 443
        name: https
        protocol: HTTPS
      hosts:
        - api.rossmck.dev
      tls:
        mode: SIMPLE
        credentialName: api-tls-cert
```

6. VirtualService routes requests to 6 services by URL path. API routes go to their respective services, static assets to the frontend, and unmatched paths fall through to the frontend catch all.

```
spec:
  hosts:
    - api.rossmck.dev
  gateways:
    - api-gateway
  http:
    - match:
        - uri:
            prefix: /auth
      route:
        - destination:
            host: identity-api.docs.svc.cluster.local
            port:
              number: 8003
    - match:
        - uri:
            prefix: /buckets
      route:
        - destination:
            host: bucket-api.docs.svc.cluster.local
            port:
              number: 8000
    - match:
        - uri:
            prefix: /admin
      route:
        - destination:
            host: admin-api.docs.svc.cluster.local
            port:
              number: 8005
    ...
    # Frontend catch all
    - route:
        - destination:
            host: frontend.docs.svc.cluster.local
            port:
              number: 8080
```
