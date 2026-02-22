# Docker Code

The images used for this project are built with Docker to ensure consistency across deployments. Various security controls can be implemented at the Docker stage.

## API Services

1. Multi stage builds ensure no build tools are carried over to prod.

```
FROM python:3.11-slim AS builder
...
FROM python:3.11-slim
COPY --from=builder /app/.venv /app/.venv
```

2. Removing pip to harden security if attacker gains access to shell.

```
RUN pip uninstall -y pip setuptools wheel 2>/dev/null || true
```

3. No root users, new user with fixed UID.

```
RUN groupadd -r appuser && useradd -r -g appuser -u 1001 appuser
USER appuser
```

4. Lockfile to ensure dependency manifest isn't tampered.

```
RUN uv sync --frozen --no-dev
```

5. Shared code is copied into every service image. All 5 services share models, auth, and audit code without needing a published package.

```
COPY services/bucket-api/src/ ./src/
COPY services/shared/ ./shared/
```

6. Python environment hardening. Unbuffered output ensures logs appear immediately for monitoring. No bytecode prevents .pyc files that could be tampered with.

```
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
```

## Frontend

7. The frontend uses a different pattern from the API services. Alpine base image is patched for known CVEs on build. No build stage needed as it only serves static files and nginx config. Nginx runs as non-root by reassigning ownership of runtime directories.

```
FROM nginx:1.27-alpine

# Upgrade Alpine packages to fix known CVEs (libcrypto3, libssl3, libpng, libxml2)
RUN apk upgrade --no-cache

# Copy custom nginx config
COPY services/frontend/nginx.conf /etc/nginx/conf.d/default.conf

# Copy static frontend
COPY frontend/app.html /usr/share/nginx/html/index.html
COPY frontend/login.html /usr/share/nginx/html/login.html
COPY frontend/js/ /usr/share/nginx/html/js/

# Run as non-root
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    touch /var/run/nginx.pid && \
    chown nginx:nginx /var/run/nginx.pid

EXPOSE 8080
```
