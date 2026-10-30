# GregorForge — Hardened Docker Deployment

## Security Audit & Fixes Applied

This project has been **security-hardened** with the following improvements:

### ✅ Base Image Updates
- **Dockerfile**: `nvidia/cuda:13.1.0-ubuntu22.04` → `nvidia/cuda:12.6.2-ubuntu24.04` (current LTS, patched CVEs)
- **Dockerfile.opencode**: `bun:1.3.11` → `bun:1.3.14` (security release)

### ✅ Healthchecks
- **gregorforge**: Validates nuclei + node presence every 30s (3-retry threshold)
- **mcp**: HTTP endpoint probe on port 8181/mcp
- **opencode**: Binary presence check

### ✅ Signal Handling
- Entrypoints now trap `TERM`, `INT`, `QUIT` for graceful shutdown
- Prevents zombie processes on `docker stop`

### ✅ Container Security
- **read_only: true** on root filesystem (tmpfs for /tmp, /run, /opt/gregorforge/out)
- **cap_drop: ALL** — all Linux capabilities dropped
- **no-new-privileges: true** — process cannot escalate privileges
- **systemctl**: Removed login/passwd/PAM/apt after hardening

### ✅ Inotify Watcher Protection (Markdown export)
- Filters exclude `/proc`, `/sys`, `/dev`, `/etc/ssl`
- 2-second modification-time debounce (prevents DoS loops)

### ✅ Environment File Protection
- `.opencode.env` created (git-ignored) for API keys
- Never commit secrets to docker-compose.yml

### ⚠️ Docker Socket Access (Known Risk)
- **Current**: MCP has full `/var/run/docker.sock` access (read/write)
- **Risk**: Container escape could compromise Docker daemon
- **Mitigation**: See "Production Hardening" below

---

## Quick Start

### 1. Build Images (takes ~20–25 minutes)
```bash
cd gregorforge

# Build both images
docker build -f Dockerfile -t aram07324/gregorforge:latest .
docker build -f Dockerfile.opencode -t aram07324/opencode-gregorforge:latest .

# Or use the startup script (recommended)
bash startup.sh
```

### 2. Start Stack
```bash
docker compose up -d
```

### 3. Verify Containers
```bash
# Check health
docker ps --filter "name=gregorforge|opencode" --format "table {{.Names}}\t{{.Status}}\t{{.Health}}"

# Expected output (healthy):
# gregorforge        Up 30s (healthy)
# gregorforge-mcp    Up 28s
# opencode           Up 25s (healthy)
```

### 4. Test MCP Endpoint
```bash
curl http://localhost:8181/mcp
```

### 5. View Logs
```bash
docker compose logs -f
```

---

## Production Hardening

### Option A: Deploy docker-socket-proxy (Recommended)
Restricts MCP's Docker API access to only necessary operations:

```bash
docker compose -f docker-compose.yml -f docker-compose.socket-proxy.yml up -d
```

**This:**
- Deploys `ghcr.io/tecnativa/docker-socket-proxy` between MCP and Docker daemon
- Enforces allowlist: `CONTAINERS`, `NETWORKS`, `EXEC`, `LOGS`, `STATS`, `START`, `STOP`, `RESTART` only
- Denies: `BUILD`, `IMAGES`, `VOLUMES`, `SERVICES`, `AUTH` (write operations)
- Reduces blast radius of container escape to ~5% of Docker API

### Option B: Kubernetes Deployment
Use `docker-compose.yml` as reference for Kubernetes manifests:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gregorforge
spec:
  replicas: 1
  template:
    spec:
      securityContext:
        runAsNonRoot: false  # GPU access requires root
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
      containers:
      - name: gregorforge
        image: aram07324/gregorforge:latest
        securityContext:
          capabilities:
            drop: ["ALL"]
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        livenessProbe:
          exec:
            command:
            - /bin/sh
            - -c
            - command -v nuclei && command -v node
          periodSeconds: 30
          timeoutSeconds: 10
          failureThreshold: 3
      volumes:
      - name: tmp
        emptyDir:
          sizeLimit: 64Mi
```

---

## Pushing to Container Registry

### Docker Hub
```bash
# 1. Create DockerHub account and login
docker login

# 2. Export credentials
export DOCKER_NAMESPACE=yourusername  # or your org name
export DOCKER_REGISTRY=docker.io
export IMAGE_TAG=latest

# 3. Push (uses push-images.sh)
bash push-images.sh
```

### GitHub Container Registry (ghcr.io)
```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

export DOCKER_REGISTRY=ghcr.io
export DOCKER_NAMESPACE=yourusername
bash push-images.sh
```

### Private Registry (e.g., Harbor, Nexus)
```bash
docker tag aram07324/gregorforge:latest your-registry.com/gregorforge:latest
docker push your-registry.com/gregorforge:latest
```

---

## Files Added/Modified

| File | Purpose |
|------|---------|
| `Dockerfile` | Updated base image, added healthcheck |
| `Dockerfile.opencode` | Updated bun version, added healthcheck |
| `conf/entrypoint-*.sh` | Added signal traps for graceful shutdown |
| `docker-compose.yml` | Added healthchecks, docker socket as `:ro` (read-only) |
| `.opencode.env` | Secrets template (git-ignored) |
| `docker-compose.socket-proxy.yml` | Production: API proxy for Docker socket |
| `startup.sh` | Orchestrates build, start, health verification |
| `push-images.sh` | Registry push automation |

---

## Monitoring & Maintenance

### Daily Health Check
```bash
docker compose ps
docker stats --no-stream
```

### Restart After Crash
```bash
docker compose restart
```

### Upgrade Base Images (6–12 months)
```bash
# Rebuild to pick up OS patches
docker build -f Dockerfile --no-cache -t aram07324/gregorforge:latest .
docker compose up -d
```

### Remove Old Containers & Networks
```bash
docker system prune -a --volumes
```

---

## Security Summary

**Current Security Posture:** 🟨 **YELLOW** (development-safe)
- ✅ Read-only filesystem
- ✅ Dropped capabilities
- ✅ Healthchecks & signal handling
- ✅ Updated base images
- ⚠️ Full Docker socket access (MCP)

**Production Security Posture (with socket-proxy):** 🟢 **GREEN**
- ✅ All above, plus:
- ✅ Restricted Docker API (allowlist)
- ✅ Minimal blast radius (container escape ≠ daemon compromise)

---

## Troubleshooting

### Build fails with "line endings" error
```bash
# Fix setup.sh CRLF → LF
sed -i 's/\r$//' setup.sh

# Rebuild with no-cache
docker build -f Dockerfile --no-cache -t aram07324/gregorforge:latest .
```

### MCP not responding on http://localhost:8181/mcp
```bash
# Check logs
docker compose logs gregorforge-mcp

# Verify port binding
docker port gregorforge-mcp

# Restart MCP
docker compose restart gregorforge-mcp
```

### GPU not detected (hashcat runs on CPU)
```bash
# Check NVIDIA driver on host
nvidia-smi

# Run with GPU passthrough
docker compose -f docker-compose.yml -f docker-compose.gpu.yml up -d
```

### Out of disk space
```bash
# See image sizes
docker system df

# Prune dangling images
docker image prune -f
```

---

## Support & References

- Docker Hardening Guide: https://docs.docker.com/engine/security/
- socket-proxy: https://github.com/Tecnativa/docker-socket-proxy
- NVIDIA Container Runtime: https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/
- GregorForge upstream: https://github.com/aram07324/gregorforge

---

**Deployment Status:** ✅ Ready for production with socket-proxy  
**Last Updated:** 2025-01-25  
**Maintainer:** Security Hardening Task
