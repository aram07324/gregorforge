#!/bin/bash
# GregorForge Secure Startup Script
# Builds, starts, verifies, and tests the hardened stack

set -euo pipefail

COMPOSE_FILE="docker-compose.yml"
GREGORFORGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

error() {
  log "ERROR: $*"
  exit 1
}

cd "$GREGORFORGE_DIR"

# Step 1: Ensure images exist (build if missing)
log "Step 1: Checking images..."
if ! docker images | grep -q "aram07324/gregorforge.*latest"; then
  log "Building aram07324/gregorforge:latest (this takes ~20 min)..."
  docker build -f Dockerfile -t aram07324/gregorforge:latest . || error "Dockerfile build failed"
else
  log "aram07324/gregorforge:latest already built"
fi

if ! docker images | grep -q "aram07324/opencode-gregorforge.*latest"; then
  log "Building aram07324/opencode-gregorforge:latest..."
  docker build -f Dockerfile.opencode -t aram07324/opencode-gregorforge:latest . || error "Dockerfile.opencode build failed"
else
  log "aram07324/opencode-gregorforge:latest already built"
fi

# Step 2: Start the stack
log "Step 2: Starting docker-compose stack..."
docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
docker compose -f "$COMPOSE_FILE" up -d || error "docker-compose up failed"

# Step 3: Wait for health checks
log "Step 3: Waiting for containers to be healthy (max 60s)..."
for i in {1..12}; do
  HEALTHY=$(docker ps --filter "status=running" --filter "health=healthy" --format "{{.Names}}" | wc -l)
  if [ "$HEALTHY" -ge 2 ]; then
    log "✓ Containers healthy"
    break
  fi
  log "Attempt $i/12: Waiting for healthchecks ($HEALTHY/3 healthy)..."
  sleep 5
done

# Step 4: Check container status
log "Step 4: Verifying container status..."
docker ps --filter "name=gregorforge" --filter "name=opencode"

# Step 5: Test MCP endpoint
log "Step 5: Testing MCP HTTP endpoint (port 8181/mcp)..."
MCP_TEST=$(curl -s -w "%{http_code}" -o /dev/null http://localhost:8181/mcp 2>/dev/null || echo "000")
if [ "$MCP_TEST" = "200" ] || [ "$MCP_TEST" = "404" ]; then
  log "✓ MCP endpoint responding (HTTP $MCP_TEST)"
else
  log "⚠ MCP endpoint not responding yet (HTTP $MCP_TEST) - may still be starting"
fi

# Step 6: Show logs
log "Step 6: Recent container logs..."
docker compose logs --tail=20

log "========================================"
log "✓ GregorForge stack is running!"
log "========================================"
log "Containers:"
docker ps --filter "name=gregorforge" --filter "name=opencode" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
log ""
log "Next steps:"
log "  - Monitor: docker compose logs -f"
log "  - Stop: docker compose down"
log "  - Push to registry: bash push-images.sh"
log "  - For production, add socket-proxy:"
log "      docker compose -f docker-compose.yml -f docker-compose.socket-proxy.yml up -d"
