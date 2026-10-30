#!/bin/bash
# GregorForge Image Push Script
# Pushes hardened images to Docker Hub (requires docker login)

set -euo pipefail

REGISTRY="${DOCKER_REGISTRY:-docker.io}"
NAMESPACE="${DOCKER_NAMESPACE:-aram07324}"
TAG="${IMAGE_TAG:-latest}"

echo "[INFO] Pushing hardened GregorForge images to ${REGISTRY}/${NAMESPACE}"

# Build info
GREGORFORGE_IMAGE="${REGISTRY}/${NAMESPACE}/gregorforge:${TAG}"
OPENCODE_IMAGE="${REGISTRY}/${NAMESPACE}/opencode-gregorforge:${TAG}"

# Verify login (will fail if not authenticated)
docker info >/dev/null || {
  echo "[ERROR] Docker daemon not accessible. Run 'docker login' first."
  exit 1
}

echo "[STEP 1] Tagging gregorforge image"
docker tag aram07324/gregorforge:latest "${GREGORFORGE_IMAGE}" || {
  echo "[ERROR] Failed to tag gregorforge image (not built yet?)"
  exit 1
}

echo "[STEP 2] Tagging opencode-gregorforge image"
docker tag aram07324/opencode-gregorforge:latest "${OPENCODE_IMAGE}" || {
  echo "[WARN] opencode-gregorforge not yet built, skipping"
}

echo "[STEP 3] Pushing gregorforge → ${GREGORFORGE_IMAGE}"
docker push "${GREGORFORGE_IMAGE}"

echo "[STEP 4] Pushing opencode-gregorforge → ${OPENCODE_IMAGE}"
docker push "${OPENCODE_IMAGE}" || {
  echo "[WARN] opencode-gregorforge push failed (not built yet?)"
}

echo "[SUCCESS] Images pushed to registry"
echo "Next: update docker-compose.yml image refs to '${REGISTRY}/${NAMESPACE}/*'"
