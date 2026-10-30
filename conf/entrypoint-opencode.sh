#!/usr/bin/env bash
set -u
# PAS de set -e global (contrôlé manuellement)
# Signal handling for clean shutdown
trap 'kill $(jobs -p) 2>/dev/null; exit 0' TERM INT

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

fatal() {
  log "FATAL: $*"
  exit 1
}

#######################################
# Paths
#######################################
AGENTS_DIR="/root/.opencode/agents"
DEFAULT_AGENTS="/opt/gregorforge/default-agents"
DEFAULT_WORKFLOWS="/opt/gregorforge/default-workflows"
WORKFLOWS_DIR="/opt/gregorforge/mcp/server/src/tools/workflows/"
OPENCODE_CONFIG_FILE="/root/.config/opencode/opencode.json"
OPENCODE_AUTH_FILE="/root/.local/share/opencode/auth.json"
APPLY_SCRIPT="/root/conf/apply-settings.sh"

#######################################
# Sanity checks
#######################################
[ -d "$DEFAULT_AGENTS" ] || fatal "Default agents dir missing: $DEFAULT_AGENTS"

#######################################
# Prepare directories (bind-mount safe)
#######################################
log "Preparing directories"
mkdir -p \
  "$AGENTS_DIR" \
  "$(dirname "$OPENCODE_CONFIG_FILE")" \
  "$(dirname "$OPENCODE_AUTH_FILE")"

#######################################
# Apply OpenCode config (ALWAYS)
#######################################
log "Applying OpenCode configuration (forced)"

log "Runtime environment variables available:"
# Redact secret values (anything whose name contains KEY/TOKEN/SECRET/PASSWORD)
env | grep -E 'OPENROUTER_|OPENCODE_' | sed -E 's/^([^=]*(KEY|TOKEN|SECRET|PASSWORD)[^=]*)=.*/\1=REDACTED/I' || true

[ -x "$APPLY_SCRIPT" ] || fatal "Apply script not executable: $APPLY_SCRIPT"

if ! "$APPLY_SCRIPT"; then
  fatal "apply-settings failed"
fi

#######################################
# Seed agents (VOLUME-SAFE)
#######################################
log "Checking agents directory"

mkdir -p "$AGENTS_DIR"

if [ -z "$(ls -A "$AGENTS_DIR" 2>/dev/null)" ]; then
  log "Agents dir empty → seeding from image"

  if ! cp -a "$DEFAULT_AGENTS/." "$AGENTS_DIR/"; then
    fatal "Failed to seed agents"
  fi

  log "Agents seeded successfully"
else
  log "Agents dir already populated → skip"
fi

#######################################
# Seed workflows (VOLUME-SAFE)
#######################################
log "Checking workflows directory"

mkdir -p "$WORKFLOWS_DIR"

if [ -z "$(ls -A "$WORKFLOWS_DIR" 2>/dev/null)" ]; then
  log "Workflows dir empty → seeding from image"

  if ! cp -a "$DEFAULT_WORKFLOWS/." "$WORKFLOWS_DIR/"; then
    fatal "Failed to seed workflows"
  fi

  log "Workflows seeded successfully"
else
  log "Workflows dir already populated → skip"
fi

#######################################
# Final state summary (debug friendly)
#######################################
log "Final agent directory content:"
ls -la "$AGENTS_DIR"


#######################################
# OpenCode Markdown export watcher
#######################################
#######################################
# Real-time Markdown watcher (inotify)
#######################################

SESSIONS_DIR="/root/.local/share/opencode/sessions"

log "Preparing OpenCode sessions directory"
mkdir -p "$SESSIONS_DIR"

log "Starting real-time Markdown watcher (inotify on /)"

inotifywait -m / \
  -e create -e moved_to -e close_write \
  --exclude '(/proc|/sys|/dev|/etc/ssl)' \
  --format '%w%f' |
while read -r path; do
  file="$(basename "$path")"
  
  # Rate limit: check modification time (skip if changed <2s ago)
  if [ -f "$path" ]; then
    mtime=$(stat -c %Y "$path" 2>/dev/null || stat -f %m "$path" 2>/dev/null || echo 0)
    now=$(date +%s)
    age=$((now - mtime))
    [ $age -lt 2 ] && continue
  fi

  case "$file" in
    *.md) ;;
    *) continue ;;
  esac

  case "$path" in
    /*.md) ;;
    *) continue ;;
  esac

  src="$path"
  dst="$SESSIONS_DIR/$file"

  [ -f "$src" ] || continue

  if [ -f "$dst" ]; then
    ts=$(date '+%Y%m%d-%H%M%S')
    dst="$SESSIONS_DIR/${file%.md}-$ts.md"
  fi

  log "Markdown detected → moving $src → $dst"
  mv -f "$src" "$dst"
done &

#######################################
# Growth signals (local, privacy-first, opt-out)
#######################################
# Both the MCP server (writer, api/growth.py) and opencode + the growth CTA plugin
# (reader/displayer) run in THIS container, so they share one growth state dir.
# Pin it under the persisted opencode share (bind-mounted to ./gregorforge-settings)
# so the "shown once" state survives container restarts. Exported before both the
# MCP boot and opencode below, so both inherit it. Honours GREGORFORGE_NO_TELEMETRY.
export GREGORFORGE_GROWTH_DIR="${GREGORFORGE_GROWTH_DIR:-/root/.local/share/opencode/.gregorforge-growth}"
mkdir -p "$GREGORFORGE_GROWTH_DIR" 2>/dev/null || true

#######################################
# Persistent GregorForge MCP (issue #40, section 3)
#######################################
# Start the gregorforge MCP as a persistent streamable-http server BEFORE opencode,
# so its per-process vault AND the pre-model tokenization socket are up before any
# session. opencode connects to it as a remote MCP (apply-settings.sh writes the
# matching config), which lets the privacy plugin tokenize the launch prompt — and
# the session-title call that precedes the first model turn — with no wait. Set
# GREGORFORGE_MCP_TRANSPORT=stdio to fall back to per-session stdio spawning.
if [ "${GREGORFORGE_MCP_SERVER:-true}" != "false" ] && \
   [ "${GREGORFORGE_MCP_TRANSPORT:-http}" != "stdio" ]; then
  export GREGORFORGE_MCP_TRANSPORT="${GREGORFORGE_MCP_TRANSPORT:-http}"
  export GREGORFORGE_MCP_HOST="${GREGORFORGE_MCP_HOST:-127.0.0.1}"
  export GREGORFORGE_MCP_PORT="${GREGORFORGE_MCP_PORT:-8181}"
  export GREGORFORGE_MCP_PATH="${GREGORFORGE_MCP_PATH:-/mcp}"
  # Persistent MCP = one long-lived vault shared by every session; give it a long
  # TTL so placeholders minted for a launch prompt still rehydrate into a report
  # generated much later in a long campaign (the vault is in-memory and local-only,
  # and resets on container restart).
  export GREGORFORGE_PRIVACY_TTL="${GREGORFORGE_PRIVACY_TTL:-604800}"
  log "Starting persistent GregorForge MCP (http) on ${GREGORFORGE_MCP_HOST}:${GREGORFORGE_MCP_PORT}${GREGORFORGE_MCP_PATH}"
  /usr/local/bin/gregorforge-mcp >/tmp/gregorforge-mcp-boot.log 2>&1 &
fi

#######################################
# Start main process
#######################################
log "Starting main process: $*"
exec "$@"