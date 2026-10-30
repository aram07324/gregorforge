#!/bin/bash
set -e
# Signal handling for graceful shutdown
trap 'exit 0' TERM INT QUIT

# =============================================================================
# GregorForge toolbox — GPU detection
# =============================================================================
# Runs at container start, not at build time: the image is built once and shipped,
# so the only hardware that matters is the machine actually running it.
#
# What this is for: hashcat. Offline hash cracking is the one workload here that a
# GPU changes by orders of magnitude (rockyou against an MD5-crypt hash is seconds
# on a discrete GPU, hours on CPU threads). Network brute-forcers -- hydra, medusa,
# ncrack -- have no GPU backend in any version: their rate is set by the target's
# response time, not by local compute, so they are deliberately out of scope.
#
# Results are exported AND written to /run/gregorforge-gpu.env, because `export` does
# not reach sibling processes started later through `docker exec`, which is how the
# MCP server runs every command.
# =============================================================================

GF_GPU=0
GF_GPU_VENDOR="none"
GF_GPU_NAME=""
GF_HASHCAT_OPTS=""

_have() { command -v "$1" >/dev/null 2>&1; }

# --- NVIDIA ------------------------------------------------------------------
# Covers bare metal, Docker with --gpus, and WSL2, where the driver arrives through
# /dev/dxg and /usr/lib/wsl/lib instead of a kernel module and nvidia-smi.
if _have nvidia-smi && nvidia-smi -L >/dev/null 2>&1; then
    GF_GPU=1
    GF_GPU_VENDOR="nvidia"
    GF_GPU_NAME="$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)"
elif [ -e /dev/dxg ] && [ -f /usr/lib/wsl/lib/libcuda.so.1 ]; then
    GF_GPU=1
    GF_GPU_VENDOR="nvidia-wsl"
    GF_GPU_NAME="NVIDIA via WSL2 (/dev/dxg)"
    export LD_LIBRARY_PATH="/usr/lib/wsl/lib:${LD_LIBRARY_PATH:-}"

# --- AMD ---------------------------------------------------------------------
elif _have rocm-smi && rocm-smi >/dev/null 2>&1; then
    GF_GPU=1
    GF_GPU_VENDOR="amd-rocm"
    GF_GPU_NAME="AMD GPU (ROCm)"
elif [ -e /dev/kfd ] && [ -d /dev/dri ]; then
    GF_GPU=1
    GF_GPU_VENDOR="amd"
    GF_GPU_NAME="AMD GPU (/dev/kfd)"

# --- Intel / generic OpenCL --------------------------------------------------
elif [ -d /dev/dri ] && ls /dev/dri/renderD* >/dev/null 2>&1; then
    GF_GPU=1
    GF_GPU_VENDOR="intel-or-generic"
    GF_GPU_NAME="OpenCL device via /dev/dri"
fi

# --- Confirm with the tool that will actually use it -------------------------
# A device node proves the kernel sees hardware; it does not prove hashcat has a
# usable backend. Only a non-CPU device in `hashcat -I` proves that. A GPU we
# cannot actually use is downgraded here rather than advertised, so the agent is
# never told it has acceleration it does not have.
if [ "$GF_GPU" = "1" ] && _have hashcat; then
    _hc="$(timeout 90 hashcat -I 2>/dev/null || true)"
    # hashcat reports two different ways depending on the backend, and only the
    # OpenCL section prints a "Type:" line. A CUDA-only device (the normal case for
    # NVIDIA) appears under a "CUDA Info:" header with no Type at all, so matching
    # on Type alone declared a perfectly usable RTX 5060 unusable.
    if printf '%s' "$_hc" | grep -qE '^CUDA Info:' \
       || printf '%s' "$_hc" | grep -qE '^(HIP|Metal) Info:' \
       || printf '%s' "$_hc" | grep -qiE 'Type[.[:space:]]*:[[:space:]]*GPU'; then
        GF_HASHCAT_OPTS="-D 2"      # restrict hashcat to GPU devices
    else
        echo "[GPU] ${GF_GPU_VENDOR} detected but hashcat exposes no GPU backend -> CPU fallback"
        GF_GPU=0
        GF_GPU_VENDOR="present-but-unusable"
    fi
fi

if [ "$GF_GPU" = "1" ]; then
    echo "[GPU] ${GF_GPU_VENDOR}: ${GF_GPU_NAME:-unnamed} -> hashcat accelerated (${GF_HASHCAT_OPTS})"
else
    echo "[GPU] no usable GPU -> hashcat runs on CPU"
    echo "[GPU] offline cracking is orders of magnitude slower: keep candidate lists"
    echo "[GPU] small, or pass a GPU through (docker run --gpus all / compose gpus: all)"
fi

export GF_GPU GF_GPU_VENDOR GF_GPU_NAME GF_HASHCAT_OPTS

mkdir -p /run 2>/dev/null || true
cat > /run/gregorforge-gpu.env <<EOF
GF_GPU=${GF_GPU}
GF_GPU_VENDOR=${GF_GPU_VENDOR}
GF_GPU_NAME=${GF_GPU_NAME}
GF_HASHCAT_OPTS=${GF_HASHCAT_OPTS}
EOF

exec "$@"
