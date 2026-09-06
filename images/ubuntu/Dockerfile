# syntax=docker/dockerfile:1
#
# Pre-baked Ubuntu cloud image on top of qemux/qemu.
# - Cloud image (qcow2) is downloaded at build time and shipped at /opt/baked/boot.qcow2
# - cloud-init NoCloud seed is generated at build time and shipped at /start.iso
# - On first run, /run/hooks.d/10-stage-image.sh copies the qcow2 from /opt/baked
#   into /storage so writes are persistent across container restarts.
#
# Build from the repository root, not from this directory:
#   docker build -f images/ubuntu/Dockerfile -t ubuntu-vm .

ARG UBUNTU_CODENAME=noble
ARG QEMU_TAG=latest
ARG GO_VERSION=1.24

############################################################
# Stage 1: the network policy enforcer (no dependencies, no network needed)
############################################################
FROM golang:${GO_VERSION}-alpine AS vmguard

WORKDIR /src
COPY shared/vmguard/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vmguard .

############################################################
# Stage 2: download cloud image and build cloud-init seed
############################################################
FROM debian:trixie-slim AS prep

ARG UBUNTU_CODENAME
ARG UBUNTU_IMG_URL=https://cloud-images.ubuntu.com/${UBUNTU_CODENAME}/current/${UBUNTU_CODENAME}-server-cloudimg-amd64.img
ARG DISK_SIZE_VIRTUAL=64G

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates curl xorriso qemu-utils && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /work

# 1. Cloud image (already-installed Ubuntu)
RUN curl -fL --retry 3 --retry-delay 5 -o boot.qcow2 "$UBUNTU_IMG_URL" && \
    qemu-img info boot.qcow2 && \
    # Grow the virtual disk so there is room for packages, logs, user data.
    qemu-img resize boot.qcow2 ${DISK_SIZE_VIRTUAL}

# 2. cloud-init seed (NoCloud datasource)
COPY images/ubuntu/cloud-init/user-data /work/seed/user-data
COPY images/ubuntu/cloud-init/meta-data /work/seed/meta-data

RUN xorriso -as mkisofs \
        -output /work/seed.iso \
        -volid CIDATA \
        -joliet -rock \
        /work/seed/

############################################################
# Stage 3: final image on top of qemux/qemu
############################################################
FROM qemux/qemu:${QEMU_TAG}

# Default boot artifacts
COPY --from=prep /work/boot.qcow2 /opt/baked/boot.qcow2
COPY --from=prep /work/seed.iso   /start.iso

# --- shared additions ------------------------------------------------------
# vmguard filters guest traffic between QEMU and passt; see docs/network.md.
COPY --from=vmguard /out/vmguard /usr/local/bin/vmguard

# Startup hook (raises the file limit, runs /run/hooks.d) and the helper
# watchdog that turns a passt crash into a container restart.
COPY --chmod=755 shared/hooks/start.sh    /run/start.sh
COPY --chmod=755 shared/hooks/watchdog.sh /run/watchdog.sh
COPY --chmod=755 shared/hooks/guard.sh    /run/guard.sh

# Wrap the base image's network setup instead of patching it: the original is
# preserved and sourced first, then vmguard and the watchdog are attached.
RUN test -f /run/network.sh || { echo "base image has no /run/network.sh" >&2; exit 1; }; \
    mv /run/network.sh /run/network.upstream.sh
COPY --chmod=755 shared/hooks/network.sh /run/network.sh

COPY --chmod=755 images/ubuntu/hooks/ /run/hooks.d/
# ---------------------------------------------------------------------------

# Reasonable defaults; user can override at run time.
ENV CPU_CORES=2
ENV RAM_SIZE=2G
ENV DISK_SIZE=64G

# Userspace networking by default: no NET_ADMIN, no /dev/net/tun, and the only
# mode vmguard can enforce a policy on.
ENV NETWORK=passt
# passt already answers DNS for the guest; the extra dnsmasq in front of it is
# one more process that can die and take name resolution with it.
ENV DNSMASQ_DISABLE=Y

ARG GITHUB_REPOSITORY=local/build
LABEL org.opencontainers.image.title="ubuntu-vm"
LABEL org.opencontainers.image.description="Pre-baked Ubuntu cloud-image VM running under QEMU/KVM"
LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}"
