# syntax=docker/dockerfile:1
#
# Pre-baked Ubuntu cloud image on top of qemux/qemu.
# - Cloud image (qcow2) is downloaded at build time and shipped at /opt/baked/boot.qcow2
# - cloud-init NoCloud seed is generated at build time and shipped at /start.iso
# - On first run, /run/start.sh copies the qcow2 from /opt/baked into /storage so
#   writes are persistent across container restarts.

ARG UBUNTU_CODENAME=noble

############################################################
# Stage 1: download cloud image and build cloud-init seed
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
COPY cloud-init/user-data /work/seed/user-data
COPY cloud-init/meta-data /work/seed/meta-data

RUN xorriso -as mkisofs \
        -output /work/seed.iso \
        -volid CIDATA \
        -joliet -rock \
        /work/seed/

############################################################
# Stage 2: final image on top of qemux/qemu
############################################################
FROM qemux/qemu:latest

# Default boot artifacts
COPY --from=prep /work/boot.qcow2 /opt/baked/boot.qcow2
COPY --from=prep /work/seed.iso   /start.iso

# Override the start hook so we can stage the qcow2 into /storage on first run.
COPY start.sh /run/start.sh
RUN chmod +x /run/start.sh

# Reasonable defaults; user can override at run time.
ENV CPU_CORES=2
ENV RAM_SIZE=2G
ENV DISK_SIZE=64G

ARG GITHUB_REPOSITORY=local/build
LABEL org.opencontainers.image.title="ubuntu-vm"
LABEL org.opencontainers.image.description="Pre-baked Ubuntu cloud-image VM running under QEMU/KVM"
LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}"
