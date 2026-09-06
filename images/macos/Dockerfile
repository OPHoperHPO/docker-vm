# syntax=docker/dockerfile:1
#
# macOS VM on top of dockurr/macos.
#
# Two things are added to the upstream image:
#
#  1. The macOS recovery image is downloaded and verified at *build* time and
#     shipped at /boot.dmg, so a fresh container boots straight into the macOS
#     installer instead of spending the first several minutes downloading from
#     Apple. This is the same pre-baked approach the Ubuntu and Windows images
#     in this repository use.
#  2. The shared hooks: passt-by-default networking, the helper watchdog, and
#     the vmguard access policy (see docs/network.md).
#
# Build from the repository root, not from this directory:
#   docker build -f images/macos/Dockerfile -t macos-vm .
#
# Apple's recovery endpoint refuses some networks, so BAKE_RECOVERY chooses what
# happens then:
#   auto (default)  try to bake; on refusal warn and leave it to first start
#   Y               bake, and fail the build if Apple refuses
#   N               never bake; download on first start, as dockurr/macos does
# Whichever path runs, the container says at startup which image it is using.

ARG DOCKURR_MACOS_TAG=latest
ARG GO_VERSION=1.24
ARG MACOS_VERSION=15
ARG BAKE_RECOVERY=auto

############################################################
# Stage 1: the network policy enforcer (no dependencies, no network needed)
############################################################
FROM golang:${GO_VERSION}-alpine AS vmguard

WORKDIR /src
COPY shared/vmguard/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vmguard .

############################################################
# Stage 2: fetch and verify the macOS recovery image
############################################################
FROM debian:trixie-slim AS recovery

ARG MACOS_VERSION
ARG BAKE_RECOVERY

COPY --chmod=755 images/macos/fetch-recovery.sh /usr/local/bin/fetch-recovery.sh

# The download tools are installed inside the conditional so that skipping the
# bake costs nothing.
RUN set -eu; \
    mkdir -p /out; \
    if [ "${BAKE_RECOVERY}" = "N" ]; then \
        echo "BAKE_RECOVERY=N: the recovery image will be downloaded on first start."; \
        exit 0; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates curl aria2 p7zip-full qemu-utils; \
    rm -rf /var/lib/apt/lists/*; \
    if fetch-recovery.sh "${MACOS_VERSION}" /out/boot.dmg; then \
        exit 0; \
    fi; \
    rm -f /out/boot.dmg; \
    if [ "${BAKE_RECOVERY}" = "Y" ]; then \
        echo "ERROR: BAKE_RECOVERY=Y and Apple refused the download." >&2; \
        exit 1; \
    fi; \
    echo "=================================================================="; \
    echo " WARNING: Apple refused the recovery download from this network."; \
    echo " The image is being built without it, so the container will fetch"; \
    echo " the recovery image on its first start instead."; \
    echo " Build with --build-arg BAKE_RECOVERY=Y to make this fatal."; \
    echo "=================================================================="

############################################################
# Stage 3: final image
############################################################
FROM dockurr/macos:${DOCKURR_MACOS_TAG}

ARG MACOS_VERSION

# dockurr/macos' install.sh prefers /boot.dmg over its own download path, but
# only accepts a valid image — so the file is published only when it exists.
# Copying the directory keeps the build working when the bake was skipped.
COPY --from=recovery /out/ /baked/
RUN if [ -s /baked/boot.dmg ]; then \
        mv /baked/boot.dmg /boot.dmg; \
        echo "Recovery image baked in: $(du -h /boot.dmg | cut -f1)"; \
    else \
        echo "No recovery image baked in; it will be downloaded on first start."; \
    fi; \
    rm -rf /baked

# --- shared additions ------------------------------------------------------
# dockurr/macos is built on qemux/qemu and keeps its /run/start.sh and
# /run/network.sh, so the same hooks apply here.
COPY --from=vmguard /out/vmguard /usr/local/bin/vmguard

COPY --chmod=755 shared/hooks/start.sh    /run/start.sh
COPY --chmod=755 shared/hooks/watchdog.sh /run/watchdog.sh
COPY --chmod=755 shared/hooks/guard.sh    /run/guard.sh

RUN test -f /run/network.sh || { echo "base image has no /run/network.sh" >&2; exit 1; }; \
    mv /run/network.sh /run/network.upstream.sh
COPY --chmod=755 shared/hooks/network.sh /run/network.sh

COPY --chmod=755 images/macos/hooks/ /run/hooks.d/
# ---------------------------------------------------------------------------

# Must match the baked recovery image: dockurr/macos keeps one installation per
# version under /storage/<version>.
ENV VERSION="${MACOS_VERSION}"

# macOS is unusable below these; the upstream defaults are the bare minimum.
ENV RAM_SIZE="8G"
ENV CPU_CORES="4"
ENV DISK_SIZE="128G"

# Userspace networking by default: no NET_ADMIN, no /dev/net/tun, and the only
# mode vmguard can enforce a policy on.
ENV NETWORK="passt"
ENV DNSMASQ_DISABLE="Y"

ARG GITHUB_REPOSITORY=local/build
LABEL org.opencontainers.image.title="macos-vm"
LABEL org.opencontainers.image.description="macOS VM with the recovery image baked in, running under QEMU/KVM"
LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}"
