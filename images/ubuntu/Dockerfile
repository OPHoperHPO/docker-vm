# syntax=docker/dockerfile:1
#
# Pre-baked Ubuntu cloud image on top of qemux/qemu.
# - Cloud image (qcow2) is downloaded at build time, checked against Canonical's
#   signed SHA256SUMS, and shipped at /opt/baked/boot.qcow2
# - cloud-init NoCloud seed is generated at build time and shipped at /start.iso
# - On first run, /run/hooks.d/10-stage-image.sh copies the qcow2 from /opt/baked
#   into /storage so writes are persistent across container restarts.
#
# Build from the repository root, not from this directory:
#   docker build -f images/ubuntu/Dockerfile -t ubuntu-vm .

ARG UBUNTU_CODENAME=noble

# Base images are pinned by digest: a floating tag would let an upstream push
# change what these images contain without a commit here. Dependabot bumps the
# digests; see .github/dependabot.yml.

############################################################
# Stage 1: the network policy enforcer (no dependencies, no network needed)
############################################################
FROM golang:1.24-alpine@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191 AS vmguard

WORKDIR /src
COPY shared/vmguard/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vmguard .

############################################################
# Stage 2: download cloud image and build cloud-init seed
############################################################
FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132 AS prep

ARG UBUNTU_CODENAME
ARG UBUNTU_IMG_URL=https://cloud-images.ubuntu.com/${UBUNTU_CODENAME}/current/${UBUNTU_CODENAME}-server-cloudimg-amd64.img
ARG DISK_SIZE_VIRTUAL=64G

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg gpgv xorriso qemu-utils && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /work

# 1. Cloud image (already-installed Ubuntu), verified before it is touched.
#
# The digest comes from Canonical's SHA256SUMS, whose signature is checked
# against the bundled key; UBUNTU_IMG_SHA256 replaces that with a fixed digest
# for mirrors and custom images. Verification happens before qemu-img writes to
# the file, since a resize changes the bytes the digest covers.
ARG UBUNTU_IMG_SHA256=""
COPY images/ubuntu/canonical-cloudimage-key.asc /usr/local/share/canonical-cloudimage-key.asc
COPY --chmod=755 images/ubuntu/fetch-cloudimage.sh /usr/local/bin/fetch-cloudimage.sh
RUN fetch-cloudimage.sh "$UBUNTU_IMG_URL" boot.qcow2 && \
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
FROM qemux/qemu:latest@sha256:e7f6fda52503a546fd649670ba46e4bc23dc6dcef275bc3fac48877fbbc430df

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
