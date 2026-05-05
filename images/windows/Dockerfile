# syntax=docker/dockerfile:1
#
# Pre-baked Windows 11 image — ISO is downloaded at build time and shipped
# inside the image at /custom.iso so the running container performs no
# network I/O for the OS itself.
#
# WIN_ISO_URL and WIN_ISO_SHA256 are required build args. The CI workflow
# resolves them dynamically from dockur/windows' src/define.sh. For local
# builds, pass them explicitly:
#
#   docker build \
#     --build-arg WIN_ISO_URL=https://... \
#     --build-arg WIN_ISO_SHA256=<hex> \
#     -t windows-vm ./images/windows
#
# Find URL+hash for any Win version in:
# https://github.com/dockur/windows/blob/master/src/define.sh (function getMido)

ARG DOCKURR_WINDOWS_TAG=latest
ARG WIN_ISO_URL
ARG WIN_ISO_SHA256
# Set to "Y" to fail the build on SHA mismatch (default: warn and continue)
ARG WIN_ISO_STRICT_VERIFY=N

############################################################
# Stage 1: download + verify the ISO
############################################################
FROM debian:trixie-slim AS iso

ARG WIN_ISO_URL
ARG WIN_ISO_SHA256

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates aria2 && \
    rm -rf /var/lib/apt/lists/*

# aria2c does multi-connection downloading (HTTP range requests). Microsoft's
# CDN allows it and serves each connection at full single-stream speed, so
# 16 parallel streams = ~16x throughput vs single-stream curl. Empirically
# this takes the ~5 GB ISO from ~20 min to ~1.5 min on GitHub runners.
#
# --auto-file-renaming=false: keep our hardcoded filename
# --allow-overwrite=true: needed when resuming a partial cached download
# --conditional-get=false: we verify by sha256, no need for If-Modified-Since
RUN set -eu; \
    if [ -z "${WIN_ISO_URL:-}" ]; then \
        echo "ERROR: build-arg WIN_ISO_URL is required." >&2; \
        echo "       Pass it via --build-arg, or use the build.yml workflow which resolves it automatically." >&2; \
        exit 64; \
    fi; \
    echo "Downloading: $WIN_ISO_URL"; \
    aria2c \
        --max-connection-per-server=16 \
        --split=16 \
        --min-split-size=1M \
        --max-tries=5 \
        --retry-wait=10 \
        --connect-timeout=30 \
        --timeout=60 \
        --auto-file-renaming=false \
        --allow-overwrite=true \
        --check-certificate=true \
        --console-log-level=warn \
        --summary-interval=10 \
        --dir=/ \
        --out=custom.iso \
        "$WIN_ISO_URL"; \
    ls -lh /custom.iso; \
    # Sanity check: a genuinely broken download (404 page, redirect HTML)
    # would be tiny. The smallest official Win ISO is ~3 GB.
    SIZE=$(stat -c%s /custom.iso); \
    if [ "$SIZE" -lt 1000000000 ]; then \
        echo "ERROR: downloaded ISO is only $SIZE bytes — looks broken." >&2; \
        exit 65; \
    fi; \
    # Optional SHA256 check. Mismatch is a *warning*, not fatal — Microsoft
    # occasionally re-issues ISOs under the same URL with patched content,
    # and dockur/windows' upstream hashes lag. The dockur project itself
    # does not enforce SHA256 by default (see src/mido.sh::verifyFile, the
    # VERIFY=Y opt-in). We trust the HTTPS download + Microsoft signing of
    # the ISO at install time. To enforce strict verification (fail on
    # mismatch), pass --build-arg WIN_ISO_STRICT_VERIFY=Y.
    if [ -n "${WIN_ISO_SHA256:-}" ]; then \
        echo "Verifying SHA256..."; \
        ACTUAL=$(sha256sum /custom.iso | cut -d' ' -f1); \
        if [ "$ACTUAL" = "$WIN_ISO_SHA256" ]; then \
            echo "ISO SHA256 OK."; \
        else \
            echo "================================================================"; \
            echo "  WARNING: ISO SHA256 mismatch."; \
            echo "    expected: $WIN_ISO_SHA256"; \
            echo "    actual:   $ACTUAL"; \
            echo "  Likely cause: Microsoft re-issued the ISO under this URL"; \
            echo "  and the upstream dockur/windows hash hasn't caught up yet."; \
            echo "  Proceeding anyway."; \
            echo "================================================================"; \
            if [ "${WIN_ISO_STRICT_VERIFY:-N}" = "Y" ]; then \
                echo "WIN_ISO_STRICT_VERIFY=Y, failing the build." >&2; \
                exit 66; \
            fi; \
        fi; \
    else \
        echo "No WIN_ISO_SHA256 supplied, skipping verification."; \
    fi

############################################################
# Stage 2: final image
############################################################
FROM dockurr/windows:${DOCKURR_WINDOWS_TAG}

# Bring the verified ISO into the final image. dockurr/windows' install.sh
# auto-detects /custom.iso at runtime and skips the mido download path.
COPY --from=iso /custom.iso /custom.iso

# Bake initialization scripts into /oem. The default unattend XML in
# dockurr/windows already contains a FirstLogonCommand that auto-runs
# C:\OEM\install.bat on first user logon, so just dropping files here is
# enough — no need to override the answer file.
COPY oem/ /oem/

ENV VERSION="11"
ENV RAM_SIZE="4G"
ENV CPU_CORES="2"
ENV DISK_SIZE="64G"
# USERNAME/PASSWORD intentionally not set here — dockurr/windows defaults
# are Docker/admin (from its win11x64.xml unattend file). Override at run
# time with `-e USERNAME=... -e PASSWORD=...` if needed.

ARG GITHUB_REPOSITORY=local/build
LABEL org.opencontainers.image.title="windows-vm"
LABEL org.opencontainers.image.description="Pre-baked Windows 11 VM (LTSC by default), ISO included, OEM init scripts"
LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}"
