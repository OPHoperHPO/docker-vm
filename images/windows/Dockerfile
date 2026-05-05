# syntax=docker/dockerfile:1
#
# Pre-baked Windows 11 image — ISO is downloaded at build time and shipped
# inside the image at /custom.iso so the running container performs no
# network I/O for the OS itself.
#
# Defaults to "Windows 11 IoT Enterprise LTSC eval" (4.7 GB) because it is the
# smallest official Win11 ISO Microsoft publishes — best for slow links. To
# bake the consumer build instead, pass:
#   --build-arg WIN_ISO_URL=...consumer URL... --build-arg WIN_ISO_SHA256=...
#
# URLs and hashes are taken verbatim from dockur/windows' src/define.sh
# (function getMido), which is the same source mido.sh uses at runtime.
# When Microsoft rotates the build, these need to be refreshed — see README.

ARG DOCKURR_WINDOWS_TAG=latest

# Win11 IoT Enterprise LTSC 24H2 — release 26100.1.240331-1435 (~4.7 GB)
ARG WIN_ISO_URL=https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26100.1.240331-1435.ge_release_CLIENT_IOT_LTSC_EVAL_x64FRE_en-us.iso
ARG WIN_ISO_SHA256=2cee70bd183df42b92a2e0da08cc2bb7a2a9ce3a3841955a012c0f77aeb3cb29

############################################################
# Stage 1: download + verify the ISO
############################################################
FROM debian:trixie-slim AS iso

ARG WIN_ISO_URL
ARG WIN_ISO_SHA256

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# --retry-all-errors makes curl recover from transient TLS / 5xx errors which
# happen on this CDN occasionally. --continue-at - resumes if the layer cache
# was partial (it won't be in clean CI, but harmless).
RUN set -eu; \
    echo "Downloading: $WIN_ISO_URL"; \
    curl -fL --retry 5 --retry-delay 10 --retry-all-errors \
         --continue-at - \
         -o /custom.iso "$WIN_ISO_URL"; \
    ls -lh /custom.iso; \
    echo "Verifying SHA256..."; \
    echo "$WIN_ISO_SHA256  /custom.iso" | sha256sum -c -; \
    echo "ISO verified."

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
# Default credentials inside the guest. Override at run time if needed.
ENV USERNAME="Docker"
ENV PASSWORD="admin"

LABEL org.opencontainers.image.title="windows-vm"
LABEL org.opencontainers.image.description="Pre-baked Windows 11 VM (LTSC by default), ISO included, OEM init scripts"
LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY:-local/build}"
