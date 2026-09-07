#!/usr/bin/env bash
#
# Replaces /run/network.sh from the base image.
#
# The upstream script is kept untouched as /run/network.upstream.sh and sourced
# first, so every network mode, option and fallback it implements keeps working
# exactly as before. Once it has decided how the guest is connected, the two
# additions in this repository are attached:
#
#   * vmguard, the network policy enforced between QEMU and passt
#   * the watchdog that restarts the container if a network helper dies
#
# Wrapping rather than patching means base image updates need no reconciliation.

set -Eeuo pipefail

# shellcheck disable=SC1091
. /run/network.upstream.sh

# shellcheck disable=SC1091
. /run/guard.sh

return 0
