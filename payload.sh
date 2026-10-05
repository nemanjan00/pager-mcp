#!/bin/bash
# Title: MCP Pager Server
# Author: nemanjan00
# Description: Runs a Model Context Protocol (MCP) server exposing the Pager's
#              recon data, loot and (optionally) full device control so an
#              operator's LLM client can drive an engagement over SSH.
# Version: 1.1
# Category: remote_access
# Target: WiFi Pineapple Pager (mipsel_24kc)
# Net Mode: N/A
# Requirements: bin/mcp-pager built for mipsel-unknown-linux-musl (see README.md)
#
# LED State Descriptions
# Magenta Solid  - Starting up
# Blue Solid     - MCP server running, waiting for clients
# Red Blink      - Startup error (missing or non-executable binary)
# Green Blink    - Clean shutdown
#
# NOTE: You usually do NOT need this payload to use the server. Because the
# DuckyScript/PINEAPPLE_* commands are plain binaries, the MCP client can launch
# mcp-pager directly over SSH (stdio) with no tunnel. See README.md. This payload
# is the on-device way to run it as a background TCP service with a status menu.

set -u

# ===========================================================================
# CONFIG
# ===========================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${PAYLOAD_HOME:=$SCRIPT_DIR}"

BIND_ADDR="127.0.0.1:8099"
MCP_TCP_TOKEN=""
MCP_LOOT_DIR="/root/loot"
ALLOW_ACTIVE="false"
MCP_READ_CAP_BYTES="262144"
[ -f "$SCRIPT_DIR/config.sh" ] && source "$SCRIPT_DIR/config.sh"

BIN="$PAYLOAD_HOME/bin/mcp-pager"
is_true() { case "${1,,}" in 1|true|yes|on) return 0 ;; *) return 1 ;; esac; }

# ===========================================================================
# STARTUP CHECKS
# ===========================================================================
LED magenta solid 2>/dev/null
LOG magenta "=== MCP Pager Server ==="

if [ ! -f "$BIN" ]; then
    LED red blink 2>/dev/null
    ERROR_DIALOG "mcp-pager binary not found at bin/mcp-pager. Build it for mipsel (see README.md) and copy it into the payload's bin/ directory."
    exit 1
fi
chmod +x "$BIN" 2>/dev/null   # zip downloads lose the executable bit

if ! "$BIN" --version >/dev/null 2>&1; then
    LED red blink 2>/dev/null
    ERROR_DIALOG "mcp-pager failed to execute. Is it built for this device (mipsel-unknown-linux-musl, soft-float)?"
    exit 1
fi

# ===========================================================================
# LAUNCH SERVER
# ===========================================================================
export MCP_LOOT_DIR MCP_READ_CAP_BYTES MCP_TCP_TOKEN
if is_true "$ALLOW_ACTIVE"; then export MCP_ALLOW_ACTIVE=1; else export MCP_ALLOW_ACTIVE=0; fi

"$BIN" --tcp "$BIND_ADDR" &
SERVER_PID=$!

sleep 1
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    LED red blink 2>/dev/null
    ERROR_DIALOG "MCP server exited immediately. Is $BIND_ADDR already in use?"
    exit 1
fi

cleanup() {
    kill "$SERVER_PID" 2>/dev/null
    LED green blink 2>/dev/null
    LOG green "MCP server stopped."
}
trap cleanup EXIT

LED blue solid 2>/dev/null
VIBRATE alert 2>/dev/null
LOG blue "MCP server listening on $BIND_ADDR"
if is_true "$ALLOW_ACTIVE"; then
    LOG red "FULL ACCESS enabled (bash / duckyscript / deauth / filters)."
else
    LOG green "Passive mode (read-only recon/loot)."
fi

PORT="${BIND_ADDR##*:}"
CONN_HELP="On your workstation, tunnel then bridge stdio<->TCP:
1) ssh -L ${PORT}:${BIND_ADDR} root@172.16.52.1
2) MCP client command: socat STDIO TCP:127.0.0.1:${PORT}
Or skip this payload entirely and run mcp-pager directly over SSH stdio.
See README.md."

# ===========================================================================
# CONTROL MENU
# ===========================================================================
while true; do
    choice=$(LIST_PICKER "MCP Server" "Status" "Connection help" "Stop & exit")
    case "$choice" in
        "Status")
            if kill -0 "$SERVER_PID" 2>/dev/null; then
                PROMPT "RUNNING on $BIND_ADDR
Full access: $(is_true "$ALLOW_ACTIVE" && echo yes || echo no)"
            else
                PROMPT "Server is NOT running. Exit and relaunch."
            fi
            ;;
        "Connection help")
            PROMPT "$CONN_HELP"
            ;;
        "Stop & exit")
            resp=$(CONFIRMATION_DIALOG "Stop the MCP server?") || continue
            [ "$resp" = "$DUCKYSCRIPT_USER_CONFIRMED" ] && exit 0
            ;;
        *)
            ;;
    esac
done
