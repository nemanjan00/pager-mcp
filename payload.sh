#!/bin/bash
# Title: MCP Pager Server
# Author: nemanjan00
# Description: Model Context Protocol (MCP) server exposing the Pager's Wi-Fi +
#              Bluetooth recon, loot and device control to an operator's LLM
#              client over SSH (stdio). This payload just validates the binary
#              and shows how to connect — the server itself is launched by the
#              MCP client over SSH, not by this payload.
# Version: 1.2
# Category: remote_access
# Target: WiFi Pineapple Pager (mipsel_24kc)
# Net Mode: N/A
# Requirements: bin/mcp-pager built for mipsel-unknown-linux-musl (see README.md)
#
# LED State Descriptions
# Magenta Solid  - Checking the binary
# Blue Solid     - Binary OK; server is launched over SSH by your MCP client
# Red Blink      - Binary missing or not runnable on this device
#
# NOTE: You do NOT run the server from here. Because DuckyScript/PINEAPPLE_*
# commands are plain binaries, the MCP client launches mcp-pager directly over
# SSH stdio with no tunnel and no daemon. See README.md.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${PAYLOAD_HOME:=$SCRIPT_DIR}"

MCP_LOOT_DIR="/root/loot"
MCP_READ_CAP_BYTES="262144"
[ -f "$SCRIPT_DIR/config.sh" ] && source "$SCRIPT_DIR/config.sh"

BIN="$PAYLOAD_HOME/bin/mcp-pager"

LED magenta solid 2>/dev/null
LOG magenta "=== MCP Pager Server ==="

if [ ! -f "$BIN" ]; then
    LED red blink 2>/dev/null
    ERROR_DIALOG "mcp-pager binary not found at bin/mcp-pager. Build it for mipsel (see README.md) and copy it into the payload's bin/ directory."
    exit 1
fi
chmod +x "$BIN" 2>/dev/null   # zip downloads lose the executable bit

VER="$("$BIN" --version 2>/dev/null)"
if [ -z "$VER" ]; then
    LED red blink 2>/dev/null
    ERROR_DIALOG "mcp-pager failed to execute. Is it built for this device (mipsel-unknown-linux-musl, soft-float)?"
    exit 1
fi

LED blue solid 2>/dev/null
VIBRATE alert 2>/dev/null
LOG blue "$VER ready. Launch it from your MCP client over SSH."

IP="$(uci get network.lan.ipaddr 2>/dev/null || echo 172.16.52.1)"
CONN_HELP="Point your MCP client at the Pager over SSH stdio (no tunnel):

  command: ssh
  args:    root@${IP} /root/mcp-pager

Install: copy bin/mcp-pager to /root/mcp-pager on the Pager.
Every tool is available (incl. bash / duckyscript / deauth / filters).
See README.md."

while true; do
    choice=$(LIST_PICKER "MCP Pager" "Binary status" "How to connect" "Exit")
    case "$choice" in
        "Binary status") PROMPT "$VER
Path: $BIN
Loot: $MCP_LOOT_DIR" ;;
        "How to connect") PROMPT "$CONN_HELP" ;;
        "Exit")
            resp=$(CONFIRMATION_DIALOG "Exit this menu? (does not stop any running SSH session)") || continue
            [ "$resp" = "$DUCKYSCRIPT_USER_CONFIRMED" ] && { LED green blink 2>/dev/null; exit 0; }
            ;;
        *) ;;
    esac
done
