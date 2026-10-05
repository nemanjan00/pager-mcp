# Configuration for the mcp_pager payload.
# Edit these values, then launch the payload from the Pager UI.

# --- Network ---------------------------------------------------------------
# Address the MCP server listens on. KEEP THIS ON LOOPBACK (127.0.0.1) and
# reach it over an SSH tunnel:
#     ssh -L 8099:127.0.0.1:8099 root@<pager-ip>
# Binding to 0.0.0.0 exposes device control to anyone on the network. Only do
# that on a trusted, isolated engagement network, and always set MCP_TCP_TOKEN.
BIND_ADDR="127.0.0.1:8099"

# Shared secret required from MCP clients (sent as "_auth" in initialize).
# Leave empty to disable auth (only acceptable on loopback). Strongly
# recommended whenever BIND_ADDR is not loopback.
MCP_TCP_TOKEN=""

# --- Scope -----------------------------------------------------------------
# Loot directory the read tools are allowed to inspect.
MCP_LOOT_DIR="/root/loot"

# Enable FULL-ACCESS tools. When true this exposes:
#   * bash          - run arbitrary shell commands on the Pager
#   * duckyscript   - run any DuckyScript / PINEAPPLE_* command by name
#   * deauth_client, device_filter_edit, network_filter_edit
# i.e. complete control of the device. Leave "false" unless you are on an
# authorized engagement and understand the impact. When false, these tools are
# neither advertised in tools/list nor executable (enforced in the binary AND
# in payload.sh). The read-only recon/loot tools are always available.
ALLOW_ACTIVE="false"

# Max bytes read_loot will return from a single file (protects client context).
MCP_READ_CAP_BYTES="262144"
