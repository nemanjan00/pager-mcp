# Configuration for the mcp_pager payload.
#
# The server speaks the MCP stdio transport and is launched over SSH by the MCP
# client (e.g. `ssh root@<pager> /root/mcp-pager`). There is no network listener
# and no auth token: SSH is the transport and the trust boundary. Anyone who can
# launch the server already has a root shell on the Pager, so every tool
# (including bash, duckyscript, deauth and filter edits) is always available.
# Use it only on engagements you are authorized to run.

# --- Scope -----------------------------------------------------------------
# Loot directory the read tools are allowed to inspect.
MCP_LOOT_DIR="/root/loot"

# Max bytes read_loot will return from a single file (protects client context).
MCP_READ_CAP_BYTES="262144"

# Optional overrides (defaults shown); normally leave unset.
# MCP_RECON_DB="/root/recon/recon.db"   # Wi-Fi recon database (pineapd)
# MCP_BT_DB="/root/recon/blue5.db"      # Bluetooth recon database (blue5)
