# MCP Pager Server

An **MCP (Model Context Protocol) server for the Hak5 WiFi Pineapple Pager**,
written in Rust. It exposes the Pager's recon data, captured loot, and
(optionally) authorized engagement controls as MCP *tools*, so an operator can
drive the Pager from an LLM client such as Claude Code or Claude Desktop.

> **Authorized use only.** This payload controls a wireless auditing device.
> Run it only against networks and clients you own or are explicitly authorized
> to test. Traffic-affecting tools are disabled by default — see *Active tools*.

---

## How it works

```
  LLM client (Claude Code / Desktop)
        │  MCP (JSON-RPC 2.0, newline-delimited)
        │  stdio over SSH   (or TCP over an SSH tunnel)
        ▼
  mcp-pager  ─┬─▶ recon env vars, /root/loot files, uname/df/...  (read-only)
  (Rust,      └─▶ DuckyScript + PINEAPPLE_* commands, run directly
   mipsel_24kc)       LOG/ALERT/LED, EXAMINE, SET_BANDS, filters, deauth, bash…
```

On the Pager, the DuckyScript/`PINEAPPLE_*` commands are plain ELF binaries on
`PATH` (verified: `/usr/bin/LOG`, `/usr/bin/PINEAPPLE_EXAMINE_RESET`, …), and
they work when invoked directly — no payload shell context required. So the Rust
binary just `exec`s them via `std::process::Command`. There is **no bridge and no
daemon dependency**: `mcp-pager` is self-contained and can run straight over SSH
stdio, or be launched on-device by `payload.sh` as a background TCP service.

Read-only introspection (loot files, recon env, system info) is done directly by
the Rust binary with path-traversal protection and size caps.

## Tools

**Always available (passive / read-only):**

| Tool | Purpose |
|------|---------|
| `system_info` | kernel, uptime, storage, memory, firmware |
| `recon_context` | the selected AP/client this payload was launched against |
| `list_loot` | list files under the loot directory |
| `read_loot` | read a text loot file (size-capped, sandboxed) |
| `handshake_stats` | count `.22000`/`.pcap`/`.pcapng`, optional MAC filter |
| `notify` | signal the operator on the Pager (log/alert/vibrate/LED/ringtone) |
| `recon_examine` | lock recon to a BSSID/channel, or reset to hopping |
| `recon_set_bands` | choose 2.4/5/6 GHz bands for channel hopping |
| `recon_new_session` | start a fresh recon session |
| `list_filters` | show device (MAC) or network (SSID) filter lists |
| `pcap_control` | start/stop the optimized Wi-Fi pcap log |
| `find_client_ip` | resolve an associated client's IP from ARP/DHCP |

**Full access, only when `ALLOW_ACTIVE=true`:**

| Tool | Purpose |
|------|---------|
| `bash` | run arbitrary shell command(s); DuckyScript functions are in scope |
| `duckyscript` | run any DuckyScript / `PINEAPPLE_*` command by name with args |
| `deauth_client` | send deauth/disassoc frames to a client (or all) on an AP |
| `device_filter_edit` | add/delete/clear/mode a MAC filter list |
| `network_filter_edit` | add/delete/clear/mode an SSID filter list |

`bash` and `duckyscript` give **complete control of the device**. The curated
`deauth_client`/`*_filter_edit` tools are structured conveniences over the same
capability. When `ALLOW_ACTIVE=false` (the default) all five are neither
advertised in `tools/list` nor executable. `bash` runs via `bash -c` (multi-line
commands supported); long-running work should be backgrounded (`cmd & echo
started`) so it does not block the request.

## Building

The Pager is a **MIPS little-endian, soft-float** OpenWRT 24.10 device
(MediaTek MT7628, 24KEc core, no FPU; OpenWRT target `ramips/mt76x8`, arch
`mipsel_24kc`). Its musl loader is `/lib/ld-musl-mipsel-sf.so.1`. Build for
`mipsel-unknown-linux-musl` (which is soft-float) with a **matching soft-float
toolchain**, and stage the binary into `bin/`.

The verified-working method uses the **OpenWRT 24.10.1 SDK** for the Pager's
exact target (soft-float gcc 13.3.0 musl), with nightly Rust building `std` from
source:

```bash
# 1) Fetch + unpack the matching SDK:
curl -LO https://downloads.openwrt.org/releases/24.10.1/targets/ramips/mt76x8/openwrt-sdk-24.10.1-ramips-mt76x8_gcc-13.3.0_musl.Linux-x86_64.tar.zst
tar --use-compress-program=unzstd -xf openwrt-sdk-24.10.1-*.tar.zst
SDK=$PWD/openwrt-sdk-24.10.1-ramips-mt76x8_gcc-13.3.0_musl.Linux-x86_64
export PATH="$SDK/staging_dir/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin:$PATH"
export STAGING_DIR="$SDK/staging_dir"

# 2) Build (nightly + build-std; rustup component add rust-src --toolchain nightly):
CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER=mipsel-openwrt-linux-musl-gcc \
RUSTFLAGS="-Zunstable-options -Cpanic=immediate-abort" \
cargo +nightly build --release --target mipsel-unknown-linux-musl \
  -Z build-std=std,panic_abort
cp target/mipsel-unknown-linux-musl/release/mcp-pager bin/mcp-pager
```

This produces a ~300 KB binary whose interpreter is `/lib/ld-musl-mipsel-sf.so.1`
— confirmed running on the device. `build.sh` also accepts `METHOD=cross` (the
`cross` tool's image is likewise soft-float) if you prefer Docker.

> **Avoid a hard-float toolchain.** The stock `mipsel-linux-musl-cross` from
> musl.cc is hard-float; it links with a soft/hard-float ABI-mismatch warning and
> targets `/lib/ld-musl-mipsel.so.1`, which does **not** exist on the Pager — the
> binary will fail to load (`not found`). Use the OpenWRT SDK or `cross`.

Binary payloads are not accepted into the public Hak5 repo yet, but run fine for
personal use. `payload.sh` restores the executable bit on every launch, so it is
safe to transfer as a zip.

## Installing the binary

Copy `bin/mcp-pager` onto the Pager — e.g. `scp bin/mcp-pager
root@172.16.52.1:/root/mcp-pager`. That alone is enough for the recommended
connection method below. To run it as an on-device background service with a
status menu, also copy `payload.sh` + `config.sh` (and `bin/mcp-pager`) into a
payload directory via the Pager UI or `/root/payloads/...`.

## Connecting an MCP client

### Recommended: stdio over SSH (no tunnel, no daemon)

Because the binary is self-contained, the MCP client just launches it over SSH
and talks to its stdio. This is how it's tested.

**Claude Code** (`.mcp.json` or `claude mcp add`):

```json
{
  "mcpServers": {
    "pager": {
      "command": "ssh",
      "args": ["root@172.16.52.1", "MCP_ALLOW_ACTIVE=1 /root/mcp-pager"]
    }
  }
}
```

Drop `MCP_ALLOW_ACTIVE=1` to keep it passive/read-only. Add `MCP_LOOT_DIR=...`
to point elsewhere. **Claude Desktop** (`claude_desktop_config.json`): same shape.

### Alternative: on-device TCP service + tunnel

Launch `payload.sh` on the Pager (LED goes **blue solid**); it runs
`mcp-pager --tcp 127.0.0.1:8099`. Then from your workstation:

```bash
ssh -L 8099:127.0.0.1:8099 root@172.16.52.1          # tunnel
# MCP client command:  socat STDIO TCP:127.0.0.1:8099
```

If you set `MCP_TCP_TOKEN` (in `config.sh`), the client must send it as `_auth`
in the `initialize` params. Keep `BIND_ADDR` on loopback unless you are on an
isolated engagement network, in which case always set a token.

Alternatively, skip TCP entirely and run the binary in **stdio** mode directly
over SSH (`command: "ssh"`, `args: ["root@pager", "/root/payloads/.../bin/mcp-pager"]`)
— though launching via `payload.sh` is recommended so the DuckyScript bridge and
on-device controls are available.

## Security notes

- Access control is the SSH/transport layer: stdio-over-SSH inherits your SSH
  auth; TCP mode defaults to a **loopback** bind, and off-loopback binds should
  always set `MCP_TCP_TOKEN` and run only on an isolated engagement network.
- `read_loot`/`list_loot` are sandboxed to `MCP_LOOT_DIR` and reject `..`
  traversal; `read_loot` is size-capped (`MCP_READ_CAP_BYTES`).
- Full-access tools (`bash`, `duckyscript`, `deauth_client`, `*_filter_edit`) are
  gated by `MCP_ALLOW_ACTIVE` and **off by default** — when off they are neither
  advertised nor executable. With them on, the client has full device control, so
  only enable them for an authorized engagement.

## Files

| File | Role |
|------|------|
| `payload.sh` | on-device launcher: runs `mcp-pager --tcp`, shows a status menu |
| `config.sh` | operator configuration |
| `build.sh` | cross-compile helper → `bin/mcp-pager` |
| `src/` | Rust MCP server (`main.rs` protocol/transport, `tools.rs` catalog + dispatch, `device.rs` introspection & direct command exec) |
| `Cargo.toml`, `.cargo/config.toml` | crate + cross-target config |
