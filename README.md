<div align="center">

![MCP Pager Server](assets/banner.svg)

![badges](assets/badges.svg)

**Your LLM, holding a Wi-Fi scanner.**
A tiny Rust [MCP](https://modelcontextprotocol.io) server that lets Claude *see* what the
Hak5 WiFi Pineapple Pager sees — nearby APs, clients, captured handshakes, loot —
and, when you explicitly arm it, *act* on an authorized engagement.

</div>

> [!WARNING]
> **Authorized use only.** This payload controls a wireless auditing device. Run it
> only against networks and clients you own or are explicitly authorized to test.
> Every traffic-affecting tool is **disabled by default** and must be armed with
> `ALLOW_ACTIVE=true` — see [What it can do](#what-it-can-do).

---

## Why this is cool

Point Claude at your Pager over SSH and ask in plain language:

> *"What APs are around me right now on 5 GHz?"*
> *"Lock to the channel of the strongest one and tell me the moment a handshake lands."*
> *"Which of my associated clients just pulled a DHCP lease, and what's its IP?"*

Claude calls the right tools, reads the recon database, watches the loot folder,
and buzzes the device when something interesting happens — no web UI, no tunnel,
no daemon. One self-contained **~300 KB** binary that runs straight over SSH stdio.

---

## What it can do

The server advertises two tiers of tools. **Passive is always on. Active is opt-in.**

### 🟦 Passive — always available, read-only

> Recon, loot, and introspection. Nothing touches the air.

| Tool | What it gives Claude |
|------|----------------------|
| `system_info` | kernel, uptime, storage, memory, firmware |
| `recon_context` | the AP/client this payload was launched against |
| `recon_list` | survey nearby **APs** or **clients** (band / min-signal / age filters; defaults to the last 120 s) |
| `recon_ap_detail` | everything about one BSSID — SSIDs, band, security, signal, handshakes, stations |
| `handshakes` | captured WPA handshakes; `since_seconds` enables **new-handshake polling** |
| `handshake_stats` | count `.22000` / `.pcap` / `.pcapng` loot, optional MAC filter |
| `channel_lock` / `channel_unlock` | pin to a channel (or an AP's channel) to catch handshakes, then resume hopping |
| `list_loot` / `read_loot` | browse and read loot files (sandboxed, size-capped) |
| `find_client_ip` | resolve an associated client's IP from ARP/DHCP |
| `recon_set_bands` / `recon_new_session` | choose 2.4/5/6 GHz bands · start a fresh recon session |
| `list_filters` | show device (MAC) or network (SSID) filter lists |
| `pcap_control` | start/stop the optimized Wi-Fi pcap log |
| `notify` | buzz the operator on the Pager (log / alert / vibrate / LED / ringtone) |

### 🟧 Active — only when `ALLOW_ACTIVE=true`

> Full device control. Advertise these **only** for an authorized engagement.

| Tool | What it does |
|------|--------------|
| `bash` | run arbitrary shell command(s); DuckyScript / `PINEAPPLE_*` are on `PATH` |
| `duckyscript` | run any DuckyScript / `PINEAPPLE_*` command by name with args |
| `deauth_broadcast` | deauth **all** clients on an AP (deauth/disassoc, or CSA) |
| `deauth_clients` | directed deauth of **specific** client MACs (feed from `recon_list`) |
| `device_filter_edit` / `network_filter_edit` | manage MAC / SSID filter lists |

When `ALLOW_ACTIVE=false` (the default) these are neither listed in `tools/list`
nor executable. With it on, the client has complete control of the device.

> 💡 **Hands-free capture loop:** poll `handshakes` with `since_seconds` (~every 30 s);
> when a new row appears, fire `notify` to buzz the operator. A device-native alert
> payload under `/root/payloads/alerts/` can also trigger on `handshake_captured`.

---

## How it works

![Architecture](assets/architecture.svg)

A typical capture loop — one sentence in, one buzz out:

![Flow](assets/flow.svg)

On the Pager, the DuckyScript / `PINEAPPLE_*` commands are plain ELF binaries on
`PATH` (`/usr/bin/LOG`, `/usr/bin/PINEAPPLE_EXAMINE_RESET`, …) that work when invoked
directly — no payload shell context required. So `mcp-pager` just `exec`s them via
`std::process::Command`. **No bridge, no daemon dependency.** Read-only
introspection (loot, recon env, system info) is handled in-process with
path-traversal protection and size caps. The `recon_*` / `handshakes` tools read the
recon daemon's SQLite DB (`/root/recon/recon.db`, override with `MCP_RECON_DB`);
MAC/BSSID args are accepted with or without `:` / `-` separators.

---

## Install

### 1. Build the binary

The Pager is a **MIPS little-endian, soft-float** OpenWRT 24.10 device
(MediaTek MT7628, 24KEc core, no FPU; target `ramips/mt76x8`, arch `mipsel_24kc`;
musl loader `/lib/ld-musl-mipsel-sf.so.1`). Build for `mipsel-unknown-linux-musl`
with a **matching soft-float toolchain**.

<details>
<summary><b>Verified method — OpenWRT 24.10.1 SDK + nightly build-std</b> (click to expand)</summary>

```bash
# 1) Fetch + unpack the matching SDK
curl -LO https://downloads.openwrt.org/releases/24.10.1/targets/ramips/mt76x8/openwrt-sdk-24.10.1-ramips-mt76x8_gcc-13.3.0_musl.Linux-x86_64.tar.zst
tar --use-compress-program=unzstd -xf openwrt-sdk-24.10.1-*.tar.zst
SDK=$PWD/openwrt-sdk-24.10.1-ramips-mt76x8_gcc-13.3.0_musl.Linux-x86_64
export PATH="$SDK/staging_dir/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin:$PATH"
export STAGING_DIR="$SDK/staging_dir"

# 2) Build (needs: rustup component add rust-src --toolchain nightly)
CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER=mipsel-openwrt-linux-musl-gcc \
RUSTFLAGS="-Zunstable-options -Cpanic=immediate-abort" \
cargo +nightly build --release --target mipsel-unknown-linux-musl \
  -Z build-std=std,panic_abort
cp target/mipsel-unknown-linux-musl/release/mcp-pager bin/mcp-pager
```

Produces a ~300 KB binary whose interpreter is `/lib/ld-musl-mipsel-sf.so.1` —
confirmed running on-device. `build.sh` also accepts `METHOD=cross` (Docker) if you prefer.

> [!CAUTION]
> **Avoid a hard-float toolchain.** The stock `mipsel-linux-musl-cross` from musl.cc
> is hard-float; it links with an ABI-mismatch warning and targets
> `/lib/ld-musl-mipsel.so.1`, which does **not** exist on the Pager — the binary
> fails to load (`not found`). Use the OpenWRT SDK or `cross`.

</details>

### 2. Copy it to the Pager

```bash
scp bin/mcp-pager root@172.16.52.1:/root/mcp-pager
```

That alone is enough for the recommended connection below. (For the on-device
background service, also copy `payload.sh` + `config.sh` into a payload directory
via the Pager UI or `/root/payloads/...`. `payload.sh` restores the executable bit
on every launch, so it's safe to ship as a zip.)

### 3. Wire up your MCP client — stdio over SSH *(recommended: no tunnel, no daemon)*

The binary is self-contained, so the client just launches it over SSH and talks to
its stdio. **Claude Code** (`.mcp.json` or `claude mcp add`):

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

Drop `MCP_ALLOW_ACTIVE=1` to stay passive/read-only. Add `MCP_LOOT_DIR=...` to point
elsewhere. **Claude Desktop** (`claude_desktop_config.json`) uses the same shape.

That's it — open the client and ask it what's on the air.

<details>
<summary><b>Alternative — on-device TCP service + SSH tunnel</b></summary>

Launch `payload.sh` on the Pager (LED → **blue solid**); it runs
`mcp-pager --tcp 127.0.0.1:8099`. Then from your workstation:

```bash
ssh -L 8099:127.0.0.1:8099 root@172.16.52.1          # tunnel
# MCP client command:  socat STDIO TCP:127.0.0.1:8099
```

Set `MCP_TCP_TOKEN` (in `config.sh`) and the client must send it as `_auth` in the
`initialize` params. Keep `BIND_ADDR` on loopback unless you're on an isolated
engagement network — in which case always set a token.

</details>

---

## Security model

- **Access control lives at the transport.** stdio-over-SSH inherits your SSH auth;
  TCP mode binds **loopback** by default, and any off-loopback bind should set
  `MCP_TCP_TOKEN` and run only on an isolated engagement network.
- `read_loot` / `list_loot` are sandboxed to `MCP_LOOT_DIR`, reject `..` traversal,
  and `read_loot` is size-capped (`MCP_READ_CAP_BYTES`).
- Active tools (`bash`, `duckyscript`, `deauth_*`, `*_filter_edit`) are gated by
  `MCP_ALLOW_ACTIVE` and **off by default** — when off they are neither advertised
  nor executable. With them on, the client has full device control, so arm them only
  for an authorized engagement.

---

## Files

| File | Role |
|------|------|
| `payload.sh` | on-device launcher: runs `mcp-pager --tcp`, shows a status menu |
| `config.sh` | operator configuration |
| `build.sh` | cross-compile helper → `bin/mcp-pager` |
| `src/` | Rust MCP server — `main.rs` (protocol/transport), `tools.rs` (catalog + dispatch), `device.rs` (introspection & direct command exec) |
| `Cargo.toml`, `.cargo/config.toml` | crate + cross-target config |
| `assets/` | README artwork (SVG) |

<div align="center">
<sub>Binary payloads aren't accepted into the public Hak5 repo yet, but run fine for personal use. · Authorized testing only.</sub>
</div>
