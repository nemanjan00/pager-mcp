//! MCP tool catalog and dispatch.
//!
//! All tools run on-device directly (introspection via fs/env, device actions by
//! exec'ing the PINEAPPLE_*/DuckyScript binaries). They fall into three groups:
//!   * direct       - read-only device introspection
//!   * passive      - recon tuning / status (non-attacking)
//!   * full-access  - bash, duckyscript, and traffic-affecting actions (deauth,
//!                    filter edits); only advertised and permitted when the
//!                    operator sets ALLOW_ACTIVE=true for an authorized engagement.

use crate::bt;
use crate::device;
use crate::recon;
use serde_json::{json, Value};
use std::path::PathBuf;

pub struct Server {
    pub loot_dir: PathBuf,
    pub allow_active: bool,
    pub read_cap: usize,
    pub recon: Value,
}

const READ_CAP_DEFAULT: usize = 256 * 1024;

impl Server {
    pub fn from_env() -> Server {
        let loot_dir = std::env::var("MCP_LOOT_DIR").unwrap_or_else(|_| "/root/loot".to_string());
        let allow_active = matches!(
            std::env::var("MCP_ALLOW_ACTIVE").unwrap_or_default().as_str(),
            "1" | "true" | "yes" | "on"
        );
        let read_cap = std::env::var("MCP_READ_CAP_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&n| n > 0)
            .unwrap_or(READ_CAP_DEFAULT);
        Server {
            loot_dir: PathBuf::from(loot_dir),
            allow_active,
            read_cap,
            recon: device::recon_context(),
        }
    }

    /// Tool definitions advertised via `tools/list`.
    pub fn tool_list(&self) -> Vec<Value> {
        let mut tools = vec![
            tool("system_info", "Kernel, uptime, storage, memory and firmware details of the Pager.", json!({"type":"object","properties":{},"additionalProperties":false})),
            tool("recon_context", "The selected access point / client recon data this payload was launched against (the _RECON_SELECTED_* fields).", json!({"type":"object","properties":{},"additionalProperties":false})),
            tool("list_loot", "List files captured under the loot directory (handshakes, pcaps, reports).", json!({
                "type":"object",
                "properties":{
                    "subpath":{"type":"string","description":"Optional path relative to the loot root, e.g. 'handshakes'."},
                    "max_entries":{"type":"integer","minimum":1,"maximum":1000,"description":"Maximum entries to return (default 200)."}
                },
                "additionalProperties":false
            })),
            tool("read_loot", "Read a text file from the loot directory (capped in size).", json!({
                "type":"object",
                "properties":{"path":{"type":"string","description":"Path relative to the loot root."}},
                "required":["path"],
                "additionalProperties":false
            })),
            tool("handshake_stats", "Count captured handshake artifacts (.22000/.pcap/.pcapng), optionally filtered by a MAC address substring.", json!({
                "type":"object",
                "properties":{"mac":{"type":"string","description":"Optional MAC to filter filenames by."}},
                "additionalProperties":false
            })),
            tool("recon_list", "Survey the wireless environment from the recon database: nearby access points or client stations. Defaults to the last 120s ('around me now'); set max_age_seconds=0 for all-time.", json!({
                "type":"object",
                "properties":{
                    "kind":{"type":"string","enum":["aps","clients"],"description":"'aps' (beaconing networks) or 'clients' (stations); default aps."},
                    "max_age_seconds":{"type":"integer","minimum":0,"description":"Only include things heard within this many seconds (default 120; 0 = all time)."},
                    "band":{"type":"string","enum":["2.4","5","6"],"description":"Optional band filter (GHz)."},
                    "min_signal":{"type":"integer","description":"Optional minimum signal in dBm, e.g. -70 (stronger/closer only)."},
                    "limit":{"type":"integer","minimum":1,"maximum":1000,"description":"Max rows (default 100)."}
                },
                "additionalProperties":false
            })),
            tool("recon_ap_detail", "Everything the recon engine knows about one access point (BSSID): its SSIDs, radio/band/security, signal, captured handshakes, and stations seen associated with it.", json!({
                "type":"object",
                "properties":{"bssid":{"type":"string","description":"AP BSSID, e.g. aa:bb:cc:dd:ee:ff."}},
                "required":["bssid"],
                "additionalProperties":false
            })),
            tool("handshakes", "List captured WPA handshakes (AP SSID/BSSID, client, time, EAPOL frames) from the recon database, newest first. Set since_seconds to poll for newly captured handshakes.", json!({
                "type":"object",
                "properties":{
                    "since_seconds":{"type":"integer","minimum":0,"description":"Only handshakes captured within this many seconds (0 = all; default 0)."},
                    "limit":{"type":"integer","minimum":1,"maximum":1000,"description":"Max rows (default 100)."}
                },
                "additionalProperties":false
            })),
            tool("channel_lock", "Stop recon channel-hopping and lock the radio to one channel (or an AP's channel) to maximize handshake capture. Call channel_unlock to resume hopping.", json!({
                "type":"object",
                "properties":{
                    "channel":{"type":"integer","minimum":1,"description":"Channel number to lock to."},
                    "bssid":{"type":"string","description":"Alternatively, lock to this AP's channel."},
                    "seconds":{"type":"integer","minimum":1,"description":"Optional auto-unlock after this many seconds."}
                },
                "additionalProperties":false
            })),
            tool("channel_unlock", "Resume recon channel-hopping after a channel_lock.", json!({"type":"object","properties":{},"additionalProperties":false})),
            tool("notify", "Signal the operator on the physical Pager (log line, popup alert, vibration, LED or ringtone).", json!({
                "type":"object",
                "properties":{
                    "kind":{"type":"string","enum":["log","alert","vibrate","led","ringtone"]},
                    "message":{"type":"string","description":"Text for log/alert/vibrate/ringtone-name, or LED spec like 'red solid'."},
                    "color":{"type":"string","enum":["red","green","blue"],"description":"Optional color for kind=log."}
                },
                "required":["kind","message"],
                "additionalProperties":false
            })),
            tool("recon_set_bands", "Select which Wi-Fi bands the recon engine hops across.", json!({
                "type":"object",
                "properties":{
                    "bands":{"type":"array","items":{"type":"integer","enum":[2,5,6]},"minItems":1,"description":"Subset of 2, 5, 6 (GHz)."},
                    "interface":{"type":"string","description":"Monitor interface (default wlan1mon)."}
                },
                "required":["bands"],
                "additionalProperties":false
            })),
            tool("recon_new_session", "Start a fresh recon session (also rotates pcap/Wigle logs if running).", json!({
                "type":"object",
                "properties":{"name":{"type":"string","description":"Optional session name."}},
                "additionalProperties":false
            })),
            tool("list_filters", "Show the contents of a Pineapple device (MAC) or network (SSID) filter list.", json!({
                "type":"object",
                "properties":{
                    "type":{"type":"string","enum":["device","network"]},
                    "list":{"type":"string","enum":["allow","deny"]}
                },
                "required":["type","list"],
                "additionalProperties":false
            })),
            tool("pcap_control", "Start or stop the recon engine's optimized Wi-Fi pcap log.", json!({
                "type":"object",
                "properties":{"action":{"type":"string","enum":["start","stop"]}},
                "required":["action"],
                "additionalProperties":false
            })),
            tool("find_client_ip", "Search ARP/DHCP records for the IP of a client associated to a Pineapple AP.", json!({
                "type":"object",
                "properties":{
                    "mac":{"type":"string"},
                    "timeout":{"type":"integer","minimum":1,"description":"Seconds before giving up."}
                },
                "required":["mac"],
                "additionalProperties":false
            })),
            // ---- Bluetooth recon (blue5, Pager 2.0) ----
            tool("bt_status", "blue5 Bluetooth scanner and adapter state: LE/Classic scan mode, device counts (LE/BR/dual), event rate, database/WiGLE logging state and GPS status.", json!({"type":"object","properties":{},"additionalProperties":false})),
            tool("bt_list", "Survey Bluetooth devices seen by the blue5 scanner (BLE and Classic) from the current scan, strongest signal first. Defaults to the last 120s ('around me now'); set max_age_seconds=0 for the whole scan.", json!({
                "type":"object",
                "properties":{
                    "type":{"type":"string","enum":["le","classic","dual"],"description":"Filter by transport: 'le' (BLE only), 'classic' (BR/EDR only) or 'dual'."},
                    "max_age_seconds":{"type":"integer","minimum":0,"description":"Only devices heard within this many seconds (default 120; 0 = whole scan)."},
                    "min_rssi":{"type":"integer","description":"Optional minimum average RSSI in dBm, e.g. -70 (stronger/closer only)."},
                    "named_only":{"type":"boolean","description":"Only devices that advertised a name."},
                    "connectable_only":{"type":"boolean","description":"Only LE-connectable devices."},
                    "no_random":{"type":"boolean","description":"Drop LE random (rotating) addresses; keep public and Classic."},
                    "company":{"type":"string","description":"Filter by Bluetooth SIG company id, e.g. '0x004C' (Apple) or '76'."},
                    "limit":{"type":"integer","minimum":1,"maximum":1000,"description":"Max rows (default 100)."}
                },
                "additionalProperties":false
            })),
            tool("bt_device_detail", "Everything blue5 knows about one Bluetooth device (MAC): name, vendor/company, transport, connectability, Class-of-Device, appearance, advertised 16-bit services, RSSI history and raw manufacturer/service data (hex).", json!({
                "type":"object",
                "properties":{"mac":{"type":"string","description":"Device MAC, e.g. aa:bb:cc:dd:ee:ff (separators optional)."}},
                "required":["mac"],
                "additionalProperties":false
            })),
            tool("bt_scan_config", "Tune the live blue5 scan: toggle active LE, Classic (BR/EDR) inquiry, LE scanning, the LE Coded (long-range) PHY, dropping LE random addresses and Classic name requests, and set inquiry round length/pause. Only the fields you set are changed.", json!({
                "type":"object",
                "properties":{
                    "active_le":{"type":"boolean","description":"Active LE scan (request scan responses, which often carry names)."},
                    "classic":{"type":"boolean","description":"BR/EDR (Classic) inquiry on/off."},
                    "le":{"type":"boolean","description":"LE scanning on/off (false = Classic only)."},
                    "coded_phy":{"type":"boolean","description":"Also scan the LE Coded (long-range) PHY."},
                    "drop_random":{"type":"boolean","description":"Drop LE random-address adverts so rotating addresses don't fill the table."},
                    "name_requests":{"type":"boolean","description":"Classic name requests (false = more passive, never page for a name)."},
                    "pause_seconds":{"type":"integer","minimum":0,"maximum":3600,"description":"Pause between Classic inquiry rounds (seconds)."},
                    "round_units":{"type":"integer","minimum":1,"maximum":48,"description":"Classic inquiry round length in 1.28s units (1-48)."}
                },
                "additionalProperties":false
            })),
            tool("bt_recon_new", "Start a fresh blue5 database scan: flush and clear the device table and log to a new scan row (analogous to recon_new_session for Wi-Fi).", json!({
                "type":"object",
                "properties":{"name":{"type":"string","description":"Optional name for the new scan."}},
                "additionalProperties":false
            })),
            tool("bt_recon_end", "End the current blue5 database scan: do a final flush, then stop writing to the database (the live scan keeps running).", json!({"type":"object","properties":{},"additionalProperties":false})),
            tool("bt_wigle", "Turn WiGLE CSV logging of Bluetooth devices on or off (needs a GPS source and blue5 started with a WiGLE directory).", json!({
                "type":"object",
                "properties":{"action":{"type":"string","enum":["on","off"]}},
                "required":["action"],
                "additionalProperties":false
            })),
        ];

        if self.allow_active {
            tools.push(tool("bash", "[FULL ACCESS] Run an arbitrary bash command on the Pager (via 'bash -c'). DuckyScript/PINEAPPLE_* commands are on PATH and callable from here too. Returns combined stdout/stderr and the exit code. Long-running work should be backgrounded (e.g. 'cmd & echo started').", json!({
                "type":"object",
                "properties":{"command":{"type":"string","description":"Shell command(s) to run. May span multiple lines."}},
                "required":["command"],
                "additionalProperties":false
            })));
            tools.push(tool("duckyscript", "[FULL ACCESS] Run any executable by name or absolute path with arguments (DuckyScript/PINEAPPLE_* or any other binary; structured alternative to 'bash'). Example: command='PINEAPPLE_EXAMINE_CHANNEL', args=['6','30'].", json!({
                "type":"object",
                "properties":{
                    "command":{"type":"string","description":"Command/function name, e.g. 'ALERT' or 'PINEAPPLE_SET_BANDS'."},
                    "args":{"type":"array","items":{"type":"string"},"description":"Positional arguments."}
                },
                "required":["command"],
                "additionalProperties":false
            })));
            tools.push(tool("deauth_broadcast", "[ACTIVE] Deauthenticate ALL clients on an AP (broadcast). Authorized engagements only.", json!({
                "type":"object",
                "properties":{
                    "bssid":{"type":"string","description":"AP BSSID to target."},
                    "channel":{"type":"integer","minimum":1},
                    "csa":{"type":"boolean","description":"Use channel-switch-announcement method instead of deauth/disassoc frames (default false)."}
                },
                "required":["bssid","channel"],
                "additionalProperties":false
            })));
            tools.push(tool("deauth_clients", "[ACTIVE] Send directed deauth/disassoc frames to specific client MACs on an AP (more reliable than broadcast). Feed it a client list from recon_list(kind=clients) or recon_ap_detail. Authorized engagements only.", json!({
                "type":"object",
                "properties":{
                    "bssid":{"type":"string","description":"AP BSSID the clients are on."},
                    "channel":{"type":"integer","minimum":1},
                    "clients":{"type":"array","items":{"type":"string"},"minItems":1,"description":"Client MAC addresses to disconnect."}
                },
                "required":["bssid","channel","clients"],
                "additionalProperties":false
            })));
            tools.push(tool("device_filter_edit", "[ACTIVE] Edit a Pineapple device (MAC) filter list defining engagement scope.", json!({
                "type":"object",
                "properties":{
                    "list":{"type":"string","enum":["allow","deny"]},
                    "action":{"type":"string","enum":["add","delete","clear","mode"]},
                    "macs":{"type":"array","items":{"type":"string"},"description":"MACs for add/delete."},
                    "mode":{"type":"string","enum":["allow","deny"],"description":"Operational mode for action=mode."}
                },
                "required":["list","action"],
                "additionalProperties":false
            })));
            tools.push(tool("network_filter_edit", "[ACTIVE] Edit a Pineapple network (SSID) filter list defining engagement scope.", json!({
                "type":"object",
                "properties":{
                    "list":{"type":"string","enum":["allow","deny"]},
                    "action":{"type":"string","enum":["add","delete","clear","mode"]},
                    "ssids":{"type":"array","items":{"type":"string"},"description":"SSIDs for add/delete."},
                    "mode":{"type":"string","enum":["allow","deny"],"description":"Operational mode for action=mode."}
                },
                "required":["list","action"],
                "additionalProperties":false
            })));
        }
        tools
    }

    /// Dispatch a `tools/call`. Returns tool text output or an error message.
    pub fn call_tool(&self, name: &str, args: &Value) -> Result<String, String> {
        match name {
            // ---- direct, read-only ----
            "system_info" => Ok(device::system_info()),
            "recon_context" => Ok(pretty(&self.recon)),
            "list_loot" => {
                let subpath = opt_str(args, "subpath").unwrap_or_default();
                let max = args.get("max_entries").and_then(Value::as_u64).unwrap_or(200) as usize;
                device::list_loot(&self.loot_dir, &subpath, max.clamp(1, 1000)).map(|v| pretty(&v))
            }
            "read_loot" => {
                let path = req_str(args, "path")?;
                device::read_loot(&self.loot_dir, &path, self.read_cap).map(|v| pretty(&v))
            }
            "handshake_stats" => {
                let mac = opt_str(args, "mac");
                Ok(pretty(&device::handshake_stats(&self.loot_dir, mac.as_deref())))
            }

            // ---- passive device commands (run directly) ----
            "notify" => {
                let kind = req_str(args, "kind")?;
                let msg = req_str(args, "message")?;
                match kind.as_str() {
                    "log" => {
                        let mut a = Vec::new();
                        if let Some(c) = opt_str(args, "color").filter(|c| !c.is_empty()) {
                            a.push(c);
                        }
                        a.push(msg);
                        device::run_cmd("LOG", &a)
                    }
                    "alert" => device::run_cmd("ALERT", &[msg]),
                    "vibrate" => device::run_cmd("VIBRATE", &[msg]),
                    // LED takes space-separated words, e.g. "red solid".
                    "led" => device::run_cmd(
                        "LED",
                        &msg.split_whitespace().map(String::from).collect::<Vec<_>>(),
                    ),
                    "ringtone" => device::run_cmd("RINGTONE", &[msg]),
                    other => Err(format!("unknown notify kind: {other}")),
                }
            }
            "recon_list" => {
                let kind = opt_str(args, "kind").unwrap_or_else(|| "aps".to_string());
                let max_age = args.get("max_age_seconds").and_then(Value::as_i64).unwrap_or(120);
                let band = opt_str(args, "band");
                let min_signal = args.get("min_signal").and_then(Value::as_i64);
                let limit = args.get("limit").and_then(Value::as_i64).unwrap_or(100);
                recon::list(&kind, max_age, band.as_deref(), min_signal, limit)
            }
            "recon_ap_detail" => {
                let bssid = req_str(args, "bssid")?;
                if !is_mac(&bssid) {
                    return Err("bssid must look like aa:bb:cc:dd:ee:ff".to_string());
                }
                recon::ap_detail(&bssid)
            }
            "handshakes" => {
                let since = args.get("since_seconds").and_then(Value::as_i64).unwrap_or(0);
                let limit = args.get("limit").and_then(Value::as_i64).unwrap_or(100);
                recon::handshakes(since, limit)
            }
            "channel_lock" => {
                let seconds = opt_num_str(args, "seconds");
                if let Some(bssid) = opt_str(args, "bssid") {
                    let bssid = norm_mac(&bssid).ok_or("bssid must look like aa:bb:cc:dd:ee:ff")?;
                    device::run_cmd("PINEAPPLE_EXAMINE_BSSID", &with_opt(&[bssid], seconds))
                } else if let Some(ch) = opt_num_str(args, "channel") {
                    device::run_cmd("PINEAPPLE_EXAMINE_CHANNEL", &with_opt(&[ch], seconds))
                } else {
                    Err("provide either 'channel' or 'bssid' to lock to".to_string())
                }
            }
            "channel_unlock" => device::run_cmd("PINEAPPLE_EXAMINE_RESET", &[]),
            "recon_set_bands" => {
                let iface = opt_str(args, "interface").unwrap_or_else(|| "wlan1mon".to_string());
                let bands = args
                    .get("bands")
                    .and_then(Value::as_array)
                    .ok_or("bands array is required")?;
                let mut call_args = vec![iface];
                for b in bands {
                    match b.as_u64() {
                        Some(n @ (2 | 5 | 6)) => call_args.push(n.to_string()),
                        _ => return Err("bands may only contain 2, 5 or 6".to_string()),
                    }
                }
                device::run_cmd("PINEAPPLE_SET_BANDS", &call_args)
            }
            "recon_new_session" => {
                let name = opt_str(args, "name");
                device::run_cmd("PINEAPPLE_RECON_NEW", &name.map(|n| vec![n]).unwrap_or_default())
            }
            "list_filters" => {
                let list = enum_arg(args, "list", &["allow", "deny"])?;
                match req_str(args, "type")?.as_str() {
                    "device" => device::run_cmd("PINEAPPLE_DEVICE_FILTER_LIST", &[list]),
                    "network" => device::run_cmd("PINEAPPLE_NETWORK_FILTER_LIST", &[list]),
                    other => Err(format!("unknown filter type: {other}")),
                }
            }
            "pcap_control" => match enum_arg(args, "action", &["start", "stop"])?.as_str() {
                "start" => device::run_cmd("WIFI_PCAP_START", &[]),
                _ => device::run_cmd("WIFI_PCAP_STOP", &[]),
            },
            "find_client_ip" => {
                let mac = norm_mac(&req_str(args, "mac")?).ok_or("mac must look like aa:bb:cc:dd:ee:ff")?;
                let timeout = opt_num_str(args, "timeout");
                device::run_cmd("FIND_CLIENT_IP", &with_opt(&[mac], timeout))
            }

            // ---- Bluetooth recon (blue5), read-only + passive control ----
            "bt_status" => device::run_cmd("blue5ctl", &["status".to_string()]),
            "bt_list" => {
                let type_filter = opt_str(args, "type");
                let max_age = args.get("max_age_seconds").and_then(Value::as_i64).unwrap_or(120);
                let min_rssi = args.get("min_rssi").and_then(Value::as_i64);
                let named = args.get("named_only").and_then(Value::as_bool).unwrap_or(false);
                let connectable = args.get("connectable_only").and_then(Value::as_bool).unwrap_or(false);
                let no_random = args.get("no_random").and_then(Value::as_bool).unwrap_or(false);
                let company = match args.get("company") {
                    Some(Value::String(s)) => Some(parse_company(s)?),
                    Some(Value::Number(n)) => n.as_i64(),
                    _ => None,
                };
                let limit = args.get("limit").and_then(Value::as_i64).unwrap_or(100);
                bt::list(type_filter.as_deref(), max_age, min_rssi, named, connectable, company, no_random, limit)
            }
            "bt_device_detail" => {
                let mac = norm_mac(&req_str(args, "mac")?).ok_or("mac must look like aa:bb:cc:dd:ee:ff")?;
                bt::detail(&mac)
            }
            "bt_scan_config" => {
                let mut call: Vec<String> = vec!["scan".to_string()];
                let mut push_bool = |key: &str, flag: &str| {
                    if let Some(b) = args.get(key).and_then(Value::as_bool) {
                        call.push(flag.to_string());
                        call.push(if b { "1" } else { "0" }.to_string());
                    }
                };
                push_bool("active_le", "-A");
                push_bool("classic", "-C");
                push_bool("le", "-E");
                push_bool("coded_phy", "-c");
                push_bool("drop_random", "-D");
                push_bool("name_requests", "-M");
                drop(push_bool);
                if let Some(p) = args.get("pause_seconds").and_then(Value::as_i64) {
                    call.push("-P".to_string());
                    call.push(p.clamp(0, 3600).to_string());
                }
                if let Some(u) = args.get("round_units").and_then(Value::as_i64) {
                    call.push("-L".to_string());
                    call.push(u.clamp(1, 48).to_string());
                }
                if call.len() == 1 {
                    return Err("set at least one scan parameter to change".to_string());
                }
                device::run_cmd("blue5ctl", &call)
            }
            "bt_recon_new" => {
                let mut call = vec!["new".to_string()];
                if let Some(name) = opt_str(args, "name").filter(|n| !n.is_empty()) {
                    call.push(name);
                }
                device::run_cmd("blue5ctl", &call)
            }
            "bt_recon_end" => device::run_cmd("blue5ctl", &["end".to_string()]),
            "bt_wigle" => {
                let action = enum_arg(args, "action", &["on", "off"])?;
                device::run_cmd("blue5ctl", &["wigle".to_string(), action])
            }

            // ---- full-access / active, gated behind ALLOW_ACTIVE ----
            "bash" | "duckyscript" | "deauth_broadcast" | "deauth_clients" | "device_filter_edit"
            | "network_filter_edit"
                if !self.allow_active =>
            {
                Err("full-access tools are disabled; set ALLOW_ACTIVE=true in config.sh for an authorized engagement".to_string())
            }
            "bash" => {
                let cmd = req_str(args, "command")?;
                device::run_bash(&cmd)
            }
            "duckyscript" => {
                let cmd = req_str(args, "command")?;
                // Full-access tool: allow any executable by name or absolute path.
                // Command::new does not invoke a shell, so args are passed verbatim.
                if cmd.trim().is_empty() || cmd.bytes().any(|b| b == 0 || b == b'\n') {
                    return Err("command must be a non-empty command name or path".to_string());
                }
                let mut call = Vec::new();
                if let Some(a) = args.get("args").and_then(Value::as_array) {
                    for v in a {
                        call.push(v.as_str().ok_or("args must be strings")?.to_string());
                    }
                }
                device::run_cmd(&cmd, &call)
            }
            "deauth_broadcast" => {
                let bssid = norm_mac(&req_str(args, "bssid")?).ok_or("bssid must be a MAC address")?;
                let channel = num_arg(args, "channel")?;
                if args.get("csa").and_then(Value::as_bool).unwrap_or(false) {
                    device::run_cmd("PINEAPPLE_DEAUTH_CLIENT_CSA", &[bssid, channel])
                } else {
                    device::run_cmd(
                        "PINEAPPLE_DEAUTH_CLIENT_ALL",
                        &[bssid, "FF:FF:FF:FF:FF:FF".to_string(), channel],
                    )
                }
            }
            "deauth_clients" => {
                let bssid = norm_mac(&req_str(args, "bssid")?).ok_or("bssid must be a MAC address")?;
                let channel = num_arg(args, "channel")?;
                let clients = str_array(args, "clients")?;
                if clients.is_empty() {
                    return Err("clients must contain at least one MAC".to_string());
                }
                let mut results = Vec::new();
                for mac in &clients {
                    let target = match norm_mac(mac) {
                        Some(m) => m,
                        None => {
                            results.push(format!("{mac}: SKIPPED (not a MAC)"));
                            continue;
                        }
                    };
                    match device::run_cmd(
                        "PINEAPPLE_DEAUTH_CLIENT",
                        &[bssid.clone(), target.clone(), channel.clone()],
                    ) {
                        Ok(_) => results.push(format!("{target}: sent")),
                        Err(e) => results.push(format!("{target}: ERROR {e}")),
                    }
                }
                Ok(format!(
                    "deauth sent to {} client(s) on {bssid} ch {channel}:\n{}",
                    clients.len(),
                    results.join("\n")
                ))
            }
            "device_filter_edit" => {
                let list = enum_arg(args, "list", &["allow", "deny"])?;
                match enum_arg(args, "action", &["add", "delete", "clear", "mode"])?.as_str() {
                    "clear" => device::run_cmd("PINEAPPLE_DEVICE_FILTER_CLEAR", &[list]),
                    "mode" => {
                        let mode = enum_arg(args, "mode", &["allow", "deny"])?;
                        device::run_cmd("PINEAPPLE_DEVICE_FILTER_MODE", &[mode])
                    }
                    action => {
                        let mut macs = str_array(args, "macs")?;
                        for m in macs.iter_mut() {
                            *m = norm_mac(m).ok_or_else(|| format!("not a MAC address: {m}"))?;
                        }
                        let cmd = if action == "add" {
                            "PINEAPPLE_DEVICE_FILTER_ADD"
                        } else {
                            "PINEAPPLE_DEVICE_FILTER_DELETE"
                        };
                        let mut call_args = vec![list];
                        call_args.extend(macs);
                        device::run_cmd(cmd, &call_args)
                    }
                }
            }
            "network_filter_edit" => {
                let list = enum_arg(args, "list", &["allow", "deny"])?;
                match enum_arg(args, "action", &["add", "delete", "clear", "mode"])?.as_str() {
                    "clear" => device::run_cmd("PINEAPPLE_NETWORK_FILTER_CLEAR", &[list]),
                    "mode" => {
                        let mode = enum_arg(args, "mode", &["allow", "deny"])?;
                        device::run_cmd("PINEAPPLE_NETWORK_FILTER_MODE", &[mode])
                    }
                    action => {
                        let ssids = str_array(args, "ssids")?;
                        if ssids.is_empty() {
                            return Err("ssids must contain at least one entry".to_string());
                        }
                        let cmd = if action == "add" {
                            "PINEAPPLE_NETWORK_FILTER_ADD"
                        } else {
                            "PINEAPPLE_NETWORK_FILTER_DELETE"
                        };
                        let mut call_args = vec![list];
                        call_args.extend(ssids);
                        device::run_cmd(cmd, &call_args)
                    }
                }
            }

            other => Err(format!("unknown tool: {other}")),
        }
    }
}

fn tool(name: &str, description: &str, schema: Value) -> Value {
    json!({ "name": name, "description": description, "inputSchema": schema })
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

fn req_str(args: &Value, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(|s| s.to_string())
        .ok_or_else(|| format!("missing required string argument: {key}"))
}

fn opt_str(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(Value::as_str).map(|s| s.to_string())
}

/// Required numeric arg, accepted as a JSON number or numeric string.
fn num_arg(args: &Value, key: &str) -> Result<String, String> {
    opt_num_str(args, key).ok_or_else(|| format!("missing required numeric argument: {key}"))
}

/// Accept a number given either as a JSON number or a numeric string.
fn opt_num_str(args: &Value, key: &str) -> Option<String> {
    match args.get(key) {
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::String(s)) if is_num(s) => Some(s.clone()),
        _ => None,
    }
}

fn enum_arg(args: &Value, key: &str, allowed: &[&str]) -> Result<String, String> {
    let v = req_str(args, key)?;
    if allowed.contains(&v.as_str()) {
        Ok(v)
    } else {
        Err(format!("{key} must be one of {allowed:?}"))
    }
}

fn str_array(args: &Value, key: &str) -> Result<Vec<String>, String> {
    let arr = args
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} must be an array of strings"))?;
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        out.push(v.as_str().ok_or_else(|| format!("{key} must contain only strings"))?.to_string());
    }
    Ok(out)
}

fn with_opt(base: &[String], extra: Option<String>) -> Vec<String> {
    let mut v = base.to_vec();
    if let Some(e) = extra {
        v.push(e);
    }
    v
}

/// Normalize a MAC/BSSID given with or without `:`/`-` separators (as the recon
/// tools emit the bare 12-hex form) into canonical `aa:bb:cc:dd:ee:ff`.
fn norm_mac(s: &str) -> Option<String> {
    let hex: String = s.chars().filter(|c| *c != ':' && *c != '-').collect();
    if hex.len() == 12 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        let lower = hex.to_lowercase();
        Some(
            (0..6)
                .map(|i| &lower[i * 2..i * 2 + 2])
                .collect::<Vec<_>>()
                .join(":"),
        )
    } else {
        None
    }
}

/// True for strings that look like a MAC/BSSID (with or without separators).
fn is_mac(s: &str) -> bool {
    norm_mac(s).is_some()
}

fn is_num(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Parse a Bluetooth SIG company id given as decimal ("76") or hex ("0x004C").
fn parse_company(s: &str) -> Result<i64, String> {
    let s = s.trim();
    let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16)
    } else {
        s.parse::<i64>()
    };
    parsed.map_err(|_| format!("company must be a decimal or 0x-hex id (got {s})"))
}
