//! MCP tool catalog and dispatch.
//!
//! All tools run on-device directly (introspection via fs/env, device actions by
//! exec'ing the PINEAPPLE_*/DuckyScript binaries). They fall into three groups:
//!   * direct       - read-only device introspection
//!   * passive      - recon tuning / status (non-attacking)
//!   * full-access  - bash, duckyscript, and traffic-affecting actions (deauth,
//!                    filter edits); only advertised and permitted when the
//!                    operator sets ALLOW_ACTIVE=true for an authorized engagement.

use crate::device;
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
            tool("recon_examine", "Focus the recon engine: lock to a BSSID's channel, lock to a specific channel, or reset to channel-hopping.", json!({
                "type":"object",
                "properties":{
                    "mode":{"type":"string","enum":["bssid","channel","reset"]},
                    "value":{"type":"string","description":"BSSID (mode=bssid) or channel number (mode=channel)."},
                    "seconds":{"type":"integer","minimum":1,"description":"Optional lock duration in seconds."}
                },
                "required":["mode"],
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
        ];

        if self.allow_active {
            tools.push(tool("bash", "[FULL ACCESS] Run an arbitrary bash command on the Pager (via 'bash -c'). DuckyScript/PINEAPPLE_* commands are on PATH and callable from here too. Returns combined stdout/stderr and the exit code. Long-running work should be backgrounded (e.g. 'cmd & echo started').", json!({
                "type":"object",
                "properties":{"command":{"type":"string","description":"Shell command(s) to run. May span multiple lines."}},
                "required":["command"],
                "additionalProperties":false
            })));
            tools.push(tool("duckyscript", "[FULL ACCESS] Run a single DuckyScript / PINEAPPLE_* command by name with arguments (structured alternative to 'bash'). Example: command='PINEAPPLE_EXAMINE_CHANNEL', args=['6','30'].", json!({
                "type":"object",
                "properties":{
                    "command":{"type":"string","description":"Command/function name, e.g. 'ALERT' or 'PINEAPPLE_SET_BANDS'."},
                    "args":{"type":"array","items":{"type":"string"},"description":"Positional arguments."}
                },
                "required":["command"],
                "additionalProperties":false
            })));
            tools.push(tool("deauth_client", "[ACTIVE] Send deauthentication/disassociation frames to a client (or FF:FF:FF:FF:FF:FF for all) on an AP. Authorized engagements only.", json!({
                "type":"object",
                "properties":{
                    "bssid":{"type":"string","description":"AP BSSID the client is on."},
                    "target":{"type":"string","description":"Client MAC, or FF:FF:FF:FF:FF:FF for all."},
                    "channel":{"type":"integer","minimum":1}
                },
                "required":["bssid","target","channel"],
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
            "recon_examine" => {
                let mode = req_str(args, "mode")?;
                let seconds = opt_num_str(args, "seconds");
                match mode.as_str() {
                    "reset" => device::run_cmd("PINEAPPLE_EXAMINE_RESET", &[]),
                    "bssid" => {
                        let v = req_str(args, "value")?;
                        if !is_mac(&v) {
                            return Err("value must be a BSSID like aa:bb:cc:dd:ee:ff".to_string());
                        }
                        device::run_cmd("PINEAPPLE_EXAMINE_BSSID", &with_opt(&[v], seconds))
                    }
                    "channel" => {
                        let v = req_str(args, "value")?;
                        if !is_num(&v) {
                            return Err("value must be a numeric channel".to_string());
                        }
                        device::run_cmd("PINEAPPLE_EXAMINE_CHANNEL", &with_opt(&[v], seconds))
                    }
                    other => Err(format!("unknown mode: {other}")),
                }
            }
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
                let mac = req_str(args, "mac")?;
                if !is_mac(&mac) {
                    return Err("mac must look like aa:bb:cc:dd:ee:ff".to_string());
                }
                let timeout = opt_num_str(args, "timeout");
                device::run_cmd("FIND_CLIENT_IP", &with_opt(&[mac], timeout))
            }

            // ---- full-access / active, gated behind ALLOW_ACTIVE ----
            "bash" | "duckyscript" | "deauth_client" | "device_filter_edit" | "network_filter_edit"
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
                if cmd.is_empty() || !cmd.bytes().all(|b| b.is_ascii_graphic() && b != b'/') {
                    return Err("command must be a bare command name".to_string());
                }
                let mut call = Vec::new();
                if let Some(a) = args.get("args").and_then(Value::as_array) {
                    for v in a {
                        call.push(v.as_str().ok_or("args must be strings")?.to_string());
                    }
                }
                device::run_cmd(&cmd, &call)
            }
            "deauth_client" => {
                let bssid = req_str(args, "bssid")?;
                let target = req_str(args, "target")?;
                let channel = req_str(args, "channel").or_else(|_| {
                    args.get("channel").and_then(Value::as_u64).map(|n| n.to_string()).ok_or_else(|| "channel is required".to_string())
                })?;
                if !is_mac(&bssid) || !is_mac(&target) {
                    return Err("bssid and target must be MAC addresses".to_string());
                }
                if !is_num(&channel) {
                    return Err("channel must be numeric".to_string());
                }
                device::run_cmd("PINEAPPLE_DEAUTH_CLIENT", &[bssid, target, channel])
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
                        let macs = str_array(args, "macs")?;
                        for m in &macs {
                            if !is_mac(m) {
                                return Err(format!("not a MAC address: {m}"));
                            }
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

/// True for strings that look like a MAC/BSSID (hex pairs separated by : or -).
fn is_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_num(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}
