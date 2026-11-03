//! Read-only "intel" tools: structured answers mined from the recon databases
//! (`/root/recon/recon.db` Wi-Fi, `/root/recon/blue5.db` Bluetooth) and the loot
//! directory.
//!
//! Everything here is read-only. Dynamic SQL values are integers or come from
//! fixed in-source constant lists (detection signatures), never from free-form
//! caller input, so these queries have no injection surface. MAC/BSSID columns
//! in recon.db are colon-less hex TEXT; blue5 stores MACs as bare upper-hex.
//! BLOB columns (ssid, names) are read with `CAST(col AS TEXT)`.

use crate::device;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

fn recon_db() -> String {
    std::env::var("MCP_RECON_DB").unwrap_or_else(|_| "/root/recon/recon.db".to_string())
}
fn bt_db() -> String {
    std::env::var("MCP_BT_DB").unwrap_or_else(|_| "/root/recon/blue5.db".to_string())
}

fn query_json(db: &str, sql: &str) -> Result<String, String> {
    let out = device::run_cmd(
        "sqlite3",
        &[
            "-json".to_string(),
            "-cmd".to_string(),
            ".timeout 3000".to_string(),
            db.to_string(),
            sql.to_string(),
        ],
    )?;
    let t = out.trim();
    Ok(if t.is_empty() || t == "(ok)" { "[]".to_string() } else { t.to_string() })
}

fn query_value(db: &str, sql: &str) -> Result<Value, String> {
    serde_json::from_str(&query_json(db, sql)?).map_err(|e| format!("query parse error: {e}"))
}

// ---------------------------------------------------------------------------
// connected_clients: stations associated to the Pager's OWN hostapd APs.
// ---------------------------------------------------------------------------
pub fn connected_clients(limit: i64) -> Result<String, String> {
    let limit = limit.clamp(1, 1000);
    let sql = format!(
        "SELECT CAST(c.mac AS TEXT) AS client_mac, CAST(c.ssid AS TEXT) AS ap_ssid, \
           c.connected_time, c.disconnected_time, \
           CASE WHEN c.disconnected_time IS NULL OR c.disconnected_time=0 THEN 1 ELSE 0 END AS currently_connected, \
           (SELECT CAST(h.apmac AS TEXT) FROM hostap_handshake h \
             WHERE CAST(h.ssid AS TEXT)=CAST(c.ssid AS TEXT) \
               AND CAST(h.stamac AS TEXT)=CAST(c.mac AS TEXT) LIMIT 1) AS ap_bssid \
         FROM hostap_client c ORDER BY c.connected_time DESC LIMIT {limit}"
    );
    query_json(&recon_db(), &sql)
}

// ---------------------------------------------------------------------------
// probes: probe-request SSIDs (ssid.type=4). action = "list" | "top".
// ---------------------------------------------------------------------------
pub fn probes(action: &str, limit: i64) -> Result<String, String> {
    let limit = limit.clamp(1, 1000);
    let sql = match action {
        "list" => format!(
            "SELECT CAST(s.ssid AS TEXT) AS probed_ssid, CAST(d.mac AS TEXT) AS client_mac, \
               s.time, s.signal, s.freq \
             FROM ssid s LEFT JOIN wifi_device d ON s.wifi_device=d.hash \
             WHERE s.type=4 AND length(s.ssid)>0 ORDER BY s.time DESC LIMIT {limit}"
        ),
        "top" => format!(
            "SELECT COUNT(DISTINCT wd.mac) AS probe_count, CAST(s.ssid AS TEXT) AS ssid_name \
             FROM ssid s LEFT JOIN wifi_device wd ON s.wifi_device=wd.hash \
             WHERE s.type=4 AND LENGTH(s.ssid)>0 GROUP BY s.ssid \
             HAVING COUNT(DISTINCT wd.mac)>1 ORDER BY probe_count DESC, ssid_name ASC LIMIT {limit}"
        ),
        other => return Err(format!("action must be 'list' or 'top' (got {other})")),
    };
    query_json(&recon_db(), &sql)
}

// ---------------------------------------------------------------------------
// captured_credentials: portal creds (loot) + WPA-Enterprise creds (recon.db).
// ---------------------------------------------------------------------------
pub fn captured_credentials(loot_dir: &Path, cap: usize) -> Result<String, String> {
    // (a) Portal credential logs under <loot>/goodportal/credentials_*.log
    let mut portal = Vec::new();
    let gp = loot_dir.join("goodportal");
    if let Ok(rd) = fs::read_dir(&gp) {
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            if name.starts_with("credentials_") && name.ends_with(".log") {
                let data = fs::read(ent.path()).unwrap_or_default();
                let truncated = data.len() > cap;
                let text = String::from_utf8_lossy(&data[..data.len().min(cap)]).into_owned();
                portal.push(json!({ "file": name, "truncated": truncated, "content": text }));
            }
        }
    }
    // (b) WPA-Enterprise identities / challenge-responses from recon.db.
    let db = recon_db();
    let basic = query_value(
        &db,
        "SELECT id, time, type, identity, password, verified FROM hostap_basic ORDER BY time DESC",
    )
    .unwrap_or_else(|_| json!([]));
    let chalresp = query_value(
        &db,
        "SELECT id, time, type, username, hex(challenge) AS challenge, hex(response) AS response, verified \
         FROM hostap_chalresp ORDER BY time DESC",
    )
    .unwrap_or_else(|_| json!([]));
    let out = json!({
        "portal_credentials": portal,
        "enterprise_identity": basic,
        "enterprise_challenge_response": chalresp,
    });
    serde_json::to_string_pretty(&out).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// handshake_quality: classify + dedupe captured handshakes from loot .22000s.
// A hashcat-22000 line is  WPA*<type>*<mic>*<apmac>*<stamac>*<essid-hex>*...
// type 01 = PMKID, 02 = EAPOL. Dedup key = the <mic> field (index 2).
// ---------------------------------------------------------------------------
pub fn handshake_quality(loot_dir: &Path) -> Result<String, String> {
    let dir = loot_dir.join("handshakes");
    let rd = match fs::read_dir(&dir) {
        Ok(r) => r,
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    };
    let mut files_22000 = 0u64;
    let mut empty_files = 0u64;
    let mut partial_named = 0u64;
    let mut pmkid = 0u64;
    let mut eapol = 0u64;
    let mut seen_mic: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut by_essid: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();

    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if !name.to_ascii_lowercase().ends_with(".22000") {
            continue;
        }
        files_22000 += 1;
        if name.contains("_partial") {
            partial_named += 1;
        }
        let text = fs::read_to_string(ent.path()).unwrap_or_default();
        let mut lines = 0u64;
        for line in text.lines() {
            let f: Vec<&str> = line.split('*').collect();
            if f.len() < 6 || f[0] != "WPA" {
                continue;
            }
            lines += 1;
            match f[1] {
                "01" => pmkid += 1,
                "02" => eapol += 1,
                _ => {}
            }
            seen_mic.insert(f[2].to_string());
            let essid = hex_to_string(f[5]);
            *by_essid.entry(if essid.is_empty() { "<hidden>".into() } else { essid }).or_insert(0) += 1;
        }
        if lines == 0 {
            empty_files += 1;
        }
    }

    let essids: Vec<Value> = by_essid
        .into_iter()
        .map(|(essid, hashes)| json!({ "essid": essid, "hashes": hashes }))
        .collect();
    let out = json!({
        "dir": dir.display().to_string(),
        "capture_files_22000": files_22000,
        "files_with_no_crackable_material": empty_files,
        "files_named_partial": partial_named,
        "unique_handshakes": seen_mic.len(),
        "pmkid_hashlines": pmkid,
        "eapol_hashlines": eapol,
        "by_essid": essids,
        "note": "FULL = file yields >=1 hashline; empty .22000 = no crackable material. Dedup is by the 32-hex MIC/PMKID field.",
    });
    serde_json::to_string_pretty(&out).map_err(|e| e.to_string())
}

fn hex_to_string(hex: &str) -> String {
    if hex.is_empty() || hex.len() % 2 != 0 {
        return String::new();
    }
    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    bytes.map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// find_suspicious: heuristic scan across BT (blue5.db) and Wi-Fi (recon.db).
// Constants are the real signatures used by the reference payloads.
// ---------------------------------------------------------------------------

// Flipper Zero BT OUIs (payloads disagree; include both) + name "flipper".
const FLIPPER_OUIS: &[&str] = &["80E126", "0CFA22"];
// Flock Safety surveillance: high-confidence OUIs + BLE name patterns.
const FLOCK_OUIS: &[&str] = &[
    "70C94E", "3C9180", "D8F3BC", "083A88", "145AFC", // Falcon WiFi
    "588E81", "EC1BBD", "9035EA", "943469", "F082C0", // FS Ext Battery
    "744CA1", "803049", // Lite-On (Flock chipset) high-confidence pair
];
const FLOCK_NAMES: &[&str] = &["fs ext battery", "penguin", "pigvision", "flock"];
// Bluetooth skimmer module name patterns (SkimmerScanner).
const SKIMMER_NAMES: &[&str] = &[
    "hc-05", "hc-06", "bt04", "bt05", "jdy-08", "jdy-09", "jdy-10", "jdy-16",
    "jdy-17", "mlt-bt", "spp-c", "linvor", "rnbt-",
];

/// Build `OR`-joined `col LIKE 'PREFIX%'` fragments for a list of MAC prefixes.
fn like_prefixes(col: &str, prefixes: &[&str]) -> String {
    prefixes
        .iter()
        .map(|p| format!("{col} LIKE '{p}%'"))
        .collect::<Vec<_>>()
        .join(" OR ")
}
/// Build `OR`-joined `col LIKE '%SUB%'` fragments for substrings.
fn like_contains(col: &str, subs: &[&str]) -> String {
    subs.iter()
        .map(|s| format!("{col} LIKE '%{s}%'"))
        .collect::<Vec<_>>()
        .join(" OR ")
}

pub fn find_suspicious() -> Result<String, String> {
    let bt = bt_db();
    let rc = recon_db();
    let cur = "scan=(SELECT MAX(id) FROM scan)";
    let mac_t = "upper(CAST(mac AS TEXT))";
    let name_l = "lower(CAST(name AS TEXT))";

    // --- Bluetooth signals (blue5.db, current scan) ---
    let flipper = query_value(
        &bt,
        &format!(
            "SELECT CAST(mac AS TEXT) AS mac, CAST(name AS TEXT) AS name, rssi, \
               (strftime('%s','now')-last_seen) AS seen_s_ago \
             FROM bt_device WHERE {cur} AND (({}) OR {name_l} LIKE '%flipper%') ORDER BY rssi DESC",
            like_prefixes(mac_t, FLIPPER_OUIS)
        ),
    )
    .unwrap_or_else(|_| json!([]));

    let flock = query_value(
        &bt,
        &format!(
            "SELECT CAST(mac AS TEXT) AS mac, CAST(name AS TEXT) AS name, rssi, \
               (strftime('%s','now')-last_seen) AS seen_s_ago \
             FROM bt_device WHERE {cur} AND (({}) OR ({})) ORDER BY rssi DESC",
            like_prefixes(mac_t, FLOCK_OUIS),
            like_contains(name_l, FLOCK_NAMES)
        ),
    )
    .unwrap_or_else(|_| json!([]));

    let skimmer = query_value(
        &bt,
        &format!(
            "SELECT CAST(mac AS TEXT) AS mac, CAST(name AS TEXT) AS name, rssi, company, \
               (strftime('%s','now')-last_seen) AS seen_s_ago \
             FROM bt_device WHERE {cur} AND name IS NOT NULL AND ({}) ORDER BY rssi DESC",
            like_contains(name_l, SKIMMER_NAMES)
        ),
    )
    .unwrap_or_else(|_| json!([]));

    // --- Wi-Fi signals (recon.db) ---
    // SSID spoofing: one BSSID advertising many distinct SSIDs (>=5 spoofer, 2-4 suspicious).
    let spoofing = query_value(
        &rc,
        "SELECT CAST(d.mac AS TEXT) AS bssid, COUNT(DISTINCT CAST(s.ssid AS TEXT)) AS ssid_count, \
           GROUP_CONCAT(DISTINCT CAST(s.ssid AS TEXT)) AS ssids, \
           CASE WHEN COUNT(DISTINCT CAST(s.ssid AS TEXT))>=5 THEN 'spoofing' ELSE 'suspicious' END AS verdict \
         FROM ssid s JOIN wifi_device d ON s.wifi_device=d.hash \
         WHERE s.type=8 AND length(s.ssid)>0 GROUP BY d.mac \
         HAVING COUNT(DISTINCT CAST(s.ssid AS TEXT))>=2 ORDER BY ssid_count DESC",
    )
    .unwrap_or_else(|_| json!([]));

    // Rogue Pineapple/Pager: beacon SSIDs containing 'pineapple' or 'pager'.
    let rogue = query_value(
        &rc,
        "SELECT DISTINCT CAST(s.ssid AS TEXT) AS ssid, CAST(d.mac AS TEXT) AS bssid, s.channel \
         FROM ssid s JOIN wifi_device d ON s.wifi_device=d.hash \
         WHERE s.type=8 AND (lower(CAST(s.ssid AS TEXT)) LIKE '%pineapple%' \
           OR lower(CAST(s.ssid AS TEXT)) LIKE '%pager%') ORDER BY ssid",
    )
    .unwrap_or_else(|_| json!([]));

    let count = |v: &Value| v.as_array().map(|a| a.len()).unwrap_or(0);
    let out = json!({
        "bluetooth": {
            "flipper_zero": flipper,
            "flock_safety": flock,
            "bt_skimmer_modules": skimmer,
        },
        "wifi": {
            "ssid_spoofing": spoofing,
            "rogue_pineapple_pager": rogue,
        },
        "summary": {
            "flipper": count(&flipper),
            "flock": count(&flock),
            "skimmer": count(&skimmer),
            "spoofing": count(&spoofing),
            "rogue": count(&rogue),
        },
        "note": "Heuristic signatures from Hak5 community payloads; corroborate before acting. BT from blue5 current scan; Wi-Fi from recon.db.",
    });
    serde_json::to_string_pretty(&out).map_err(|e| e.to_string())
}
