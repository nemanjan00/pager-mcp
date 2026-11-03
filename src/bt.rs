//! Queries against the Bluetooth recon database written by `blue5` (Pager 2.0's
//! BLE + Classic scanner). The daemon runs as `blue5 -D -S /tmp/blue5_sock ...
//! -d /root/recon/` and logs devices to `blue5.db`; its control client is
//! `blue5ctl` (used from tools.rs for status/scan tuning), while live status and
//! control go over the socket.
//!
//! Schema essentials (one row per device per scan):
//!   scan(id, uuid, time, name)
//!   bt_device(scan, mac, first_seen, last_seen, transports, le_random,
//!             connectable, rssi, rssi_min, rssi_max, rssi_avg, tx_power,
//!             company, cod, packets, name BLOB, name_complete, ad_flags,
//!             appearance, svc16 TEXT, svc_other, mfr BLOB, svcd BLOB)
//!     transports: 1=LE, 2=Classic(BR/EDR), 3=dual.  name is UTF-8 bytes.
//!     company is a Bluetooth SIG company identifier.
//!
//! Every dynamic SQL value is an integer or an enum-selected keyword; the only
//! free-form input (a MAC, in `detail`) is validated to hex and upper-cased, so
//! these read-only queries have no injection surface. Output is sqlite `-json`.

use crate::device;
use serde_json::{Map, Value};

fn db_path() -> String {
    std::env::var("MCP_BT_DB").unwrap_or_else(|_| "/root/recon/blue5.db".to_string())
}

/// Run a read-only query and return sqlite's JSON text (always valid JSON).
fn query_json(sql: &str) -> Result<String, String> {
    let out = device::run_cmd(
        "sqlite3",
        &[
            "-json".to_string(),
            "-cmd".to_string(),
            ".timeout 3000".to_string(),
            db_path(),
            sql.to_string(),
        ],
    )?;
    let t = out.trim();
    Ok(if t.is_empty() || t == "(ok)" { "[]".to_string() } else { t.to_string() })
}

fn query_value(sql: &str) -> Result<Value, String> {
    let json = query_json(sql)?;
    serde_json::from_str(&json).map_err(|e| format!("bt query parse error: {e}"))
}

/// Resolve the most common Bluetooth SIG company identifiers to a vendor name.
/// Unknown IDs are left to the caller (the hex id is always included too).
fn company_name(id: i64) -> Option<&'static str> {
    Some(match id {
        0x0000 => "Ericsson",
        0x0001 => "Nokia",
        0x0002 => "Intel",
        0x0003 => "IBM",
        0x0006 => "Microsoft",
        0x000F => "Broadcom",
        0x004C => "Apple",
        0x0059 => "Nordic Semiconductor",
        0x0075 => "Samsung Electronics",
        0x0087 => "Garmin",
        0x00D7 => "Qualcomm",
        0x00E0 => "Google",
        0x0171 => "Amazon",
        0x038F => "Xiaomi",
        _ => return None,
    })
}

/// SQL `scan` selector for the current (latest) scan session.
const CURRENT_SCAN: &str = "scan=(SELECT MAX(id) FROM scan)";

/// Shared SELECT column list for a device row (list and detail share most of it).
const ROW_COLS: &str = "mac, \
    CASE transports WHEN 1 THEN 'LE' WHEN 2 THEN 'Classic' WHEN 3 THEN 'dual' \
        ELSE CAST(transports AS TEXT) END AS type, \
    le_random, connectable, \
    COALESCE(NULLIF(CAST(name AS TEXT),''), NULL) AS name, \
    company AS company_id, \
    rssi, rssi_avg, rssi_min, rssi_max, tx_power, packets, \
    svc16, \
    datetime(first_seen,'unixepoch','localtime') AS first_seen, \
    datetime(last_seen,'unixepoch','localtime') AS last_seen, \
    (strftime('%s','now')-last_seen) AS seen_s_ago";

/// Add the resolved `company` (hex + name) fields to one device row in place.
fn enrich(row: &mut Value) {
    if let Some(obj) = row.as_object_mut() {
        if let Some(id) = obj.get("company_id").and_then(Value::as_i64) {
            obj.insert("company_hex".into(), Value::String(format!("0x{id:04X}")));
            if let Some(name) = company_name(id) {
                obj.insert("company".into(), Value::String(name.to_string()));
            }
        }
    }
}

/// `bt_list` backend: survey Bluetooth devices from the current scan.
#[allow(clippy::too_many_arguments)]
pub fn list(
    type_filter: Option<&str>,
    max_age_s: i64,
    min_rssi: Option<i64>,
    named_only: bool,
    connectable_only: bool,
    company: Option<i64>,
    no_random: bool,
    limit: i64,
) -> Result<String, String> {
    let limit = limit.clamp(1, 1000);
    let mut f = String::new();
    if max_age_s > 0 {
        f.push_str(&format!(" AND last_seen > strftime('%s','now')-{max_age_s}"));
    }
    match type_filter {
        None => {}
        Some("le") => f.push_str(" AND transports=1"),
        Some("classic") => f.push_str(" AND transports=2"),
        Some("dual") => f.push_str(" AND transports=3"),
        Some(other) => return Err(format!("type must be le, classic or dual (got {other})")),
    }
    if let Some(m) = min_rssi {
        f.push_str(&format!(" AND rssi_avg >= {m}"));
    }
    if named_only {
        f.push_str(" AND name IS NOT NULL AND length(name)>0");
    }
    if connectable_only {
        f.push_str(" AND connectable=1");
    }
    if no_random {
        f.push_str(" AND le_random=0");
    }
    if let Some(c) = company {
        f.push_str(&format!(" AND company={c}"));
    }
    let sql = format!(
        "SELECT {ROW_COLS} FROM bt_device WHERE {CURRENT_SCAN}{f} \
         ORDER BY rssi_avg DESC LIMIT {limit}"
    );
    let mut rows = query_value(&sql)?;
    if let Some(arr) = rows.as_array_mut() {
        for row in arr.iter_mut() {
            enrich(row);
        }
    }
    serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())
}

/// `bt_device_detail` backend: the full record for one MAC in the current scan,
/// including Class-of-Device, appearance, advertised services and raw
/// manufacturer/service data (hex).
pub fn detail(mac: &str) -> Result<String, String> {
    let m = mac.replace([':', '-'], "").to_uppercase();
    let sql = format!(
        "SELECT {ROW_COLS}, name_complete, cod, appearance, svc_other, ad_flags, \
           hex(mfr) AS mfr_hex, hex(svcd) AS svcd_hex \
         FROM bt_device WHERE {CURRENT_SCAN} AND mac='{m}' LIMIT 1"
    );
    let val = query_value(&sql)?;
    let mut row = match val.as_array().and_then(|a| a.first()).cloned() {
        Some(r) => r,
        None => return Err(format!("no Bluetooth device with MAC {m} in the current scan")),
    };
    enrich(&mut row);
    // Fold the current scan's name/id in for context.
    if let Some(obj) = row.as_object_mut() {
        if let Ok(Value::Array(scan)) =
            query_value("SELECT id, name, datetime(time,'unixepoch','localtime') AS started \
                         FROM scan ORDER BY id DESC LIMIT 1")
        {
            if let Some(s) = scan.into_iter().next() {
                obj.insert("scan".into(), s);
            }
        }
    }
    let mut out = Map::new();
    out.insert("device".into(), row);
    serde_json::to_string_pretty(&Value::Object(out)).map_err(|e| e.to_string())
}
