//! Queries against the recon daemon's SQLite database (`pineapd` writes it).
//!
//! Schema essentials:
//!   wifi_device(hash, mac, time, signal, freq, packets)
//!   ssid(hash, wifi_device, type, bssid, ssid BLOB, hidden, time, signal,
//!        freq, channel, encryption)   -- type 8=beacon(AP) 4=probe 5=response
//!   handshake(hash, stahash, aphash, time, hs1..hs4)
//!
//! All dynamic SQL parameters are integers or enum-selected keywords; the only
//! free-form value (a BSSID) is validated to hex and normalized, so these
//! read-only queries have no injection surface. Output uses sqlite's `-json`.

use crate::device;
use serde_json::Value;

fn db_path() -> String {
    std::env::var("MCP_RECON_DB").unwrap_or_else(|_| "/root/recon/recon.db".to_string())
}

/// Run a read-only query and return sqlite's JSON text (always valid JSON).
/// `.timeout` is a dot-command (no output) so it can't pollute the JSON.
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
    serde_json::from_str(&json).map_err(|e| format!("recon query parse error: {e}"))
}

/// SQL `band` filter fragment for a freq column, or empty string.
fn band_clause(col: &str, band: Option<&str>) -> Result<String, String> {
    Ok(match band {
        None => String::new(),
        Some("2.4") => format!(" AND {col}<2500"),
        Some("5") => format!(" AND {col}>=4900 AND {col}<5925"),
        Some("6") => format!(" AND {col}>=5925"),
        Some(other) => return Err(format!("band must be 2.4, 5 or 6 (got {other})")),
    })
}

const BAND_EXPR: &str =
    "CASE WHEN freq<2500 THEN '2.4' WHEN freq<5925 THEN '5' ELSE '6' END";

/// Build the shared ` AND ...` filter fragments for the given column names.
fn filters(
    time_col: &str,
    freq_col: &str,
    signal_col: &str,
    max_age_s: i64,
    band: Option<&str>,
    min_signal: Option<i64>,
) -> Result<String, String> {
    let mut f = String::new();
    if max_age_s > 0 {
        f.push_str(&format!(" AND {time_col} > strftime('%s','now')-{max_age_s}"));
    }
    f.push_str(&band_clause(freq_col, band)?);
    if let Some(m) = min_signal {
        f.push_str(&format!(" AND {signal_col} >= {m}"));
    }
    Ok(f)
}

/// `recon_list` backend. `kind` is "aps" or "clients".
pub fn list(
    kind: &str,
    max_age_s: i64,
    band: Option<&str>,
    min_signal: Option<i64>,
    limit: i64,
) -> Result<String, String> {
    let limit = limit.clamp(1, 1000);
    match kind {
        "aps" => {
            let f = filters("time", "freq", "signal", max_age_s, band, min_signal)?;
            let sql = format!(
                "SELECT COALESCE(NULLIF(CAST(ssid AS TEXT),''),'<hidden>') AS ssid, \
                   bssid, channel, {BAND_EXPR} AS band, MAX(signal) AS signal, \
                   CASE encryption WHEN 0 THEN 'open' ELSE 'wpa' END AS security, \
                   encryption AS enc_code, (strftime('%s','now')-MAX(time)) AS seen_s_ago \
                 FROM ssid WHERE type=8 AND bssid<>''{f} \
                 GROUP BY bssid, ssid ORDER BY signal DESC LIMIT {limit}"
            );
            query_json(&sql)
        }
        "clients" => {
            // A client is a device that never beacons an SSID of its own.
            let f = filters("w.time", "w.freq", "w.signal", max_age_s, band, min_signal)?;
            let band_expr =
                "CASE WHEN w.freq<2500 THEN '2.4' WHEN w.freq<5925 THEN '5' ELSE '6' END";
            let sql = format!(
                "SELECT w.mac AS mac, {band_expr} AS band, w.signal AS signal, \
                   w.packets AS packets, (strftime('%s','now')-w.time) AS seen_s_ago, \
                   (SELECT group_concat(DISTINCT CAST(s.ssid AS TEXT)) FROM ssid s \
                      WHERE s.wifi_device=w.hash AND s.type=4 AND CAST(s.ssid AS TEXT)<>'') \
                      AS probing_for \
                 FROM wifi_device w \
                 WHERE w.hash NOT IN (SELECT wifi_device FROM ssid WHERE type=8){f} \
                 ORDER BY w.signal DESC LIMIT {limit}"
            );
            query_json(&sql)
        }
        other => Err(format!("kind must be 'aps' or 'clients' (got {other})")),
    }
}

/// `handshakes` backend: captured WPA handshakes, newest first. `since_s>0`
/// limits to recently captured ones (for new-handshake polling).
pub fn handshakes(since_s: i64, limit: i64) -> Result<String, String> {
    let limit = limit.clamp(1, 1000);
    let since = if since_s > 0 {
        format!(" WHERE h.time > strftime('%s','now')-{since_s}")
    } else {
        String::new()
    };
    let sql = format!(
        "SELECT (SELECT COALESCE(NULLIF(CAST(ssid AS TEXT),''),'<hidden>') FROM ssid \
                   WHERE wifi_device=h.aphash AND type=8 LIMIT 1) AS ssid, \
           ap.mac AS ap_bssid, sta.mac AS client, \
           datetime(h.time,'unixepoch','localtime') AS captured, \
           (strftime('%s','now')-h.time) AS age_s, \
           ((h.hs1 IS NOT NULL)+(h.hs2 IS NOT NULL)+(h.hs3 IS NOT NULL)+(h.hs4 IS NOT NULL)) AS eapol_frames \
         FROM handshake h \
         LEFT JOIN wifi_device ap ON ap.hash=h.aphash \
         LEFT JOIN wifi_device sta ON sta.hash=h.stahash{since} \
         ORDER BY h.time DESC LIMIT {limit}",
        since = since,
    );
    query_json(&sql)
}

/// `recon_ap_detail` backend: everything known about one BSSID.
pub fn ap_detail(bssid: &str) -> Result<String, String> {
    let b = bssid.replace([':', '-'], "").to_uppercase();
    // NOTE: pineapd stores bssid/mac as BLOBs (TEXT affinity), so a plain
    // `col = 'text'` never matches in SQLite — compare CAST(col AS TEXT).
    let ssids = query_value(&format!(
        "SELECT COALESCE(NULLIF(CAST(ssid AS TEXT),''),'<hidden>') AS ssid, hidden, \
           channel, {BAND_EXPR} AS band, signal, \
           CASE encryption WHEN 0 THEN 'open' ELSE 'wpa' END AS security, \
           encryption AS enc_code, (strftime('%s','now')-time) AS seen_s_ago \
         FROM ssid WHERE type=8 AND CAST(bssid AS TEXT)='{b}' ORDER BY time DESC"
    ))?;
    if ssids.as_array().map(|a| a.is_empty()).unwrap_or(true) {
        return Err(format!("no beaconing AP with BSSID {b} in recon.db"));
    }
    let device = query_value(&format!(
        "SELECT CAST(mac AS TEXT) AS mac, signal, packets, (strftime('%s','now')-time) AS seen_s_ago \
         FROM wifi_device WHERE CAST(mac AS TEXT)='{b}' LIMIT 1"
    ))?;
    // Stations seen handshaking with this AP (the only reliable association).
    let clients = query_value(&format!(
        "SELECT CAST(sta.mac AS TEXT) AS client, datetime(MAX(h.time),'unixepoch','localtime') AS last_seen \
         FROM handshake h JOIN wifi_device ap ON ap.hash=h.aphash \
           JOIN wifi_device sta ON sta.hash=h.stahash \
         WHERE CAST(ap.mac AS TEXT)='{b}' GROUP BY sta.mac ORDER BY MAX(h.time) DESC"
    ))?;
    let handshakes = query_value(&format!(
        "SELECT CAST(sta.mac AS TEXT) AS client, datetime(h.time,'unixepoch','localtime') AS captured, \
           ((h.hs1 IS NOT NULL)+(h.hs2 IS NOT NULL)+(h.hs3 IS NOT NULL)+(h.hs4 IS NOT NULL)) AS eapol_frames \
         FROM handshake h JOIN wifi_device ap ON ap.hash=h.aphash \
           LEFT JOIN wifi_device sta ON sta.hash=h.stahash \
         WHERE CAST(ap.mac AS TEXT)='{b}' ORDER BY h.time DESC"
    ))?;
    let detail = serde_json::json!({
        "bssid": b,
        "device": device.as_array().and_then(|a| a.first()).cloned().unwrap_or(Value::Null),
        "ssids": ssids,
        "associated_clients": clients,
        "handshakes": handshakes,
    });
    serde_json::to_string_pretty(&detail).map_err(|e| e.to_string())
}
