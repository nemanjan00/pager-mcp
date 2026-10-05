//! Direct device access: reading recon environment variables, inspecting the
//! loot directory, and running device commands (POSIX tools plus the Pager's
//! DuckyScript/PINEAPPLE_* binaries) via std::process::Command.

use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

/// Snapshot of the `_RECON_SELECTED_*` environment captured at process start.
/// Recon payloads receive these when launched against a selected AP/client.
pub fn recon_context() -> serde_json::Value {
    let mut ap = serde_json::Map::new();
    let mut client = serde_json::Map::new();
    for (key, val) in std::env::vars() {
        if let Some(rest) = key.strip_prefix("_RECON_SELECTED_AP_") {
            ap.insert(rest.to_lowercase(), serde_json::Value::String(val));
        } else if let Some(rest) = key.strip_prefix("_RECON_SELECTED_CLIENT_") {
            client.insert(rest.to_lowercase(), serde_json::Value::String(val));
        }
    }
    serde_json::json!({
        "has_ap": !ap.is_empty(),
        "has_client": !client.is_empty(),
        "ap": ap,
        "client": client,
        "payload_home": std::env::var("PAYLOAD_HOME").unwrap_or_default(),
    })
}

/// Run a plain system command, capturing combined stdout/stderr. Used only for
/// well-known read-only POSIX tools, never for arbitrary caller-supplied input.
fn run(cmd: &str, args: &[&str]) -> String {
    match Command::new(cmd).args(args).output() {
        Ok(out) => {
            let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
            if !out.stderr.is_empty() {
                s.push_str(&String::from_utf8_lossy(&out.stderr));
            }
            if s.trim().is_empty() {
                "(no output)".to_string()
            } else {
                s.trim_end().to_string()
            }
        }
        Err(e) => format!("(unavailable: {e})"),
    }
}

/// Run an allowlisted device command (e.g. `LOG`, `PINEAPPLE_EXAMINE_RESET`)
/// directly. On the Pager these are real ELF binaries in PATH, so no shell is
/// needed. Returns combined stdout/stderr; `Err` carries the failure output.
pub fn run_cmd(program: &str, args: &[String]) -> Result<String, String> {
    match Command::new(program).args(args).output() {
        Ok(out) => {
            let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
            let errtext = String::from_utf8_lossy(&out.stderr);
            if !errtext.trim().is_empty() {
                if !s.is_empty() && !s.ends_with('\n') {
                    s.push('\n');
                }
                s.push_str(&errtext);
            }
            let s = s.trim_end().to_string();
            if out.status.success() {
                Ok(if s.is_empty() { "(ok)".to_string() } else { s })
            } else {
                let code = out
                    .status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".to_string());
                Err(if s.is_empty() {
                    format!("command failed (exit {code})")
                } else {
                    s
                })
            }
        }
        Err(e) => Err(format!("failed to run {program}: {e}")),
    }
}

/// Run an arbitrary shell command via `bash -c` (full-access `bash` tool).
pub fn run_bash(script: &str) -> Result<String, String> {
    run_cmd("bash", &["-c".to_string(), script.to_string()])
}

/// Human-readable system overview for the operator's LLM client.
pub fn system_info() -> String {
    let mut out = String::new();
    out.push_str("## kernel\n");
    out.push_str(&run("uname", &["-a"]));
    out.push_str("\n\n## uptime / load\n");
    out.push_str(&run("uptime", &[]));
    out.push_str("\n\n## storage (/root)\n");
    out.push_str(&run("df", &["-h", "/root"]));
    out.push_str("\n\n## memory\n");
    out.push_str(&run("free", &["-m"]));

    // Firmware/version markers vary by firmware; include whichever exists.
    for path in ["/etc/pineapple/version", "/etc/openwrt_release", "/proc/version"] {
        if let Ok(v) = fs::read_to_string(path) {
            out.push_str(&format!("\n\n## {path}\n{}", v.trim_end()));
        }
    }
    out
}

/// Resolve `subpath` safely inside `base`, rejecting any traversal outside it.
/// Returns an absolute, lexically-normalized path still rooted at `base`.
pub fn safe_join(base: &Path, subpath: &str) -> Result<PathBuf, String> {
    let mut resolved = base.to_path_buf();
    for comp in Path::new(subpath).components() {
        match comp {
            Component::Normal(c) => resolved.push(c),
            Component::CurDir => {}
            // Reject `..`, absolute roots, and Windows prefixes outright.
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err("path escapes the loot directory".to_string());
            }
        }
    }
    if !resolved.starts_with(base) {
        return Err("path escapes the loot directory".to_string());
    }
    Ok(resolved)
}

/// List entries under `base`/`subpath` (one level deep), with size and mtime.
pub fn list_loot(base: &Path, subpath: &str, max_entries: usize) -> Result<serde_json::Value, String> {
    let dir = safe_join(base, subpath)?;
    let meta = fs::metadata(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    let mut entries: Vec<serde_json::Value> = Vec::new();
    let mut truncated = false;
    let read = fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for item in read {
        let item = match item {
            Ok(i) => i,
            Err(_) => continue,
        };
        if entries.len() >= max_entries {
            truncated = true;
            break;
        }
        let name = item.file_name().to_string_lossy().into_owned();
        let md = item.metadata().ok();
        let is_dir = md.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let size = md.as_ref().map(|m| m.len()).unwrap_or(0);
        let mtime = md
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        entries.push(serde_json::json!({
            "name": name,
            "type": if is_dir { "dir" } else { "file" },
            "size": size,
            "mtime": mtime,
        }));
    }
    entries.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(serde_json::json!({
        "dir": dir.display().to_string(),
        "entries": entries,
        "truncated": truncated,
    }))
}

/// Read a (text) loot file, capped to `cap` bytes to protect the client context.
pub fn read_loot(base: &Path, subpath: &str, cap: usize) -> Result<serde_json::Value, String> {
    let file = safe_join(base, subpath)?;
    let meta = fs::metadata(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    if meta.is_dir() {
        return Err(format!("{} is a directory", file.display()));
    }
    let data = fs::read(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    let truncated = data.len() > cap;
    let slice = &data[..data.len().min(cap)];
    let text = String::from_utf8_lossy(slice).into_owned();
    Ok(serde_json::json!({
        "path": file.display().to_string(),
        "size": meta.len(),
        "truncated": truncated,
        "content": text,
    }))
}

/// Count captured handshake artifacts, optionally filtered by a client/AP MAC.
pub fn handshake_stats(base: &Path, mac: Option<&str>) -> serde_json::Value {
    let dir = base.join("handshakes");
    let needle = mac.map(|m| m.replace([':', '-'], "").to_uppercase());
    let mut counts = (0u64, 0u64, 0u64); // (.22000, .pcap, .pcapng)
    walk(&dir, &mut |p| {
        let name = p.file_name().map(|n| n.to_string_lossy().to_uppercase()).unwrap_or_default();
        if let Some(n) = &needle {
            if !name.replace([':', '-'], "").contains(n.as_str()) {
                return;
            }
        }
        if name.ends_with(".22000") {
            counts.0 += 1;
        } else if name.ends_with(".PCAPNG") {
            counts.2 += 1;
        } else if name.ends_with(".PCAP") {
            counts.1 += 1;
        }
    });
    serde_json::json!({
        "dir": dir.display().to_string(),
        "filter_mac": mac,
        "hashcat_22000": counts.0,
        "pcap": counts.1,
        "pcapng": counts.2,
    })
}

/// Depth-first walk invoking `f` on each regular file. Best-effort; ignores
/// unreadable entries rather than failing the whole call.
fn walk(dir: &Path, f: &mut dyn FnMut(&Path)) {
    let read = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for item in read.flatten() {
        let path = item.path();
        match item.file_type() {
            Ok(t) if t.is_dir() => walk(&path, f),
            Ok(t) if t.is_file() => f(&path),
            _ => {}
        }
    }
}
