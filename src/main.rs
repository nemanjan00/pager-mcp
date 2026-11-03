//! mcp-pager: a Model Context Protocol (MCP) server for the Hak5 WiFi Pineapple
//! Pager.
//!
//! It exposes the Pager's Wi-Fi and Bluetooth recon data, loot and controls as
//! MCP tools so an operator's LLM client can drive an engagement. Messages are
//! newline-delimited JSON-RPC 2.0 over the MCP **stdio** transport: run it over
//! SSH directly, e.g. an MCP client whose command is
//! `ssh root@<pager> /root/mcp-pager`. SSH is the transport and the trust
//! boundary — anyone who can launch this already has a root shell on the device.
//!
//! On the Pager, DuckyScript/`PINEAPPLE_*` commands are real binaries in PATH, so
//! tools execute them directly — the server is self-contained and needs no shell
//! bridge.

mod bt;
mod device;
mod intel;
mod recon;
mod tools;

use serde_json::{json, Value};
use std::io::{BufRead, Write};

const SERVER_NAME: &str = "mcp-pager";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_PROTOCOL: &str = "2024-11-05";

fn main() {
    for a in std::env::args().skip(1) {
        match a.as_str() {
            "--version" | "-V" => {
                println!("{SERVER_NAME} {SERVER_VERSION}");
                return;
            }
            "--help" | "-h" => {
                eprintln!("usage: mcp-pager\nSpeaks the MCP stdio transport; run it over SSH.");
                return;
            }
            other => eprintln!("mcp-pager: ignoring unknown argument: {other}"),
        }
    }

    let server = tools::Server::from_env();
    run_stdio(&server);
}

fn run_stdio(server: &tools::Server) {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        if let Some(resp) = handle_line(server, &line) {
            let _ = writeln!(stdout, "{resp}");
            let _ = stdout.flush();
        }
    }
}

/// Parse and dispatch one JSON-RPC line. Returns the serialized response, or
/// `None` for notifications (which get no reply).
fn handle_line(server: &tools::Server, line: &str) -> Option<String> {
    let msg: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return Some(err(Value::Null, -32700, "parse error")),
    };

    let id = msg.get("id").cloned();
    let method = match msg.get("method").and_then(Value::as_str) {
        Some(m) => m,
        None => {
            // A response/garbage with no method: only answer if it carried an id.
            return id.filter(|v| !v.is_null()).map(|id| err(id, -32600, "invalid request"));
        }
    };

    // Notifications (including notifications/initialized) carry no id; do nothing.
    let is_notification = id.is_none();

    match method {
        "initialize" => {
            let params = msg.get("params").cloned().unwrap_or(Value::Null);
            let protocol = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_PROTOCOL)
                .to_string();
            let result = json!({
                "protocolVersion": protocol,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
                "instructions": "Tools for the Hak5 WiFi Pineapple Pager: Wi-Fi and Bluetooth (blue5) recon, loot, device control (bash/duckyscript), deauth and filter management. Reached over SSH; use responsibly on authorized engagements only."
            });
            id.map(|id| ok(id, result))
        }
        "ping" => id.map(|id| ok(id, json!({}))),
        _ if method.starts_with("notifications/") => None,
        other => {
            if is_notification {
                return None;
            }
            match other {
                "tools/list" => id.map(|id| ok(id, json!({ "tools": server.tool_list() }))),
                "tools/call" => {
                    let params = msg.get("params").cloned().unwrap_or(Value::Null);
                    let name = match params.get("name").and_then(Value::as_str) {
                        Some(n) => n,
                        None => return id.map(|id| err(id, -32602, "missing params.name")),
                    };
                    let empty = json!({});
                    let arguments = params.get("arguments").unwrap_or(&empty);
                    let result = match server.call_tool(name, arguments) {
                        Ok(text) => json!({
                            "content": [ { "type": "text", "text": text } ],
                            "isError": false
                        }),
                        Err(e) => json!({
                            "content": [ { "type": "text", "text": e } ],
                            "isError": true
                        }),
                    };
                    id.map(|id| ok(id, result))
                }
                _ => id.map(|id| err(id, -32601, "method not found")),
            }
        }
    }
}

fn ok(id: Value, result: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

fn err(id: Value, code: i64, message: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}
