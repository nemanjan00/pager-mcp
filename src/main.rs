//! mcp-pager: a Model Context Protocol (MCP) server for the Hak5 WiFi Pineapple
//! Pager.
//!
//! It exposes the Pager's recon data, loot and (authorized) controls as MCP
//! tools so an operator's LLM client can drive an engagement. Messages are
//! newline-delimited JSON-RPC 2.0, per the MCP stdio transport.
//!
//! Transports:
//!   * stdio (default)         - run it over SSH directly, e.g. an MCP client
//!                               whose command is `ssh root@<pager> .../mcp-pager`.
//!                               Also how `payload.sh` launches it.
//!   * --tcp <addr>            - optional listener (e.g. 127.0.0.1:8099). When
//!                               MCP_TCP_TOKEN is set, clients must present it as
//!                               `_auth` in `initialize` params. Bind to loopback
//!                               and reach it over an SSH tunnel; do not expose it.
//!
//! On the Pager, DuckyScript/`PINEAPPLE_*` commands are real binaries in PATH, so
//! tools execute them directly — the server is self-contained and needs no shell
//! bridge.

mod device;
mod recon;
mod tools;

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Arc;

const SERVER_NAME: &str = "mcp-pager";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_PROTOCOL: &str = "2024-11-05";

fn main() {
    let mut tcp_addr: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--tcp" => tcp_addr = args.next(),
            "--version" | "-V" => {
                println!("{SERVER_NAME} {SERVER_VERSION}");
                return;
            }
            "--help" | "-h" => {
                eprintln!("usage: mcp-pager [--tcp ADDR]\nDefaults to the MCP stdio transport.");
                return;
            }
            other => {
                eprintln!("mcp-pager: ignoring unknown argument: {other}");
            }
        }
    }

    let server = Arc::new(tools::Server::from_env());
    let token = std::env::var("MCP_TCP_TOKEN").ok().filter(|t| !t.is_empty());

    match tcp_addr {
        Some(addr) => run_tcp(server, &addr, token),
        None => run_stdio(server, token),
    }
}

/// Per-connection session state.
struct Session {
    authed: bool,
}

fn run_stdio(server: Arc<tools::Server>, token: Option<String>) {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    // Without a token, stdio is implicitly trusted (it is a local child process).
    let mut sess = Session { authed: token.is_none() };
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        if let Some(resp) = handle_line(&server, &line, &mut sess, token.as_deref()) {
            let _ = writeln!(stdout, "{resp}");
            let _ = stdout.flush();
        }
    }
}

fn run_tcp(server: Arc<tools::Server>, addr: &str, token: Option<String>) {
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("mcp-pager: cannot bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("mcp-pager: listening on {addr}");
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let server = Arc::clone(&server);
        let token = token.clone();
        std::thread::spawn(move || {
            let mut writer = match stream.try_clone() {
                Ok(w) => w,
                Err(_) => return,
            };
            let reader = BufReader::new(stream);
            let mut sess = Session { authed: token.is_none() };
            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                if line.trim().is_empty() {
                    continue;
                }
                if let Some(resp) = handle_line(&server, &line, &mut sess, token.as_deref()) {
                    if writeln!(writer, "{resp}").is_err() {
                        break;
                    }
                    let _ = writer.flush();
                }
            }
        });
    }
}

/// Parse and dispatch one JSON-RPC line. Returns the serialized response, or
/// `None` for notifications (which get no reply).
fn handle_line(
    server: &tools::Server,
    line: &str,
    sess: &mut Session,
    token: Option<&str>,
) -> Option<String> {
    let msg: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return Some(err_str(Value::Null, -32700, "parse error")),
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
            if let Some(tok) = token {
                if !sess.authed {
                    let supplied = params.get("_auth").and_then(Value::as_str);
                    if supplied != Some(tok) {
                        return id.map(|id| err(id, -32001, "unauthorized: bad or missing _auth"));
                    }
                    sess.authed = true;
                }
            }
            let protocol = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_PROTOCOL)
                .to_string();
            let result = json!({
                "protocolVersion": protocol,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
                "instructions": "Tools for the Hak5 WiFi Pineapple Pager. Read-only recon/loot tools are always available; traffic-affecting tools appear only when the operator enabled them for an authorized engagement."
            });
            id.map(|id| ok(id, result))
        }
        "ping" => id.map(|id| ok(id, json!({}))),
        _ if method.starts_with("notifications/") => None,
        other => {
            if is_notification {
                return None;
            }
            // Enforce auth for everything past initialize when a token is set.
            if token.is_some() && !sess.authed {
                return id.map(|id| err(id, -32001, "unauthorized: call initialize with _auth first"));
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

fn err_str(id: Value, code: i64, message: &str) -> String {
    err(id, code, message)
}
