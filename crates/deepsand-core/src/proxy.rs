//! The allowlisting egress proxy used by the `allowlisted` network mode.
//!
//! When a project is in allowlisted mode the container's own kernel rules allow it
//! to reach exactly one destination it did not name: this proxy. The proxy then
//! decides, per connection, whether the destination is on the operator's allowlist.
//!
//! Three properties matter:
//!
//! * **The allowlist is by hostname, and the proxy does the resolving.** The
//!   sandbox cannot influence name resolution.
//! * **Resolved addresses are checked too.** An allowlisted hostname that
//!   resolves into loopback, RFC1918, link-local or CGNAT space is refused, so
//!   a rebinding trick or a DNS entry pointed at the operator's router cannot
//!   turn an allowlisted domain into a path onto the local network.
//! * **Unless the operator named the address.** An entry that *is* an address
//!   literal is an instruction to reach that address, so it overrides the refusal
//!   above. That is how a database on the LAN, or a service on the operator's own
//!   machine, is expressed — and it is the only form that can be, because a hostname
//!   entry must keep failing closed against rebinding.
//!
//! The port is part of the decision: an entry that names one allows only that port,
//! and an entry that names none allows every port. See [`crate::allowlist`].
//!
//! A path prefix only binds where a path exists. Inside a `CONNECT` tunnel the
//! request is an opaque pipe, so a path-prefixed entry degrades to host-only —
//! documented in the allowlist module, and disclosed in the UI rather than implied.

use crate::allowlist::{Allowlist, Decision};
use crate::error::{Result, SandboxError};
use crate::model::BlockedEgress;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

/// Where the sandbox should be told the proxy lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
}

impl ProxyEndpoint {
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address to listen on. Use the project's bridge gateway so the proxy is
    /// reachable from the sandbox but not from the LAN.
    pub bind: IpAddr,
    /// Allowlist entries in the syntax understood by [`crate::allowlist`]:
    /// hostnames, `*.suffix`, `host/path/prefix`, `re:^…$`, and `!`-prefixed
    /// deny rules. Parsed at start and on every replacement, so a malformed entry
    /// is reported to the operator rather than silently skipped.
    pub allow: Vec<String>,
    /// Maximum bytes accepted for the request head.
    pub max_head_bytes: usize,
    /// How long the attempt on the other side may take: resolving the name, then
    /// connecting.
    ///
    /// Both stages were unbounded, and both hang on a real network in ways that look like a
    /// frozen app rather than a failure. `TcpStream::connect` with several resolved
    /// addresses waits out the kernel's SYN retry once per address, so an allowlisted host
    /// on a *filtered* port sat there for most of a minute per address; resolution is
    /// bounded only by the system resolver, which on a bad network is tens of seconds.
    ///
    /// The budget covers the attempt rather than each stage, because what has to be true is
    /// that the request comes back. Measured in this crate's own tests, four such requests
    /// took 168 seconds before and under one second after.
    pub upstream_timeout: Duration,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow: Vec::new(),
            max_head_bytes: 16 * 1024,
            upstream_timeout: Duration::from_secs(10),
        }
    }
}

pub struct EgressProxy {
    addr: SocketAddr,
    allow: Arc<RwLock<Allowlist>>,
    /// Entries that failed to parse, kept so the operator can be told which line
    /// of their allowlist is doing nothing.
    malformed: Arc<Mutex<Vec<String>>>,
    blocked: Arc<Mutex<Vec<BlockedEgress>>>,
    counters: Arc<Counters>,
    /// Taken exactly once, by `shutdown`. Behind a mutex so `shutdown` can take
    /// `&self` and proxies can therefore live behind an `Arc`.
    shutdown: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

#[derive(Debug, Default)]
pub struct Counters {
    pub accepted: AtomicU64,
    pub denied: AtomicU64,
    pub failed: AtomicU64,
}

#[derive(Debug, Clone, Default)]
pub struct ProxyStats {
    pub accepted: u64,
    pub denied: u64,
    pub failed: u64,
}

impl EgressProxy {
    /// Bind and start serving. Uses an ephemeral port so two projects never
    /// collide.
    pub async fn start(config: ProxyConfig) -> Result<Self> {
        let listener = TcpListener::bind(SocketAddr::new(config.bind, 0))
            .await
            .map_err(|err| {
                SandboxError::Broker(format!(
                    "the egress proxy could not bind to {}: {err}",
                    config.bind
                ))
            })?;
        let addr = listener.local_addr()?;

        let (parsed, malformed) = Allowlist::parse_lenient(&config.allow);
        for problem in &malformed {
            tracing::warn!("egress allowlist entry ignored: {problem}");
        }
        let allow = Arc::new(RwLock::new(parsed));
        let malformed = Arc::new(Mutex::new(malformed));
        let blocked = Arc::new(Mutex::new(Vec::new()));
        let counters = Arc::new(Counters::default());
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();

        let accept_allow = Arc::clone(&allow);
        let accept_malformed = Arc::clone(&malformed);
        let accept_blocked = Arc::clone(&blocked);
        let accept_counters = Arc::clone(&counters);
        let max_head = config.max_head_bytes;
        let upstream_timeout = config.upstream_timeout;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accepted = listener.accept() => {
                        let Ok((stream, peer)) = accepted else { break };
                        let allow = Arc::clone(&accept_allow);
                        let malformed = Arc::clone(&accept_malformed);
                        let blocked = Arc::clone(&accept_blocked);
                        let counters = Arc::clone(&accept_counters);
                        tokio::spawn(async move {
                            if let Err(err) = serve(
                                stream,
                                allow,
                                malformed,
                                blocked,
                                counters,
                                max_head,
                                upstream_timeout,
                            )
                            .await
                            {
                                tracing::debug!("egress proxy connection from {peer} ended: {err}");
                            }
                        });
                    }
                }
            }
        });

        Ok(Self {
            addr,
            allow,
            malformed,
            blocked,
            counters,
            shutdown: Mutex::new(Some(tx)),
        })
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The endpoint to advertise to the sandbox. `host` is normally the
    /// project's bridge gateway address.
    pub fn endpoint(&self, host: impl Into<String>) -> ProxyEndpoint {
        ProxyEndpoint { host: host.into(), port: self.addr.port() }
    }

    /// Replace the allowlist. Takes effect for the next connection, so an
    /// operator can fix a blocked host without restarting the sandbox.
    pub async fn set_allowlist(&self, allow: Vec<String>) {
        let (parsed, malformed) = Allowlist::parse_lenient(&allow);
        for problem in &malformed {
            tracing::warn!("egress allowlist entry ignored: {problem}");
        }
        if let Ok(mut slot) = self.malformed.lock() {
            *slot = malformed;
        }
        *self.allow.write().await = parsed;
    }

    /// The current allowlist, so a UI or the request broker can inspect it
    /// without holding the lock.
    pub async fn allowlist(&self) -> Allowlist {
        self.allow.read().await.clone()
    }

    /// Entries that did not parse, so the operator can be told which lines of
    /// their allowlist are doing nothing. Synchronous, like [`Self::blocked`].
    pub fn malformed_entries(&self) -> Vec<String> {
        self.malformed.lock().map(|m| m.clone()).unwrap_or_default()
    }

    /// Hosts the proxy refused, newest last, for the "add to allowlist" UI.
    pub fn blocked(&self) -> Vec<BlockedEgress> {
        self.blocked.lock().map(|b| b.clone()).unwrap_or_default()
    }

    pub fn clear_blocked(&self) {
        if let Ok(mut blocked) = self.blocked.lock() {
            blocked.clear();
        }
    }

    pub fn stats(&self) -> ProxyStats {
        ProxyStats {
            accepted: self.counters.accepted.load(Ordering::Relaxed),
            denied: self.counters.denied.load(Ordering::Relaxed),
            failed: self.counters.failed.load(Ordering::Relaxed),
        }
    }

    pub fn shutdown(&self) {
        let sender = self.shutdown.lock().map(|mut guard| guard.take()).unwrap_or(None);
        if let Some(tx) = sender {
            let _ = tx.send(());
        }
    }
}

impl Drop for EgressProxy {
    fn drop(&mut self) {
        let sender = self.shutdown.lock().map(|mut guard| guard.take()).unwrap_or(None);
        if let Some(tx) = sender {
            let _ = tx.send(());
        }
    }
}

async fn serve(
    mut client: TcpStream,
    allow: Arc<RwLock<Allowlist>>,
    malformed: Arc<Mutex<Vec<String>>>,
    blocked: Arc<Mutex<Vec<BlockedEgress>>>,
    counters: Arc<Counters>,
    max_head: usize,
    upstream_timeout: Duration,
) -> std::io::Result<()> {
    let head = match read_head(&mut client, max_head).await? {
        Some(head) => head,
        None => return Ok(()),
    };

    let request = match parse_request(&head) {
        Some(request) => request,
        None => {
            counters.failed.fetch_add(1, Ordering::Relaxed);
            write_status(&mut client, 400, "Bad Request", "Deepsand could not parse this request.").await?;
            return Ok(());
        }
    };

    // Inside a CONNECT tunnel there is no path: the client is asking for an
    // opaque pipe to host:port. Passing `None` is what lets a path-prefixed rule
    // degrade to host-only, instead of appearing to match a path nobody can see.
    let is_connect = request.method.eq_ignore_ascii_case("CONNECT");
    let path = if is_connect || request.path.is_empty() {
        None
    } else {
        Some(request.path.as_str())
    };

    let list = allow.read().await.clone();
    let decision = list.decide(&request.host, path, Some(request.port));

    if !decision.is_allowed() {
        counters.denied.fetch_add(1, Ordering::Relaxed);
        let reason = match &decision {
            Decision::Denied { rule } => format!("denied by the rule '{rule}'"),
            _ => "not on the Deepsand egress allowlist, and the default is to deny".to_string(),
        };
        record_blocked(&blocked, &request, &reason);

        // If part of the operator's allowlist is unparseable, say so here rather
        // than letting them wonder why the entry they just added did nothing.
        let problems = malformed.lock().map(|m| m.clone()).unwrap_or_default();
        let note = if problems.is_empty() {
            String::new()
        } else {
            format!(
                "\n\nDeepsand also ignored {} allowlist entr{} that could not be parsed: {}",
                problems.len(),
                if problems.len() == 1 { "y" } else { "ies" },
                problems.join("; ")
            )
        };

        // Name the host and path, and say which of the two refusal reasons
        // applies. Somebody reading this in a package-manager trace needs to know
        // whether a rule refused them or whether nothing matched at all.
        let target = match path {
            Some(path) => format!("{}{}", request.host, path),
            None => request.host.clone(),
        };
        let detail = match &decision {
            Decision::Denied { rule } => {
                format!("Deepsand's egress allowlist denies '{target}' by the rule '{rule}'")
            }
            _ => format!(
                "'{target}' is not on the Deepsand egress allowlist, and the default is to deny"
            ),
        };

        write_status(
            &mut client,
            403,
            "Forbidden",
            &format!(
                "{detail}. Add it to the allowlist, or use the network-access request tool so the \
                 operator can approve it deliberately.{note}"
            ),
        )
        .await?;
        return Ok(());
    }
    // The request is permitted. The port was part of that decision, so there is no
    // separate port gate here any more: an entry that names a port allows only that
    // port, and one that names none allows any.
    //
    // Resolve ourselves, then refuse anything that lands on local or private address
    // space -- unless the operator named that address, in which case reaching it is
    // the entire point of the entry.
    let mut resolved = match tokio::time::timeout(
        upstream_timeout,
        tokio::net::lookup_host((request.host.as_str(), request.port)),
    )
    .await
    {
        Ok(Ok(addrs)) => addrs.collect::<Vec<_>>(),
        Ok(Err(err)) => {
            counters.failed.fetch_add(1, Ordering::Relaxed);
            write_status(
                &mut client,
                502,
                "Bad Gateway",
                &format!("Deepsand could not resolve '{}': {err}", request.host),
            )
            .await?;
            return Ok(());
        }
        Err(_elapsed) => {
            counters.failed.fetch_add(1, Ordering::Relaxed);
            write_status(
                &mut client,
                504,
                "Gateway Timeout",
                &format!(
                    "Deepsand could not resolve '{}' within {upstream_timeout:?}.",
                    request.host
                ),
            )
            .await?;
            return Ok(());
        }
    };

    // An explicit address entry overrides the refusal, but only for a request that
    // arrived *as* that address. A hostname that merely resolves there is still refused:
    // otherwise listing one literal would silently bless every allowlisted name that
    // resolves to it, which is the rebinding case the refusal exists for.
    let named: Vec<IpAddr> = if request.host.parse::<IpAddr>().is_ok() {
        list.explicit_addresses_for_port(request.port)
    } else {
        Vec::new()
    };
    let mut blocked_addresses: Vec<SocketAddr> = Vec::new();
    resolved.retain(|address| {
        if is_blocked_target(address.ip()) && !named.contains(&address.ip()) {
            blocked_addresses.push(*address);
            false
        } else {
            true
        }
    });

    if resolved.is_empty() {
        counters.denied.fetch_add(1, Ordering::Relaxed);
        let first_blocked = blocked_addresses.first().copied();
        let detail = first_blocked
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "no address".to_string());
        record_blocked(&blocked, &request, "resolves into local or private address space");
        // The suggestion has to be an entry the allowlist parser accepts, which for an
        // IPv6 address means brackets: a bare `::1:9` would be read as an address with
        // no port, so the advice would not work if it were followed.
        let suggestion = first_blocked
            .map(|a| entry_suggestion(a.ip(), request.port))
            .unwrap_or_else(|| format!("{detail}:{}", request.port));
        write_status(
            &mut client,
            403,
            "Forbidden",
            &format!(
                "Deepsand refused '{}': it resolves to {detail}, which is local or private address space. \
                 An allowlisted name is never allowed to become a route onto the operator's own network. \
                 If that address is what you meant, allowlist the address itself -- '{suggestion}' -- so \
                 the decision is explicit.",
                request.host
            ),
        )
        .await?;
        return Ok(());
    }

    let mut upstream = match tokio::time::timeout(
        upstream_timeout,
        TcpStream::connect(&resolved[..]),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            counters.failed.fetch_add(1, Ordering::Relaxed);
            write_status(
                &mut client,
                502,
                "Bad Gateway",
                &format!("Deepsand could not reach '{}': {err}", request.host),
            )
            .await?;
            return Ok(());
        }
        Err(_elapsed) => {
            counters.failed.fetch_add(1, Ordering::Relaxed);
            write_status(
                &mut client,
                504,
                "Gateway Timeout",
                &format!(
                    "Deepsand could not reach '{}' within {upstream_timeout:?}. The allowlist \
                     permits it, so the connection was attempted and nothing answered; a \
                     filtered port behaves this way.",
                    request.host
                ),
            )
            .await?;
            return Ok(());
        }
    };

    if request.kind == RequestKind::Connect {
        counters.accepted.fetch_add(1, Ordering::Relaxed);
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    } else {
        counters.accepted.fetch_add(1, Ordering::Relaxed);
        // Origin-form rewrite for plain HTTP proxying.
        let rewritten = format!("{} {}{} HTTP/1.1\r\n", request.method, request.path, "");
        upstream.write_all(rewritten.as_bytes()).await?;
        upstream.write_all(request.remaining_headers.as_bytes()).await?;
    }

    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    Connect,
    Absolute,
}

#[derive(Debug, Clone)]
struct ProxyRequest {
    kind: RequestKind,
    method: String,
    host: String,
    port: u16,
    path: String,
    remaining_headers: String,
}

/// Read up to the end of the request head.
async fn read_head(client: &mut TcpStream, max: usize) -> std::io::Result<Option<String>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = client.read(&mut chunk).await?;
        if read == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > max {
            return Ok(None);
        }
    }
    Ok(Some(String::from_utf8_lossy(&buf).to_string()))
}

fn parse_request(head: &str) -> Option<ProxyRequest> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();

    // Everything after the request line is forwarded verbatim.
    let remaining_headers = {
        let mut out = String::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            out.push_str(line);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out
    };

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_authority(&target, 443)?;
        return Some(ProxyRequest {
            kind: RequestKind::Connect,
            method,
            host,
            port,
            path: String::new(),
            remaining_headers,
        });
    }

    // Absolute-form: GET http://host:port/path HTTP/1.1
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(&target);
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = split_authority(authority, 80)?;

    Some(ProxyRequest {
        kind: RequestKind::Absolute,
        method,
        host,
        port,
        path: path.to_string(),
        remaining_headers,
    })
}

fn split_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }
    // Strip any userinfo; the proxy does not forward credentials.
    let hostport = authority.rsplit('@').next().unwrap_or(authority);

    let parsed = if let Some(rest) = hostport.strip_prefix('[') {
        // IPv6 literal
        let close = rest.find(']')?;
        let host = rest[..close].to_string();
        let port = rest[close + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        (host, port)
    } else {
        match hostport.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), port.parse().ok()?),
            None => (hostport.to_string(), default_port),
        }
    };

    if !is_plausible_host(&parsed.0) {
        return None;
    }
    Some(parsed)
}

/// Reject anything that is not plausibly a hostname or IP literal.
///
/// This exists so a malformed or hostile request head cannot smuggle a path, an
/// extra header line, or shell metacharacters into the value that is later
/// handed to name resolution and to the operator's allowlist.
fn is_plausible_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.starts_with('.') || host.contains("..") {
        return false;
    }
    // Labels use letters, digits and hyphens, plus the underscore seen in some
    // internal names; IPv6 literals additionally use colons.
    host.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// Render an address and port the way an allowlist entry is written.
///
/// Used in refusal messages, so the advice has to be something the parser accepts:
/// `127.0.0.1:9` for v4, `[::1]:9` for v6. A bare `::1:9` would be read as an address
/// with no port, and the operator would follow the suggestion and stay blocked.
fn entry_suggestion(address: IpAddr, port: u16) -> String {
    match address {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

fn record_blocked(blocked: &Arc<Mutex<Vec<BlockedEgress>>>, request: &ProxyRequest, reason: &str) {
    if let Ok(mut list) = blocked.lock() {
        if list.iter().any(|b| b.host == request.host && b.port == request.port) {
            return;
        }
        // Bounded: the sandbox controls how many distinct hosts it tries.
        if list.len() >= 200 {
            list.remove(0);
        }
        list.push(BlockedEgress {
            host: request.host.clone(),
            port: request.port,
            at_ms: crate::now_ms(),
            reason: reason.to_string(),
        });
    }
}

async fn write_status(client: &mut TcpStream, code: u16, reason: &str, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         X-Deepsand-Proxy: denied\r\n\r\n{}",
        body.len(),
        body
    );
    client.write_all(response.as_bytes()).await?;
    client.flush().await
}

/// Match a hostname against the allowlist, ignoring ports and paths.
///
/// Supported patterns: an exact host, `*.suffix` for any single-or-multi label
/// subdomain, an address literal, and `*` for everything.
///
/// The predicate form, for callers that only need a yes or no — "is this destination
/// reachable at all?" — and have neither a path nor a port to offer. A rule that names
/// a port counts, because the sandbox can reach that host.
///
/// The live connection path goes through [`Allowlist::decide`] instead, because it must
/// pass the port and the path and report which rule was responsible. This function is
/// strictly wider than that decision and must never be used to permit a connection.
pub fn host_allowed(host: &str, patterns: &[String]) -> bool {
    if normalise_host(host).is_empty() {
        return false;
    }
    Allowlist::parse_lenient(patterns).0.decide_host_only(host).is_allowed()
}

fn normalise_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Addresses that must never be reachable through the proxy, even via an
/// allowlisted name.
pub fn is_blocked_target(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_documentation()
                // CGNAT 100.64.0.0/10
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
                // 192.0.0.0/24 IETF protocol assignments
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
                // 198.18.0.0/15 benchmarking
                || (v4.octets()[0] == 198 && (18..20).contains(&v4.octets()[1]))
                // 240.0.0.0/4 reserved
                || v4.octets()[0] >= 240
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique local fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped: judge by the embedded v4 address
                || v6.to_ipv4_mapped().is_some_and(|v4| is_blocked_target(IpAddr::V4(v4)))
        }
    }
}

/// Convenience for callers that only have a string.
pub fn is_blocked_target_str(value: &str) -> bool {
    value.parse::<IpAddr>().map(is_blocked_target).unwrap_or(false)
}

/// Handle used by the desktop app to keep one proxy per running project.
pub struct ProxyHandle {
    pub proxy: tokio::sync::Mutex<Option<EgressProxy>>,
}

impl ProxyHandle {
    pub fn new() -> Self {
        Self { proxy: tokio::sync::Mutex::new(None) }
    }
}

impl Default for ProxyHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Bound the IPv6 helpers used above so the intent stays obvious.
#[allow(dead_code)]
fn _documented_v6_ranges(v6: Ipv6Addr) -> bool {
    let _ = v6;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterns(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn exact_hosts_match_and_others_do_not() {
        let allow = patterns(&["api.deepseek.com", "registry.npmjs.org"]);
        assert!(host_allowed("api.deepseek.com", &allow));
        assert!(host_allowed("API.DeepSeek.com", &allow));
        assert!(host_allowed("api.deepseek.com.", &allow));
        assert!(!host_allowed("evil.com", &allow));
        assert!(!host_allowed("api.deepseek.com.evil.com", &allow));
        assert!(!host_allowed("deepseek.com", &allow));
        assert!(!host_allowed("", &allow));
    }

    #[test]
    fn wildcard_matches_subdomains_but_not_the_apex() {
        let allow = patterns(&["*.github.com"]);
        assert!(host_allowed("gist.github.com", &allow));
        assert!(host_allowed("a.b.github.com", &allow));
        assert!(!host_allowed("github.com", &allow));
        assert!(!host_allowed("notgithub.com", &allow));
        assert!(!host_allowed("github.com.evil.net", &allow));
    }

    #[test]
    fn a_lone_star_allows_everything() {
        let allow = patterns(&["*"]);
        assert!(host_allowed("anything.example", &allow));
    }

    #[test]
    fn a_lookalike_suffix_is_not_accepted_as_a_prefix_match() {
        // Regression guard: naive `starts_with` logic would allow this.
        let allow = patterns(&["*.example.com"]);
        assert!(!host_allowed("notexample.com", &allow));
        assert!(!host_allowed("example.com.attacker.net", &allow));
    }

    /// The port is now part of the allowlist decision rather than a fixed 80/443 rule,
    /// so these assert the *refusal set* rather than a port whitelist. `is_blocked_target`
    /// is the remaining port-independent rule and is covered separately below.
    #[test]
    fn the_private_address_set_is_unchanged_by_the_port_work() {
        for blocked in ["127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "::1"] {
            assert!(is_blocked_target_str(blocked), "{blocked} must stay blocked by default");
        }
    }

    #[test]
    fn local_and_private_addresses_are_never_targets() {
        for blocked in [
            "127.0.0.1",
            "127.9.9.9",
            "0.0.0.0",
            "10.1.2.3",
            "172.16.0.1",
            "172.17.0.1",
            "172.28.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "198.18.0.1",
            "192.0.0.1",
            "240.0.0.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:192.168.0.1",
        ] {
            assert!(is_blocked_target_str(blocked), "{blocked} must be blocked");
        }
    }

    #[test]
    fn public_addresses_are_permitted() {
        for allowed in ["8.8.8.8", "1.1.1.1", "104.18.32.7", "2606:4700::1111", "::ffff:8.8.8.8"] {
            assert!(!is_blocked_target_str(allowed), "{allowed} must be allowed");
        }
    }

    #[test]
    fn request_parsing_handles_connect_and_absolute_forms() {
        let connect = parse_request("CONNECT api.deepseek.com:443 HTTP/1.1\r\nHost: api.deepseek.com\r\n\r\n").unwrap();
        assert_eq!(connect.kind, RequestKind::Connect);
        assert_eq!(connect.host, "api.deepseek.com");
        assert_eq!(connect.port, 443);

        let absolute = parse_request("GET http://registry.npmjs.org/left-pad HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(absolute.kind, RequestKind::Absolute);
        assert_eq!(absolute.host, "registry.npmjs.org");
        assert_eq!(absolute.port, 80);
        assert_eq!(absolute.path, "/left-pad");
        assert_eq!(absolute.method, "GET");
        assert!(absolute.remaining_headers.contains("Host: x"));

        let default_port = parse_request("CONNECT example.com HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(default_port.port, 443);

        // Userinfo is dropped rather than forwarded.
        let with_userinfo = parse_request("CONNECT user:pass@example.com:443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(with_userinfo.host, "example.com");

        // IPv6 literals.
        let v6 = parse_request("CONNECT [2606:4700::1111]:443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(v6.host, "2606:4700::1111");
        assert_eq!(v6.port, 443);

        assert!(parse_request("garbage").is_none());
    }

    #[test]
    fn implausible_authorities_are_rejected_before_resolution() {
        // A malformed head must not be able to put a path, a second request
        // line, or shell metacharacters into the value later handed to DNS.
        //
        // Note "CONNECT bad host:443" is deliberately absent: the request line
        // is whitespace-split, so that becomes the authority "bad", which is a
        // well-formed hostname that simply will not resolve. Refusing it here
        // would buy nothing.
        for hostile in [
            "CONNECT  HTTP/1.1\r\n\r\n",
            "CONNECT /etc/passwd:443 HTTP/1.1\r\n\r\n",
            "CONNECT ../../etc/passwd:443 HTTP/1.1\r\n\r\n",
            "CONNECT $(id):443 HTTP/1.1\r\n\r\n",
            "CONNECT .leading.dot:443 HTTP/1.1\r\n\r\n",
            "CONNECT double..dot:443 HTTP/1.1\r\n\r\n",
            "CONNECT :443 HTTP/1.1\r\n\r\n",
            "CONNECT host/../../x:443 HTTP/1.1\r\n\r\n",
        ] {
            assert!(parse_request(hostile).is_none(), "{hostile:?} must be refused");
        }

        // Ordinary names still parse.
        for fine in [
            "CONNECT api.deepseek.com:443 HTTP/1.1\r\n\r\n",
            "CONNECT registry.npmjs.org:443 HTTP/1.1\r\n\r\n",
            "CONNECT my_host.internal:443 HTTP/1.1\r\n\r\n",
            "CONNECT xn--fsq.com:443 HTTP/1.1\r\n\r\n",
        ] {
            assert!(parse_request(fine).is_some(), "{fine:?} must parse");
        }
    }

    #[test]
    fn an_overlong_host_is_rejected() {
        let long = format!("CONNECT {}.com:443 HTTP/1.1\r\n\r\n", "a".repeat(250));
        assert!(parse_request(&long).is_none());
        let ok = format!("CONNECT {}.com:443 HTTP/1.1\r\n\r\n", "a".repeat(60));
        assert!(parse_request(&ok).is_some());
    }

    #[tokio::test]
    async fn a_denied_host_gets_a_403_and_is_recorded_for_the_ui() {
        let proxy = EgressProxy::start(ProxyConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow: patterns(&["allowed.example"]),
            ..ProxyConfig::default()
        })
        .await
        .unwrap();

        let mut stream = TcpStream::connect(proxy.local_addr()).await.unwrap();
        stream
            .write_all(b"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 403"), "{text}");
        assert!(text.contains("egress allowlist"), "{text}");

        let blocked = proxy.blocked();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].host, "blocked.example");
        assert_eq!(proxy.stats().denied, 1);
        assert_eq!(proxy.stats().accepted, 0);
    }

    /// A hostname that resolves into private space is refused even when it is on the
    /// allowlist — and the *literal* it resolves to is not, because that is the entry
    /// form that says "I mean this address". Both halves matter: the first is the
    /// rebinding defence, the second is the whole point of the change.
    #[tokio::test]
    async fn an_allowlisted_but_private_resolving_name_is_refused_while_its_literal_is_not() {
        let proxy = EgressProxy::start(ProxyConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow: patterns(&["localhost", "127.0.0.1"]),
            ..ProxyConfig::default()
        })
        .await
        .unwrap();

        // By name: refused, because a name that resolves to loopback proves nothing
        // about what it will resolve to next time.
        let by_name = request(&proxy, "CONNECT localhost:443 HTTP/1.1\r\n\r\n").await;
        assert!(by_name.starts_with("HTTP/1.1 403"), "{by_name}");
        assert!(by_name.contains("local or private address space"), "{by_name}");

        // By literal: dialled. Port 443 on loopback is almost certainly closed, so the
        // dial is expected to fail; the point is that it is not a policy refusal.
        let by_literal = request(&proxy, "CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n").await;
        assert!(
            !by_literal.starts_with("HTTP/1.1 403"),
            "a literal the operator named must not be refused as private: {by_literal}"
        );

        // One policy refusal, one attempt that got through.
        assert_eq!(proxy.stats().denied, 1, "{:?}", proxy.stats());
    }

    /// A named port is enforced: the entry allows that port and only that port. This is
    /// the narrowing the old 80/443 rule could not express, and the regression it must
    /// not introduce is "a port-qualified rule matches everything anyway".
    #[tokio::test]
    async fn a_named_port_is_allowed_and_every_other_port_is_refused() {
        let proxy = EgressProxy::start(ProxyConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow: patterns(&["example.com:8443"]),
            ..decision_only()
        })
        .await
        .unwrap();

        // The named port passes the allowlist and then fails at DNS, which is what
        // "not refused by the allowlist" looks like with no network.
        let allowed = request(&proxy, "CONNECT example.com:8443 HTTP/1.1\r\n\r\n").await;
        assert!(!allowed.starts_with("HTTP/1.1 403"), "the named port was refused: {allowed}");

        for other in ["443", "80", "22", "8444"] {
            let refused = request(&proxy, &format!("CONNECT example.com:{other} HTTP/1.1\r\n\r\n")).await;
            assert!(
                refused.starts_with("HTTP/1.1 403"),
                "port {other} must not inherit a rule written for 8443: {refused}"
            );
        }
    }

    /// An entry with no port allows every port — the documented widening. Asserted so
    /// that the absence of a port can never quietly turn into 80/443-only again.
    #[tokio::test]
    async fn an_entry_without_a_port_covers_every_port() {
        let proxy = EgressProxy::start(ProxyConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow: patterns(&["example.com"]),
            ..decision_only()
        })
        .await
        .unwrap();

        for port in ["22", "3306", "6379", "65535"] {
            let response = request(&proxy, &format!("CONNECT example.com:{port} HTTP/1.1\r\n\r\n")).await;
            assert!(
                !response.starts_with("HTTP/1.1 403"),
                "port {port} should be covered by an entry that names no port: {response}"
            );
        }
    }

    /// The load-bearing exception: a hostname that resolves into private space stays
    /// refused, but an address the operator named literally is allowed through to the
    /// connection attempt. Asserted through the live proxy so the call site is covered,
    /// not just the matcher.
    /// A destination that swallows packets instead of refusing them must not tie the proxy
    /// up for the kernel's retry budget, and the model has to be told what happened rather
    /// than left waiting. This covers the resolution stage too: the name here is an address
    /// literal, so what is under test at that stage is only that it is bounded. `192.0.2.1` is TEST-NET-1: reserved for documentation and not
    /// routed, which is the closest thing to "hangs" a test can rely on. Should a network
    /// answer with a refusal instead, that is a 502 -- still bounded, still explained, which
    /// is the property under test.
    #[tokio::test]
    async fn a_destination_that_never_answers_is_bounded_and_reported() {
        let proxy = EgressProxy::start(ProxyConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            // An address literal, which is the form allowed to reach an unroutable
            // address: a hostname that resolved there would be refused.
            allow: patterns(&["192.0.2.1"]),
            upstream_timeout: Duration::from_millis(300),
            ..ProxyConfig::default()
        })
        .await
        .unwrap();

        let started = std::time::Instant::now();
        let response = request(&proxy, "CONNECT 192.0.2.1:443 HTTP/1.1\r\n\r\n").await;
        let elapsed = started.elapsed();

        assert!(
            !response.starts_with("HTTP/1.1 403"),
            "the allowlist permits this address, so it must not be a refusal: {response}"
        );
        assert!(
            response.starts_with("HTTP/1.1 504") || response.starts_with("HTTP/1.1 502"),
            "an unreachable destination must be reported as a gateway failure: {response}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the attempt must be bounded by upstream_timeout, not by the kernel: took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn a_named_address_reaches_private_space_where_a_hostname_may_not() {
        let proxy = EgressProxy::start(ProxyConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            // Both forms are "allowlisted"; only the literal may touch loopback.
            allow: patterns(&["localhost:9", "127.0.0.1:9"]),
            ..ProxyConfig::default()
        })
        .await
        .unwrap();

        // The name resolves into loopback, so it is refused even though a rule covers
        // it: that is the rebinding defence, and it must survive this change.
        let by_name = request(&proxy, "CONNECT localhost:9 HTTP/1.1\r\n\r\n").await;
        assert!(by_name.starts_with("HTTP/1.1 403"), "a private-resolving name must stay refused: {by_name}");
        assert!(by_name.contains("local or private address space"), "{by_name}");
        // The refusal has to say how to do it deliberately, and the entry it suggests
        // must be one the parser accepts — advice that does not parse would leave the
        // operator still blocked. `localhost` resolves to `::1` as well as `127.0.0.1`,
        // so this also pins the bracketed IPv6 form.
        let suggested = by_name
            .split("allowlist the address itself -- '")
            .nth(1)
            .and_then(|rest| rest.split('\'').next())
            .unwrap_or_else(|| panic!("the refusal should suggest a literal to allow: {by_name}"));
        crate::allowlist::Rule::parse(suggested)
            .unwrap_or_else(|err| panic!("the suggested entry '{suggested}' does not parse: {err}"));

        // The literal is allowed past the checks. Nothing is listening on port 9, so the
        // dial itself fails — what matters is that it got as far as dialling instead of
        // being refused by policy.
        let by_address = request(&proxy, "CONNECT 127.0.0.1:9 HTTP/1.1\r\n\r\n").await;
        assert!(
            !by_address.starts_with("HTTP/1.1 403"),
            "the named address should have been dialled rather than refused: {by_address}"
        );
    }

    /// The port on an address entry is enforced too: naming `127.0.0.1:9` must not open
    /// every port on loopback.
    #[tokio::test]
    async fn a_named_address_on_another_port_is_still_refused() {
        let proxy = EgressProxy::start(ProxyConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow: patterns(&["127.0.0.1:9"]),
            ..ProxyConfig::default()
        })
        .await
        .unwrap();

        let other = request(&proxy, "CONNECT 127.0.0.1:9000 HTTP/1.1\r\n\r\n").await;
        assert!(other.starts_with("HTTP/1.1 403"), "port 9000 was not allowed: {other}");
    }

    #[tokio::test]
    async fn an_unparseable_request_gets_a_400() {
        let proxy = EgressProxy::start(ProxyConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow: patterns(&["*"]),
            ..ProxyConfig::default()
        })
        .await
        .unwrap();

        let mut stream = TcpStream::connect(proxy.local_addr()).await.unwrap();
        stream.write_all(b"nonsense\r\n\r\n").await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400"));
        assert_eq!(proxy.stats().failed, 1);
    }

    #[tokio::test]
    async fn two_proxies_get_distinct_ports() {
        let a = EgressProxy::start(ProxyConfig::default()).await.unwrap();
        let b = EgressProxy::start(ProxyConfig::default()).await.unwrap();
        assert_ne!(a.port(), b.port());
        assert_eq!(a.endpoint("172.28.0.1").authority(), format!("172.28.0.1:{}", a.port()));
    }

    #[tokio::test]
    async fn the_allowlist_can_be_changed_at_runtime() {
        let proxy = EgressProxy::start(ProxyConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow: vec![],
            ..ProxyConfig::default()
        })
        .await
        .unwrap();

        let deny = |proxy: &EgressProxy| {
            let addr = proxy.local_addr();
            async move {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                stream.write_all(b"CONNECT later.example:443 HTTP/1.1\r\n\r\n").await.unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await.unwrap();
                String::from_utf8_lossy(&response).to_string()
            }
        };

        assert!(deny(&proxy).await.starts_with("HTTP/1.1 403"));
        proxy.set_allowlist(patterns(&["later.example"])).await;
        // Now it passes the allowlist (it will fail later at DNS, which is fine:
        // what we are asserting is that the allowlist decision changed).
        let after = deny(&proxy).await;
        assert!(!after.contains("egress allowlist"), "{after}");
    }

    /// Acceptance criterion: an allowlist entry `api.github.com` must not permit
    /// `api.github.com.attacker.com`.
    ///
    /// Asserted through a live proxy connection rather than against the matcher,
    /// because a correct matcher behind an incorrect call site would still be a
    /// vulnerability.
    #[tokio::test]
    async fn an_allowlisted_host_does_not_permit_a_longer_hostname_through_the_proxy() {
        let proxy = EgressProxy::start(ProxyConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow: patterns(&["api.github.com"]),
            ..decision_only()
        })
        .await
        .unwrap();

        // The exact host is allowed, and then fails later at DNS because the name
        // does not resolve. Either way it must not be a 403.
        let allowed = request(&proxy, "CONNECT api.github.com:443 HTTP/1.1\r\n\r\n").await;
        assert!(
            !allowed.starts_with("HTTP/1.1 403"),
            "the allowlisted host was refused: {allowed}"
        );

        // The attack: a domain that merely ends with the allowlisted name.
        let attack = request(
            &proxy,
            "CONNECT api.github.com.attacker.com:443 HTTP/1.1\r\n\r\n",
        )
        .await;
        assert!(
            attack.starts_with("HTTP/1.1 403"),
            "a longer hostname must not inherit the allowlist entry: {attack}"
        );
    }

    /// Deny entries beat allow entries, through the live proxy and regardless of
    /// the order they were written in.
    #[tokio::test]
    async fn a_deny_entry_wins_over_a_wildcard_allow_through_the_proxy() {
        for entries in [
            patterns(&["*.example.com", "!tracker.example.com"]),
            patterns(&["!tracker.example.com", "*.example.com"]),
        ] {
            let proxy = EgressProxy::start(ProxyConfig {
                bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                allow: entries,
                ..ProxyConfig::default()
            })
            .await
            .unwrap();

            let ok = request(&proxy, "CONNECT app.example.com:443 HTTP/1.1\r\n\r\n").await;
            assert!(!ok.starts_with("HTTP/1.1 403"), "app.example.com was refused: {ok}");

            let denied =
                request(&proxy, "CONNECT tracker.example.com:443 HTTP/1.1\r\n\r\n").await;
            assert!(
                denied.starts_with("HTTP/1.1 403"),
                "the deny entry did not win: {denied}"
            );
        }
    }

    /// A path prefix is enforced where the path is visible. The request reaches
    /// DNS and fails there, which is what "not refused by the allowlist" looks
    /// like in a test with no network.
    #[tokio::test]
    async fn a_path_prefix_is_enforced_for_absolute_form_requests() {
        let proxy = EgressProxy::start(ProxyConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow: patterns(&["github.com/org/repo"]),
            ..decision_only()
        })
        .await
        .unwrap();

        let inside = request(
            &proxy,
            "GET http://github.com/org/repo/tree/main HTTP/1.1\r\nHost: github.com\r\n\r\n",
        )
        .await;
        assert!(
            !inside.starts_with("HTTP/1.1 403"),
            "a path under the prefix was refused: {inside}"
        );

        let outside = request(
            &proxy,
            "GET http://github.com/other/place HTTP/1.1\r\nHost: github.com\r\n\r\n",
        )
        .await;
        assert!(
            outside.starts_with("HTTP/1.1 403"),
            "a path outside the prefix must be refused: {outside}"
        );
    }

    /// The documented HTTPS caveat, asserted rather than merely described: a
    /// CONNECT tunnel carries no path, so a path-prefixed entry degrades to
    /// host-only. This is the behaviour the UI has to disclose.
    #[tokio::test]
    async fn a_path_prefix_degrades_to_host_only_for_connect_tunnels() {
        let proxy = EgressProxy::start(ProxyConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow: patterns(&["github.com/org/repo"]),
            ..decision_only()
        })
        .await
        .unwrap();

        let tunnel = request(&proxy, "CONNECT github.com:443 HTTP/1.1\r\n\r\n").await;
        assert!(
            !tunnel.starts_with("HTTP/1.1 403"),
            "a CONNECT tunnel cannot be path-filtered, so it must degrade to host-only: {tunnel}"
        );
    }

    /// A malformed entry is reported rather than silently ignored, and does not
    /// take the whole allowlist down with it.
    #[tokio::test]
    async fn a_malformed_entry_is_reported_and_the_rest_still_applies() {
        let proxy = EgressProxy::start(ProxyConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow: patterns(&["good.example", "re:not-anchored"]),
            ..ProxyConfig::default()
        })
        .await
        .unwrap();

        let problems = proxy.malformed_entries();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("anchored"), "{problems:?}");

        let ok = request(&proxy, "CONNECT good.example:443 HTTP/1.1\r\n\r\n").await;
        assert!(!ok.starts_with("HTTP/1.1 403"), "the good entry was lost: {ok}");
    }

    /// The parsed allowlist is inspectable, which is what the request broker and
    /// the exfiltration warning need in order to reason about a proposal.
    #[tokio::test]
    async fn the_allowlist_is_inspectable_for_callers_that_need_to_reason_about_it() {
        let proxy = EgressProxy::start(ProxyConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow: patterns(&["*", "!metadata.google.internal"]),
            ..ProxyConfig::default()
        })
        .await
        .unwrap();

        let list = proxy.allowlist().await;
        assert_eq!(list.broad_allow_rules().len(), 1, "the blanket allow should be flagged");
        assert!(matches!(
            list.decide("metadata.google.internal", None, None),
            Decision::Denied { .. }
        ));
    }

    /// Drive one request through a proxy and return the raw response.
    /// A config for tests that assert on the *decision* the proxy makes rather than on
    /// completing a connection to the internet.
    ///
    /// Every one of them asserts "not a 403" -- the code says as much: a request that
    /// reaches DNS and fails there is what "not refused by the allowlist" looks like
    /// without a network. What they must not do is wait out the kernel's SYN retry on a
    /// filtered port once per address a name resolves to, which is where 168 seconds of
    /// this suite's 169 went. The decision is identical either way; only the waiting is not.
    fn decision_only() -> ProxyConfig {
        ProxyConfig {
            upstream_timeout: Duration::from_millis(150),
            ..ProxyConfig::default()
        }
    }

    /// Send one request to the proxy and return what it says back.
    ///
    /// Deliberately not `read_to_end`. When the proxy accepts a tunnel it answers
    /// "200 Connection Established" and then relays, so the connection stays open until the
    /// *far end* closes it -- GitHub's and Cloudflare's idle timeouts are tens of seconds,
    /// and a helper waiting for them is where most of this suite's runtime went: 91 seconds
    /// for one test that asserts on a status line it already had.
    ///
    /// The loop ends at end-of-stream, at an error, or when a read takes longer than the
    /// quiet period below, which means the proxy has nothing further to say right now. Every
    /// assertion here is about what the proxy says, and that arrives in one write.
    async fn request(proxy: &EgressProxy, head: &str) -> String {
        const QUIET: Duration = Duration::from_millis(500);
        let mut stream = TcpStream::connect(proxy.local_addr()).await.unwrap();
        stream.write_all(head.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let mut chunk = [0u8; 1024];
        while let Ok(Ok(read)) = tokio::time::timeout(QUIET, stream.read(&mut chunk)).await {
            if read == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..read]);
        }
        String::from_utf8_lossy(&response).to_string()
    }

}
