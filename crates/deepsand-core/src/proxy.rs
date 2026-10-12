//! The allowlisting egress proxy used by the `restricted` network mode.
//!
//! When a project is in `restricted` mode the container's own kernel rules allow
//! it to reach exactly one address: this proxy. Everything else is dropped
//! inside the container. The proxy then decides, per connection, whether the
//! destination is on the operator's allowlist.
//!
//! Two properties matter:
//!
//! * **The allowlist is by hostname, and the proxy does the resolving.** The
//!   sandbox cannot influence name resolution.
//! * **Resolved addresses are checked too.** An allowlisted hostname that
//!   resolves into loopback, RFC1918, link-local or CGNAT space is refused, so
//!   a rebinding trick or a DNS entry pointed at the operator's router cannot
//!   turn an allowlisted domain into a path onto the local network.

use crate::allowlist::{Allowlist, Decision};
use crate::error::{Result, SandboxError};
use crate::model::BlockedEgress;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
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
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow: Vec::new(),
            max_head_bytes: 16 * 1024,
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
                            if let Err(err) =
                                serve(stream, allow, malformed, blocked, counters, max_head).await
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
    let decision = list.decide(&request.host, path);

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
    // The request is permitted, but local and private addressing is still
    // refused below.

    if !is_allowed_port(request.port) {
        counters.denied.fetch_add(1, Ordering::Relaxed);
        record_blocked(&blocked, &request, "port not permitted through the allowlist proxy");
        write_status(
            &mut client,
            403,
            "Forbidden",
            &format!(
                "Deepsand's egress proxy only permits ports 80 and 443; '{}' was requested.",
                request.port
            ),
        )
        .await?;
        return Ok(());
    }

    // Resolve ourselves, then refuse anything that lands on local or private
    // address space. An allowlisted hostname must not become a route to the
    // operator's own network.
    let mut resolved = match tokio::net::lookup_host((request.host.as_str(), request.port)).await {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(err) => {
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
    };

    let blocked_addresses: Vec<SocketAddr> = resolved.iter().copied().filter(|a| is_blocked_target(a.ip())).collect();
    resolved.retain(|a| !is_blocked_target(a.ip()));

    if resolved.is_empty() {
        counters.denied.fetch_add(1, Ordering::Relaxed);
        let detail = blocked_addresses
            .first()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "no address".to_string());
        record_blocked(&blocked, &request, "resolves into local or private address space");
        write_status(
            &mut client,
            403,
            "Forbidden",
            &format!(
                "Deepsand refused '{}': it resolves to {detail}, which is local or private address space. An \
                 allowlisted name is never allowed to become a route onto the operator's own network.",
                request.host
            ),
        )
        .await?;
        return Ok(());
    }

    let mut upstream = match TcpStream::connect(&resolved[..]).await {
        Ok(stream) => stream,
        Err(err) => {
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

/// Match a hostname against the allowlist.
///
/// Supported patterns: an exact host, `*.suffix` for any single-or-multi label
/// subdomain, and `*` for everything.
/// The predicate form of an allowlist check, for host-only requests where the
/// caller only needs a yes or no and has no path to offer.
///
/// Equivalent to asking a parsed [`Allowlist`] about a host-only request. The
/// live connection path goes through [`Allowlist::decide`] directly so that it
/// can pass the path and report which rule was responsible.
pub fn host_allowed(host: &str, patterns: &[String]) -> bool {
    if normalise_host(host).is_empty() {
        return false;
    }
    Allowlist::parse_lenient(patterns).0.decide(host, None).is_allowed()
}

fn normalise_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Ports the proxy will tunnel.
pub fn is_allowed_port(port: u16) -> bool {
    matches!(port, 80 | 443)
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

    #[test]
    fn only_http_ports_are_tunnelled() {
        assert!(is_allowed_port(80));
        assert!(is_allowed_port(443));
        assert!(!is_allowed_port(22));
        assert!(!is_allowed_port(3306));
        assert!(!is_allowed_port(8080));
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

    #[tokio::test]
    async fn an_allowlisted_but_private_resolving_host_is_refused() {
        let proxy = EgressProxy::start(ProxyConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            // localhost is "allowlisted", but must still be refused because it
            // resolves into loopback space.
            allow: patterns(&["localhost", "127.0.0.1"]),
            ..ProxyConfig::default()
        })
        .await
        .unwrap();

        let mut stream = TcpStream::connect(proxy.local_addr()).await.unwrap();
        stream
            .write_all(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 403"), "{text}");
        assert!(text.contains("local or private address space"), "{text}");
        assert_eq!(proxy.stats().denied, 1);
    }

    #[tokio::test]
    async fn a_disallowed_port_is_refused_even_for_an_allowed_host() {
        let proxy = EgressProxy::start(ProxyConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow: patterns(&["example.com"]),
            ..ProxyConfig::default()
        })
        .await
        .unwrap();

        let mut stream = TcpStream::connect(proxy.local_addr()).await.unwrap();
        stream.write_all(b"CONNECT example.com:22 HTTP/1.1\r\n\r\n").await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 403"), "{text}");
        assert!(text.contains("ports 80 and 443"), "{text}");
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
            ..ProxyConfig::default()
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
            ..ProxyConfig::default()
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
            ..ProxyConfig::default()
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
            list.decide("metadata.google.internal", None),
            Decision::Denied { .. }
        ));
    }

    /// Drive one request through a proxy and return the raw response.
    async fn request(proxy: &EgressProxy, head: &str) -> String {
        let mut stream = TcpStream::connect(proxy.local_addr()).await.unwrap();
        stream.write_all(head.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).to_string()
    }

}
