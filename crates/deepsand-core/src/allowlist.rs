//! The egress allowlist: parsing, matching, and the presets shipped with it.
//!
//! # The entry syntax
//!
//! One string per entry. The operator can edit these as plain text, which is why
//! the format is a small DSL rather than a nested structure:
//!
//! | Entry | Meaning |
//! | --- | --- |
//! | `example.com` | that exact hostname, on any port |
//! | `example.com:8443` | that hostname, only on that port |
//! | `*.example.com` | `a.example.com` and `a.b.example.com`, but **not** `example.com` |
//! | `example.com/org/repo` | that hostname, but only for paths under `/org/repo` |
//! | `192.168.1.50:5432` | an address literal, on that port |
//! | `192.168.1.50` | an address literal, on any port |
//! | `[fe80::1]:8080` | an IPv6 address literal, on that port |
//! | `re:^api\.example\.(com\|org)$` | an anchored regular expression |
//! | `!evil.example` | a **deny** entry; any prefix form is allowed here too |
//! | `*` | everything (permitted, but always flagged — see [`Rule::is_broad`]) |
//!
//! # Addresses are the exception to the private-address refusal
//!
//! An entry that is an address literal is an explicit instruction to reach *that
//! address*, so it overrides the proxy's refusal to touch loopback and RFC1918 space.
//! That is the point of it: a database on the LAN, or a service on the operator's own
//! machine, is a legitimate destination that no hostname entry can express without
//! also re-opening DNS rebinding.
//!
//! A **hostname** entry never overrides that refusal, however narrow it looks. A name
//! that resolves into private space is exactly the rebinding case the refusal exists
//! for, and "it is on my allowlist" is not evidence about what it resolves to. A local
//! service is listed by its address.
//!
//! Address entries are also the only ones enforceable without the proxy: the netfilter
//! gets a rule per literal, so a database client that speaks no HTTP can reach it.
//! Hostname entries are proxy-only, which is where the path rules and the rebinding
//! check live.
//!
//! # Ports
//!
//! The port is optional and means what it says: omitting it allows every port on that
//! entry. That is a deliberate widening from the earlier "ports 80 and 443 only" rule,
//! which could not express a database or a development server at all. A port named on
//! an address entry is also the port published on the host, so a server the sandbox
//! runs there can be reached from the operator's side.
//!
//! # Deny always wins
//!
//! Every deny rule is evaluated before any allow rule, so an operator can write
//! `*.example.com` followed by `!tracker.example.com` and get the obvious result.
//! Order in the list never matters.
//!
//! # Why regexes must be anchored
//!
//! A raw regex is matched against the **whole** hostname with [`regex::Regex`],
//! and the pattern is required to be anchored (`^`…`$`). Both halves of that are
//! deliberate:
//!
//! * Matching the full hostname means `api.github.com` cannot be matched by an
//!   unanchored `github.com` written as a regex — substring matching against
//!   hostnames is how `api.github.com.attacker.com` ends up allowed.
//! * Requiring explicit `^`/`$` stops an author from writing `re:github\.com`
//!   believing it is anchored when `Regex::is_match` would happily find that
//!   substring inside `github.com.attacker.com`.
//!
//! # Path prefixes, and the HTTPS caveat
//!
//! A path prefix is only enforceable where the path is visible. Over HTTPS the
//! proxy receives a `CONNECT host:443` and then an opaque tunnel, so a
//! path-prefixed entry degrades to host-only. [`Rule::path_is_enforceable`]
//! reports that, and [`Rule::scope_note`] renders it for the operator, so the UI
//! never implies a guarantee the transport cannot deliver. See `docs/SECURITY.md`.

use regex::Regex;
use std::fmt;
use std::net::IpAddr;

/// The allowlist entry shipped for ordinary development work.
///
/// Deliberately narrow: the package registries and code hosts that a
/// `git clone` + `npm install` + `npm test` cycle needs, and nothing else. No
/// wildcard over a whole TLD, no telemetry endpoints, no CDNs.
pub const DEVELOPER_PRESET: &[&str] = &[
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "github.com",
    "*.githubusercontent.com",
];

/// A preset for people who want registries for more ecosystems.
pub const POLYGLOT_PRESET: &[&str] = &[
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "github.com",
    "*.githubusercontent.com",
    "crates.io",
    "static.crates.io",
    "index.crates.io",
    "proxy.golang.org",
    "sum.golang.org",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "rubygems.org",
    "*.rubygems.org",
    "registry.yarnpkg.com",
    "deb.debian.org",
    "archive.ubuntu.com",
    "security.ubuntu.com",
];

/// Look a preset up by name, for a UI to offer.
pub fn preset(name: &str) -> Option<&'static [&'static str]> {
    presets()
        .into_iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, entries)| entries)
}

/// Every preset name, with the entries, for listing in a UI.
pub fn presets() -> Vec<(&'static str, &'static [&'static str])> {
    vec![
        ("developer", DEVELOPER_PRESET),
        ("polyglot", POLYGLOT_PRESET),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub enum HostMatcher {
    /// Exactly this hostname.
    Exact(String),
    /// A strict subdomain of this domain: `*.example.com` never matches
    /// `example.com` itself.
    Subdomain(String),
    /// An address literal. Matched against the literal, so `192.168.1.50` and
    /// `[fe80::1]` are compared as addresses rather than as text, and it is what
    /// lets the proxy admit a private destination the operator named on purpose.
    Address(IpAddr),
    /// Matches any hostname. Permitted because an operator may genuinely want it,
    /// but it is always flagged by [`Rule::is_broad`].
    Any,
    /// A pre-compiled, anchored regular expression matched against the full
    /// hostname.
    Regex(Regex),
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub kind: RuleKind,
    pub matcher: HostMatcher,
    /// Path prefix such as `/org/repo`, if the entry had one.
    pub path_prefix: Option<String>,
    /// Port the entry names, if it named one. `None` means every port.
    pub port: Option<u16>,
    /// Exactly what the operator wrote, so diagnostics and the UI can show the
    /// source text rather than a re-rendered approximation.
    pub raw: String,
}

impl Rule {
    /// Parse one entry.
    ///
    /// Returns a human-readable error rather than silently ignoring malformed
    /// input: a rule the operator believes is protecting them, which is actually
    /// being skipped, is worse than a failure.
    pub fn parse(entry: &str) -> Result<Self, String> {
        let raw = entry.trim().to_string();
        if raw.is_empty() {
            return Err("empty entry".to_string());
        }
        if raw.starts_with('#') {
            return Err("comments are not entries".to_string());
        }

        let (kind, body) = match raw.strip_prefix('!') {
            Some(rest) => (RuleKind::Deny, rest.trim()),
            None => (RuleKind::Allow, raw.as_str()),
        };
        if body.is_empty() {
            return Err(format!("'{raw}': nothing after the '!'"));
        }

        // A regex body owns the whole entry; it must not also be split on '/'.
        if let Some(pattern) = body.strip_prefix("re:") {
            let pattern = pattern.trim();
            if !pattern.starts_with('^') || !pattern.ends_with('$') {
                return Err(format!(
                    "'{raw}': a regex entry must be anchored with ^ and $. \
                     Write re:^{pattern}$ so it cannot match a substring of a hostname."
                ));
            }
            if pattern.len() < 2 {
                return Err(format!("'{raw}': the regex is empty"));
            }
            let compiled = Regex::new(pattern)
                .map_err(|err| format!("'{raw}': that is not a valid regular expression ({err})"))?;
            return Ok(Self {
                kind,
                matcher: HostMatcher::Regex(compiled),
                path_prefix: None,
                // The regex owns the whole entry, so there is nowhere to put a port.
                port: None,
                raw,
            });
        }

        // Split host from an optional path prefix at the first '/'.
        let (host_part, path_prefix) = match body.split_once('/') {
            Some((host, rest)) => {
                let prefix = format!("/{}", rest.trim_end_matches('/'));
                (host.trim(), Some(prefix))
            }
            None => (body.trim(), None),
        };
        if host_part.is_empty() {
            return Err(format!("'{raw}': no hostname"));
        }

        let (host_part, port) = split_port(host_part).map_err(|err| format!("'{raw}': {err}"))?;
        if host_part.is_empty() {
            return Err(format!("'{raw}': nothing before the port"));
        }

        let matcher = if host_part == "*" {
            HostMatcher::Any
        } else if let Some(suffix) = host_part.strip_prefix("*.") {
            let suffix = normalise_host(suffix);
            if suffix.is_empty() || !is_plausible_host(&suffix) {
                return Err(format!(
                    "'{raw}': a wildcard needs a domain, for example *.example.com"
                ));
            }
            // A single-label wildcard such as `*.com` is accepted on purpose. It
            // is over-broad, but refusing it would push the operator to `*`,
            // which is broader still and harder to reason about; flagging it via
            // `is_broad` is more useful than rejecting it.
            HostMatcher::Subdomain(suffix)
        } else if let Ok(address) = host_part.parse::<IpAddr>() {
            // An address literal, checked before the hostname rules so that a colon
            // in an IPv6 address is never mistaken for a port.
            HostMatcher::Address(address)
        } else {
            if host_part.contains('*') {
                return Err(format!(
                    "'{raw}': '*' is only allowed as the whole entry or as a leading '*.'"
                ));
            }
            let host = normalise_host(host_part);
            if !is_plausible_host(&host) {
                return Err(format!("'{raw}': '{host}' is not a plausible hostname"));
            }
            HostMatcher::Exact(host)
        };

        // A port on `*` has no reading: it would say "any host, but only this port",
        // which is not something the operator can have meant.
        if port.is_some() && matches!(matcher, HostMatcher::Any) {
            return Err(format!(
                "'{raw}': a port cannot be combined with '*'. Name a host or an address instead."
            ));
        }

        // A path prefix on a `*` or a wildcard is almost never what was meant,
        // and it cannot be enforced over HTTPS anyway.
        if path_prefix.is_some() && matches!(matcher, HostMatcher::Any) {
            return Err(format!(
                "'{raw}': a path prefix cannot be combined with '*'. Use a hostname so the rule means something."
            ));
        }

        Ok(Self {
            kind,
            matcher,
            path_prefix,
            port,
            raw,
        })
    }

    /// Whether this rule matches `host`, ignoring the path and the port.
    pub fn matches_host(&self, host: &str) -> bool {
        let host = normalise_host(host);
        if host.is_empty() {
            return false;
        }
        match &self.matcher {
            HostMatcher::Any => true,
            HostMatcher::Exact(expected) => &host == expected,
            HostMatcher::Subdomain(suffix) => {
                // `*.example.com` must not match `example.com` itself, and must
                // not match `notexample.com`.
                host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}"))
            }
            // Compared as an address, so `[fe80::1]` and `fe80::1` are one rule.
            HostMatcher::Address(expected) => {
                host_literal(&host).is_some_and(|actual| actual == *expected)
            }
            // `is_match` on an anchored pattern is a full-hostname comparison,
            // because the pattern is required to carry ^ and $.
            HostMatcher::Regex(re) => re.is_match(&host),
        }
    }

    /// Whether this rule's port constraint admits `port`.
    ///
    /// A rule that names no port allows every port. A rule that names one does **not**
    /// match when the caller does not know the port: an unknown port must never
    /// satisfy a constraint, or a rule written to narrow one service would quietly
    /// allow all of them.
    pub fn matches_port(&self, port: Option<u16>) -> bool {
        match (self.port, port) {
            (None, _) => true,
            (Some(expected), Some(actual)) => expected == actual,
            (Some(_), None) => false,
        }
    }

    /// Whether this rule matches the request. `path` is the request path when the
    /// transport exposes one, and `None` inside a `CONNECT` tunnel.
    pub fn matches(&self, host: &str, path: Option<&str>, port: Option<u16>) -> bool {
        if !self.matches_host(host) || !self.matches_port(port) {
            return false;
        }
        match (&self.path_prefix, path) {
            // No path prefix: the host is enough.
            (None, _) => true,
            // A path prefix, and a path to check against it.
            (Some(prefix), Some(path)) => path_prefix_matches(prefix, path),
            // A path prefix, but the transport is opaque (HTTPS via CONNECT), so
            // the prefix degrades to host-only. This is the documented caveat.
            (Some(_), None) => true,
        }
    }

    /// The address and port this rule names, when it names an address literal.
    ///
    /// The netfilter needs this: an address entry is reachable without the proxy, so
    /// the plan turns each one into an iptables rule of its own.
    pub fn literal_target(&self) -> Option<(IpAddr, Option<u16>)> {
        match &self.matcher {
            HostMatcher::Address(address) => Some((*address, self.port)),
            _ => None,
        }
    }

    /// Whether the path prefix on this rule can actually be enforced.
    ///
    /// False for rules with no path prefix (nothing to enforce) and for those
    /// whose traffic will arrive as an opaque tunnel.
    pub fn path_is_enforceable(&self) -> bool {
        self.path_prefix.is_some()
    }

    /// True when this rule permits essentially everything, so the operator can be
    /// warned before secrets become exfiltratable.
    ///
    /// A heuristic, used only to decide whether to warn; it never affects
    /// matching. `*` and any regex that matches every probe hostname count.
    pub fn is_broad(&self) -> bool {
        match &self.matcher {
            HostMatcher::Any => true,
            // `*.com` covers every registrable domain under a public suffix.
            HostMatcher::Subdomain(suffix) => !suffix.contains('.'),
            HostMatcher::Regex(re) => {
                // Probe with hostnames that a legitimate narrow rule would never
                // all accept: several unrelated registrable domains.
                const PROBES: &[&str] = &[
                    "example.com",
                    "a.example.com",
                    "attacker.test",
                    "xn--80ak6aa92e.com",
                    "1.2.3.4",
                    "localhost",
                ];
                PROBES.iter().all(|probe| re.is_match(probe))
            }
            _ => false,
        }
    }

    /// A short phrase for the UI describing what the rule actually enforces,
    /// including the HTTPS caveat where it applies.
    pub fn scope_note(&self) -> String {
        match &self.path_prefix {
            None => "every path on this hostname".to_string(),
            Some(prefix) => format!(
                "paths under {prefix} on HTTP; the whole hostname on HTTPS, \
                 because a CONNECT tunnel hides the path"
            ),
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Permitted, naming the rule that permitted it.
    Allowed { rule: String },
    /// Refused, naming the rule that refused it. Deny always wins.
    Denied { rule: String },
    /// Nothing matched, and the policy is default-deny.
    NoMatch,
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allowed { .. })
    }

    /// A one-line explanation for logs and for telling the agent.
    pub fn explain(&self, host: &str, path: Option<&str>) -> String {
        let target = match path {
            Some(path) => format!("{host}{path}"),
            None => host.to_string(),
        };
        match self {
            Decision::Allowed { rule } => format!("{target} allowed by '{rule}'"),
            Decision::Denied { rule } => format!("{target} denied by '{rule}'"),
            Decision::NoMatch => {
                format!("{target} is not in the allowlist, and the default is to deny")
            }
        }
    }
}

/// A parsed, ordered set of rules plus the hostnames that can never be removed.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    rules: Vec<Rule>,
    /// Entries that exist because the sandbox cannot function without them, such
    /// as the model endpoint. Rendered in the UI as locked.
    required: Vec<String>,
}

impl Allowlist {
    pub fn empty() -> Self {
        Self::default()
    }

    /// The `developer` preset, with no required hosts.
    pub fn developer_preset() -> Self {
        Self::parse(DEVELOPER_PRESET).expect("the developer preset must always parse")
    }

    /// Parse a list of entries, collecting every problem rather than stopping at
    /// the first, so the operator can fix them in one pass.
    pub fn parse<I, S>(entries: I) -> Result<Self, Vec<String>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut rules = Vec::new();
        let mut problems = Vec::new();
        for entry in entries {
            match Rule::parse(entry.as_ref()) {
                Ok(rule) => rules.push(rule),
                Err(err) => problems.push(err),
            }
        }
        if problems.is_empty() {
            Ok(Self {
                rules,
                required: Vec::new(),
            })
        } else {
            Err(problems)
        }
    }

    /// Parse the operator's entries, tolerating broken ones by reporting them as
    /// warnings instead of failing.
    ///
    /// Used on the load path, where refusing to start the whole app because one
    /// line of an allowlist is malformed would be worse than running with that
    /// line skipped — as long as the operator is told which line was skipped.
    pub fn parse_lenient<I, S>(entries: I) -> (Self, Vec<String>)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut rules = Vec::new();
        let mut problems = Vec::new();
        for entry in entries {
            match Rule::parse(entry.as_ref()) {
                Ok(rule) => rules.push(rule),
                Err(err) => problems.push(err),
            }
        }
        (
            Self {
                rules,
                required: Vec::new(),
            },
            problems,
        )
    }

    /// Add operator entries to an existing list. Used when a list is built in
    /// stages, for example a preset followed by operator entries.
    pub fn with_entries<I, S>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let (extra, _) = Allowlist::parse_lenient(entries);
        self.rules.extend(extra.rules);
        self
    }

    /// Hostnames that are always allowed, whatever else the list says.
    ///
    /// This exists for the model endpoint. With a default-deny policy, forgetting
    /// it would leave a sandbox that cannot reach the model at all — which looks
    /// like a Deepsand bug rather than a policy choice.
    pub fn with_required_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for host in hosts {
            let host = normalise_host(host.as_ref());
            if host.is_empty() || !is_plausible_host(&host) {
                continue;
            }
            if !self.required.contains(&host) {
                self.required.push(host);
            }
        }
        self
    }

    pub fn required_hosts(&self) -> &[String] {
        &self.required
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Decide a request.
    ///
    /// Deny rules are all evaluated first and short-circuit, so ordering in the
    /// list is irrelevant: this is what makes `*.example.com` + `!tracker.example.com`
    /// behave the way an operator expects.
    ///
    /// `port` is the destination port when the caller knows it. `None` means "not
    /// known", which is not the same as "any": a rule that names a port refuses to
    /// match, because an unknown port must not be able to satisfy a narrower rule.
    pub fn decide(&self, host: &str, path: Option<&str>, port: Option<u16>) -> Decision {
        let host = normalise_host(host);
        if host.is_empty() {
            return Decision::Denied {
                rule: "empty hostname".to_string(),
            };
        }

        for rule in self.rules.iter().filter(|r| r.kind == RuleKind::Deny) {
            if rule.matches(&host, path, port) {
                return Decision::Denied {
                    rule: rule.raw.clone(),
                };
            }
        }

        // Required hosts are checked before the operator's allows so that a
        // narrow `re:` entry cannot accidentally exclude the model endpoint.
        if self.required.iter().any(|required| required == &host) {
            return Decision::Allowed {
                rule: format!("{host} (required)"),
            };
        }

        for rule in self.rules.iter().filter(|r| r.kind == RuleKind::Allow) {
            if rule.matches(&host, path, port) {
                return Decision::Allowed {
                    rule: rule.raw.clone(),
                };
            }
        }

        Decision::NoMatch
    }

    /// Decide a request where only the host is known, ignoring port and path.
    ///
    /// This answers "is there a rule that reaches this destination at all?", which is
    /// what telling the model it *already has* something needs. A rule that names a
    /// port counts, because the sandbox really can reach that host — refusing to
    /// acknowledge it would send the model to ask for something else it cannot have.
    ///
    /// Reporting only. It must never be used to enforce a connection: it is strictly
    /// wider than [`Self::decide`], and enforcing with it would ignore the port.
    pub fn decide_host_only(&self, host: &str) -> Decision {
        let host = normalise_host(host);
        if host.is_empty() {
            return Decision::Denied {
                rule: "empty hostname".to_string(),
            };
        }
        for rule in self.rules.iter().filter(|r| r.kind == RuleKind::Deny) {
            if rule.matches_host(&host) {
                return Decision::Denied {
                    rule: rule.raw.clone(),
                };
            }
        }
        if self.required.iter().any(|required| required == &host) {
            return Decision::Allowed {
                rule: format!("{host} (required)"),
            };
        }
        for rule in self.rules.iter().filter(|r| r.kind == RuleKind::Allow) {
            if rule.matches_host(&host) {
                return Decision::Allowed {
                    rule: rule.raw.clone(),
                };
            }
        }
        Decision::NoMatch
    }

    /// Every address literal this list allows, with its port when it named one.
    ///
    /// Address entries are enforceable without the proxy, so the plan turns each of
    /// these into a netfilter rule and a published port. Hostname entries are absent
    /// on purpose: they stay proxy-only, which is where the path rules and the
    /// rebinding refusal live.
    pub fn direct_targets(&self) -> Vec<(IpAddr, Option<u16>)> {
        let mut found: Vec<(IpAddr, Option<u16>)> = self
            .rules
            .iter()
            .filter(|rule| rule.kind == RuleKind::Allow)
            .filter_map(Rule::literal_target)
            .collect();
        found.sort_by_key(|(address, port)| (address.to_string(), *port));
        found.dedup();
        found
    }

    /// The ports this list publishes on the host, for the entries that name an
    /// address and a port.
    ///
    /// Deduplicated and sorted, because a port published twice would make `docker run`
    /// fail with "port is already allocated" for a reason the operator cannot see.
    pub fn published_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self
            .direct_targets()
            .into_iter()
            .filter_map(|(_, port)| port)
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Addresses this list names literally that may be reached on `port`, even though
    /// they are in loopback or private space.
    ///
    /// An address entry with no port covers every port, which is what makes
    /// `127.0.0.1` mean the operator's own machine rather than nothing.
    pub fn explicit_addresses_for_port(&self, port: u16) -> Vec<IpAddr> {
        self.direct_targets()
            .into_iter()
            .filter(|(_, target_port)| target_port.is_none() || *target_port == Some(port))
            .map(|(address, _)| address)
            .collect()
    }

    /// Whether this list would let a secret leave, which is what the approval
    /// dialog warns about.
    ///
    /// Only allow rules matter: a deny rule cannot widen anything.
    pub fn broad_allow_rules(&self) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|rule| rule.kind == RuleKind::Allow && rule.is_broad())
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Re-render as editable entries, for the settings textarea.
    pub fn to_entries(&self) -> Vec<String> {
        self.rules.iter().map(|rule| rule.raw.clone()).collect()
    }
}

/// Does `path` fall under `prefix`?
///
/// Segment-aware: `/org/repo` matches `/org/repo` and `/org/repo/x` but not
/// `/org/repository`, which a naive `starts_with` would wrongly permit.
fn path_prefix_matches(prefix: &str, path: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }
    if !path.starts_with(prefix) {
        return false;
    }
    match path[prefix.len()..].chars().next() {
        None => true,
        Some('/') => true,
        // A query string directly after the prefix is still the same resource.
        Some('?') => true,
        Some('#') => true,
        Some(_) => false,
    }
}

/// Split a trailing `:port` off a host or an address literal.
///
/// The ambiguous case is IPv6, so the rules are stated rather than guessed:
///
/// * `[fe80::1]:8080` — a bracketed literal, port after the bracket.
/// * `[fe80::1]` — a bracketed literal, no port.
/// * `2001:db8::1` — more than one colon and no brackets, so it is an address and
///   **not** a host with port `1`. Reading a port out of it would silently narrow a
///   rule the operator wrote to cover every port.
/// * `example.com:8080` — one colon, digits after it, so it is a port.
/// * `example.com:http` — a non-numeric port is an error rather than a hostname,
///   because `example.com:http` cannot be meant as a hostname either.
fn split_port(value: &str) -> Result<(&str, Option<u16>), String> {
    let value = value.trim();

    if let Some(rest) = value.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return Err("a '[' needs a matching ']'".to_string());
        };
        let host = rest[..close].trim();
        let after = rest[close + 1..].trim();
        if after.is_empty() {
            return Ok((host, None));
        }
        let Some(digits) = after.strip_prefix(':') else {
            return Err(format!("'{after}' cannot follow an address"));
        };
        return Ok((host, Some(parse_port(digits)?)));
    }

    match value.rsplit_once(':') {
        // Exactly one colon and no ':' in the host part: host and port.
        Some((host, digits)) if !host.contains(':') => {
            Ok((host.trim(), Some(parse_port(digits)?)))
        }
        // A bare IPv6 literal, or no colon at all.
        _ => Ok((value, None)),
    }
}

fn parse_port(digits: &str) -> Result<u16, String> {
    let port = digits
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("'{digits}' is not a port number"))?;
    if port == 0 {
        return Err("port 0 is not a destination".to_string());
    }
    Ok(port)
}

/// Parse a host value as an address, if it is one. Brackets are tolerated, so a
/// value straight out of an authority parses the same as the allowlist entry.
fn host_literal(host: &str) -> Option<IpAddr> {
    let host = host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<IpAddr>().ok()
}

pub fn normalise_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// A cheap sanity check that we are looking at a hostname and not, say, a path
/// or a shell fragment. Deliberately permissive; its job is to catch mistakes,
/// not to be a complete hostname grammar.
pub fn is_plausible_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.contains('/') || host.contains('\\') || host.contains(' ') {
        return false;
    }
    if host.contains("..") || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

/// The hostname of an `http(s)://host[:port][/path]` URL, lowercased.
///
/// Used to turn the project's model base URL into the one host a `none` sandbox is
/// allowed to reach. Returns `None` for anything that is not a usable absolute URL,
/// so a malformed base URL cannot silently produce an allowlist entry like "" that
/// would match nothing and leave the sandbox unable to reach its model with no
/// explanation.
/// The addresses a URL resolves to, as `ip:port`.
///
/// Resolved on the host, because a sandbox in `none` or `restricted` mode cannot look
/// the name up itself: its DNS is limited to its own resolver and its egress to what
/// the netfilter allows. An address-level allowance is therefore the only way the
/// model API can be reached by a client that does not use the proxy.
///
/// IPv6 is skipped deliberately. The netfilter's IPv4 and IPv6 paths differ, and
/// returning a v6 address would produce a rule the v4 chain never matches.
pub fn endpoints_for_url(url: &str) -> Vec<String> {
    use std::net::ToSocketAddrs as _;

    let Some(host) = host_from_url(url) else {
        return Vec::new();
    };
    let port = url_port(url);

    let mut found: Vec<String> = Vec::new();
    if let Ok(addresses) = (host.as_str(), port).to_socket_addrs() {
        for address in addresses {
            if let std::net::IpAddr::V4(v4) = address.ip() {
                found.push(format!("{v4}:{port}"));
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// The port a URL implies: an explicit one, else 443 for https and 80 otherwise.
fn url_port(url: &str) -> u16 {
    let trimmed = url.trim();
    let after_scheme = trimmed.split_once("://").map(|(_, rest)| rest).unwrap_or(trimmed);
    let authority = after_scheme.split('/').next().unwrap_or("");
    // Userinfo precedes the host and may contain a colon of its own.
    let host_part = authority.rsplit('@').next().unwrap_or(authority);
    if let Some((_, port)) = host_part.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return port;
        }
    }
    if trimmed.starts_with("https://") {
        443
    } else {
        80
    }
}

pub fn host_from_url(url: &str) -> Option<String> {
    let rest = url.trim();
    let rest = rest
        .strip_prefix("https://")
        .or_else(|| rest.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Drop userinfo and the port; IPv6 literals keep their brackets.
    let host = match authority.rsplit_once('@') {
        Some((_, after)) => after,
        None => authority,
    };
    let host = if let Some(end) = host.strip_prefix('[') {
        format!("[{}]", end.split(']').next().unwrap_or(""))
    } else {
        host.split(':').next().unwrap_or("").to_string()
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || !is_plausible_host(&host) {
        None
    } else {
        Some(host)
    }
}

/// Merge the operator-wide allowlist with one project's own entries.
///
/// The global list is the operator's "allowed everywhere" set; a project's list is
/// what that project additionally needs. The union is what gets enforced.
///
/// Because deny rules are evaluated across the whole merged set before any allow
/// rule, a global `!host` still refuses a host that a project allows. That gives
/// the operator a single lever to ban something fleet-wide without editing every
/// project, and it is the main reason to keep two levels rather than collapse them
/// into one.
///
/// Duplicates are dropped case-insensitively so the merged list does not show the
/// same rule twice. Parsing is lenient and the problems are returned, so a caller
/// can report them instead of letting an entry sit in the list doing nothing.
pub fn effective(global: &[String], project: &[String]) -> (Allowlist, Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    let mut entries: Vec<String> = Vec::with_capacity(global.len() + project.len());
    for entry in global.iter().chain(project.iter()) {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !seen.insert(trimmed.to_ascii_lowercase()) {
            continue;
        }
        entries.push(trimmed.to_string());
    }
    Allowlist::parse_lenient(entries)
}

/// What an operator needs to know about a list before it is saved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Validation {
    /// Entries that will not parse, and therefore will not be enforced. These
    /// have to be fixed or removed: a rule the operator believes is protecting
    /// them, which is silently skipped, is worse than an error.
    pub problems: Vec<String>,
    /// Entries that parse and will be enforced, but widen access a great deal.
    /// Worth confirming rather than refusing, since they are occasionally what the
    /// operator actually wants.
    pub risky: Vec<String>,
}

impl Validation {
    pub fn is_acceptable(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Check a list before saving it.
///
/// The one entry that is *refused* rather than merely flagged is a blanket `*`.
/// It is the single rule that makes the allowlist meaningless, it is almost always
/// the result of a paste or a misunderstanding, and an operator who genuinely
/// wants no filtering has the unrestricted network mode for that. Everything else
/// over-broad -- a whole-TLD wildcard, a regex that matches every probe -- is
/// reported through `risky` so a UI can ask for confirmation.
pub fn validate(entries: &[String]) -> Validation {
    let mut problems = Vec::new();
    let mut risky = Vec::new();
    for entry in entries {
        if entry.trim().is_empty() {
            continue;
        }
        match Rule::parse(entry) {
            Ok(rule) => {
                if matches!(rule.matcher, HostMatcher::Any) {
                    problems.push(format!(
                        "'{}': a blanket '*' is not allowed here. Name the hosts this project needs, \
                         or switch the project to the unrestricted network mode if you really mean to \
                         allow everything.",
                        rule.raw
                    ));
                } else if rule.is_broad() {
                    risky.push(rule.raw.clone());
                }
            }
            Err(err) => problems.push(err),
        }
    }
    Validation { problems, risky }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> Allowlist {
        Allowlist::parse(entries).expect("entries should parse")
    }

    /* --------------------------------------------------------------------- */
    /* Acceptance criterion: api.github.com must not permit                   */
    /* api.github.com.attacker.com                                            */
    /* --------------------------------------------------------------------- */

    #[test]
    fn an_exact_host_does_not_permit_a_longer_hostname() {
        let allow = list(&["api.github.com"]);
        assert!(allow.decide("api.github.com", None, None).is_allowed());
        // The attack this guards against: a suffix match would permit this.
        assert_eq!(
            allow.decide("api.github.com.attacker.com", None, None),
            Decision::NoMatch
        );
        assert_eq!(
            allow.decide("attacker.com.api.github.com", None, None),
            Decision::NoMatch
        );
        assert_eq!(allow.decide("github.com", None, None), Decision::NoMatch);
    }

    #[test]
    fn an_exact_host_does_not_permit_a_prefix_either() {
        let allow = list(&["github.com"]);
        assert_eq!(allow.decide("api.github.com", None, None), Decision::NoMatch);
        assert_eq!(allow.decide("notgithub.com", None, None), Decision::NoMatch);
    }

    #[test]
    fn a_wildcard_covers_subdomains_but_not_the_apex_or_a_lookalike() {
        let allow = list(&["*.githubusercontent.com"]);
        assert!(allow.decide("raw.githubusercontent.com", None, None).is_allowed());
        assert!(allow.decide("a.b.githubusercontent.com", None, None).is_allowed());
        assert_eq!(
            allow.decide("githubusercontent.com", None, None),
            Decision::NoMatch
        );
        assert_eq!(
            allow.decide("raw.githubusercontent.com.attacker.com", None, None),
            Decision::NoMatch
        );
        assert_eq!(
            allow.decide("notgithubusercontent.com", None, None),
            Decision::NoMatch
        );
    }

    #[test]
    fn hostnames_are_compared_case_insensitively_and_without_a_trailing_dot() {
        let allow = list(&["Registry.NPMJS.org"]);
        assert!(allow.decide("registry.npmjs.org", None, None).is_allowed());
        assert!(allow.decide("REGISTRY.NPMJS.ORG.", None, None).is_allowed());
    }

    /* --------------------------------------------------------------------- */
    /* Deny precedence                                                        */
    /* --------------------------------------------------------------------- */

    #[test]
    fn a_deny_entry_beats_a_matching_allow_entry() {
        let allow = list(&["*.example.com", "!tracker.example.com"]);
        assert!(allow.decide("app.example.com", None, None).is_allowed());
        assert!(matches!(
            allow.decide("tracker.example.com", None, None),
            Decision::Denied { .. }
        ));
    }

    #[test]
    fn deny_precedence_does_not_depend_on_the_order_of_the_entries() {
        let deny_first = list(&["!tracker.example.com", "*.example.com"]);
        let deny_last = list(&["*.example.com", "!tracker.example.com"]);
        for allow in [deny_first, deny_last] {
            assert!(matches!(
                allow.decide("tracker.example.com", None, None),
                Decision::Denied { .. }
            ));
            assert!(allow.decide("app.example.com", None, None).is_allowed());
        }
    }

    #[test]
    fn a_deny_entry_beats_the_all_rule() {
        let allow = list(&["*", "!metadata.google.internal"]);
        assert!(allow.decide("example.com", None, None).is_allowed());
        assert!(matches!(
            allow.decide("metadata.google.internal", None, None),
            Decision::Denied { .. }
        ));
    }

    /* --------------------------------------------------------------------- */
    /* The default is to deny                                                 */
    /* --------------------------------------------------------------------- */

    #[test]
    fn an_empty_allowlist_denies_everything() {
        let allow = Allowlist::empty();
        assert_eq!(allow.decide("registry.npmjs.org", None, None), Decision::NoMatch);
        assert_eq!(allow.decide("example.com", Some("/x"), None), Decision::NoMatch);
    }

    #[test]
    fn the_developer_preset_permits_a_standard_install_flow() {
        let allow = Allowlist::developer_preset();
        // Acceptance criterion: git clone + npm install + npm test, no prompts.
        for host in [
            "github.com",
            "registry.npmjs.org",
            "pypi.org",
            "files.pythonhosted.org",
            "raw.githubusercontent.com",
            "objects.githubusercontent.com",
        ] {
            assert!(
                allow.decide(host, None, None).is_allowed(),
                "the developer preset should permit {host}"
            );
        }
        // And it should not be a blanket allow.
        for host in ["evil.example", "telemetry.vendor.io", "attacker.test"] {
            assert_eq!(
                allow.decide(host, None, None),
                Decision::NoMatch,
                "the developer preset must not permit {host}"
            );
        }
    }

    /* --------------------------------------------------------------------- */
    /* Regex entries                                                          */
    /* --------------------------------------------------------------------- */

    #[test]
    fn an_unanchored_regex_is_rejected_with_an_explanation() {
        let err = Rule::parse("re:github\\.com").unwrap_err();
        assert!(err.contains("anchored"), "unhelpful error: {err}");
        assert!(Rule::parse("re:^github\\.com").is_err());
        assert!(Rule::parse("re:github\\.com$").is_err());
    }

    #[test]
    fn an_anchored_regex_matches_the_full_hostname_only() {
        let allow = list(&[r"re:^api\d*\.example\.com$"]);
        assert!(allow.decide("api.example.com", None, None).is_allowed());
        assert!(allow.decide("api12.example.com", None, None).is_allowed());
        // Anchoring is what forbids these.
        assert_eq!(
            allow.decide("api.example.com.attacker.com", None, None),
            Decision::NoMatch
        );
        assert_eq!(
            allow.decide("xapi.example.com", None, None),
            Decision::NoMatch
        );
    }

    #[test]
    fn an_invalid_regex_is_rejected() {
        assert!(Rule::parse(r"re:^([a-z$").is_err());
    }

    /* --------------------------------------------------------------------- */
    /* Path prefixes                                                          */
    /* --------------------------------------------------------------------- */

    #[test]
    fn a_path_prefix_is_segment_aware() {
        let allow = list(&["github.com/org/repo"]);
        assert!(allow.decide("github.com", Some("/org/repo"), None).is_allowed());
        assert!(allow
            .decide("github.com", Some("/org/repo/tree/main"), None)
            .is_allowed());
        assert!(allow
            .decide("github.com", Some("/org/repo?tab=readme"), None)
            .is_allowed());
        // `/org/repository` must not be covered by the `/org/repo` prefix.
        assert_eq!(
            allow.decide("github.com", Some("/org/repository"), None),
            Decision::NoMatch
        );
        assert_eq!(
            allow.decide("github.com", Some("/other/repo"), None),
            Decision::NoMatch
        );
    }

    /// The documented HTTPS caveat: inside a CONNECT tunnel there is no path, so
    /// a path-prefixed rule degrades to host-only rather than being unenforceable
    /// and therefore silently ignored.
    #[test]
    fn a_path_prefix_degrades_to_host_only_when_the_transport_hides_the_path() {
        let allow = list(&["github.com/org/repo"]);
        assert_eq!(
            allow.decide("github.com", Some("/other/place"), None),
            Decision::NoMatch
        );
        // `None` means "opaque tunnel": the path cannot be checked.
        assert!(allow.decide("github.com", None, None).is_allowed());
    }

    #[test]
    fn a_path_prefix_cannot_be_attached_to_the_all_rule() {
        assert!(Rule::parse("*/org").is_err());
    }

    #[test]
    fn the_scope_note_admits_the_https_limitation() {
        let rule = Rule::parse("github.com/org/repo").unwrap();
        let note = rule.scope_note();
        assert!(note.contains("/org/repo"));
        assert!(note.contains("HTTPS"), "the note must mention the caveat");
        assert!(rule.path_is_enforceable());

        let plain = Rule::parse("github.com").unwrap();
        assert!(!plain.path_is_enforceable());
        assert!(!plain.scope_note().contains("HTTPS"));
    }

    /* --------------------------------------------------------------------- */
    /* Broad rules and exfiltration warnings                                  */
    /* --------------------------------------------------------------------- */

    #[test]
    fn the_all_rule_is_flagged_as_broad() {
        let allow = list(&["*"]);
        assert!(allow.decide("anything.example", None, None).is_allowed());
        let broad = allow.broad_allow_rules();
        assert_eq!(broad.len(), 1);
        assert_eq!(broad[0].raw, "*");
    }

    #[test]
    fn a_regex_that_matches_everything_is_flagged_as_broad() {
        let allow = list(&[r"re:^.*$"]);
        assert_eq!(allow.broad_allow_rules().len(), 1);
    }

    #[test]
    fn a_narrow_allowlist_has_nothing_to_warn_about() {
        let allow = Allowlist::developer_preset();
        assert!(allow.broad_allow_rules().is_empty());
    }

    #[test]
    fn a_broad_deny_rule_is_not_reported_as_an_exfiltration_risk() {
        // A deny rule cannot widen anything, so it must not generate a warning.
        let allow = list(&["example.com", "!*"]);
        assert!(allow.broad_allow_rules().is_empty());
    }

    /* --------------------------------------------------------------------- */
    /* Required hosts                                                         */
    /* --------------------------------------------------------------------- */

    #[test]
    fn a_required_host_is_allowed_even_when_the_rest_is_default_deny() {
        let allow = Allowlist::empty().with_required_hosts(["api.deepseek.com"]);
        assert!(allow.decide("api.deepseek.com", None, None).is_allowed());
        assert_eq!(allow.decide("example.com", None, None), Decision::NoMatch);
    }

    #[test]
    fn a_required_host_is_still_subject_to_deny_rules() {
        // An operator who explicitly denies the model endpoint gets that, rather
        // than an invisible rule quietly overriding their decision.
        let allow = Allowlist::empty()
            .with_required_hosts(["api.deepseek.com"])
            .with_entries(["!api.deepseek.com"]);
        assert!(matches!(
            allow.decide("api.deepseek.com", None, None),
            Decision::Denied { .. }
        ));
    }

    #[test]
    fn required_hosts_are_reported_separately_from_operator_entries() {
        let allow = Allowlist::empty().with_required_hosts(["api.deepseek.com"]);
        assert_eq!(allow.required_hosts(), ["api.deepseek.com"]);
        // They are not operator rules, so they never appear in the editable list.
        assert!(allow.to_entries().is_empty());
    }

    #[test]
    fn an_implausible_required_host_is_ignored_rather_than_inserted() {
        let allow = Allowlist::empty().with_required_hosts(["../../etc/passwd", ""]);
        assert!(allow.required_hosts().is_empty());
    }

    /* --------------------------------------------------------------------- */
    /* Parsing and message quality                                            */
    /* --------------------------------------------------------------------- */

    #[test]
    fn malformed_entries_are_reported_individually() {
        let problems = Allowlist::parse(["good.example", "re:nope", "*.", "!"]).unwrap_err();
        assert_eq!(problems.len(), 3, "got {problems:?}");
        assert!(problems.iter().all(|p| !p.is_empty()));
    }

    #[test]
    fn the_lenient_parse_keeps_the_good_entries_and_reports_the_rest() {
        let (allow, problems) = Allowlist::parse_lenient(["good.example", "re:nope"]);
        assert_eq!(problems.len(), 1);
        assert!(allow.decide("good.example", None, None).is_allowed());
    }

    #[test]
    fn a_wildcard_needs_a_domain_but_may_be_a_public_suffix() {
        // `*.` is meaningless and rejected.
        assert!(Rule::parse("*.").is_err());
        // `**.` and a wildcard in the middle are rejected: neither is a form the
        // matcher implements, so accepting them would imply support that is not
        // there.
        assert!(Rule::parse("**.example.com").is_err());
        assert!(Rule::parse("api.*.com").is_err());
        // A whole TLD is accepted but flagged, rather than pushed towards `*`.
        let tld = Rule::parse("*.com").expect("*.com should parse");
        assert!(tld.is_broad());
        // A normal wildcard is not broad.
        assert!(!Rule::parse("*.example.com").unwrap().is_broad());
    }

    #[test]
    fn the_decision_explanation_names_the_rule_responsible() {
        let allow = list(&["registry.npmjs.org", "!evil.example"]);
        let text = allow.decide("registry.npmjs.org", None, None).explain("registry.npmjs.org", None);
        assert!(text.contains("allowed"), "{text}");
        assert!(text.contains("registry.npmjs.org"), "{text}");

        let text = allow.decide("evil.example", None, None).explain("evil.example", None);
        assert!(text.contains("denied"), "{text}");

        let text = allow.decide("other.example", None, None).explain("other.example", None);
        assert!(text.contains("default is to deny"), "{text}");
    }

    #[test]
    fn entries_round_trip_through_the_textarea_representation() {
        let entries = ["registry.npmjs.org", "!tracker.example", r"re:^api\.x\.com$", "github.com/o/r"];
        let allow = list(&entries);
        assert_eq!(allow.to_entries(), entries);
        // And the re-parsed list behaves identically.
        let again = Allowlist::parse(allow.to_entries()).unwrap();
        assert!(again.decide("registry.npmjs.org", None, None).is_allowed());
        assert!(matches!(
            again.decide("tracker.example", None, None),
            Decision::Denied { .. }
        ));
    }

    #[test]
    fn every_shipped_preset_parses_and_is_not_broad() {
        for (name, entries) in presets() {
            let allow = Allowlist::parse(entries)
                .unwrap_or_else(|problems| panic!("preset {name} failed to parse: {problems:?}"));
            assert!(
                allow.broad_allow_rules().is_empty(),
                "preset {name} contains a blanket allow"
            );
            assert!(!allow.is_empty());
        }
    }

    #[test]
    fn preset_polyglot_permits_the_extra_ecosystems() {
        let allow = Allowlist::parse(POLYGLOT_PRESET).unwrap();
        for host in ["crates.io", "static.crates.io", "proxy.golang.org", "rubygems.org"] {
            assert!(allow.decide(host, None, None).is_allowed(), "missing {host}");
        }
    }

    /* --------------------------------------------------------------------- */
    /* Global + project merge                                                 */
    /* --------------------------------------------------------------------- */

    fn merged(global: &[&str], project: &[&str]) -> Allowlist {
        let global: Vec<String> = global.iter().map(|s| (*s).to_string()).collect();
        let project: Vec<String> = project.iter().map(|s| (*s).to_string()).collect();
        let (list, problems) = effective(&global, &project);
        assert!(problems.is_empty(), "unexpected problems: {problems:?}");
        list
    }

    #[test]
    fn the_effective_list_is_the_union_of_global_and_project() {
        let allow = merged(&["registry.npmjs.org"], &["api.example.com"]);
        assert!(allow.decide("registry.npmjs.org", None, None).is_allowed());
        assert!(allow.decide("api.example.com", None, None).is_allowed());
        assert_eq!(allow.decide("other.example", None, None), Decision::NoMatch);
    }

    /// The reason for keeping two levels: one lever to ban something everywhere.
    #[test]
    fn a_global_deny_overrides_a_project_allow() {
        let allow = merged(&["!metrics.vendor.io"], &["metrics.vendor.io", "app.example.com"]);
        assert!(matches!(
            allow.decide("metrics.vendor.io", None, None),
            Decision::Denied { .. }
        ));
        assert!(allow.decide("app.example.com", None, None).is_allowed());
    }

    #[test]
    fn a_project_deny_narrows_its_own_project_only() {
        let project_a = merged(&["*.example.com"], &["!internal.example.com"]);
        let project_b = merged(&["*.example.com"], &[]);
        assert!(matches!(
            project_a.decide("internal.example.com", None, None),
            Decision::Denied { .. }
        ));
        // Project B has no such deny, so the global wildcard still applies.
        assert!(project_b.decide("internal.example.com", None, None).is_allowed());
    }

    #[test]
    fn the_merge_is_case_insensitively_deduplicated() {
        let allow = merged(&["Registry.NPMJS.org"], &["registry.npmjs.org"]);
        assert_eq!(allow.to_entries().len(), 1, "{:?}", allow.to_entries());
        assert!(allow.decide("registry.npmjs.org", None, None).is_allowed());
    }

    #[test]
    fn the_merge_keeps_blank_lines_out_and_reports_bad_entries() {
        let global = vec!["good.example".to_string(), "   ".to_string()];
        let project = vec!["re:broken".to_string()];
        let (allow, problems) = effective(&global, &project);
        assert_eq!(allow.to_entries(), ["good.example"]);
        assert_eq!(problems.len(), 1, "{problems:?}");
    }

    #[test]
    fn the_merge_preserves_deny_order_independence_across_both_lists() {
        // A deny written in the project list must beat an allow written in the
        // global list, and vice versa.
        let a = merged(&["tracker.example"], &["!tracker.example"]);
        let b = merged(&["!tracker.example"], &["tracker.example"]);
        for allow in [a, b] {
            assert!(matches!(
                allow.decide("tracker.example", None, None),
                Decision::Denied { .. }
            ));
        }
    }

    /* --------------------------------------------------------------------- */
    /* Save-time validation                                                   */
    /* --------------------------------------------------------------------- */

    #[test]
    fn a_clean_list_validates_with_nothing_to_report() {
        let entries: Vec<String> = DEVELOPER_PRESET.iter().map(|s| (*s).to_string()).collect();
        let v = validate(&entries);
        assert!(v.is_acceptable(), "{v:?}");
        assert!(v.risky.is_empty(), "{v:?}");
    }

    #[test]
    fn a_blanket_all_is_refused_rather_than_flagged() {
        let v = validate(&["*".to_string()]);
        assert!(!v.is_acceptable());
        assert_eq!(v.problems.len(), 1);
        assert!(v.problems[0].contains("blanket"), "{:?}", v.problems);
        // The message has to point at the alternative.
        assert!(v.problems[0].contains("unrestricted"), "{:?}", v.problems);
    }

    #[test]
    fn an_over_broad_but_meaningful_entry_is_flagged_for_confirmation() {
        let v = validate(&["*.com".to_string(), "app.example.com".to_string()]);
        assert!(v.is_acceptable(), "a TLD wildcard should be allowed, not refused");
        assert_eq!(v.risky, ["*.com"]);
    }

    #[test]
    fn unparseable_entries_are_reported_with_their_own_message() {
        let v = validate(&["re:not-anchored".to_string(), "good.example".to_string()]);
        assert!(!v.is_acceptable());
        assert_eq!(v.problems.len(), 1);
        assert!(v.problems[0].contains("anchored"), "{:?}", v.problems);
    }

    #[test]
    fn the_new_entry_syntax_survives_validation() {
        // The old sanitizer silently dropped all of these, which is the bug this
        // replaces: !, re: and / are all meaningful now.
        for entry in [
            "!tracker.example.com",
            r"re:^api\d*\.example\.com$",
            "github.com/org/repo",
            "*.githubusercontent.com",
        ] {
            let v = validate(&[entry.to_string()]);
            assert!(v.is_acceptable(), "{entry} was refused: {:?}", v.problems);
        }
    }

    #[test]
    fn blank_entries_are_ignored_by_validation() {
        let v = validate(&["".to_string(), "   ".to_string(), "good.example".to_string()]);
        assert!(v.is_acceptable(), "{v:?}");
    }

    #[test]
    fn a_url_implies_its_port() {
        assert_eq!(super::url_port("https://api.example.com"), 443);
        assert_eq!(super::url_port("http://api.example.com"), 80);
        assert_eq!(super::url_port("https://api.example.com:8443/v1"), 8443);
        assert_eq!(super::url_port("https://user:secret@api.example.com/v1"), 443);
    }

    /// Resolution is real, so this only asserts the shape: whatever comes back must be
    /// `ip:port`, and a name that cannot resolve must give nothing rather than a guess.
    #[test]
    fn unresolvable_names_produce_no_endpoints() {
        assert!(endpoints_for_url("https://this-name-does-not-exist.invalid").is_empty());
        assert!(endpoints_for_url("").is_empty());
    }

    #[test]
    fn localhost_resolves_to_a_v4_endpoint_on_its_url_port() {
        let found = endpoints_for_url("http://localhost:9/");
        assert_eq!(found, vec!["127.0.0.1:9".to_string()]);
    }

    /* --------------------------------------------------------------------- */
    /* Ports                                                                  */
    /* --------------------------------------------------------------------- */

    #[test]
    fn an_entry_may_name_a_port() {
        let allow = list(&["example.com:8443"]);
        assert!(allow.decide("example.com", None, Some(8443)).is_allowed());
        for other in [443, 80, 8444, 1] {
            assert_eq!(
                allow.decide("example.com", None, Some(other)),
                Decision::NoMatch,
                "port {other} must not be covered by a rule written for 8443"
            );
        }
    }

    #[test]
    fn an_entry_without_a_port_covers_every_port() {
        let allow = list(&["example.com"]);
        for port in [1, 80, 443, 3306, 65535] {
            assert!(allow.decide("example.com", None, Some(port)).is_allowed());
        }
    }

    /// An unknown port is not "any port": a rule that names one must not match when the
    /// caller cannot say what the port is, or narrowing a rule would widen it instead.
    #[test]
    fn a_rule_that_names_a_port_does_not_match_an_unknown_port() {
        let allow = list(&["example.com:8443"]);
        assert_eq!(allow.decide("example.com", None, None), Decision::NoMatch);
        // ...while a rule that names no port still matches, which is what keeps this
        // usable for callers that only know the host.
        let any = list(&["example.com"]);
        assert!(any.decide("example.com", None, None).is_allowed());
    }

    #[test]
    fn a_deny_entry_with_a_port_only_denies_that_port() {
        let allow = list(&["example.com", "!example.com:22"]);
        assert!(allow.decide("example.com", None, Some(443)).is_allowed());
        assert!(matches!(
            allow.decide("example.com", None, Some(22)),
            Decision::Denied { .. }
        ));
    }

    #[test]
    fn a_port_cannot_be_attached_to_the_all_rule() {
        let err = Rule::parse("*:80").unwrap_err();
        assert!(err.contains("port"), "unhelpful error: {err}");
    }

    #[test]
    fn a_non_numeric_port_is_an_error_rather_than_a_hostname() {
        assert!(Rule::parse("example.com:http").is_err());
        assert!(Rule::parse("example.com:0").is_err());
        assert!(Rule::parse("example.com:99999").is_err());
    }

    #[test]
    fn a_port_survives_the_round_trip_through_the_textarea_form() {
        let entries = ["example.com:8443", "192.168.1.50:5432", "!db.internal:6379"];
        let allow = list(&entries);
        assert_eq!(allow.to_entries(), entries);
        let again = Allowlist::parse(allow.to_entries()).unwrap();
        assert!(again.decide("example.com", None, Some(8443)).is_allowed());
        assert!(matches!(
            again.decide("db.internal", None, Some(6379)),
            Decision::Denied { .. }
        ));
    }

    /* --------------------------------------------------------------------- */
    /* Address literals                                                       */
    /* --------------------------------------------------------------------- */

    #[test]
    fn an_address_entry_matches_the_literal_and_not_the_text() {
        let allow = list(&["192.168.1.50"]);
        assert!(allow.decide("192.168.1.50", None, Some(5432)).is_allowed());
        assert_eq!(allow.decide("192.168.1.51", None, Some(5432)), Decision::NoMatch);
        // A hostname is not an address, in either direction.
        assert_eq!(allow.decide("db.internal", None, Some(5432)), Decision::NoMatch);
    }

    #[test]
    fn an_address_entry_narrows_to_its_port_when_it_names_one() {
        let allow = list(&["192.168.1.50:5432"]);
        assert!(allow.decide("192.168.1.50", None, Some(5432)).is_allowed());
        assert_eq!(
            allow.decide("192.168.1.50", None, Some(6379)),
            Decision::NoMatch
        );
    }

    #[test]
    fn an_ipv6_address_may_be_bracketed_with_a_port() {
        let allow = list(&["[fe80::1]:8080"]);
        assert!(allow.decide("fe80::1", None, Some(8080)).is_allowed());
        assert_eq!(allow.decide("fe80::1", None, Some(8081)), Decision::NoMatch);
        // The bracketed form and the bare form are the same address.
        let bare = list(&["fe80::1"]);
        assert!(bare.decide("[fe80::1]", None, Some(9)).is_allowed());
    }

    /// A bare IPv6 literal has several colons, so it must not be read as a host with a
    /// port — doing so would silently narrow a rule that was meant to cover every port.
    #[test]
    fn a_bare_ipv6_literal_is_not_read_as_a_host_and_port() {
        let rule = Rule::parse("2001:db8::1").unwrap();
        assert_eq!(rule.port, None);
        assert!(rule.matches_host("2001:db8::1"));
        // The trailing group is a real address component, not a port.
        assert!(Rule::parse("2001:db8::1").unwrap().matches_port(Some(443)));
    }

    #[test]
    fn an_address_entry_is_flagged_as_neither_broad_nor_a_hostname() {
        let allow = list(&["127.0.0.1:8080"]);
        assert!(allow.broad_allow_rules().is_empty());
        assert!(validate(&["127.0.0.1:8080".to_string()]).is_acceptable());
    }

    /* --------------------------------------------------------------------- */
    /* What the netfilter and the publish flags are derived from              */
    /* --------------------------------------------------------------------- */

    #[test]
    fn direct_targets_are_only_the_address_entries_that_are_allowed() {
        let allow = list(&[
            "registry.npmjs.org",
            "192.168.1.50:5432",
            "127.0.0.1",
            "!10.0.0.9",
            "[fe80::1]:8080",
        ]);
        assert_eq!(
            allow.direct_targets(),
            vec![
                ("127.0.0.1".parse::<IpAddr>().unwrap(), None),
                ("192.168.1.50".parse::<IpAddr>().unwrap(), Some(5432)),
                ("fe80::1".parse::<IpAddr>().unwrap(), Some(8080)),
            ]
        );
    }

    #[test]
    fn a_denied_address_is_not_a_direct_target() {
        let allow = list(&["!192.168.1.50:5432"]);
        assert!(allow.direct_targets().is_empty());
    }

    #[test]
    fn published_ports_are_deduplicated_and_sorted() {
        let allow = list(&["192.168.1.50:5432", "127.0.0.1:5432", "10.0.0.1:3000"]);
        assert_eq!(allow.published_ports(), vec![3000, 5432]);
        // An entry with no port publishes nothing: it would otherwise publish every port.
        let no_port = list(&["127.0.0.1"]);
        assert!(no_port.published_ports().is_empty());
    }

    #[test]
    fn an_explicit_address_covers_its_port_and_an_unported_entry_covers_all() {
        let allow = list(&["192.168.1.50:5432", "127.0.0.1"]);
        let named = allow.explicit_addresses_for_port(5432);
        assert!(named.contains(&"192.168.1.50".parse().unwrap()));
        assert!(named.contains(&"127.0.0.1".parse().unwrap()));
        // Port 6379 is covered only by the entry that names no port.
        let other = allow.explicit_addresses_for_port(6379);
        assert!(!other.contains(&"192.168.1.50".parse().unwrap()));
        assert!(other.contains(&"127.0.0.1".parse().unwrap()));
    }

    /// `decide_host_only` is the reporting form: it answers "can this sandbox reach this
    /// destination at all", which is what telling the model it already has something
    /// needs. It must be wider than `decide`, and that difference is the point.
    #[test]
    fn the_host_only_decision_ignores_the_port_while_the_real_one_does_not() {
        let allow = list(&["192.168.1.50:5432"]);
        assert_eq!(allow.decide("192.168.1.50", None, Some(6379)), Decision::NoMatch);
        assert!(allow.decide_host_only("192.168.1.50").is_allowed());
    }
}
