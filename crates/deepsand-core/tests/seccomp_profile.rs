//! Claims about the seccomp profile that is attached to every sandbox.
//!
//! Round 3 of the escape assessment found the pattern this file exists to break:
//! the deny-list covered `unshare` but not `clone`, and `ptrace` but not
//! `pidfd_getfd`. The primitive that gets forgotten is the sibling of one that is
//! listed, and it is forgotten silently. So these tests enumerate families and flags
//! instead of naming single primitives, and they assert the *union* is covered rather
//! than that one entry is present.
//!
//! They read `runtime/seccomp-hardened.json` from the repository, so they run without
//! Docker. What they cannot check is whether a given image bundles those same bytes;
//! only the running container can answer that, which is why
//! `deepsand_core::seccomp::verify_against_image` exists.

use std::collections::BTreeSet;

/// `CLONE_NEW*` bits, from `include/uapi/linux/sched.h`.
///
/// Each needs its own rule: several `args` entries inside one rule are ANDed together,
/// and `SCMP_CMP_MASKED_EQ` tests one bit at a time, so "any of these bits" can only be
/// spelled as one rule per bit. That is why the profile has eight `clone` rules.
const CLONE_NEW_BITS: [(&str, u64); 8] = [
    ("CLONE_NEWTIME", 0x0000_0080),
    ("CLONE_NEWNS", 0x0002_0000),
    ("CLONE_NEWCGROUP", 0x0200_0000),
    ("CLONE_NEWUTS", 0x0400_0000),
    ("CLONE_NEWIPC", 0x0800_0000),
    ("CLONE_NEWUSER", 0x1000_0000),
    ("CLONE_NEWPID", 0x2000_0000),
    ("CLONE_NEWNET", 0x4000_0000),
];

/// Address families the profile filters out, and the ones it must leave alone.
///
/// Only families a kernel actually registers need a rule; an unregistered family is
/// refused by the kernel itself, and `EAFNOSUPPORT` cannot tell the two apart. These
/// five are the ones that carry an escape or a side channel: `AF_VSOCK` reaches the
/// hypervisor (that was F3 in round 1), `AF_PACKET` is raw frames, and `AF_TIPC`,
/// `AF_ALG` and `AF_XDP` are all reachable non-IP transports.
const FILTERED_FAMILIES: [u64; 5] = [17 /* AF_PACKET */, 30 /* AF_TIPC */, 38 /* AF_ALG */, 40 /* AF_VSOCK */, 44 /* AF_XDP */];

/// The families ordinary work needs, and which a careless widening would break.
const REQUIRED_FAMILIES: [(&str, u64); 4] = [
    ("AF_UNIX", 1),    // the MCP bridge
    ("AF_INET", 2),    // the model API, package installs
    ("AF_INET6", 10),  // the same, wherever the network is v6
    ("AF_NETLINK", 16), // node and glibc use it for interface information
];

fn profile() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("runtime")
        .join("seccomp-hardened.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("could not read {}: {err}", path.display()));
    let parsed: serde_json::Value =
        serde_json::from_str(&raw).expect("the seccomp profile must be valid JSON");
    assert_eq!(
        parsed["defaultAction"].as_str(),
        Some("SCMP_ACT_ALLOW"),
        "the profile is a denylist over an allow default; changing that is a decision, not a tidy-up"
    );
    parsed
}

fn rules<'a>(profile: &'a serde_json::Value, syscall: &str) -> Vec<&'a serde_json::Value> {
    profile["syscalls"]
        .as_array()
        .expect("syscalls is an array")
        .iter()
        .filter(|rule| {
            rule["names"]
                .as_array()
                .expect("names is an array")
                .iter()
                .any(|name| name.as_str() == Some(syscall))
        })
        .collect()
}

/// This syscall is refused outright, whatever its arguments. Returns the errno.
fn wholesale_errno(profile: &serde_json::Value, syscall: &str) -> Option<i64> {
    rules(profile, syscall)
        .into_iter()
        .find(|rule| rule.get("args").is_none())
        .and_then(|rule| {
            assert_eq!(rule["action"].as_str(), Some("SCMP_ACT_ERRNO"));
            rule["errnoRet"].as_i64()
        })
}

fn assert_refused(profile: &serde_json::Value, syscall: &str) {
    assert!(
        wholesale_errno(profile, syscall).is_some(),
        "`{syscall}` is not refused by the profile"
    );
}

#[test]
fn hardening_is_a_denylist_and_every_rule_denies() {
    let profile = profile();
    let rules = profile["syscalls"].as_array().expect("syscalls");
    assert!(!rules.is_empty());
    for rule in rules {
        assert_eq!(
            rule["action"].as_str(),
            Some("SCMP_ACT_ERRNO"),
            "the profile only ever denies; an allow rule here would be a hole: {rule}"
        );
        assert!(
            rule.get("comment").is_some(),
            "every rule states its reason, so an auditor reading the artifact can see it: {rule}"
        );
    }
}

#[test]
fn every_filtered_address_family_is_refused() {
    let profile = profile();
    let socket_rules = rules(&profile, "socket");
    let mut filtered = BTreeSet::new();
    for rule in &socket_rules {
        let args = rule["args"]
            .as_array()
            .expect("a socket rule that names no family denies nothing");
        assert_eq!(args.len(), 1, "one family per rule, so they are OR'd: {rule}");
        assert_eq!(args[0]["index"].as_u64(), Some(0), "arg 0 is the family");
        assert_eq!(
            args[0]["op"].as_str(),
            Some("SCMP_CMP_EQ"),
            "an exact family match; MASKED_EQ would also work, but EQ is what the profile uses"
        );
        assert_eq!(
            rule["errnoRet"].as_i64(),
            Some(97),
            "EAFNOSUPPORT, the errno a missing family returns: {rule}"
        );
        filtered.insert(args[0]["value"].as_u64().expect("a numeric family"));
    }

    for family in FILTERED_FAMILIES {
        assert!(
            filtered.contains(&family),
            "address family {family} is not filtered; AF_VSOCK(40) is the one that reached a root shell in round 1"
        );
    }
    for (name, family) in REQUIRED_FAMILIES {
        assert!(
            !filtered.contains(&family),
            "{name}({family}) must keep working or the sandbox cannot reach its own model API"
        );
    }
}

#[test]
fn clone_is_refused_when_any_namespace_flag_is_set() {
    let profile = profile();
    let clone_rules = rules(&profile, "clone");
    assert!(
        !clone_rules.is_empty(),
        "`clone` needs an argument filter: `unshare` is denied, but CLONE_NEWUSER needs no capability and reaches the same place"
    );

    let mut covered = BTreeSet::new();
    for rule in &clone_rules {
        assert_eq!(rule["action"].as_str(), Some("SCMP_ACT_ERRNO"));
        assert_eq!(rule["errnoRet"].as_i64(), Some(1), "EPERM");
        let args = rule["args"].as_array().expect("clone rules filter by flag");
        assert_eq!(args.len(), 1);
        assert_eq!(args[0]["index"].as_u64(), Some(0), "arg 0 is the flag word");
        assert_eq!(args[0]["op"].as_str(), Some("SCMP_CMP_MASKED_EQ"));
        covered.insert(args[0]["value"].as_u64().expect("a numeric bit"));
    }

    for (name, bit) in CLONE_NEW_BITS {
        assert!(
            covered.contains(&bit),
            "{name} (0x{bit:x}) is not covered: one rule per bit, because a rule with several args is ANDed"
        );
    }
    for bit in CLONE_NEW_BITS.map(|(_, bit)| bit) {
        assert!(
            bit.count_ones() == 1,
            "0x{bit:x} is not a single bit, so MASKED_EQ would not mean \"this flag is set\""
        );
    }
}

#[test]
fn namespace_syscalls_are_refused_wholesale() {
    let profile = profile();
    for syscall in ["unshare", "setns", "mount", "umount", "pivot_root", "chroot"] {
        assert_refused(&profile, syscall);
    }
    assert_eq!(
        wholesale_errno(&profile, "clone3"),
        Some(38),
        "clone3 returns ENOSYS so glibc falls back to the argument-filterable `clone`"
    );
}

#[test]
fn the_ptrace_family_is_closed_including_pidfd_getfd() {
    let profile = profile();
    // Duplicating another process's descriptors is the capability ptrace was disabled to
    // remove, and round 3 measured it working between same-uid processes in the sandbox.
    for syscall in ["ptrace", "process_vm_readv", "process_vm_writev", "pidfd_getfd", "kcmp"] {
        assert_refused(&profile, syscall);
    }
    // pidfd_open is left allowed on purpose: it only yields a handle, and the runtime may
    // use it to wait on children. Denying it would be hardening with a real chance of
    // breaking the process tree for no gain.
    assert!(
        wholesale_errno(&profile, "pidfd_open").is_none(),
        "pidfd_open is deliberately allowed; if that changes, change this expectation on purpose"
    );
}

#[test]
fn the_mount_api_siblings_of_mount_are_refused() {
    let profile = profile();
    // The new mount API reaches the same kernel paths as mount(2). They are refused today
    // because they need CAP_SYS_ADMIN and the capability set is empty, but listing them
    // means the closure does not depend on that second control surviving.
    for syscall in [
        "fsopen",
        "fsconfig",
        "fsmount",
        "fspick",
        "move_mount",
        "open_tree",
        "mount_setattr",
    ] {
        assert_refused(&profile, syscall);
    }
}

#[test]
fn the_other_escape_primitives_from_round_three_stay_refused() {
    let profile = profile();
    for syscall in [
        "bpf",
        "keyctl",
        "add_key",
        "request_key",
        "perf_event_open",
        "userfaultfd",
        "open_by_handle_at",
        "name_to_handle_at",
        "init_module",
        "finit_module",
        "kexec_load",
        "kexec_file_load",
        "reboot",
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
    ] {
        assert_refused(&profile, syscall);
    }
}

/// Every masked comparison has to say what the masked bits must equal.
///
/// For `SCMP_CMP_MASKED_EQ` the first value is the *mask* and `valueTwo` is what the masked bits are
/// compared against. With `valueTwo` absent it defaults to zero, so the rule matches every call where
/// those bits are *clear* -- the opposite of what each of these rules intends. This is not
/// hypothetical: it made the eight `clone` rules block `fork` itself, and every sandbox exited on
/// start with `FATAL tini (1)] fork failed: Operation not permitted`, which from the window looked
/// like a launch that hung with no container and no error. The earlier test here checked that a
/// masked comparison *existed*, which it did, while the profile was inverted.
#[test]
fn every_masked_comparison_says_what_the_bits_must_equal() {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../runtime/seccomp-hardened.json"),
    )
    .expect("the profile ships with the crate");
    let profile: serde_json::Value = serde_json::from_str(&text).expect("valid json");

    let mut checked = 0;
    for rule in profile["syscalls"].as_array().expect("syscalls") {
        let name = rule["names"][0].as_str().unwrap_or("?");
        for arg in rule["args"].as_array().cloned().unwrap_or_default() {
            if arg["op"].as_str() != Some("SCMP_CMP_MASKED_EQ") {
                continue;
            }
            let mask = arg["value"].as_u64().expect("a mask");
            let wanted = arg["valueTwo"].as_u64().unwrap_or_else(|| {
                panic!("{name}: a masked comparison with no valueTwo means \"bits clear\", not \"bit set\"")
            });
            assert_eq!(
                wanted, mask,
                "{name}: these rules block a flag by setting it, so the wanted bits are the mask"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 8, "the eight clone namespace flags");
}
