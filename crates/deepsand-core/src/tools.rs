//! The catalogue of tools a sandbox can be given.
//!
//! A "tool" here is something installed into the runtime image, not something the
//! agent runs: the image is built per project, and the tools a project asked for are
//! baked in. That is why the catalogue is data rather than code -- the Dockerfile,
//! the GUI and the request broker all read the same table, so a tool cannot be
//! offered in one place and unavailable in another.
//!
//! # Two things worth knowing
//!
//! * **The container is always Linux**, even when Deepsand runs on Windows or macOS.
//!   So "incompatible with the host operating system" is not the useful test;
//!   what matters is the *base image*. `apk` is unavailable because the image is
//!   Debian, not because of the operator's platform. Availability is reported with
//!   its reason rather than hidden, so a greyed-out entry explains itself.
//! * **Latest versions are requested, not pinned.** Every provider asks for the
//!   newest release. That is what "up to date" means here, and the cost is that two
//!   builds a week apart need not produce the same image. The image records what it
//!   resolved to (see `TOOLS_MANIFEST`) so drift is visible rather than mysterious.
//!
//! # Network
//!
//! A tool may declare hosts it needs to reach. Those are added to the sandbox's
//! effective egress allowlist while the tool is enabled and removed when it is
//! switched off, so turning a capability on and off changes what the sandbox can
//! reach rather than leaving a door propped open.

use serde::{Deserialize, Serialize};

/// Which package mechanism installs a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Provider {
    /// `apt-get install`
    Apt,
    /// `apt-get install` after adding a third-party repository.
    AptRepo,
    /// `npm install -g`
    Npm,
    /// `pip install`
    Pip,
    /// `cargo install`
    Cargo,
    /// `go install`
    Go,
    /// `brew install` (Homebrew on Linux)
    Brew,
    /// `nix profile install`
    Nix,
    /// `apk add` (Alpine only)
    Apk,
    /// Already in the base image; enabling only asserts a minimum version.
    BuiltIn,
}

impl Provider {
    pub fn label(self) -> &'static str {
        match self {
            Provider::Apt => "apt",
            Provider::AptRepo => "apt (third-party repo)",
            Provider::Npm => "npm",
            Provider::Pip => "pip",
            Provider::Cargo => "cargo",
            Provider::Go => "go",
            Provider::Brew => "brew",
            Provider::Nix => "nix",
            Provider::Apk => "apk",
            Provider::BuiltIn => "built in",
        }
    }
}

/// The base image a tool needs. Kept separate from the host platform on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    /// Works on the Debian-based runtime image, which is the one Deepsand builds.
    Debian,
    /// Alpine only. Nothing Deepsand builds today uses it.
    Alpine,
    /// Any Linux base.
    Any,
}

impl Base {
    /// What to show the operator when a tool cannot be installed here.
    ///
    /// Naming the base rather than the host operating system is deliberate: Deepsand
    /// runs the same Linux container on Windows and macOS, so a tool is never
    /// unavailable because of the operator's platform. It is unavailable because the
    /// image is not the one it needs.
    pub fn label(self) -> &'static str {
        match self {
            Base::Debian => "Debian",
            Base::Alpine => "Alpine",
            Base::Any => "any Linux",
        }
    }

    /// The other base, for a sentence like "Alpine only; this image is Debian".
    fn is_other_image(self) -> bool {
        !matches!(self, Base::Any) && self != RUNTIME_BASE
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ToolCategory {
    /// Switched on for every new project unless the operator says otherwise.
    Utility,
    /// A language runtime or compiler.
    Language,
    /// Something that installs other things.
    PackageManager,
    /// Connectivity the agent can use.
    Capability,
}

impl ToolCategory {
    pub fn label(self) -> &'static str {
        match self {
            ToolCategory::Utility => "Utilities",
            ToolCategory::Language => "Languages",
            ToolCategory::PackageManager => "Package managers",
            ToolCategory::Capability => "Capabilities",
        }
    }
}

impl Default for ToolCategory {
    fn default() -> Self {
        ToolCategory::Utility
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Tool {
    pub id: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub category: ToolCategory,
    pub provider: Provider,
    /// What the provider is asked to install. A space-separated list for `apt`.
    pub package: &'static str,
    /// On for a new project unless switched off.
    pub default_on: bool,
    /// Hosts the tool needs to reach while it is enabled.
    pub hosts: &'static [&'static str],
    pub base: Base,
}

/// The base image Deepsand builds against. Changing this changes what is available.
pub const RUNTIME_BASE: Base = Base::Debian;

/// Every tool the GUI may offer.
pub const CATALOG: &[Tool] = &[
    /* --- default utilities ------------------------------------------------ */
    Tool {
        id: "jq",
        label: "jq",
        description: "Command-line JSON processor, for reading and reshaping API responses.",
        category: ToolCategory::Utility,
        provider: Provider::Apt,
        package: "jq",
        default_on: true,
        hosts: &[],
        base: Base::Debian,
    },
    Tool {
        id: "ripgrep",
        label: "ripgrep",
        description: "Very fast recursive search. What the agent reaches for instead of grep -r.",
        category: ToolCategory::Utility,
        provider: Provider::Apt,
        package: "ripgrep",
        default_on: true,
        hosts: &[],
        base: Base::Debian,
    },
    Tool {
        id: "curl",
        label: "curl",
        description: "HTTP client, for fetching a URL the agent has been allowed to reach.",
        category: ToolCategory::Utility,
        provider: Provider::Apt,
        package: "curl",
        default_on: true,
        hosts: &[],
        base: Base::Debian,
    },
    Tool {
        id: "zip",
        label: "zip / unzip",
        description: "Archive creation and extraction.",
        category: ToolCategory::Utility,
        provider: Provider::Apt,
        package: "zip unzip",
        default_on: true,
        hosts: &[],
        base: Base::Debian,
    },
    Tool {
        id: "htmlq",
        label: "htmlq",
        description: "CSS-selector queries over HTML, like jq for markup. Useful for scraping.",
        category: ToolCategory::Utility,
        provider: Provider::Cargo,
        package: "htmlq",
        default_on: true,
        hosts: &[],
        base: Base::Debian,
    },
    Tool {
        id: "git",
        label: "Git",
        description:
            "Version control. On by default because a development sandbox without git is hard to              use, but it is a tool like any other: switch it off and neither the binary nor the              git config ships.",
        category: ToolCategory::Utility,
        provider: Provider::Apt,
        package: "git",
        default_on: true,
        hosts: &[],
        base: Base::Debian,
    },
    /* --- capabilities ----------------------------------------------------- */
    Tool {
        id: "web-search",
        label: "Web search",
        description:
            "DeepCode's own web search. Needs the vendor's API, so it also opens that API in the \
             network filter while it is on.",
        category: ToolCategory::Capability,
        provider: Provider::BuiltIn,
        package: "",
        default_on: false,
        // The three hosts DeepCode resolves its search API to. Allowed only while
        // this tool is on, so switching search off closes them again.
        hosts: &[
            "deepcode.vegamo.cn",
            "www.deepcodeplus.com",
            "chat.deepcodeplus.com",
        ],
        base: Base::Any,
    },
    /* --- languages -------------------------------------------------------- */
    Tool {
        id: "node",
        label: "Node.js",
        description: "JavaScript runtime. Already in the base image; enabling asserts the newest line.",
        category: ToolCategory::Language,
        provider: Provider::AptRepo,
        package: "nodejs",
        default_on: false,
        hosts: &["deb.nodesource.com"],
        base: Base::Debian,
    },
    Tool {
        id: "npm",
        label: "npm",
        description: "JavaScript package manager, updated to the newest release.",
        category: ToolCategory::PackageManager,
        provider: Provider::Npm,
        package: "npm",
        default_on: false,
        hosts: &["registry.npmjs.org"],
        base: Base::Debian,
    },
    Tool {
        id: "python",
        label: "Python 3",
        description: "Python runtime with pip and a virtualenv module.",
        category: ToolCategory::Language,
        provider: Provider::Apt,
        package: "python3 python3-pip python3-venv",
        default_on: false,
        hosts: &["pypi.org", "files.pythonhosted.org"],
        base: Base::Debian,
    },
    Tool {
        id: "cargo",
        label: "Rust / cargo",
        description: "Rust toolchain via rustup, in the sandbox user's home.",
        category: ToolCategory::Language,
        provider: Provider::AptRepo,
        package: "cargo",
        default_on: false,
        hosts: &["sh.rustup.rs", "static.rust-lang.org", "crates.io", "static.crates.io"],
        base: Base::Debian,
    },
    Tool {
        id: "go",
        label: "Go",
        description: "Go toolchain, installed from the official tarball.",
        category: ToolCategory::Language,
        provider: Provider::AptRepo,
        package: "golang-go",
        default_on: false,
        hosts: &["go.dev", "proxy.golang.org", "sum.golang.org"],
        base: Base::Debian,
    },
    /* --- package managers ------------------------------------------------- */
    Tool {
        id: "apt",
        label: "apt",
        description:
            "Let the agent install Debian packages itself. This is the base image's own package \
             manager, and it can install almost anything, so treat it as the widest of these.",
        category: ToolCategory::PackageManager,
        provider: Provider::BuiltIn,
        package: "",
        default_on: false,
        hosts: &["deb.debian.org", "security.debian.org"],
        base: Base::Debian,
    },
    Tool {
        id: "apk",
        label: "apk",
        description: "Alpine's package manager.",
        category: ToolCategory::PackageManager,
        provider: Provider::Apk,
        package: "",
        default_on: false,
        hosts: &["dl-cdn.alpinelinux.org"],
        base: Base::Alpine,
    },
    Tool {
        id: "brew",
        label: "Homebrew",
        description: "Homebrew on Linux. Self-contained under the sandbox user's home.",
        category: ToolCategory::PackageManager,
        provider: Provider::Brew,
        package: "",
        default_on: false,
        hosts: &["brew.sh", "github.com", "*.githubusercontent.com"],
        base: Base::Debian,
    },
    Tool {
        id: "nix",
        label: "Nix",
        description:
            "Nix with flakes. Gives reproducible per-project toolchains, at the cost of a large \
             image and a slower first build.",
        category: ToolCategory::PackageManager,
        provider: Provider::Nix,
        package: "",
        default_on: false,
        hosts: &["nixos.org", "cache.nixos.org", "releases.nixos.org"],
        base: Base::Debian,
    },
];

/// Why a tool cannot be installed, or `None` when it can.
pub fn unavailable_reason(tool: &Tool) -> Option<String> {
    if tool.base == Base::Any || tool.base == RUNTIME_BASE {
        return None;
    }
    if tool.base.is_other_image() {
        return Some(format!(
            "'{}' needs a {} image. The Deepsand runtime image is {}, so it cannot be installed \
             here and is switched off.",
            tool.label,
            tool.base.label(),
            RUNTIME_BASE.label()
        ));
    }
    None
}

pub fn is_available(tool: &Tool) -> bool {
    unavailable_reason(tool).is_none()
}

pub fn find(id: &str) -> Option<&'static Tool> {
    CATALOG.iter().find(|tool| tool.id == id)
}

/// The tools a new project starts with.
///
/// Empty, deliberately. A tool is minutes of build time and a larger image, and most of the
/// catalogue is only needed by some projects; a sandbox that starts with nothing installs
/// exactly what its project asked for and no more. The catalogue is one dialog away, and an
/// empty selection is a first-class choice everywhere else, so this is not a special case.
pub fn default_selection() -> Vec<String> {
    Vec::new()
}

/// The tools a project from before the tool system is given.
///
/// This list used to be the default for everything. A project with no stored selection has
/// to keep resolving to the image it already has -- the one its tools were built into -- so
/// the old list lives here, for `resolve(None)` only. New projects never see it, and the
/// only way to reach it is to have been created before there was a choice.
fn legacy_selection() -> Vec<String> {
    CATALOG
        .iter()
        .filter(|tool| tool.default_on && is_available(tool))
        .map(|tool| tool.id.to_string())
        .collect()
}

/// The set of tools that will actually be installed for a project.
///
/// `None` means the project predates the tool system, so it keeps the tools that were
/// the default when it was created -- which is what its image already contains. An
/// explicit list is honoured as given, including an empty one, so "no tools" is
/// expressible, and it is now what a new project starts with.
pub fn resolve(selection: Option<&[String]>) -> Vec<&'static Tool> {
    let ids: Vec<String> = match selection {
        Some(ids) => ids.to_vec(),
        None => legacy_selection(),
    };
    let mut tools: Vec<&'static Tool> = ids
        .iter()
        .filter_map(|id| find(id))
        .filter(|tool| is_available(tool))
        .collect();
    tools.sort_by_key(|tool| tool.id);
    tools.dedup_by_key(|tool| tool.id);
    tools
}

/// The concrete work needed to install a selection.
///
/// This is the single place the catalogue's `provider`/`package` pair is translated
/// into the commands the image build runs. Keeping it here means a tool cannot be
/// listed in the GUI as installable while the Dockerfile quietly does nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstallPlan {
    /// Passed to one `apt-get install`.
    pub apt: Vec<String>,
    /// Installed globally with npm, at `@latest`.
    pub npm: Vec<String>,
    /// Installed with `cargo install`.
    pub cargo: Vec<String>,
    /// A toolchain that needs a bespoke installer rather than a package.
    pub rustup: bool,
    pub go: bool,
    pub brew: bool,
    pub nix: bool,
    /// Add the NodeSource repository so `nodejs` is a current line, not Debian's.
    pub node_repo: bool,
    /// The ids this plan came from, for the image label.
    pub ids: Vec<String>,
}

impl InstallPlan {
    /// Whether anything at all will be installed.
    pub fn is_empty(&self) -> bool {
        self.apt.is_empty()
            && self.npm.is_empty()
            && self.cargo.is_empty()
            && !self.rustup
            && !self.go
            && !self.brew
            && !self.nix
            && !self.node_repo
    }
}

pub fn install_plan(selection: Option<&[String]>) -> InstallPlan {
    let mut plan = InstallPlan::default();
    for tool in resolve(selection) {
        plan.ids.push(tool.id.to_string());
        match tool.provider {
            Provider::Apt => {
                for package in tool.package.split_whitespace() {
                    plan.apt.push(package.to_string());
                }
            }
            Provider::Npm => plan.npm.push(tool.package.to_string()),
            Provider::Cargo => plan.cargo.push(tool.package.to_string()),
            // `AptRepo` means "not a plain Debian package". Which bespoke installer
            // is needed depends on the tool, so the ids are matched explicitly here
            // rather than guessed from the package name.
            Provider::AptRepo => match tool.id {
                "node" => plan.node_repo = true,
                "cargo" => plan.rustup = true,
                "go" => plan.go = true,
                other => {
                    debug_assert!(false, "{other} uses AptRepo with no installer mapped");
                    for package in tool.package.split_whitespace() {
                        plan.apt.push(package.to_string());
                    }
                }
            },
            Provider::Pip => {
                for package in tool.package.split_whitespace() {
                    plan.apt.push(format!("python3-{package}"));
                }
            }
            Provider::Go => plan.go = true,
            Provider::Brew => plan.brew = true,
            Provider::Nix => plan.nix = true,
            // Unavailable on this base image, so `resolve` already dropped it.
            Provider::Apk => {}
            // Already in the image: enabling it only documents the intent, which the
            // label records. Nothing is installed.
            Provider::BuiltIn => {}
        }
    }
    plan.apt.sort();
    plan.apt.dedup();
    plan.npm.sort();
    plan.npm.dedup();
    plan.cargo.sort();
    plan.cargo.dedup();
    plan
}

/// Hosts contributed by the enabled tools, for the egress allowlist.
///
/// Derived rather than stored, so it cannot fall out of step with the selection:
/// switching a tool off removes its hosts in the same operation.
pub fn hosts_for(selection: Option<&[String]>) -> Vec<String> {
    let mut hosts: Vec<String> = resolve(selection)
        .iter()
        .flat_map(|tool| tool.hosts.iter().map(|host| (*host).to_string()))
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// The image tag that carries a tool selection.
///
/// Tools are installed into the image, and projects want different tools, so a single
/// shared tag would mean the last project built decided everyone else's toolchain --
/// a bug that would look like "my tools vanished" and be very hard to explain. The
/// selection is folded into the tag instead, so each distinct selection gets its own
/// image and Docker's layer cache still does the right thing.
///
/// FNV-1a, chosen because it is short, deterministic and dependency-free; this is a
/// cache key, not a security boundary.
pub fn image_for(base: &str, selection: Option<&[String]>) -> String {
    let argument = build_argument(selection);
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in argument.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{base}-t{hash:08x}")
}

/// The ids to pass to the image build, in a stable order so identical selections
/// produce identical build arguments (and therefore reuse cache).
pub fn build_argument(selection: Option<&[String]>) -> String {
    resolve(selection)
        .iter()
        .map(|tool| tool.id)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(tools: &[&Tool]) -> Vec<String> {
        tools.iter().map(|tool| tool.id.to_string()).collect()
    }

    #[test]
    fn the_catalogue_has_unique_ids_and_no_blank_labels() {
        let mut seen = std::collections::HashSet::new();
        for tool in CATALOG {
            assert!(seen.insert(tool.id), "duplicate tool id: {}", tool.id);
            assert!(!tool.label.trim().is_empty(), "{} has no label", tool.id);
            assert!(
                !tool.description.trim().is_empty(),
                "{} has no description, so the GUI cannot explain it",
                tool.id
            );
        }
    }

    /// Nothing is installed unless the operator asked for it.
    #[test]
    fn no_tool_is_on_by_default() {
        assert!(
            default_selection().is_empty(),
            "a new project should start with no tools"
        );
        // The ones that used to be on are still there to be chosen -- the default changed,
        // the catalogue did not.
        for id in ["git", "jq", "ripgrep", "curl", "zip", "htmlq"] {
            assert!(find(id).is_some(), "{id} left the catalogue");
        }
    }

    /// `tree` was explicitly excluded from the defaults.
    #[test]
    fn tree_is_not_in_the_catalogue() {
        assert!(find("tree").is_none());
        assert!(!default_selection().contains(&"tree".to_string()));
    }

    #[test]
    fn every_tool_the_operator_asked_for_exists() {
        for id in [
            "git", "npm", "node", "python", "cargo", "go", "brew", "nix", "apt", "apk",
        ] {
            assert!(find(id).is_some(), "{id} is missing from the catalogue");
        }
    }

    /* --- availability ----------------------------------------------------- */

    #[test]
    fn an_alpine_package_manager_is_unavailable_on_a_debian_image() {
        let apk = find("apk").expect("apk exists");
        let reason = unavailable_reason(apk).expect("apk should be unavailable");
        // The reason has to say why, not just refuse.
        assert!(reason.contains("Alpine"), "{reason}");
        assert!(reason.contains("Debian"), "{reason}");
        assert!(!is_available(apk));
    }

    #[test]
    fn everything_else_is_available_on_the_runtime_image() {
        for tool in CATALOG.iter().filter(|tool| tool.id != "apk") {
            assert!(
                is_available(tool),
                "{} should be installable: {:?}",
                tool.id,
                unavailable_reason(tool)
            );
        }
    }

    #[test]
    fn an_unavailable_tool_is_never_installed_even_if_selected() {
        let selection = vec!["apk".to_string(), "jq".to_string()];
        assert_eq!(ids(&resolve(Some(&selection))), ["jq"]);
    }

    /* --- selection -------------------------------------------------------- */

    /// A project from before the tool system keeps the tools its image was built with.
    #[test]
    fn no_selection_means_the_tools_from_before_the_tool_system() {
        let kept = ids(&resolve(None));
        assert_eq!(kept, {
            let mut legacy = legacy_selection();
            legacy.sort();
            legacy
        });
        assert!(!kept.is_empty(), "an older project must not lose the tools it has");
    }

    #[test]
    fn an_explicit_empty_selection_installs_nothing() {
        // "No tools" has to be expressible, or the defaults could never be removed.
        assert!(resolve(Some(&[])).is_empty());
    }

    #[test]
    fn an_unknown_id_is_ignored_rather_than_failing_the_build() {
        let selection = vec!["jq".to_string(), "not-a-tool".to_string()];
        assert_eq!(ids(&resolve(Some(&selection))), ["jq"]);
    }

    #[test]
    fn duplicates_are_collapsed() {
        let selection = vec!["jq".to_string(), "jq".to_string()];
        assert_eq!(ids(&resolve(Some(&selection))), ["jq"]);
    }

    #[test]
    fn the_build_argument_is_stable_for_the_same_selection() {
        let a = vec!["ripgrep".to_string(), "jq".to_string()];
        let b = vec!["jq".to_string(), "ripgrep".to_string()];
        assert_eq!(build_argument(Some(&a)), build_argument(Some(&b)));
        assert_eq!(build_argument(Some(&a)), "jq,ripgrep");
    }

    /* --- the install plan -------------------------------------------------- */

    #[test]
    fn the_default_plan_installs_the_default_utilities() {
        let plan = install_plan(None);
        for package in ["git", "jq", "ripgrep", "curl", "zip", "unzip"] {
            assert!(plan.apt.contains(&package.to_string()), "apt is missing {package}");
        }
        // htmlq is a Rust binary, so it comes from cargo rather than apt.
        assert_eq!(plan.cargo, ["htmlq"]);
        assert!(!plan.is_empty());
    }

    /// Each bespoke toolchain has to map to its own installer, or the image would
    /// silently install the wrong (or no) thing.
    #[test]
    fn the_bespoke_toolchains_map_to_their_installers() {
        let plan = install_plan(Some(&[
            "node".to_string(),
            "cargo".to_string(),
            "go".to_string(),
            "brew".to_string(),
            "nix".to_string(),
        ]));
        assert!(plan.node_repo, "node needs the NodeSource repository");
        assert!(plan.rustup, "cargo needs rustup");
        assert!(plan.go, "go needs its own installer");
        assert!(plan.brew, "brew needs its own installer");
        assert!(plan.nix, "nix needs its own installer");
        // None of them should have leaked into the plain apt list.
        assert!(plan.apt.is_empty(), "unexpected apt packages: {:?}", plan.apt);
    }

    #[test]
    fn an_empty_selection_produces_an_empty_plan() {
        assert!(install_plan(Some(&[])).is_empty());
    }

    /// A built-in capability installs nothing but still has to be recorded.
    #[test]
    fn a_builtin_capability_records_its_id_without_installing() {
        let plan = install_plan(Some(&["web-search".to_string()]));
        assert!(plan.is_empty(), "web search has nothing to install");
        assert_eq!(plan.ids, ["web-search"]);
    }

    #[test]
    fn the_plan_is_deduplicated_and_stable() {
        let a = install_plan(Some(&["jq".to_string(), "ripgrep".to_string()]));
        let b = install_plan(Some(&["ripgrep".to_string(), "jq".to_string()]));
        assert_eq!(a.apt, b.apt);
        assert_eq!(a.ids, b.ids);
    }

    /* --- image tags -------------------------------------------------------- */

    #[test]
    fn different_selections_get_different_images() {
        let a = image_for("deepsand/runtime:0.1.0", Some(&["jq".to_string()]));
        let b = image_for("deepsand/runtime:0.1.0", Some(&["jq".to_string(), "go".to_string()]));
        assert_ne!(a, b, "two selections must not share one image");
        assert!(a.starts_with("deepsand/runtime:0.1.0-t"), "{a}");
    }

    #[test]
    fn the_same_selection_always_maps_to_the_same_tag() {
        // Order must not matter, or a project would rebuild its image on every save.
        let a = image_for("base", Some(&["go".to_string(), "jq".to_string()]));
        let b = image_for("base", Some(&["jq".to_string(), "go".to_string()]));
        assert_eq!(a, b);
        assert_eq!(a, image_for("base", Some(&["go".to_string(), "jq".to_string()])));
    }

    #[test]
    fn an_empty_selection_and_the_defaults_differ() {
        assert_ne!(image_for("base", None), image_for("base", Some(&[])));
    }

    /* --- the bulk selections ---------------------------------------------- */

    /// What the "Enable all tools" button sends: every tool this image can hold.
    #[test]
    fn every_available_tool_together_produces_a_usable_plan() {
        let all: Vec<String> = CATALOG
            .iter()
            .filter(|tool| is_available(tool))
            .map(|tool| tool.id.to_string())
            .collect();

        let plan = install_plan(Some(&all));
        // Nothing silently dropped: a button that says "all" must install all.
        assert_eq!(plan.ids.len(), all.len());
        // `apk` cannot be installed here, so it must not be in the list at all.
        assert!(!plan.ids.contains(&"apk".to_string()));

        // The heavy installers are all requested, which is what makes this the largest
        // image Deepsand can build -- and why the UI warns about it.
        assert!(plan.brew, "brew should be requested");
        assert!(plan.nix, "nix should be requested");
        assert!(plan.rustup, "rustup should be requested");
        assert!(plan.go, "go should be requested");
        assert!(plan.node_repo, "the node repository should be requested");

        // No duplicate packages: apt would accept them, but the build argument would
        // change for no reason and invalidate the cache layer.
        let mut sorted = plan.apt.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(plan.apt, sorted, "apt packages must be deduplicated");

        // And it is a different image from the defaults, so switching to it builds
        // rather than silently reusing the default image.
        assert_ne!(image_for("base", Some(&all)), image_for("base", None));
    }

    /// What "Disable all tools" sends: an explicit empty list.
    #[test]
    fn switching_everything_off_is_expressed_and_distinct_from_the_defaults() {
        let off = image_for("base", Some(&[]));
        assert_ne!(off, image_for("base", None), "off must not look like the defaults");
        assert!(install_plan(Some(&[])).is_empty());
        assert!(hosts_for(Some(&[])).is_empty());
    }

    /* --- network ---------------------------------------------------------- */

    #[test]
    fn the_search_tool_contributes_the_vendor_domains() {
        let hosts = hosts_for(Some(&["web-search".to_string()]));
        assert_eq!(
            hosts,
            ["chat.deepcodeplus.com", "deepcode.vegamo.cn", "www.deepcodeplus.com"]
        );
    }

    /// The behaviour the operator asked for: switching search off closes the door
    /// again, rather than leaving it propped open from an earlier session.
    #[test]
    fn switching_search_off_removes_its_hosts() {
        let on = hosts_for(Some(&["web-search".to_string()]));
        let off = hosts_for(Some(&[]));
        assert!(!on.is_empty());
        assert!(off.is_empty());
        for host in on {
            assert!(!off.contains(&host), "{host} lingered after search was switched off");
        }
    }

    #[test]
    fn a_default_utility_contributes_no_hosts() {
        assert!(hosts_for(Some(&["jq".to_string(), "ripgrep".to_string()])).is_empty());
    }

    #[test]
    fn tool_hosts_are_deduplicated() {
        let hosts = hosts_for(Some(&["brew".to_string(), "go".to_string()]));
        let mut sorted = hosts.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(hosts, sorted);
    }

    /* --- serialisation ---------------------------------------------------- */

    #[test]
    fn a_project_without_a_tool_selection_still_loads() {
        // An older project has no `tools` key at all; it must resolve to defaults
        // rather than to nothing, or every existing image would silently lose jq.
        let selection: Option<Vec<String>> = None;
        assert!(!resolve(selection.as_deref()).is_empty());
    }
}
