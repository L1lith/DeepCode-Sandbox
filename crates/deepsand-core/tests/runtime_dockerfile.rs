//! Claims about `runtime/Dockerfile` that can be checked without Docker.
//!
//! The image build is the one part of Deepsand that needs a container, a network and
//! several minutes, which is exactly why a bug in it is expensive: it is found by an
//! operator pressing Run, not by a test run.

use std::path::PathBuf;

fn dockerfile() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("runtime")
        .join("Dockerfile");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("could not read {}: {err}", path.display()))
}

/// The app passes the tool plan to the image as comma-separated lists, because a build
/// argument is a single argv entry and commas need no quoting. Whatever consumes one has
/// to split it first.
///
/// The apt branch did not, so apt was handed the whole list as one package name:
///
///     E: Unable to locate package curl,git,jq,ripgrep,unzip,zip
///
/// and every project whose tools needed an apt package failed to build its image -- in
/// four seconds, with an error that said only "the build failed; see the build log
/// above". This test is cheap and would have caught it.
#[test]
fn every_comma_separated_build_argument_is_split_before_it_is_used() {
    let text = dockerfile();

    let apt_use = text
        .find("apt-get install -y --no-install-recommends $APT_PACKAGES")
        .expect("the apt branch takes $APT_PACKAGES");
    let npm_use = text
        .find("for pkg in $NPM_GLOBALS")
        .expect("the npm branch iterates $NPM_GLOBALS");
    let cargo_use = text
        .find("for crate in $CARGO_INSTALLS")
        .expect("the cargo branch iterates $CARGO_INSTALLS");

    for (name, use_at) in [
        ("APT_PACKAGES", apt_use),
        ("NPM_GLOBALS", npm_use),
        ("CARGO_INSTALLS", cargo_use),
    ] {
        // Split once, near the top of the step, rather than at each use: the bug was a
        // branch that forgot, and a shared split cannot be forgotten.
        let split = format!("{name}=$(echo \"${name}\" | tr ',' ' ')");
        let split_at = text.find(&split).unwrap_or_else(|| {
            panic!(
                "{name} is used at byte {use_at} but never split on commas. The app sends it \
                 comma-separated, so whatever reads it sees one item."
            )
        });
        assert!(
            split_at < use_at,
            "{name} is split at byte {split_at} but used at {use_at}: the split has to come first"
        );
    }
}

/// The split has to be a reassignment of the same name, so a later branch cannot
/// accidentally use the unsplit value it was given.
#[test]
fn no_branch_re_splits_a_list_that_was_already_split() {
    let text = dockerfile();
    for name in ["APT_PACKAGES", "NPM_GLOBALS", "CARGO_INSTALLS"] {
        let inline = format!("$(echo \"${name}\" | tr ',' ' ')");
        // Exactly once, at the normalisation, and not again inside a loop.
        assert_eq!(
            text.matches(&inline).count(),
            1,
            "{name} should be split exactly once, where it is normalised"
        );
    }
}

/// The build and the app have to agree on what "there is a cache" means, and they have to agree
/// on it in the direction that fails safe.
///
/// They did not. `toolcache::prepare_entry` creates `bin/` and `node_modules/` before every build
/// -- a build context has to exist -- and the build tested for exactly those directories. So the
/// test was always true, every build took the "cached" path, and no npm global or cargo tool was
/// ever installed. The images were then labelled with the tools that were *asked for*:
/// `htmlq,puppeteer,wrangler`, none of which were in them, verified against a real image built
/// here. The label is what `deepsand_sandbox_info` reports to the agent as the truth, so an agent
/// went hunting for a browser its own sandbox had told it it had.
///
/// The marker is the signal the app itself uses (`toolcache::cache_is_usable`), so this asserts
/// both halves read it and that the marker name has not drifted apart.
#[test]
fn a_tools_cache_is_only_used_when_the_app_says_it_is_filled() {
    let text = dockerfile();
    let marker = deepsand_core::toolcache::FILLED_MARKER;

    assert!(
        text.contains(&format!("[ -f /toolcache/{marker} ]")),
        "the tools step has to ask for the marker the app writes ({marker}), not for the \
         directories the app always creates. Testing those is a test that is always true, and \
         the image then claims tools that were never installed."
    );
    assert!(
        !text.contains("[ -d /toolcache/bin ]"),
        "the tools step must not decide from the cache directories: the app creates them before \
         every build, so that test is always true"
    );
}

/// A cache entry is an accelerator, not an authority.
///
/// Even with the marker agreed on, an entry can be missing one package. The npm branch therefore
/// asks npm about each package rather than trusting the entry, which is the same rule
/// `tool_updates.rs` follows when it compares "the listing the tools produced" rather than what
/// the cache was asked for -- and it means a partial entry heals itself instead of producing an
/// image that claims a tool it does not have.
#[test]
fn every_npm_global_is_verified_against_npm_before_the_cache_stands_in_for_it() {
    let text = dockerfile();
    let verify = text.find("npm ls -g --depth=0 \"$pkg\"").expect(
        "the npm branch has to ask npm whether the package is there, not assume it from a cache",
    );
    let after = &text[verify..];
    let install = after
        .find("npm install -g --no-fund")
        .expect("and install it when npm says it is missing");
    let otherwise = after
        .find("else")
        .expect("the install belongs in the branch that is missing the package");

    // The check comes first, and the install is what happens when it fails -- not a step beside
    // it, which would run either way.
    assert!(
        otherwise < install,
        "the install has to be the `else` of npm's own answer, not a second unconditional step"
    );
    assert!(
        !text.contains("if [ \"$TOOLS_CACHED\" = \"0\" ] && [ -n \"$NPM_GLOBALS\" ]"),
        "the npm installs must not be gated on the cache as a whole: that is what skipped them"
    );
}

/// The cache key has to move when the install steps move, and this file is the one where that can
/// be checked against the real Dockerfile rather than a fixture.
///
/// `toolcache`'s own test of this used a fixture with no base layer, so its first apt-mounting
/// `RUN` was the tools layer -- while the real file's base apt layer carries that same mount and
/// comes first. The fingerprint therefore covered the base layer, and a change to the install
/// steps left the key alone: a build would take the "cached" path into an entry the previous,
/// broken step had filled. That is why this is asserted here, against the shipping file.
#[test]
fn the_tools_fingerprint_comes_from_the_real_tools_layer() {
    use deepsand_core::toolcache::tools_layer_fingerprint;

    let text = dockerfile();
    let before = tools_layer_fingerprint(&text);
    assert!(!before.is_empty(), "the real Dockerfile has a tools layer to fingerprint");

    // Something well outside the tools layer must not disturb it.
    let elsewhere = text.replace(
        "LABEL org.opencontainers.image.licenses=\"MIT\"",
        "LABEL org.opencontainers.image.licenses=\"MIT-0\"",
    );
    assert_ne!(
        text, elsewhere,
        "the test anchor moved, so this proves nothing: pick another line outside the tools layer"
    );
    assert_eq!(
        before,
        tools_layer_fingerprint(&elsewhere),
        "a change outside the tools layer must not change the cache key, or every runtime edit \
         recompiles the tools"
    );

    // The gate that decides whether a cache entry is used at all is *in* the tools layer, so a
    // fix to it has to produce a key that does not name an entry the broken version filled.
    let gated = text.replace("[ -f /toolcache/filled-at ]", "[ -d /toolcache/bin ]");
    assert_ne!(
        before,
        tools_layer_fingerprint(&gated),
        "the cache gate is part of the tools layer: changing it has to change the key, or the fix \
         is applied by a build that reuses the entry the broken step filled"
    );
}

/// The `puppeteer` tool promises "a browser controlled from Node, with its own copy of Chromium",
/// and for a while it delivered neither half: the npm package installs in seconds and fetches no
/// browser, and a browser links against libraries this base image does not carry. An agent asked
/// for a screenshot spent its turn finding that out and then reported the sandbox as having no
/// browser. Each of these assertions is one of the things that has to be true for the description
/// to be honest, and each was false at some point today.
#[test]
fn the_browser_the_puppeteer_tool_promises_is_actually_built_in() {
    let text = dockerfile();

    // Gated on the tool, not on the plan's apt list: the libraries are needed by the browser
    // rather than chosen by the operator.
    assert!(
        text.contains("case \",$INSTALL_TOOLS,\" in") && text.contains("*,puppeteer*)"),
        "the browser step has to be gated on the puppeteer tool being selected"
    );

    // The libraries a browser links against, without which it downloads and cannot start.
    for lib in ["libnss3", "libgbm1", "libatk1.0-0", "libcups2", "libpango-1.0-0"] {
        assert!(
            text.contains(lib),
            "the browser step no longer installs {lib}: a browser that cannot link is a browser \
             that does not start, whichever half of the tool is installed"
        );
    }

    // Without an archiver the browser downloads and cannot be unpacked, and because that happens
    // inside a package's postinstall the failure is swallowed -- which is exactly how an image
    // came to hold the driver and no browser. It must not depend on the `zip` tool being on.
    assert!(
        text.contains("fonts-liberation xdg-utils unzip;"),
        "the browser step has to install unzip itself: extraction is not optional and the failure \
         is silent"
    );

    // The package's own postinstall download is what leaves a browser folder with no executable
    // in it, which then makes every later fetch refuse to repair it.
    assert!(
        text.contains("PUPPETEER_SKIP_DOWNLOAD=1 npm install"),
        "the npm install has to skip the postinstall download, or it leaves a half-fetched \
         browser folder that blocks the real fetch"
    );
    assert!(
        text.contains("rm -rf \"$PUPPETEER_CACHE_DIR\""),
        "the fetch has to start from an empty cache: puppeteer refuses to fill a browser folder \
         that exists without an executable in it"
    );

    // Fetched for the sandbox user, and checked as that user rather than assumed: an image that
    // says puppeteer and has no browser is the whole failure being fixed here.
    assert!(
        text.contains("setpriv --reuid=1000 --regid=1000 --clear-groups"),
        "the browser has to be verified as the sandbox user, because that is who will look for it"
    );
    assert!(
        text.contains("the browser could not be fetched or is not where the sandbox user looks"),
        "a build that cannot produce a browser has to fail, not ship an image that claims one"
    );
}

fn entrypoint() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("runtime")
        .join("bin")
        .join("entrypoint.sh");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("could not read {}: {err}", path.display()))
}

/// The generated operator-instructions skill crosses three files: the host writes it into the
/// config directory, the entrypoint copies it into the container, and DeepCode discovers it by
/// directory name. Only one of those names exists twice, and a mismatch fails in the quietest
/// possible way -- the model simply never sees the operator's instructions in exactly the projects
/// whose own `AGENTS.md` shadows the generated file.
#[test]
fn the_entrypoint_installs_the_operator_skill_under_the_name_the_host_writes() {
    let text = entrypoint();
    let name = deepsand_core::settings::OPERATOR_SKILL_NAME;

    assert!(
        text.contains(&format!("\nOPERATOR_SKILL_NAME={name}\n")),
        "the shell's copy of the name has to match settings::OPERATOR_SKILL_NAME ({name})"
    );

    // One of DeepCode's four skill roots, reached from the writable side: this is the user-level
    // `~/.deepcode/skills`, and the read-only rootfs is why it is not `~/.agents/skills`.
    assert!(
        text.contains("SKILL_DIR=\"$DEEPCODE_DIR/skills/$OPERATOR_SKILL_NAME\""),
        "the skill has to land in a directory DeepCode scans"
    );
    assert!(
        text.contains(&format!(
            "/etc/deepsand/skills/$OPERATOR_SKILL_NAME/SKILL.md"
        )),
        "and it has to be read from the config mount, which is where the host writes it \
         ({} in the container)",
        deepsand_core::settings::CONTAINER_CONFIG_DIR
    );

    // Removal comes first, and that order is the point: the home volume survives the container, so
    // a skill that outlives its reason would go on instructing later sessions from a file nobody
    // looks at.
    let remove = text
        .find("rm -rf \"$SKILL_DIR\"")
        .expect("the generated skill directory has to be reclaimed before it is installed");
    let install = text
        .find("place_file \"/etc/deepsand/skills/$OPERATOR_SKILL_NAME/SKILL.md\"")
        .expect("the skill has to be installed from the config mount");
    assert!(
        remove < install,
        "the skill directory must be emptied before it is filled, or a prompt turned off stays \
         in force"
    );

    // A skill without these two lines is skipped by the CLI, so writing one is not enough.
    assert!(
        text.contains("mkdir -p \"$SKILL_DIR\""),
        "the skill's own directory has to exist before the file is placed in it"
    );
}

/// Every path that builds the image has to hand BuildKit the tools layer's named context.
///
/// The layer mounts `from=toolcache`, which is a *named build context* and not an image only
/// because something supplies it. The app supplies its keyed cache. The documented
/// `npm run runtime:build` supplied nothing, so BuildKit resolved it as
/// `docker.io/library/toolcache:latest` and the build died with
/// "pull access denied ... insufficient_scope: authorization failed" -- a registry message for a
/// problem that has nothing to do with the registry, on the one command a contributor outside the
/// app has for building the sandbox.
#[test]
fn every_build_path_supplies_the_toolcache_context() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let read = |relative: &str| {
        let path = repo.join(relative);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("could not read {}: {err}", path.display()))
    };

    // The claim is only load-bearing while the Dockerfile really does mount a named context.
    assert!(
        read("runtime/Dockerfile").contains("--mount=type=bind,from=toolcache"),
        "if the tools layer stops using the named context, this test can go"
    );
    assert!(
        read("crates/deepsand-core/src/docker.rs").contains("--build-context"),
        "the app's build has to pass the context"
    );

    let script = read("runtime/scripts/build-image.mjs");
    assert!(
        script.contains("\"--build-context\""),
        "so does the command-line build, or the documented way to build the image fails"
    );
    assert!(
        script.contains("toolcache=${toolCache}"),
        "and the context has to be named `toolcache`, which is what the Dockerfile asks for"
    );
}
