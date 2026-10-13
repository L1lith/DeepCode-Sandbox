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
