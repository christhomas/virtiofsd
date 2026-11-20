// The version a build reports, run as the real binary.
//
// `--version` belongs to upstream: hypervisors, management tools and scripts
// read it, so its output must stay exactly what upstream's binary prints.
// `--port-version` is this fork's addition. It prints the release this build
// was published as, which can carry a fourth, packaging component (1.14.0.1)
// that `--version` never shows.

use std::process::{Command, Output};

const PORT_VERSION_FILE: &str = include_str!("../PORT_VERSION");

fn virtiofsd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_virtiofsd"))
        .args(args)
        .output()
        .expect("run virtiofsd")
}

#[test]
fn version_prints_the_upstream_version_unchanged() {
    for flag in ["--version", "-V"] {
        let out = virtiofsd(&[flag]);
        assert!(out.status.success(), "{} failed: {:?}", flag, out);
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            format!("virtiofsd {}\n", env!("CARGO_PKG_VERSION")),
            "{}",
            flag
        );
        assert!(out.stderr.is_empty(), "{} wrote to stderr", flag);
    }
}

#[test]
fn port_version_prints_the_release_version_alone() {
    let out = virtiofsd(&["--port-version"]);
    assert!(out.status.success(), "--port-version failed: {:?}", out);
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("{}\n", PORT_VERSION_FILE.trim()),
    );
    assert!(out.stderr.is_empty(), "--port-version wrote to stderr");
}

#[test]
fn port_version_is_the_upstream_version_with_an_optional_revision() {
    let port = PORT_VERSION_FILE.trim();
    let upstream = env!("CARGO_PKG_VERSION");
    let ok = port == upstream
        || port
            .strip_prefix(upstream)
            .and_then(|rest| rest.strip_prefix('.'))
            .is_some_and(|rev| !rev.is_empty() && rev.bytes().all(|b| b.is_ascii_digit()));
    assert!(
        ok,
        "PORT_VERSION {:?} must be Cargo.toml's {} or {}.N",
        port, upstream, upstream
    );
}

#[test]
fn port_version_stands_alone() {
    let out = virtiofsd(&["--port-version", "--print-capabilities"]);
    assert!(!out.status.success(), "combined flags were accepted");
    assert!(out.stdout.is_empty());
}

#[test]
fn print_capabilities_is_unchanged() {
    let out = virtiofsd(&["--print-capabilities"]);
    assert!(out.status.success(), "{:?}", out);
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "{\n  \"type\": \"fs\",\n  \"features\": [\n    \"migrate-precopy\",\n    \
         \"posix-acl-negotiation-mode\",\n    \"security-label-negotiation-mode\",\n    \
         \"separate-options\"\n  ]\n}\n"
    );
}
