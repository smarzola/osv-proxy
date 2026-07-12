use std::fs;

#[test]
fn workflows_pin_actions_and_moving_tool_inputs() {
    for path in [".github/workflows/ci.yml", ".github/workflows/release.yml"] {
        let workflow = fs::read_to_string(path).unwrap();
        for line in workflow
            .lines()
            .filter(|line| line.trim_start().starts_with("uses:"))
        {
            let revision = line.split('@').nth(1).expect("action reference contains @");
            let revision = revision.split_whitespace().next().unwrap();
            assert_eq!(revision.len(), 40, "{path} has movable action: {line}");
            assert!(
                revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "{path}: {line}"
            );
        }
        assert!(!workflow.contains("toolchain install stable"), "{path}");
        assert!(!workflow.contains("node-version: lts/*"), "{path}");
        assert!(workflow.contains("node-version: '24.18.0'"), "{path}");
        assert!(workflow.contains("version: '0.11.28'"), "{path}");
        assert!(
            workflow.contains("cargo clippy --all-targets --all-features --locked -- -D warnings"),
            "{path}"
        );
    }

    let toolchain = fs::read_to_string("rust-toolchain.toml").unwrap();
    assert!(toolchain.contains("channel = \"1.97.0\""));
    let release = fs::read_to_string(".github/workflows/release.yml").unwrap();
    assert!(release.contains("TOOLCHAIN.txt"));
}
