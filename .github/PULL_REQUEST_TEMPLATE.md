## Summary

<!-- What problem does this solve, and how? Link issues: Fixes #... -->

## Changes

- 

## Validation

<!-- Commands run and their results. -->

- [ ] `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings` and `cargo test --locked` pass
- [ ] New or changed behaviour has a test (rules: `matches` / `ignores` examples)
- [ ] Rule or scanner changes: `python3 eval/run_eval.py --only clean` shows no new false positive; any recall change is noted above

## Checklist

- [ ] Focused change; no unrelated formatting or generated files
- [ ] `CHANGELOG.md` (`[Unreleased]`) and docs updated for user-facing changes
- [ ] No live malware, real credentials or private indicators added
- [ ] Security-relevant changes checked against [SECURITY.md](../SECURITY.md)
