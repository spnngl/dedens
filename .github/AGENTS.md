# .github

Shared workflows come from `spnngl/.github` at `@main`; third-party actions are pinned by full SHA with a
`# vX` comment, and tool versions carry a `# renovate:` comment. The shared Renovate regex reads only
`KEY: "version"` lines, so `taiki-e/install-action` takes `tool@${{ env.TOOL_VERSION }}` from a job `env`.
Every job running steps has a `timeout-minutes`; every workflow a `concurrency` group cancelling only pull request
runs. `actionlint` and `zizmor` lint these files. `ci.yml`'s `gate` job is the one check the ruleset
requires: no other workflow blocks a merge. Each opens with a comment saying what it runs and when; a new one does
too.

Release (D153): `v0.1.0` is out and the `dedensd` package public; left by hand, a tag ruleset on `v*` (the only
ruleset is `main`'s). Check a release's archives and packages against `SHA256SUMS` and `gh attestation verify`.
