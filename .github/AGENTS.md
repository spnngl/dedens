# .github

Shared workflows come from `spnngl/.github` at `@main`; third-party actions are pinned by full SHA with a
`# vX` comment, and tool versions carry a `# renovate:` comment. The shared Renovate regex reads only
`KEY: "version"` lines, so `taiki-e/install-action` takes `tool@${{ env.TOOL_VERSION }}` from a job `env`.
Every job running steps has a `timeout-minutes`; every workflow a `concurrency` group cancelling only pull request
runs. `actionlint` and `zizmor` lint these files.

`mutants.yml` runs `just mutants-diff` on pull requests: informational, outside the gate (D103); so does `loom.yml`
with `just loom` (D135). `ci.yml` runs dedensd's
root-only `privileges` tests with `sudo` (D122).
