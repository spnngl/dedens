# .github

Shared workflows come from `spnngl/.github` at `@main`; third-party actions are pinned by full SHA with a
`# vX` comment, and tool versions carry a `# renovate:` comment. The shared Renovate regex reads only
`KEY: "version"` lines, so `taiki-e/install-action` takes `tool@${{ env.TOOL_VERSION }}` from a job `env`.
Every job running steps has a `timeout-minutes`; every workflow a `concurrency` group cancelling only pull request
runs. `actionlint` and `zizmor` lint these files.

`mutants.yml` runs `just mutants-diff` on pull requests, in shards: informational, outside the gate (D103, D142).
`deep.yml` is the other informational workflow, with three jobs: `loom` runs `just loom` (D135), `sim` runs
`just sim 100`, the simulation scenarios under random seeds, a job per scenario file (D133), and `careful` runs
`just careful address`, a job per package (D144). `ci.yml` runs dedensd's root-only `privileges` tests with `sudo`
(D122). Scheduled: `fuzz.yml`, a job per fuzz target, and `advisories.yml` (D141); weekly, `rapx.yml` (D16),
`kani.yml` (D145) and `codeql.yml` (D146), whose alerts go to the Security tab. `release.yml` runs on a pushed tag
`v*`, after `ci.yml`'s gate through `workflow_call` (D153); by hand with `publish` off it builds and attests but
releases and pushes nothing.
