# .github

CI workflows. `ci.yml` runs `just check` on Linux and macOS, `just hack`, `msrv`, `minimal-versions` and `deny`,
and `just cov` outside the gate; `fuzz.yml` (nightly) and `rapx.yml` (weekly) run on a schedule.
Shared workflows come from `spnngl/.github` at `@main`; third-party actions are pinned by full SHA with a
`# vX` comment, and tool versions carry a `# renovate:` comment. The shared Renovate regex reads only
`KEY: "version"` lines, so `taiki-e/install-action` takes `tool@${{ env.TOOL_VERSION }}` from a job `env`.
Every job has a `timeout-minutes`, every workflow a `concurrency` group cancelling only pull request runs.
`actionlint` and `zizmor` lint these files.
