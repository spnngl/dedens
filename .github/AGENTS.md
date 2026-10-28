# .github

CI workflows. `ci.yml` runs `just check` on Linux and macOS, `just hack`, `msrv`, `minimal-versions` and `deny`,
and `just cov` outside the gate; `fuzz.yml` (nightly) and `rapx.yml` (weekly) run on a schedule.
Shared workflows come from `spnngl/.github` at `@main`; third-party actions are pinned by full SHA with a
`# vX` comment, and tool versions carry a `# renovate:` comment. `actionlint` and `zizmor` lint these files.
