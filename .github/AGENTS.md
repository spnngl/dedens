# .github

Shared workflows come from `spnngl/.github` at `@main`; third-party actions are pinned by full SHA with a
`# vX` comment, and tool versions carry a `# renovate:` comment. The shared Renovate regex reads only
`KEY: "version"` lines, so `taiki-e/install-action` takes `tool@${{ env.TOOL_VERSION }}` from a job `env`.
Every job running steps has a `timeout-minutes`; every workflow a `concurrency` group cancelling only pull request
runs, but `fuzz-lock.yml`, which cancels on its Renovate branches too. `actionlint` and `zizmor` lint these files. The ruleset requires `ci.yml`'s `gate`, `betterleaks` and
`conventional-commits`: no other workflow blocks a merge. Each opens with a comment saying what it runs and when; a
new one does too.

The account runs 20 jobs at once, and a job queues behind every job already waiting. `gate` queues last, once
`check` ends: with `deep.yml` (38 jobs) and `mutants.yml`'s shards unbounded, it waited 1 h 15 min. So each
matrix outside the gate has a `max-parallel` (`sim` and `careful` 3, mutants shards 4), keeping a pull request's
informational jobs to about 10 runners beside `ci.yml`'s 10; a new matrix gets one too.

`fuzz-lock.yml` commits `fuzz/Cargo.lock` to Renovate's branches with the token of the app named in
`renovate.json5`'s `gitIgnoredAuthors` (secrets `APP_CLIENT_ID`, `APP_PRIVATE_KEY`): a push with GITHUB_TOKEN starts
no workflow, so the required checks would never run on that commit. Another app means changing both.

Release (D153): `v0.1.0` is out and the `dedensd` package public; left by hand, a tag ruleset on `v*` (the only
ruleset is `main`'s). Check a release's archives and packages against `SHA256SUMS` and `gh attestation verify`.
