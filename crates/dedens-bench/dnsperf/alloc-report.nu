#!/usr/bin/env nu
# Markdown tables of a session of `alloc.sh` (D152), a row a measure, a column a binary:
#   nu alloc-report.nu runs RESULTS/runs.tsv     queries/s, p99 and average latency of `alloc.sh rounds`
#   nu alloc-report.nu divan RESULTS/divan       the benches of `alloc.sh divan`
#   nu alloc-report.nu rss RESULTS               startup and churn resident sets, MiB
# Per round, a binary's queries/s are over the round's fastest, its latencies over the round's lowest; a cell is the
# median over the rounds, with the range of the ratio.

# The columns: the binaries, in this order, under short names.
const BINARIES = {
    musl-mallocng: ng, musl-mimalloc: mi, musl-mimalloc-min: mi-min, musl-mimalloc-secure: mi-sec,
    musl-jemalloc: je, glibc-malloc: g, glibc-mimalloc: g-mi
}

def short [] { let name = $in; $BINARIES | get $name }

# A table of one row per `key` and one column per binary, `cell` computing a cell from the rows of the two.
def grid [rows: table, key: string, cell: closure] {
    $rows | get $key | uniq | each {|k|
        $BINARIES | columns | reduce --fold {($key): $k} {|b, acc|
            $acc | insert ($b | short) (do $cell ($rows | where {|r| $r.binary == $b and ($r | get $key) == $k}))
        }
    } | to md --pretty | str replace --all '&#x2f;' '/'
}

# The rows with `qps_ratio` over the best (highest) of their round and cell, `p99_ratio` and `avg_ratio` over the lowest.
def rated [rows: table] {
    $rows | group-by round cell --to-table | each {|g|
        let qps = ($g.items | get qps | math max)
        let p99 = ($g.items | get p99_ms | math min)
        let avg = ($g.items | get avg_ms | math min)
        $g.items | each {|r| $r | insert qps_ratio ($r.qps / $qps) | insert p99_ratio ($r.p99_ms / $p99) | insert avg_ratio ($r.avg_ms / $avg) }
    } | flatten
}

def main [] { help main }

def "main runs" [runs: path] {
    let all = (rated (open $runs | where qps != "" | into float qps avg_ms p99_ms | insert cell {|r| $"($r.mode) ($r.cores)" }))
    print "Queries/s over the round's fastest, median (range):\n"
    print (grid $all cell {|v| $"($v | get qps_ratio | math median | math round --precision 2) \((($v | get qps_ratio | math min | math round --precision 2))-(($v | get qps_ratio | math max | math round --precision 2))\)" })
    print "\np99, ms, median (median ratio to the round's lowest):\n"
    print (grid $all cell {|v| $"($v | get p99_ms | math median | math round --precision 2) \(($v | get p99_ratio | math median | math round --precision 2)\)" })
    print "\nAverage latency, ms, median (median ratio to the round's lowest):\n"
    print (grid $all cell {|v| $"($v | get avg_ms | math median | math round --precision 2) \(($v | get avg_ratio | math median | math round --precision 2)\)" })
    print "\nQueries/s, median:\n"
    print (grid $all cell {|v| $v | get qps | math median | math round })
    print "\nPer binary: geometric mean of the cells' median ratios (queries/s), cells of 8 with a median ratio of 0.90 or more, cells of 8 with a median p99 ratio of 1.25 or less:\n"
    print ($BINARIES | columns | each {|b|
        let cells = ($all | where binary == $b | group-by cell --to-table | each {|g| {q: ($g.items | get qps_ratio | math median), p: ($g.items | get p99_ratio | math median)} })
        {binary: ($b | short), geomean: (($cells | get q | each {|x| $x | math ln } | math avg | math exp) | math round --precision 3), at_090: ($cells | where q >= 0.9 | length), p99_within_125: ($cells | where p <= 1.25 | length)}
    } | to md --pretty)
    print $"\nQueries lost: ($all | get lost | into int | math sum). Drivers: ($all | get driver | uniq | str join ', ')."
}

# A divan median column, in nanoseconds.
def to-ns [] {
    let p = ($in | str trim | split row " ")
    ($p.0 | into float) * (match $p.1 { "ns" => 1.0, "µs" => 1000.0, "ms" => 1000000.0, "s" => 1000000000.0 })
}

# The medians of one divan output: group (`hit`), case (`a`), median in ns.
def parse-divan [file: path] {
    open --raw $file | lines | reduce --fold {group: "", rows: []} {|l, acc|
        let top = ($l | parse --regex '^[├╰]─ (?<name>\S+)\s+│')
        let row = ($l | parse --regex '^[│ ]+[├╰]─ (?<case>a|mx|txt_large)\s+(?<rest>.*)$')
        if ($top | is-not-empty) {
            $acc | update group $top.0.name
        } else if ($row | is-not-empty) {
            let median = ($row.0.rest | split row "│" | get 2 | to-ns)
            $acc | update rows ($acc.rows | append {group: $acc.group, case: $row.0.case, median_ns: $median})
        } else { $acc }
    } | get rows
}

def "main divan" [dir: path] {
    let rows = (ls $dir | get name | each {|f|
        let p = ($f | path basename | str replace ".txt" "" | parse --regex '^(?<round>\d+)-(?<binary>.+)-(?<bench>server|cache|message)$' | get 0)
        parse-divan $f | each {|r| $p | merge $r }
    } | flatten | insert key {|r| $"($r.bench)::($r.group)/($r.case)" })
    let rated = ($rows | group-by round key --to-table | each {|g|
        let best = ($g.items | get median_ns | math min)
        $g.items | each {|r| $r | insert ratio ($r.median_ns / $best) }
    } | flatten)
    print "divan medians, ns, median over the rounds (median ratio to the round's fastest):\n"
    print (grid $rated key {|v| $"($v | get median_ns | math median | math round --precision 1) \(($v | get ratio | math median | math round --precision 2)\)" })
}

def "main rss" [dir: path] {
    let mib = {|kb| $kb / 1024 | math round --precision 1 }
    print "Startup RSS, MiB, median of three:\n"
    let startup = (open ($dir | path join startup.tsv) | into float vmrss_kb)
    print (grid $startup threads {|v| do $mib ($v | get vmrss_kb | math median) })
    print "\nChurn, MiB: VmHWM, RSS at the end of the load, RSS 20 s later, and the queries/s dnsperf got (30,000 offered):\n"
    print (churn-table $dir)
}

# One row a churn file of `dir`: the resident set (VmHWM, RSS at the marks in seconds, 20 s after the load) and dnsperf's
# queries/s.
def churn-table [dir: path, marks: list<int> = []] {
    let mib = {|kb| $kb / 1024 | math round --precision 1 }
    let said = (open ($dir | path join churn.txt) | lines | parse '{head}: {qps}	{avg}	{p99}	{lost}	{done}' | insert name {|r| $r.head | str replace 'churn ' '' })
    $BINARIES | columns | where {|b| $dir | path join $"churn-($b).tsv" | path exists } | each {|b|
        let t = (open ($dir | path join $"churn-($b).tsv") | into float vmrss_kb vmhwm_kb)
        let a = ($said | where name == $b | first)
        let marked = ($marks | reduce --fold {} {|m, acc| $acc | insert $"rss_($m)s" (do $mib ($t | get $m | get vmrss_kb)) })
        {binary: ($b | short), peak: (do $mib ($t | get vmhwm_kb | math max))}
        | merge $marked
        | merge {end_of_load: (do $mib ($t | get ($t | length | $in - 21) | get vmrss_kb)), after_20s: (do $mib ($t | last | get vmrss_kb)), qps: ($a.qps | into float | math round)}
    } | to md --pretty
}

def "main soak" [dir: path] {
    print "Soak, MiB: VmHWM, RSS at 10 and 30 minutes, at the end of the load (60), 20 s later, and the queries/s dnsperf got:\n"
    print (churn-table $dir [600 1800])
}
