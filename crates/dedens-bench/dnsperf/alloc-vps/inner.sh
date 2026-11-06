#!/bin/sh
# Inside the container: timed dedensd build, then the benches. Env: NAME, OUT (release dir), FEATS (cargo args).
if [ -z "${SKIP_DEDENSD:-}" ]; then
    s=$(date +%s)
    cargo build -vv --release -p dedensd $FEATS >/logs/$NAME.build.log 2>&1; rc=$?
    t=$(date +%s)
    echo "$NAME dedensd rc=$rc seconds=$((t - s))" >>/logs/times
    cp $OUT/dedensd /out/dedensd
fi
cargo build -vv --release -p dedens-bench --bench server --bench cache --bench message $FEATS_BENCH >/logs/$NAME.bench.log 2>&1; rc=$?
echo "$NAME bench rc=$rc" >>/logs/times
for b in server cache message; do
    cp "$(ls -t $OUT/deps/$b-* | grep -v "\.d$" | head -1)" /out/$b
done
chmod -R a+rwX /out /target 2>/dev/null
true
