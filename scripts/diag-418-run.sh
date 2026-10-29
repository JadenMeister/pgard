#!/bin/bash
# Temporary (#418): run vitest, and when it does not finish in time dump what is still alive.
out="${RUNNER_TEMP:-/tmp}/vitest-418.log"
npx vitest run "$@" > "$out" 2>&1 &
pid=$!
for i in $(seq 1 60); do
  kill -0 $pid 2>/dev/null || break
  sleep 4
done
if kill -0 $pid 2>/dev/null; then
  echo "=== HUNG after 240s; log size $(wc -c < "$out") bytes, $(wc -l < "$out") lines"
  echo "=== last 60 log lines"
  tail -60 "$out" | cut -c1-240
  echo "=== processes"
  ps -axo pid,ppid,etime,stat,pcpu,rss,command | grep -v "ps -axo" | sort -k5 -rn | head -40 | cut -c1-240
  echo "=== load / memory"
  uptime; vm_stat | head -8
  kill -9 $pid 2>/dev/null
  exit 3
fi
wait $pid; rc=$?
tail -12 "$out"
exit $rc
