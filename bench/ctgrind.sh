#!/bin/sh
# ctgrind check: needs valgrind on x86-64 Linux.   sh bench/ctgrind.sh   (from the repository root)
set -e
for mode in shipped naive; do
  if [ "$mode" = naive ]; then F="--features naive-select"; else F=""; fi
  cargo build --release -p hec-bench --bin ctgrind $F >/dev/null 2>&1
  cp target/release/ctgrind /tmp/ctgrind_$mode
  for r in control-clean control-leaky fixed-base-ed25519 fixed-base-secp256k1 var-base-ed25519 var-base-secp256k1 x25519; do
    out=$(valgrind -q --error-exitcode=9 /tmp/ctgrind_$mode $r 2>&1) && rc=0 || rc=$?
    echo "$mode $r exit=$rc cond_jump=$(echo "$out" | grep -c 'Conditional jump') uninit_address=$(echo "$out" | grep -c 'Use of uninitialised')"
  done
done
