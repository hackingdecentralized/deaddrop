#!/usr/bin/env bash
set -euo pipefail

addr="$1"
block_num="$2"
bug="$3"
inv="$4"

mkdir -p bin

forge init --no-git bin/bug-verify &> /dev/null

# move bug and inv file to test folder
dest="./bin/bug-verify/test"
mkdir -p $dest/inv
cp -- "$bug" "$dest/"
cp -- "$inv" "$dest/inv/"

cd bin/bug-verify 

(
  export TARGET="$addr"
  export MAINNET_RPC_URL="https://mainnet.infura.io/v3/27ce2d06142643c28dc2d477400fd430"
  export block_num=$block_num

  JSON_OUT="$(forge test test/inv/* \
    --fork-url "$MAINNET_RPC_URL" \
    --fork-block-number "$block_num" \
    --json 2>&1)" || true

  #echo "$JSON_OUT"

  curr="$(basename "$PWD")"
  cd .. || exit 1
  rm -rf -- "$curr"

  if ! echo "$JSON_OUT" | jq . >/dev/null 2>&1; then
    # not valid JSON
    echo "$JSON_OUT"
    exit 2
  fi

  if echo "$JSON_OUT" | \
      jq -r '.[].test_results[] | .status' | \
      grep -q '^Failure$'
  then
    echo "fail"
    exit 1
  else
    echo "success"
    exit 0
  fi
)
