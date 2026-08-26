#!/bin/bash
set -e
GOOS=js GOARCH=wasm go build -o minerva.wasm ./wasm/cmd/
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" .
echo "Built minerva.wasm ($(du -h minerva.wasm | cut -f1))"
