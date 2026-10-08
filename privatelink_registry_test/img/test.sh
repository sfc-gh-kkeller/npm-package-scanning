#!/bin/sh
echo "=== 1. npm install @kk/hello-private from private registry via Private Link ==="
mkdir -p /w && cd /w && npm init -y >/dev/null
npm install @kk/hello-private --registry http://npm.kk-private.internal/ --fetch-retries=0 --fetch-timeout=20000 2>&1 | tail -3
node -e 'console.log("RESULT:", require("@kk/hello-private")())' 2>&1
echo "=== 2. npm install lodash from PUBLIC registry.npmjs.org (expect failure) ==="
npm install lodash --registry https://registry.npmjs.org/ --fetch-retries=0 --fetch-timeout=15000 2>&1 | tail -3
echo "=== 3. public npm package via private registry (expect 404, no uplink) ==="
npm view lodash version --registry http://npm.kk-private.internal/ 2>&1 | tail -2
echo "=== 4. arbitrary internet egress (expect failure) ==="
curl -sm10 -o /dev/null -w "example.com http=%{http_code}\n" https://example.com || echo "example.com blocked"
echo "=== DONE ==="
