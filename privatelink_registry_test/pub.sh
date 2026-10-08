cd /opt/pkg && printf '//127.0.0.1:4873/:_auth=%s\n' "$(printf pub:pubpass123 | base64)" > .npmrc && npm publish --registry http://127.0.0.1:4873/ 2>&1 | tail -2
curl -s http://127.0.0.1:4873/@kk%2fhello-private | head -c 150
