set -e
curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null
apt-get install -y nodejs >/dev/null
npm install -g verdaccio@5 >/dev/null 2>&1
mkdir -p /opt/verdaccio/storage && touch /opt/verdaccio/htpasswd
systemctl daemon-reload && systemctl enable --now verdaccio
sleep 8
TOKEN=$(curl -s -XPUT -H 'content-type: application/json' -d '{"name":"pub","password":"pubpass123"}' http://127.0.0.1:4873/-/user/org.couchdb.user:pub | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
cd /opt/pkg && npm publish --registry http://127.0.0.1:4873/ --//127.0.0.1:4873/:_authToken=$TOKEN
curl -s http://127.0.0.1:4873/@kk%2fhello-private | head -c 200
