const http = require("http");
const hello = require("@kk/hello-private");
http.createServer((req, res) => { res.writeHead(200, {"content-type": "text/plain"}); res.end(hello() + "\n"); })
  .listen(process.env.PORT || 8080, "0.0.0.0");
