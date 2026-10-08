const express = require("express");
const app = express();
app.get("/", (_q, r) => r.send(`bn-sar-internal ok, express ${require("express/package.json").version}\n`));
app.listen(8080, "0.0.0.0");
