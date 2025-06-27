const express = require('express')
const app = express()
var { Liquid } = require('liquidjs');
var engine = new Liquid();
const { verifyPoW, verifySignature } = require("./modules/pow.js");
const { nodeSchema } = require("./schemas.js")
const { PrismaClient } = require('@prisma/client')
const prisma = new PrismaClient()
const geoIp2 = require('geoip-lite2');
const bcrypt = require("bcryptjs")

app.use(express.json())
app.engine('liquid', engine.express());
app.set('views', './views');
app.set('view engine', 'liquid');

app.get('/', (req, res) => {
  const lookup = geoIp2.lookup(req.ip)
  var location = { lat: "33.7501", lng: "-84.3885" }
  if (lookup) location = { lat: lookup.ll[0], lng: lookup.ll[1]}
  res.render("index", location)
})


app.get('/beacon/list', async (req, res) => {
  res.json(await prisma.node.findMany({}))
})
app.post('/beacon/update', async (req, res) => {
  const { publicKey, message, signature, nonce, password } = req.body;

  if (password) {
    const node = await prisma.node.findUnique({ where: { publicKey } });
    if (!node || !node.password || !bcrypt.compareSync(password, node.password)) {
      return res.status(403).send({ ok: false, error: 'Invalid password' });
    }
  } else {
    if (!verifyPoW(publicKey, nonce)) {
      return res.status(400).send({ ok: false, error: 'Invalid PoW' });
    }
    if (!verifySignature(message, signature, publicKey)) {
      return res.status(403).send({ ok: false, error: 'Invalid signature' });
    }
  }

  var json = JSON.parse(message)
  console.log(json)
  if (!nodeSchema.safeParse(json).success) {
    return res.status(403).send({ ok: false, error: 'Invalid message' });
  }

  delete json.timestamp
  if (json.password) json.password = bcrypt.hashSync(json.password, bcrypt.genSaltSync(10));
  await prisma.node.upsert({
    where: { publicKey },
    update: { ...json },
    create: { publicKey, ...json }
  })
  res.send({ status: 'ok' });
});
const server = app.listen(process.env.PORT || 3000, () => {
  console.log(`Beacon listening on port ${server.address().port}`)
})
