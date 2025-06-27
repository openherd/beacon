const crypto = require('crypto');
const nacl = require('tweetnacl');
const util = require('tweetnacl-util');

function solvePoW(publicKey, difficulty = 5) {
  const prefix = '0'.repeat(difficulty);
  let nonce = 0;

  while (true) {
    const hash = crypto.createHash('sha256')
      .update(publicKey + nonce)
      .digest('hex');

    if (hash.startsWith(prefix)) {
      return { nonce, hash };
    }
    nonce++;
  }
}
function verifyPoW(publicKey, nonce, difficulty = 5) {
  const prefix = '0'.repeat(difficulty);
  const hash = crypto.createHash('sha256')
    .update(publicKey + nonce)
    .digest('hex');
  return hash.startsWith(prefix);
}
function verifySignature(message, signature, publicKeyBase64) {
  const publicKey = util.decodeBase64(publicKeyBase64);
  const sigBytes = util.decodeBase64(signature);
  const msgBytes = util.decodeUTF8(message);

  return nacl.sign.detached.verify(msgBytes, sigBytes, publicKey);
}

module.exports = { solvePoW, verifyPoW, verifySignature }