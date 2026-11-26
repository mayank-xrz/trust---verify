// AES-256-GCM, HKDF-SHA256, and X25519 from the Node.js standard crypto implementation.
const crypto = require('node:crypto');

function runOp(req) {
  if (req.op === 'hkdf') {
    const ikm = Buffer.from(req.ikm, 'base64');
    const salt = Buffer.from(req.salt, 'base64');
    const info = Buffer.from(req.info, 'base64');
    if (!Number.isSafeInteger(req.length) || req.length < 1 || req.length > 8160 || ikm.length === 0) {
      throw Error('invalid KDF input');
    }
    return { data: Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, req.length)).toString('base64') };
  }
  if (req.op === 'x25519_keypair') {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    return {
      public_key: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
      private_key: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64')
    };
  }
  if (req.op === 'x25519_ephemeral_shared') {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    const peerPub = crypto.createPublicKey({ key: Buffer.from(req.peer_public_key, 'base64'), format: 'der', type: 'spki' });
    if (peerPub.asymmetricKeyType !== 'x25519') throw Error('wrong DH key type');
    return {
      public_key: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
      private_key: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
      data: crypto.diffieHellman({ privateKey, publicKey: peerPub }).toString('base64')
    };
  }
  if (req.op === 'hkdf_session') {
    const root = Buffer.from(crypto.hkdfSync(
      'sha256',
      Buffer.from(req.ikm, 'base64'),
      Buffer.from(req.salt, 'base64'),
      Buffer.from(req.info, 'base64'),
      32
    ));
    const sendChain = Buffer.from(crypto.hkdfSync(
      'sha256', root, Buffer.from(req.send_salt, 'base64'), Buffer.from(req.send_info, 'base64'), 32
    ));
    const recvChain = Buffer.from(crypto.hkdfSync(
      'sha256', root, Buffer.from(req.recv_salt, 'base64'), Buffer.from(req.recv_info, 'base64'), 32
    ));
    const out = {
      root: root.toString('base64'),
      send_chain: sendChain.toString('base64'),
      recv_chain: recvChain.toString('base64')
    };
    if (req.confirm_salt && req.confirm_info) {
      out.confirm_key = Buffer.from(crypto.hkdfSync(
        'sha256', root, Buffer.from(req.confirm_salt, 'base64'), Buffer.from(req.confirm_info, 'base64'), 32
      )).toString('base64');
    }
    return out;
  }
  if (req.op === 'x25519_shared') {
    const privateKey = crypto.createPrivateKey({ key: Buffer.from(req.private_key, 'base64'), format: 'der', type: 'pkcs8' });
    const publicKey = crypto.createPublicKey({ key: Buffer.from(req.public_key, 'base64'), format: 'der', type: 'spki' });
    if (privateKey.asymmetricKeyType !== 'x25519' || publicKey.asymmetricKeyType !== 'x25519') {
      throw Error('wrong DH key type');
    }
    return { data: crypto.diffieHellman({ privateKey, publicKey }).toString('base64') };
  }
  const key = Buffer.from(req.key, 'base64');
  const nonce = Buffer.from(req.nonce, 'base64');
  const aad = Buffer.from(req.aad, 'base64');
  if (key.length !== 32 || nonce.length !== 12) throw Error('invalid key or nonce');
  if (req.op === 'encrypt') {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(req.data, 'base64')), cipher.final()]);
    return { data: ciphertext.toString('base64'), tag: cipher.getAuthTag().toString('base64') };
  }
  if (req.op === 'decrypt') {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    decipher.setAAD(aad);
    decipher.setAuthTag(Buffer.from(req.tag, 'base64'));
    try {
      return { data: Buffer.concat([decipher.update(Buffer.from(req.data, 'base64')), decipher.final()]).toString('base64') };
    } catch (_) {
      const err = Error('AEAD_AUTH_FAILED');
      err.code = 'AEAD_AUTH_FAILED';
      throw err;
    }
  }
  throw Error('invalid operation');
}

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; if (input.length > 32 * 1024 * 1024) process.exit(2); });
process.stdin.on('end', () => {
  try {
    const req = JSON.parse(input);
    if (req.op === 'batch') {
      if (!Array.isArray(req.ops)) throw Error('invalid batch');
      const results = req.ops.map(runOp);
      process.stdout.write(JSON.stringify({ results }));
      return;
    }
    process.stdout.write(JSON.stringify(runOp(req)));
  } catch (err) {
    if (err && err.code === 'AEAD_AUTH_FAILED') {
      process.stderr.write('AEAD_AUTH_FAILED\n');
      process.exitCode = 3;
    } else {
      process.stderr.write('NODE_CRYPTO_FAILED\n');
      process.exitCode = 1;
    }
  }
});
