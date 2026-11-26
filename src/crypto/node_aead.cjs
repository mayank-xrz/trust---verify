// AES-256-GCM and HKDF-SHA256 from the Node.js standard crypto implementation.
const crypto = require('node:crypto');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; if (input.length > 32 * 1024 * 1024) process.exit(2); });
process.stdin.on('end', () => {
  try {
    const req = JSON.parse(input);
    if (req.op === 'hkdf') {
      const ikm = Buffer.from(req.ikm, 'base64');
      const salt = Buffer.from(req.salt, 'base64');
      const info = Buffer.from(req.info, 'base64');
      if (!Number.isSafeInteger(req.length) || req.length < 1 || req.length > 8160 || ikm.length === 0) throw Error('invalid KDF input');
      process.stdout.write(JSON.stringify({ data: Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, req.length)).toString('base64') }));
      return;
    }
    if (req.op === 'x25519_keypair') {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
      process.stdout.write(JSON.stringify({
        public_key: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
        private_key: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64')
      }));
      return;
    }
    if (req.op === 'x25519_shared') {
      const privateKey = crypto.createPrivateKey({ key: Buffer.from(req.private_key, 'base64'), format: 'der', type: 'pkcs8' });
      const publicKey = crypto.createPublicKey({ key: Buffer.from(req.public_key, 'base64'), format: 'der', type: 'spki' });
      if (privateKey.asymmetricKeyType !== 'x25519' || publicKey.asymmetricKeyType !== 'x25519') throw Error('wrong DH key type');
      process.stdout.write(JSON.stringify({ data: crypto.diffieHellman({ privateKey, publicKey }).toString('base64') }));
      return;
    }
    const key = Buffer.from(req.key, 'base64');
    const nonce = Buffer.from(req.nonce, 'base64');
    const aad = Buffer.from(req.aad, 'base64');
    if (key.length !== 32 || nonce.length !== 12) throw Error('invalid key or nonce');
    let out;
    if (req.op === 'encrypt') {
      const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
      cipher.setAAD(aad);
      const ciphertext = Buffer.concat([cipher.update(Buffer.from(req.data, 'base64')), cipher.final()]);
      out = { data: ciphertext.toString('base64'), tag: cipher.getAuthTag().toString('base64') };
    } else if (req.op === 'decrypt') {
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
      decipher.setAAD(aad);
      decipher.setAuthTag(Buffer.from(req.tag, 'base64'));
      out = { data: Buffer.concat([decipher.update(Buffer.from(req.data, 'base64')), decipher.final()]).toString('base64') };
    } else throw Error('invalid operation');
    process.stdout.write(JSON.stringify(out));
  } catch (_) { process.stderr.write('AEAD operation failed\n'); process.exitCode = 1; }
});
