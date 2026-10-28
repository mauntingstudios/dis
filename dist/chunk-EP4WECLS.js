import { subtle } from './chunk-CYIGDF63.js';
import { DisInvalidArgumentError } from './chunk-MJO7IJZC.js';

// src/signing/index.ts
var ECDSA_P256_ALGORITHM = { name: "ECDSA", namedCurve: "P-256" };
var ECDSA_P256_PARAMS = { name: "ECDSA", hash: "SHA-256" };
var P256_ORDER = BigInt(
  "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
);
var P256_HALF_ORDER = P256_ORDER / 2n;
var ECDSA_P256_SIGNATURE_LENGTH = 64;
function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) {
    value = value << 8n | BigInt(byte);
  }
  return value;
}
function bigIntToBytes32(value) {
  const out = new Uint8Array(32);
  let remaining = value;
  for (let i = 31; i >= 0; i -= 1) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}
async function generateEcdsaP256KeyPair() {
  const keyPair = await subtle().generateKey(
    ECDSA_P256_ALGORITHM,
    /* extractable */
    false,
    ["sign", "verify"]
  );
  const spki = await subtle().exportKey("spki", keyPair.publicKey);
  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    publicKeySpki: new Uint8Array(spki)
  };
}
async function importEcdsaP256PublicKeySpki(spki) {
  return subtle().importKey(
    "spki",
    spki,
    ECDSA_P256_ALGORITHM,
    false,
    ["verify"]
  );
}
async function signEcdsaP256(privateKey, data) {
  const signature = await subtle().sign(ECDSA_P256_PARAMS, privateKey, data);
  const bytes = new Uint8Array(signature);
  if (bytes.length !== ECDSA_P256_SIGNATURE_LENGTH) {
    throw new DisInvalidArgumentError("unexpected ECDSA signature byte length");
  }
  const s = bytesToBigInt(bytes.subarray(32));
  if (s > P256_HALF_ORDER) {
    bytes.set(bigIntToBytes32(P256_ORDER - s), 32);
  }
  return bytes;
}
async function verifyEcdsaP256(publicKey, signature, data) {
  if (signature.length !== ECDSA_P256_SIGNATURE_LENGTH) {
    throw new DisInvalidArgumentError("unexpected ECDSA signature byte length");
  }
  try {
    return await subtle().verify(
      ECDSA_P256_PARAMS,
      publicKey,
      signature,
      data
    );
  } catch {
    return false;
  }
}

export { ECDSA_P256_SIGNATURE_LENGTH, generateEcdsaP256KeyPair, importEcdsaP256PublicKeySpki, signEcdsaP256, verifyEcdsaP256 };
//# sourceMappingURL=chunk-EP4WECLS.js.map
//# sourceMappingURL=chunk-EP4WECLS.js.map