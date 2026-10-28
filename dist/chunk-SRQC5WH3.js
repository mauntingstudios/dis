import { sha256Hex, importHmacSha256Key, hmacSha256WithKey, constantTimeEqual } from './chunk-MPWYZXW7.js';
import { randomBytes, randomInt } from './chunk-NGBC4E73.js';
import { bytesToHex, utf8ToBytes } from './chunk-JSKIWIEC.js';
import { DisInvalidArgumentError } from './chunk-MJO7IJZC.js';

// src/altcha/index.ts
async function createAltchaChallenge(hmacKey, options = {}) {
  const maxnumber = options.maxnumber ?? 5e4;
  if (maxnumber < 1) {
    throw new DisInvalidArgumentError("maxnumber must be >= 1");
  }
  const expiresInSeconds = options.expiresInSeconds ?? 300;
  if (expiresInSeconds < 1) {
    throw new DisInvalidArgumentError("expiresInSeconds must be >= 1");
  }
  const expiresAt = Math.floor(Date.now() / 1e3) + expiresInSeconds;
  const saltHex = bytesToHex(randomBytes(16));
  const salt = `${saltHex}?expires=${expiresAt}`;
  const targetNumber = randomInt(0, maxnumber);
  const challenge = await sha256Hex(utf8ToBytes(salt + targetNumber));
  const key = hmacKey instanceof Uint8Array ? await importHmacSha256Key(hmacKey, ["sign"]) : hmacKey;
  const sigBytes = await hmacSha256WithKey(key, utf8ToBytes(challenge));
  const signature = bytesToHex(sigBytes);
  return {
    algorithm: "SHA-256",
    challenge,
    maxnumber,
    salt,
    signature
  };
}
async function verifyAltchaSolution(hmacKey, payload, replayCache) {
  let parsed;
  if (typeof payload === "string") {
    try {
      const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
      const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
      const jsonStr = atob(padded);
      parsed = JSON.parse(jsonStr);
    } catch {
      return { valid: false };
    }
  } else if (typeof payload === "object" && payload !== null) {
    parsed = payload;
  } else {
    return { valid: false };
  }
  if (!parsed || parsed.algorithm !== "SHA-256" || typeof parsed.challenge !== "string" || typeof parsed.salt !== "string" || typeof parsed.signature !== "string" || typeof parsed.number !== "number" || !Number.isInteger(parsed.number) || parsed.number < 0) {
    return { valid: false };
  }
  const qIndex = parsed.salt.indexOf("?");
  if (qIndex === -1) {
    return { valid: false };
  }
  const params = new URLSearchParams(parsed.salt.slice(qIndex + 1));
  const expiresStr = params.get("expires");
  if (!expiresStr) {
    return { valid: false };
  }
  const expiresAt = parseInt(expiresStr, 10);
  const now = Math.floor(Date.now() / 1e3);
  if (isNaN(expiresAt) || expiresAt < now) {
    return { valid: false };
  }
  if (replayCache) {
    if (replayCache instanceof Map) {
      if (replayCache.has(parsed.signature)) {
        return { valid: false };
      }
    } else if (replayCache instanceof Set) {
      if (replayCache.has(parsed.signature)) {
        return { valid: false };
      }
    }
  }
  const key = hmacKey instanceof Uint8Array ? await importHmacSha256Key(hmacKey, ["sign"]) : hmacKey;
  const expectedSigBytes = await hmacSha256WithKey(key, utf8ToBytes(parsed.challenge));
  const expectedSig = bytesToHex(expectedSigBytes);
  const expectedSigBuf = utf8ToBytes(expectedSig);
  const suppliedSigBuf = utf8ToBytes(parsed.signature);
  if (expectedSigBuf.length !== suppliedSigBuf.length || !constantTimeEqual(expectedSigBuf, suppliedSigBuf)) {
    return { valid: false };
  }
  const computedChallenge = await sha256Hex(utf8ToBytes(parsed.salt + parsed.number));
  if (computedChallenge.toLowerCase() !== parsed.challenge.toLowerCase()) {
    return { valid: false };
  }
  if (replayCache) {
    if (replayCache instanceof Map) {
      replayCache.set(parsed.signature, expiresAt * 1e3);
    } else if (replayCache instanceof Set) {
      replayCache.add(parsed.signature);
    }
  }
  return {
    valid: true,
    signature: parsed.signature,
    expiresAt
  };
}
async function solveAltchaChallenge(challenge) {
  const max = challenge.maxnumber;
  for (let i = 0; i <= max; i++) {
    const hash = await sha256Hex(utf8ToBytes(challenge.salt + i));
    if (hash.toLowerCase() === challenge.challenge.toLowerCase()) {
      const solution = {
        algorithm: challenge.algorithm,
        challenge: challenge.challenge,
        number: i,
        salt: challenge.salt,
        signature: challenge.signature
      };
      return btoa(JSON.stringify(solution));
    }
  }
  throw new Error("Could not solve ALTCHA challenge within maxnumber range");
}

export { createAltchaChallenge, solveAltchaChallenge, verifyAltchaSolution };
//# sourceMappingURL=chunk-SRQC5WH3.js.map
//# sourceMappingURL=chunk-SRQC5WH3.js.map