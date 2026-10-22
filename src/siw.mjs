// Sign in with Solana: message format, ed25519 verification, replay guard, allowlist.
//
// LAX seat job 6417a35b "Sign in with Solana: message, verification, allowlist".
//
// Interface (from the job text):
//   createMessage(params) -> string
//   verify({message, signature, address, allowlist, now, seen}) -> {ok, reason}
//
// Pure: no RPC, no clock, no keys. `now` and `seen` are passed in so the caller
// owns time and replay state; the module never reads Date.now() or any store.

import { createPublicKey, verify as cryptoVerify } from "node:crypto";

// The message format is a small, line based, human readable header. Field names
// and order are fixed so an independent implementation can parse the same text.
// Address and nonce are lower-case hex / base58 as supplied; domain is exact.
const HEADER = "Sign in with Solana";

// Build the canonical message. Issued-at and expiry are unix seconds. Every
// field is required; a missing or non-string field is a programming error, so
// the builder throws rather than emit a half message that could still verify.
export function createMessage(params) {
  if (!params || typeof params !== "object") {
    throw new TypeError("createMessage requires an object");
  }
  const { domain, address, nonce, issuedAt, expiresAt } = params;
  const fields = { domain, address, nonce, issuedAt, expiresAt };
  for (const [k, v] of Object.entries(fields)) {
    if (typeof v !== "string" && typeof v !== "number") {
      throw new TypeError(`createMessage: ${k} is required`);
    }
  }
  if (!Number.isInteger(Number(issuedAt)) || !Number.isInteger(Number(expiresAt))) {
    throw new TypeError("createMessage: issuedAt and expiresAt must be integer unix seconds");
  }
  if (Number(expiresAt) <= Number(issuedAt)) {
    throw new RangeError("createMessage: expiresAt must be after issuedAt");
  }
  // Keep the exact field order: an independent parser can split on the newline
  // and match positionally, so the order is part of the contract.
  return [
    HEADER,
    `domain: ${domain}`,
    `address: ${address}`,
    `nonce: ${nonce}`,
    `issued at: ${Number(issuedAt)}`,
    `expires at: ${Number(expiresAt)}`,
  ].join("\n");
}

// Parse a message produced by createMessage. Strict: the header must match and
// every field must be present exactly once, in order. Returns the fields or null
// when the text is not a well formed message.
export function parseMessage(message) {
  if (typeof message !== "string") return null;
  const lines = message.split("\n");
  if (lines.length !== 6) return null;
  if (lines[0] !== HEADER) return null;
  const grab = (line, label) => {
    const prefix = `${label}: `;
    if (!line.startsWith(prefix)) return null;
    return line.slice(prefix.length);
  };
  const domain = grab(lines[1], "domain");
  const address = grab(lines[2], "address");
  const nonce = grab(lines[3], "nonce");
  const issuedRaw = grab(lines[4], "issued at");
  const expiresRaw = grab(lines[5], "expires at");
  if (domain === null || address === null || nonce === null) return null;
  if (issuedRaw === null || expiresRaw === null) return null;
  if (!/^\d+$/.test(issuedRaw) || !/^\d+$/.test(expiresRaw)) return null;
  return { domain, address, nonce, issuedAt: Number(issuedRaw), expiresAt: Number(expiresRaw) };
}

// A Solana address is a base58 ed25519 public key. We accept the 32 byte
// (44 char) or 64 byte forms, decoded, then hand the raw key to node's ed25519
// verifier. This keeps the module dependency free while still checking the
// signature against the key the message names.
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_MAP = (() => {
  const m = new Map();
  for (let i = 0; i < B58.length; i++) m.set(B58[i], i);
  return m;
})();

export function base58Decode(s) {
  if (typeof s !== "string" || s.length === 0) return null;
  let n = 0n;
  for (const ch of s) {
    const v = B58_MAP.get(ch);
    if (v === undefined) return null;
    n = n * 58n + BigInt(v);
  }
  // Preserve leading zero bytes ("1" encodes a zero byte).
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const leadingZeros = s.length - s.replace(/^1+/, "").length;
  const bytes = Buffer.from(hex, "hex");
  return Buffer.concat([Buffer.alloc(leadingZeros), bytes]);
}

export function base58Encode(buf) {
  if (!Buffer.isBuffer(buf)) return null;
  let n = 0n;
  for (const b of buf) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n = n / 58n;
  }
  for (const b of buf) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out || "";
}

// Wrap a raw 32 byte ed25519 public key in the SPKI DER prefix node expects.
function ed25519Key(raw32) {
  const DER_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({ key: Buffer.concat([DER_PREFIX, raw32]), format: "der", type: "spki" });
}

// verify({message, signature, address, allowlist, now, seen}) -> {ok, reason}
//
// Reasons are single, stable strings so a caller can branch on them:
//   ok | malformed-message | bad-signature | expired | not-yet-valid
//   | replayed | not-allowed | bad-address | bad-signature-encoding
//
// Order of checks is deliberate: shape, then signature (proves the address owns
// the message), then time, then allowlist, then replay. A caller who wants the
// replay guard to only fire for authentic messages gets that for free.
export function verify(input) {
  if (!input || typeof input !== "object") return { ok: false, reason: "malformed-message" };
  const { message, signature, address, allowlist, now, seen } = input;

  const parsed = parseMessage(message);
  if (!parsed) return { ok: false, reason: "malformed-message" };

  // The message must name the address being authenticated, otherwise a valid
  // signature over someone else's message would sign us in as them.
  if (typeof address !== "string" || parsed.address !== address) {
    return { ok: false, reason: "bad-address" };
  }

  const pub = base58Decode(address);
  if (!pub || pub.length !== 32) return { ok: false, reason: "bad-address" };

  const sig = base58Decode(signature);
  if (!sig || sig.length !== 64) return { ok: false, reason: "bad-signature-encoding" };

  let sigOk = false;
  try {
    sigOk = cryptoVerify(null, Buffer.from(message, "utf8"), ed25519Key(pub), sig);
  } catch {
    sigOk = false;
  }
  if (!sigOk) return { ok: false, reason: "bad-signature" };

  if (typeof now !== "number" || !Number.isFinite(now)) {
    return { ok: false, reason: "malformed-message" };
  }
  if (now < parsed.issuedAt) return { ok: false, reason: "not-yet-valid" };
  if (now >= parsed.expiresAt) return { ok: false, reason: "expired" };

  if (allowlist !== undefined && allowlist !== null) {
    if (!Array.isArray(allowlist) || !allowlist.includes(address)) {
      return { ok: false, reason: "not-allowed" };
    }
  }

  if (seen !== undefined && seen !== null) {
    const isSeen = typeof seen === "function" ? seen : (n) => seen.has && seen.has(n);
    if (isSeen(parsed.nonce)) return { ok: false, reason: "replayed" };
  }

  return { ok: true, reason: "ok" };
}

export { HEADER };
