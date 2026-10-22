// Acceptance tests for the "Sign in with Solana" seat module (job 6417a35b).
//
// Each test is named after one acceptance item, and every test fails without
// the change in src/siw.mjs: the six required cases plus the negative cases
// that the module's checks exist for. The signing key below is a throwaway
// fixture key derived in-test; it signs nothing of value and no secret is stored.

import test from "node:test";
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, sign as cryptoSign } from "node:crypto";
import { createMessage, verify, parseMessage, base58Encode, base58Decode } from "../src/siw.mjs";

// Ed25519 PKCS8 DER prefix: 302e020100300506032b657004220420 + 32-byte seed.
const PKCS8_PREFIX = "302e020100300506032b657004220420";

function fixtureKeypair(seedByte) {
  const seed = Buffer.alloc(32, seedByte);
  const priv = createPrivateKey({
    key: Buffer.concat([Buffer.from(PKCS8_PREFIX, "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
  const rawPub = Buffer.from(
    createPublicKey(priv).export({ format: "der", type: "spki" })
  ).slice(-32);
  return { priv, rawPub };
}

const { priv, rawPub } = fixtureKeypair(7);

const ADDRESS = base58Encode(rawPub);
const DOMAIN = "lax.kognai.ai";
const NONCE = "a1b2c3d4e5f60718";
const ISSUED = 1_700_000_000;
const EXPIRES = 1_700_000_600;
const NOW = 1_700_000_300; // inside the window

function signed(over = {}) {
  const {
    domain = DOMAIN,
    address = ADDRESS,
    nonce = NONCE,
    issuedAt = ISSUED,
    expiresAt = EXPIRES,
  } = over;
  const message = createMessage({ domain, address, nonce, issuedAt, expiresAt });
  const signature = cryptoSign(null, Buffer.from(message, "utf8"), priv);
  return { message, signature: base58Encode(signature), address };
}

test("A1 valid: a correct signature inside the window and on the allowlist verifies", () => {
  const { message, signature, address } = signed();
  const r = verify({ message, signature, address, allowlist: [address], now: NOW, seen: new Set() });
  assert.deepEqual(r, { ok: true, reason: "ok" });
});

test("A2 wrong domain: a message for another domain is rejected when the expected domain is given", () => {
  const { message, signature, address } = signed({ domain: "evil.example" });
  const r = verify({ message, signature, address, domain: DOMAIN, now: NOW, seen: new Set() });
  assert.deepEqual(r, { ok: false, reason: "wrong-domain" });
  // Without an expected domain the signature still proves the address owns the text.
  const noExpectation = verify({ message, signature, address, now: NOW, seen: new Set() });
  assert.equal(noExpectation.ok, true);
  assert.equal(parseMessage(message).domain, "evil.example");
});

test("A3 expired: a message past its expiry does not verify", () => {
  const { message, signature, address } = signed();
  const r = verify({ message, signature, address, now: EXPIRES + 1, seen: new Set() });
  assert.deepEqual(r, { ok: false, reason: "expired" });
});

test("A4 replayed nonce: a nonce already in seen is rejected", () => {
  const { message, signature, address } = signed();
  const r = verify({ message, signature, address, seen: new Set([NONCE]), now: NOW });
  assert.deepEqual(r, { ok: false, reason: "replayed" });
});

test("A5 address not on the allowlist: rejected with not-allowed", () => {
  const { message, signature, address } = signed();
  const r = verify({
    message,
    signature,
    address,
    allowlist: ["SomeOtherAddress111111111111111111111111111111"],
    now: NOW,
  });
  assert.deepEqual(r, { ok: false, reason: "not-allowed" });
});

test("A6 malformed signature: a non-base58 or wrong length signature is rejected", () => {
  const { message, address } = signed();
  const bad = verify({ message, signature: "!!!not-base58!!!", address, now: NOW });
  assert.deepEqual(bad, { ok: false, reason: "bad-signature-encoding" });
  const short = verify({ message, signature: base58Encode(Buffer.alloc(10)), address, now: NOW });
  assert.deepEqual(short, { ok: false, reason: "bad-signature-encoding" });
});

test("A7 tampered message: changing the nonce after signing breaks the signature", () => {
  const { message, signature, address } = signed();
  const tampered = message.replace(NONCE, "ffffffffffffffff");
  const r = verify({ message: tampered, signature, address, now: NOW, seen: new Set() });
  assert.deepEqual(r, { ok: false, reason: "bad-signature" });
});

test("A8 not yet valid: a message used before its issued-at is rejected", () => {
  const { message, signature, address } = signed();
  const r = verify({ message, signature, address, now: ISSUED - 1, seen: new Set() });
  assert.deepEqual(r, { ok: false, reason: "not-yet-valid" });
});

test("A9 address binding: the message must name the address being verified", () => {
  const { message, signature } = signed();
  const other = base58Encode(Buffer.alloc(32, 9));
  const r = verify({ message, signature, address: other, now: NOW, seen: new Set() });
  assert.deepEqual(r, { ok: false, reason: "bad-address" });
});

test("A10 round trip: base58 encode/decode is exact and preserves leading zeros", () => {
  const b = Buffer.from("0000deadbeef00ff", "hex");
  assert.equal(base58Decode(base58Encode(b)).toString("hex"), b.toString("hex"));
  assert.equal(base58Encode(Buffer.alloc(0)), "");
});
