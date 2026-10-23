# siw-solana

Sign in with Solana, as a pure module for LAX job `6417a35b-ee4b-4a4b-a7bd-8fafad9f980b`.

A Sign in with Solana component: the message format (domain, address, nonce,
issued at, expiry), ed25519 verification, a replay guard and an allowlist check.

Pure: no RPC, no clock, no keys, no network. `now` and `seen` are passed in, so
the caller owns time and replay state. The module never reads `Date.now()` and
holds no store.

## Interface

```js
import { createMessage, verify, parseMessage } from "siw-solana";

const message = createMessage({
  domain: "lax.kognai.ai",
  address: "3f7x...",          // base58 ed25519 public key
  nonce: "a1b2c3d4e5f60718",
  issuedAt: 1700000000,        // unix seconds
  expiresAt: 1700000600,
});

verify({ message, signature, address, allowlist, now, seen, domain });
// -> { ok: boolean, reason: string }
```

`signature` is the base58 ed25519 signature over the exact message bytes.
`allowlist` is optional (array of addresses). `seen` is optional (a `Set`, or a
function `nonce => boolean`) used for replay protection: a nonce already in the
store is refused with `replayed`, and a successful verify adds the nonce to the
store, so the same store refuses the second use of one message. A refused
message consumes nothing, so a corrected retry still works. Pass a check-only
function if the caller wants to record the nonce itself. `now` is the current
unix time in seconds. `domain` is optional: when supplied (also as
`expectedDomain`), the message must carry exactly that domain, so a signature
harvested from another site cannot be replayed here.

`createMessage` takes `domain`, `address`, `nonce`, `issuedAt` and `expiresAt`;
the expiry is also accepted as `expirationTime`, `expires_at`, `expires` or
`expiry`, and the issue time as `issued_at` or `issued`, because the seat spec
names the fields but not the keys. The message text uses one spelling, so an
independent parser sees the same six lines.

## Reasons

Stable, single strings so a caller can branch on them:

| reason | meaning |
|---|---|
| `ok` | valid |
| `malformed-message` | the text is not a well formed message |
| `wrong-domain` | an expected `domain` was supplied and the message names another |
| `bad-address` | the message does not name the verified address, or it is not a 32 byte key |
| `bad-signature-encoding` | the signature is not base58 or not 64 bytes |
| `bad-signature` | the signature does not verify over the message |
| `not-yet-valid` | `now < issuedAt` |
| `expired` | `now >= expiresAt` |
| `not-allowed` | the address is not on the allowlist |
| `replayed` | the nonce is in `seen` |

## Message format

```
Sign in with Solana
domain: lax.kognai.ai
address: <base58>
nonce: <string>
issued at: <unix seconds>
expires at: <unix seconds>
```

The header and field order are fixed so an independent implementation can parse
the same text. `createMessage` throws on a missing field, a non integer time, or
an expiry at or before the issue time, rather than emit a half message that could
still verify.

## Tests

```
node --test test/*.test.mjs
```

Thirteen tests, each named after an acceptance item and each failing without the
change: valid, wrong domain, expired, replayed nonce, not on the allowlist,
malformed signature, plus tampered message, not yet valid, address binding, a
base58 round trip, a real two-use replay guard, a refused message not consuming
its nonce, and the field spellings. No install, no network, Node 20 or later.