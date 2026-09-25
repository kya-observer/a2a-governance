# Signed Agent Cards

`a2a-gov-card` signs and verifies A2A Agent Cards as A2A v1.0 §8.4 specifies. Governance
uses it to check who is asking: a verifier checks the calling agent's card against
issuer keys it trusts, and pins the card's fingerprint.

## What is signed (§8.4.1)

1. Remove `signatures`.
2. Remove default values, following the protobuf field rules in `a2a.proto`:
   - `REQUIRED` fields are always kept, even when empty (`"description": ""`,
     `"skills": []`);
   - `optional` fields and oneof members are kept whenever present;
   - other fields are removed at their default (`""`, `false`, `0`, `[]`, `{}`).

   The field table is generated from `a2a.proto` by `scripts/gen-card-schema.py`, pinned
   to `a2aproject/A2A@72b3761`, not transcribed by hand. Fields this version doesn't
   know are kept, so they're signed too.
3. Canonicalize with RFC 8785 (`jcs`).

The JWS protected header is `{"alg":"ES256","typ":"JOSE","kid":…}`, and the signature
covers the canonical bytes exactly as produced.

## Keys

Keys come from the verifier's configuration, looked up by `kid`. §8.4.3 lets a verifier
fetch the `jku` from the protected header; this implementation never does, because the
card's signer, or an attacker who rewrote the header, chooses that URL. Only ES256 is
accepted. Several signatures may be present (key rotation); one valid signature from a
trusted key is enough.

## Interoperability with the official a2a-sdk (1.1.5)

Tested both ways: cards signed by the SDK verify here, and the SDK's verifier accepts
cards signed here. The two canonicalizers are byte-identical on the RFC 8785 examples,
20,006 random doubles and 2,000 random documents.

The SDK doesn't sign exactly the §8.4.1 payload. It parses the card into protobuf (which
drops unknown fields and has no notion of `REQUIRED`), then also removes **every** empty
string, list and object, recursively. That includes empty `REQUIRED` fields and empty
values inside extension `params`. So:

- For cards without empty values, the two payloads are identical.
- A card that carries an empty `REQUIRED` field, as §5.7 requires, has two different
  payloads. By default this crate accepts a signature over either and reports which one
  in `Verified::form`. Set `accept_a2a_sdk_form: false` to require §8.4.1 exactly.
  Under the SDK's form, empty values aren't covered by the signature.
- Cards signed here in the §8.4.1 form with an empty `REQUIRED` field fail the SDK's
  verifier. `sign_a2a_sdk_form` produces the SDK's variant when that peer matters.

Other SDK behaviours to be aware of:
- `create_agent_card_signer` defaults `alg` to `HS256` (a shared-secret MAC) when the
  caller gives none.
- The verifier passes the unverified header's `jku` to the key provider, which invites
  fetching a key the signer chose.

## Fingerprints

`fingerprint(card)` is the SHA-256 of the §8.4.1 payload. It ignores formatting and
explicit defaults, but changes with any content change, including empty values the SDK's
form doesn't sign. So a pin forces re-consent even for changes the signature didn't
cover.
