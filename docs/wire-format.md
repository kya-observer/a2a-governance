# Wire format

Mandates and receipts use the **Agent Authorization** model of
[AP2 v0.2](https://github.com/google-agentic-commerce/AP2/blob/main/docs/ap2/agent_authorization.md):
SD-JWT ([RFC 9901](https://www.rfc-editor.org/rfc/rfc9901)) chained with key-bound hops
([draft-gco-oauth-delegate-sd-jwt](https://github.com/GarethCOliver/gco-delegate-sd-jwt)).
Compatibility is tested in both directions against Google's AP2 Python SDK at commit
[`e1ea56d`](https://github.com/google-agentic-commerce/AP2/tree/e1ea56db72a6385bce3e5c1112b3a56ce60acb43).

## A chain, hop by hop

```
<open mandate>~<disclosures>~~<hop>~<disclosures>~~<closing hop>~<disclosures>~
```

Hops are joined with `~~`. Every segment except the last loses its trailing `~` when
joined, and the verifier restores it before hashing.

| Hop | JWS `typ` | Signed by | Mandate carries `cnf`? | Binds to previous hop |
|---|---|---|---|---|
| Open mandate | `dc+sd-jwt` | The trusted surface that showed the mandate to the user | Yes: the agent's key | — |
| Delegation | `kb+sd-jwt+kb` | The key named by the previous hop's `cnf` | Yes: the next holder's key | `sd_hash` (or `issuer_jwt_hash`) |
| Closing hop | `kb+sd-jwt` | The key named by the previous hop's `cnf` | No | `sd_hash` (or `issuer_jwt_hash`) |

Each hop's payload holds exactly one mandate as a selectively disclosable element of
`delegate_payload`:

```json
{ "delegate_payload": [{ "...": "<digest>" }], "_sd_alg": "sha-256" }
```

Hops after the first also carry `iat`, `aud`, `nonce` and the binding hash. Inside a
mandate, individual fields (`_sd`) and array elements (`{"...": digest}`) can also be
encoded as disclosures, as AP2 does. This profile still requires every disclosure to be
presented: a holder can't withhold any part of a mandate (see
[Where this implementation is stricter than AP2 v0.2](#where-this-implementation-is-stricter-than-ap2-v02)).

## The access mandate (`mandate.access.1`)

```json
{
  "vct": "mandate.access.1",
  "cnf": { "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } },
  "iat": 1790000000,
  "exp": 1790007200,
  "constraints": [
    { "type": "access.authorization_details", "authorization_details": [
        { "type": "calendar", "actions": ["read.freebusy"], "fields": ["start", "end"] } ] },
    { "type": "access.purpose", "purpose": "dpv:ServiceProvision" },
    { "type": "access.release", "release": "answer-only" },
    { "type": "access.max_uses", "max_uses": 3 }
  ]
}
```

The open mandate **must** carry `vct`, `cnf.jwk` and `exp`. A mandate without `exp`
would never expire.

The closed mandate in the closing hop keeps the same `vct` and states the one call it
authorizes. The verifier requires these fields to equal the call it's about to serve:

```json
{
  "vct": "mandate.access.1",
  "method": "SendMessage",
  "task_id": "task-7f3c",
  "authorization_details": [{ "type": "reading", "actions": ["search"], "fields": ["title"] }]
}
```

Hop IDs, used for use counting and revocation, are the digest of each hop's JWS signing
input (`header.payload`) without the signature, because ECDSA signatures are malleable.

## Where this implementation is stricter than AP2 v0.2

AP2 accepts all of these. We refuse them because each one widens what an attacker can
present:

| Case | AP2 v0.2 SDK | This implementation | Why |
|---|---|---|---|
| Disclosure not referenced by any digest | Accepted (ignored) | **Rejected** | RFC 9901 §7.1 requires rejection. An agent signs its own closing hop, so it can make `sd_hash` cover anything it appends |
| Digest whose disclosure is withheld (or a decoy) | Accepted; the claim is silently absent | **Rejected** | The holder picks what to forward and signs the next hop over its choice, so a withheld constraint or `exp` simply disappears |
| Open mandate without `exp` | Accepted (`exp` is optional in AP2's schemas) | **Rejected** | It would never expire |
| Duplicate JSON keys | Last value wins | **Rejected** | Parsers disagree on which duplicate wins |
| `aud` / `nonce` on the closing hop | Checked only if the caller passes expected values | **Always required** | A closing hop without them is replayable anywhere |
| Age of the closing hop | Unbounded | **At most 300 s** (configurable) | Limits the window for a captured presentation |
| Mandates per hop | The closing hop may carry several | **Exactly one** | One call, one mandate; simpler to evaluate |
| Hop `typ` spellings | `kb+sd-jwt` and `kb-sd-jwt` (and `+kb` forms) | Only the `+` forms AP2 emits | Fewer parser paths |
| Chain limits | None | 64 KiB, 8 hops | Bounded work before signatures are checked |
| JWK in `cnf` containing `d` | Not checked | **Rejected** | A private key in a mandate is a leak, never a binding |
| `_sd_alg` | sha-256, sha-384, sha-512 | sha-256 only | One algorithm to get right |

We also *emit* `dc+sd-jwt` for the open mandate, the SD-JWT VC type, and *accept*
`example+sd-jwt`, which is what AP2's SDK emits (see below).

## Observations about AP2 v0.2 (commit `e1ea56d`)

Found while building the interop suite. None of them blocks interoperability.

1. **Root `typ` is `example+sd-jwt`.** That's the placeholder default of the Python
   `sd-jwt` library, not the SD-JWT VC type `dc+sd-jwt`.
2. **Unreferenced disclosures are accepted.** A chain with disclosures appended by the
   agent still verifies. In our probes the forged values didn't reach the verified
   output, so this is a conformance gap with RFC 9901 §7.1, not a demonstrated exploit.
   Duplicate disclosures *are* rejected.
3. **Presentations are logged to disk.** `ap2/sdk/mandate.py` appends every
   presentation (the closing KB-SD-JWT and its disclosures) to
   `<python prefix>/lib/python3.x/.logs/mandate_operations.log`. The file is created
   `0644`, and there is no switch to turn it off. The presentations are bound to one
   audience and nonce, which limits replay, but they carry mandate content.
4. **`MandateClient.present()` extends only one hop** (reported upstream as
   [#353](https://github.com/google-agentic-commerce/AP2/issues/353)). It can't take an
   already joined chain. Multi-hop chains are built with `kb_sd_jwt.create` and joined by hand, as AP2's
   own `chain_tests.py` does.
5. **The receipt field differs between spec and SDK.** The spec's Mandate Receipt has
   `result`; the SDK's `ReceiptClient` writes `status`.
6. **Withheld disclosures and missing `exp` are accepted.** If an issuer makes a whole
   constraint, or `exp`, selectively disclosable, the agent can withhold it and the
   chain still verifies, minus that restriction. AP2's own payment and checkout mandates
   keep whole constraints non-disclosable (selective disclosure is used inside
   allow-lists, where withholding only narrows), but `exp` is optional in their schemas
   and the verifier never requires it.
7. **The PyPI package named `ap2` is not Google's.** Install the SDK from git, pinned by
   commit (see `interop/ap2/pyproject.toml`).
