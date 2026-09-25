# Security properties and the tests that prove them

Every property below has a test that fails if the check is removed. We confirmed this
by **mutation testing**: each check was disabled in turn and the suite rerun. All 18
mutations were caught.

## Mandate verification (`a2a-gov-mandate`)

| Threat | Control | Test |
|---|---|---|
| Forged open mandate | ES256 signature by a trusted surface the verifier knows | `the_wrong_trusted_surface_key_is_rejected`, `an_unknown_trusted_surface_is_rejected` |
| Algorithm substitution (`alg: none`, HS256) | Only ES256 is accepted | `only_es256_is_accepted` |
| Stolen mandate used by another agent | Each hop must be signed by the key the previous hop named in `cnf` | `a_hop_signed_by_anyone_but_the_bound_key_is_rejected` |
| Closing hop moved onto another chain | The signature key comes from the chain being verified | `a_closing_hop_cannot_be_moved_to_another_chain` |
| Agent drops a constraint it dislikes | `sd_hash` covers the previous hop's disclosures | `a_constraint_cannot_be_stripped_from_the_open_mandate` |
| Agent adds a constraint or claim | Every disclosure must be referenced by a signed digest (RFC 9901 §7.1) | `an_agent_cannot_smuggle_disclosures_into_the_open_mandate` |
| Tampered or duplicated disclosure | Digests over the exact encoded string; duplicates rejected | `a_tampered_disclosure_is_rejected`, `duplicate_disclosures_are_rejected`, `a_digest_referenced_twice_is_rejected` |
| Replay to another verifier or call | `aud` and `nonce` must match the verifier's challenge | `audience_and_nonce_must_match_the_verifier` |
| Replay of a captured presentation later | The closing hop is at most 300 s old | `stale_closing_hops_are_rejected` |
| Use after expiry, or pre-dated tokens | `exp`, `iat`, `nbf` checks with bounded skew | `an_expired_mandate_is_rejected`, `hops_issued_in_the_future_are_rejected` |
| Mandate type confusion (e.g. access → payment) | `vct` is fixed along the chain | `the_mandate_type_cannot_change_along_the_chain` |
| A delegation passed off as a closed mandate | Hop type, `cnf` and position must agree | `a_closing_hop_must_not_carry_cnf`, `a_closing_typed_hop_carrying_cnf_is_rejected`, `a_delegation_typed_hop_without_cnf_is_rejected`, `a_chain_ending_in_a_delegation_is_not_a_presentation` |
| An open mandate replayed as authorization | A presentation needs a closing hop | `an_open_mandate_alone_is_not_a_presentation` |
| Leaked private key in a mandate | JWKs containing `d` are refused | `a_cnf_carrying_a_private_key_is_rejected` |
| Resource exhaustion | 64 KiB and 8-hop limits, checked before parsing | `oversized_input_is_rejected_before_parsing`, `overlong_chains_are_rejected` |

## Error profile (`a2a-gov-extension`)

| Threat | Control | Test |
|---|---|---|
| A governance error mistaken for an A2A error (or the reverse) | Codes outside JSON-RPC's reserved block; clients match on `ErrorInfo.domain` + `reason` | `codes_never_collide_with_a2a_core_errors`, `clients_ignore_errors_from_other_domains_or_unknown_reasons` |
| Approval links that are phishable or plain HTTP | Challenge URLs must be absolute `https` | `challenge_urls_must_be_https` |

## Not covered yet

Use counting (`max_uses`), revocation, constraint evaluation against the concrete call,
and receipts are part of the decision point and are still to come. See the project
status in the README.
