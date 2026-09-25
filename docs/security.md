# Security properties and the tests that prove them

Every property below has a test that fails if its check is removed. We check this by
**mutation testing**: `scripts/mutation-check.py` disables each check in turn, reruns
the suite, and fails if any mutation survives. CI runs it on every change.

## Mandate verification (`a2a-gov-mandate`)

| Threat | Control | Test |
|---|---|---|
| Forged open mandate | ES256 signature by a trusted surface the verifier knows | `the_wrong_trusted_surface_key_is_rejected`, `an_unknown_trusted_surface_is_rejected` |
| Algorithm substitution (`alg: none`, HS256) | Only ES256 is accepted | `only_es256_is_accepted` |
| Stolen mandate used by another agent | Each hop must be signed by the key the previous hop named in `cnf` | `a_hop_signed_by_anyone_but_the_bound_key_is_rejected` |
| Closing hop moved onto another chain | The signature key comes from the chain being verified | `a_closing_hop_cannot_be_moved_to_another_chain` |
| **Agent withholds a constraint it dislikes** | Every digest must be disclosed. The agent signs its own closing hop, so `sd_hash` can't catch what the agent itself left out; this profile therefore accepts no withheld or decoy digests | `the_agent_cannot_withhold_a_constraint_it_dislikes`, `withheld_or_decoy_digests_are_refused` |
| Agent adds a constraint or claim | Every disclosure must be referenced by a signed digest (RFC 9901 §7.1) | `an_agent_cannot_smuggle_disclosures_into_the_open_mandate` |
| Someone alters a hop after the next holder signed | `sd_hash` covers the previous hop as presented | `any_change_to_the_open_mandate_after_the_agent_signed_breaks_the_binding` |
| Tampered or duplicated disclosure | Digests over the exact encoded string; duplicates rejected | `a_tampered_disclosure_is_rejected`, `duplicate_disclosures_are_rejected`, `a_digest_referenced_twice_is_rejected` |
| **A mandate that never expires** | The open mandate must carry `vct`, `cnf.jwk` and `exp`, and can't withhold them | `an_open_mandate_without_exp_is_refused`, `the_agent_cannot_withhold_exp` |
| **Signature malleability** (`s` → `n − s`) creating a second ID for one mandate | Hop IDs hash the signing input, not the signature (`hop_id`) | `a_malleated_root_signature_keeps_the_same_mandate_id` |
| Parsers disagreeing on duplicate JSON keys | Duplicate keys anywhere in a header, payload or disclosure are rejected | `jws_headers_and_payloads_with_duplicate_keys_are_rejected`, `disclosures_with_duplicate_keys_are_rejected` |
| Replay to another verifier or call | `aud` and `nonce` must match the verifier's challenge | `audience_and_nonce_must_match_the_verifier` |
| Replay of a captured presentation later | The closing hop is at most 300 s old | `stale_closing_hops_are_rejected` |
| Use after expiry, or pre-dated tokens | `exp`, `iat`, `nbf` checks with bounded, non-negative skew | `an_expired_mandate_is_rejected`, `hops_issued_in_the_future_are_rejected` |
| Mandate type confusion (e.g. access → payment) | `vct` is fixed along the chain | `the_mandate_type_cannot_change_along_the_chain` |
| A delegation passed off as a closed mandate | Hop type, `cnf` and position must agree | `a_closing_hop_must_not_carry_cnf`, `a_closing_typed_hop_carrying_cnf_is_rejected`, `a_delegation_typed_hop_without_cnf_is_rejected`, `a_chain_ending_in_a_delegation_is_not_a_presentation` |
| An open mandate replayed as authorization | A presentation needs a closing hop | `an_open_mandate_alone_is_not_a_presentation` |
| Leaked private key in a mandate | JWKs containing `d` are refused | `a_cnf_carrying_a_private_key_is_rejected` |
| Resource exhaustion | 64 KiB and 8-hop limits, checked before parsing | `oversized_input_is_rejected_before_parsing`, `overlong_chains_are_rejected` |

## Decision engine (`a2a-gov-pdp`)

| Threat | Control | Test |
|---|---|---|
| A mandate for one call used for another | The closed mandate must state this call's method, task and authorization details exactly | `a_closed_mandate_for_another_call_is_refused` |
| Requests beyond what was approved | `access.authorization_details`, `access.purpose`, `access.release`, with restricted dimensions required in the request | `requests_outside_the_authorization_details_are_refused`, `a_request_must_state_every_dimension_the_mandate_restricts`, `records_cannot_be_released_under_an_answer_only_mandate`, `a_different_purpose_is_refused` |
| **A delegation loosening the mandate** | Constraints of *every* authorizing hop apply, so a delegation can only narrow | `a_delegation_can_only_narrow`, `a_delegation_cannot_raise_the_roots_use_limit`, `delegation_depth_is_enforced` |
| Using a mandate more often than approved | Use limits counted by the verifier, atomically across hops, keyed on malleability-proof IDs | `max_uses_is_counted_by_the_verifier`, `use_limits_on_a_delegation_count_separately_and_atomically`, `a_malleated_open_mandate_shares_its_use_count` |
| Replaying a presentation | Nonces are single-use | `a_presentation_cannot_be_replayed`, `a_nonce_the_verifier_never_issued_is_refused` |
| Revoked authority | Revocation checked for the open mandate and every delegation | `revoked_mandates_are_refused`, `a_revoked_delegation_is_refused_even_though_the_open_mandate_is_live` |
| Constraints the verifier doesn't understand | Unknown constraint types never pass; they bring the user back in (Challenge) | `an_unknown_constraint_brings_the_user_back_in` |
| Storage failure | Any backend error denies (fail closed) | `any_backend_failure_fails_closed` |

## Receipts (`a2a-gov-receipt`)

| Threat | Control | Test |
|---|---|---|
| Forged receipt | ES256 by the verifier's key | `a_receipt_signed_by_another_key_is_rejected` |
| Values leaking into receipts | `released` accepts field names only | `released_entries_must_be_field_names_not_values` |
| Ambiguous outcome | Exactly one of `status` / `result`; error fields only on errors | `malformed_receipts_are_rejected` |
| Two receipts for one presentation via malleability | Receipts carry signature-free `mandate_id` and `presentation_id` and match on them; AP2's `reference` is kept for compatibility but is malleable | `receipts_identify_presentations_independently_of_the_signature_encoding` |
| Silent edits to the receipt log | Hash chain over sequence, previous hash and receipt | `an_edited_entry_is_detected_at_its_position`, `a_rehashed_forgery_still_breaks_the_next_link`, `a_renumbered_last_entry_is_detected` |

## Agent Cards (`a2a-gov-card`)

| Threat | Control | Test |
|---|---|---|
| A tampered card (name, endpoint, extension flags, skills) | ES256 over the §8.4.1 canonical payload | `any_change_to_signed_content_is_detected` |
| A signer, or header rewrite, pointing verification at its own key | Keys only from the verifier's configuration by `kid`; `jku` is never fetched | `keys_come_only_from_the_verifiers_configuration` |
| Algorithm confusion (`none`, `HS256`, which the a2a-sdk signer defaults to) | ES256 only | `only_es256_signatures_are_accepted` |
| Two JSON forms of one card treated differently | RFC 8785, byte-identical to the a2a-sdk; default values and formatting normalized | `the_specs_worked_example_canonicalizes_as_documented`, `every_document_canonicalizes_like_the_a2a_sdk`, `fingerprints_change_with_content_but_not_with_formatting` |
| Different integers sharing one canonical form | Integers outside ±(2^53 − 1) are refused | `integers_outside_the_exact_range_are_refused` |
| Unsigned card content accepted silently | Verification reports whether the a2a-sdk's weaker form was used; it can be refused | `cards_signed_over_the_a2a_sdk_form_verify_only_when_allowed` |

## Error profile and binding (`a2a-gov-extension`, `a2a-gov-binding`)

| Threat | Control | Test |
|---|---|---|
| A governance error mistaken for an A2A error (or the reverse) | Codes outside JSON-RPC's reserved block; clients match on `ErrorInfo.domain` + `reason` | `codes_never_collide_with_a2a_core_errors`, `clients_ignore_errors_from_other_domains_or_unknown_reasons` |
| Phishable or plain-HTTP approval links | Challenge and approval URLs must be absolute `https` | `challenge_urls_must_be_https`, `approval_urls_must_be_https` |
| Extension data smuggled onto objects that don't activate the extension | Metadata is read only when the object lists the extension | `a_presentation_is_ignored_unless_the_message_activates_the_extension` |

## Not covered by this library, or not yet

- **Nonce single use** isn't enforced by `verify_chain`, which only checks that the
  nonce matches. `a2a-gov-pdp` enforces it through its `Nonces` store; anyone calling
  `verify_chain` directly must do the same.
- **Trusted-surface key lookup** is the caller's. The `root_key` callback receives the
  *unverified* header: look keys up by `kid` in your own configuration, and never use a
  key named in the header (`jwk`, `jku`, `x5c`, `x5u`).
- **Selective disclosure** is limited in this profile: withholding and decoy digests are
  refused (see above), so a holder can't minimize what it shows a verifier. Safe
  minimization (withholding entries of an allow-list, which only narrows) is future
  work.
- **Revocation propagation**, sender-constrained presentations (DPoP) and intent checks
  are later conformance levels.
