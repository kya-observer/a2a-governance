# References

Versions and dates are the ones this implementation was built and tested against.

## Normative

| Reference | Used for |
|---|---|
| [A2A Protocol Specification v1.0](https://a2a-protocol.org/latest/specification/) ([source](https://github.com/a2aproject/A2A/blob/main/docs/specification.md), `main` @ `72b3761`, 2026-09-25; release v1.0.1, 2026-05-26) | §3.2.6 `A2A-Extensions`; §3.3.2, §5.4, §9.5 errors; §4.6 extensions; §7.6 in-task authorization, including §7.6.4 *In-Task Authorization Scope* ([#2081](https://github.com/a2aproject/A2A/pull/2081), 2026-07-30) |
| [RFC 9901: Selective Disclosure for JWTs](https://www.rfc-editor.org/rfc/rfc9901) (Nov 2025) | Disclosures, digests, verification (§7.1); test values from §5.2 |
| [RFC 7515: JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515) | Compact serialization |
| [RFC 7518 §3.4: ES256](https://www.rfc-editor.org/rfc/rfc7518#section-3.4) | Signature algorithm |
| [RFC 7517: JSON Web Key](https://www.rfc-editor.org/rfc/rfc7517) and [RFC 7800: Proof-of-Possession Key Semantics](https://www.rfc-editor.org/rfc/rfc7800) | `cnf.jwk` |
| [draft-gco-oauth-delegate-sd-jwt](https://github.com/GarethCOliver/gco-delegate-sd-jwt) (individual draft, as of 2026-09-24) | Chained, key-bound SD-JWT hops |
| [AP2 v0.2: Agent Authorization](https://github.com/google-agentic-commerce/AP2/blob/main/docs/ap2/agent_authorization.md) (released 2026-04-28; commit `e1ea56d`) | Open and closed mandates, trusted surface, Mandate Receipts, action-authorization errors |
| [JSON-RPC 2.0 §5.1](https://www.jsonrpc.org/specification#error_object) | Reserved error-code range |
| [`google.rpc.ErrorInfo`](https://github.com/googleapis/googleapis/blob/master/google/rpc/error_details.proto), [`google.rpc.Help`](https://github.com/googleapis/googleapis/blob/master/google/rpc/error_details.proto) | Error details, per A2A §9.5 |

## Informative

| Reference | Relevance |
|---|---|
| [A2A Extension and Protocol Binding Governance](https://a2a-protocol.org/latest/topics/extension-and-binding-governance/) | How extensions become experimental, then official |
| [`a2aproject/experimental-ext-oid4vp-auth`](https://github.com/a2aproject/experimental-ext-oid4vp-auth) | Adjacent in-task authorization extension (caller credentials via OpenID4VP) |
| [FIDO Alliance: standards for trusted AI agent interactions](https://fidoalliance.org/fido-alliance-to-develop-standards-for-trusted-ai-agent-interactions/) (2026-04-28) | AP2 donated to FIDO; Agentic Authentication and Payments technical working groups |
| [Google: donating AP2 to the FIDO Alliance](https://blog.google/products-and-platforms/platforms/google-pay/agent-payments-protocol-fido-alliance/) | Governance of the mandate format |
| [RFC 9396: OAuth 2.0 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396) | `access.authorization_details` |
| [W3C Data Privacy Vocabulary](https://w3id.org/dpv) | `access.purpose` values |
| [MCP SEP-1036: URL-mode elicitation](https://modelcontextprotocol.io/seps/1036-url-mode-elicitation-for-secure-out-of-band-intera) | The out-of-band approval pattern behind Challenge |
| [Signing the Transaction but Not the Decision (arXiv 2609.11757)](https://arxiv.org/pdf/2609.11757) | Attacks on AP2-style approval, and binding defenses |

## Software

| Component | Version | Licence |
|---|---|---|
| [`p256`](https://github.com/RustCrypto/elliptic-curves) (RustCrypto) | 0.14 | Apache-2.0 OR MIT |
| [`sha2`](https://github.com/RustCrypto/hashes) | 0.11 | Apache-2.0 OR MIT |
| [`base64`](https://github.com/marshallpierce/rust-base64) | 0.23 | Apache-2.0 OR MIT |
| [`getrandom`](https://github.com/rust-random/getrandom) | 0.4 | Apache-2.0 OR MIT |
| [`serde_json`](https://github.com/serde-rs/json) | 1 | Apache-2.0 OR MIT |
| [Google AP2 Python SDK](https://github.com/google-agentic-commerce/AP2/tree/main/code/sdk/python) (test oracle only) | commit `e1ea56d` | Apache-2.0 |
