//! Verifying a `~~`-joined mandate chain.

use serde_json::{Map, Value};

use crate::sdjwt::{self, digest, hop_id};
use crate::{Error, PublicJwk, jws};

/// Largest chain accepted, checked before any parsing.
pub const MAX_CHAIN_BYTES: usize = 64 * 1024;
/// Most segments (root + hops) accepted in one chain.
pub const MAX_HOPS: usize = 8;

/// `dc+sd-jwt` is the SD-JWT VC type. AP2 v0.2's SDK emits its library's
/// placeholder `example+sd-jwt`, accepted for interoperability.
const ROOT_TYPS: [&str; 2] = ["dc+sd-jwt", "example+sd-jwt"];
pub(crate) const TYP_CLOSING: &str = "kb+sd-jwt";
pub(crate) const TYP_DELEGATION: &str = "kb+sd-jwt+kb";

/// What the verifier expects of the closing hop, and its clock.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    aud: String,
    nonce: String,
    now: i64,
    clock_skew: i64,
    max_closing_age: i64,
}

impl VerifyOptions {
    /// `aud` and `nonce` are the values this verifier issued for the call;
    /// `now` is the current Unix time. Defaults: 60 s clock skew, closing hop
    /// at most 300 s old.
    pub fn new(aud: &str, nonce: &str, now: i64) -> Self {
        Self {
            aud: aud.to_owned(),
            nonce: nonce.to_owned(),
            now,
            clock_skew: 60,
            max_closing_age: 300,
        }
    }

    /// Tolerance for `exp`, `nbf` and `iat` checks, in seconds.
    pub fn clock_skew(mut self, seconds: u32) -> Self {
        self.clock_skew = i64::from(seconds);
        self
    }

    /// Maximum age of the closing hop's `iat`, in seconds.
    pub fn max_closing_age(mut self, seconds: u32) -> Self {
        self.max_closing_age = i64::from(seconds);
        self
    }
}

/// The role of a hop in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopKind {
    /// The open mandate, signed by the trusted surface.
    Root,
    /// Narrows the mandate and names the next holder's key.
    Delegation,
    /// Binds the chain to one call for one verifier.
    Closing,
}

/// One verified hop.
#[derive(Debug, Clone)]
pub struct VerifiedHop {
    id: String,
    kind: HopKind,
    header: Map<String, Value>,
    claims: Map<String, Value>,
    mandate: Map<String, Value>,
}

impl VerifiedHop {
    /// A stable identifier ([`crate::sdjwt::hop_id`]): the digest of the hop's
    /// signing input, without the signature, so every presentation of one open
    /// mandate, and every malleated twin of it, shares the root's ID. Verifiers
    /// key use counts and revocations on it.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The hop's role.
    pub fn kind(&self) -> HopKind {
        self.kind
    }

    /// The JWS protected header.
    pub fn header(&self) -> &Map<String, Value> {
        &self.header
    }

    /// Hop-level claims (`iat`, `aud`, `nonce`, `sd_hash`, ...), without the mandate.
    pub fn claims(&self) -> &Map<String, Value> {
        &self.claims
    }

    /// The disclosed mandate content.
    pub fn mandate(&self) -> &Map<String, Value> {
        &self.mandate
    }
}

/// A chain whose structure and cryptography checked out: signatures, hop
/// bindings, key binding, required claims, times, audience and nonce.
///
/// Verification does **not** evaluate constraints. A caller must apply the
/// constraints of **every** authorizing hop (the open mandate and each
/// delegation), not just [`VerifiedChain::open`]: a delegation can carry any
/// value, including a looser one, and only applying all of them makes a
/// delegation narrow the mandate. Nonce single use is also the caller's job.
#[derive(Debug, Clone)]
pub struct VerifiedChain {
    hops: Vec<VerifiedHop>,
}

impl VerifiedChain {
    /// All hops, root first.
    pub fn hops(&self) -> &[VerifiedHop] {
        &self.hops
    }

    /// The open mandate the user approved.
    pub fn open(&self) -> &Map<String, Value> {
        &self.hops[0].mandate
    }

    /// The closed mandate describing this call.
    pub fn closed(&self) -> &Map<String, Value> {
        &self.hops[self.hops.len() - 1].mandate
    }
}

struct Segment<'a> {
    canonical: String,
    jwt: &'a str,
}

impl<'a> Segment<'a> {
    fn disclosures(&self) -> Result<Vec<&str>, Error> {
        let inner = &self.canonical[self.jwt.len()..];
        let inner = inner.strip_prefix('~').unwrap_or(inner);
        let inner = inner.strip_suffix('~').unwrap_or(inner);
        if inner.is_empty() {
            return Ok(Vec::new());
        }
        let parts: Vec<&str> = inner.split('~').collect();
        if parts.iter().any(|p| p.is_empty()) {
            return Err(Error::Malformed("empty disclosure".into()));
        }
        Ok(parts)
    }
}

fn split(chain: &str) -> Result<Vec<Segment<'_>>, Error> {
    if chain.len() > MAX_CHAIN_BYTES {
        return Err(Error::Malformed(format!(
            "chain exceeds {MAX_CHAIN_BYTES} bytes"
        )));
    }
    let raw: Vec<&str> = chain.split("~~").collect();
    if raw.len() > MAX_HOPS {
        return Err(Error::Chain(format!("more than {MAX_HOPS} hops")));
    }
    if raw.len() < 2 {
        return Err(Error::Chain(
            "a presentation needs an open mandate and a closing hop".into(),
        ));
    }
    let last = raw.len() - 1;
    raw.into_iter()
        .enumerate()
        .map(|(i, seg)| {
            // Joining strips each non-final segment's trailing '~' (AP2, Delegate SD-JWT).
            let canonical = if i == last {
                if !seg.ends_with('~') {
                    return Err(Error::Malformed("final segment must end with '~'".into()));
                }
                seg.to_owned()
            } else {
                format!("{seg}~")
            };
            let jwt = seg.split('~').next().unwrap_or_default();
            if jwt.is_empty() {
                return Err(Error::Malformed("empty JWT in segment".into()));
            }
            Ok(Segment { canonical, jwt })
        })
        .collect()
}

/// Verifies a presentation chain: an open mandate, optional delegations, and a
/// closing hop addressed to this verifier.
///
/// `root_key` maps the open mandate's JWS header to the trusted surface's
/// public key, or `None` if the issuer isn't trusted. The header is
/// **unverified** when it's called: look the key up by `kid` (or use a fixed
/// key) in the verifier's own configuration, and never take a key from the
/// header itself (`jwk`, `jku`, `x5c`, `x5u`).
pub fn verify_chain(
    chain: &str,
    root_key: impl Fn(&Map<String, Value>) -> Option<PublicJwk>,
    opts: &VerifyOptions,
) -> Result<VerifiedChain, Error> {
    let segments = split(chain)?;
    let last = segments.len() - 1;
    let mut hops: Vec<VerifiedHop> = Vec::with_capacity(segments.len());

    for (i, seg) in segments.iter().enumerate() {
        let unverified = jws::decode(seg.jwt)?;
        let typ = unverified
            .header
            .get("typ")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let (kind, key) = if i == 0 {
            if !ROOT_TYPS.contains(&typ) {
                return Err(Error::Chain(format!("root typ {typ:?} is not an SD-JWT")));
            }
            (
                HopKind::Root,
                root_key(&unverified.header).ok_or(Error::UnknownIssuer)?,
            )
        } else {
            let kind = match typ {
                TYP_CLOSING => HopKind::Closing,
                TYP_DELEGATION => HopKind::Delegation,
                other => return Err(Error::Chain(format!("hop typ {other:?}"))),
            };
            (kind, bound_key(&hops[i - 1])?)
        };

        let verified = jws::verify(seg.jwt, &key)?;
        let mut claims = sdjwt::resolve(verified.payload, &seg.disclosures()?)?;
        let mandate = single_mandate(&mut claims)?;

        check_times(&claims, opts)?;
        check_times(&mandate, opts)?;

        if i > 0 {
            check_binding(&claims, &segments[i - 1])?;
            if !matches!(claims.get("iat"), Some(Value::Number(_))) {
                return Err(Error::Malformed("hop missing iat".into()));
            }
            let has_cnf = mandate.contains_key("cnf");
            match (kind, i == last) {
                (HopKind::Closing, true) if !has_cnf => check_closing(&claims, opts)?,
                (HopKind::Closing, true) => {
                    return Err(Error::Chain("closing hop carries cnf".into()));
                }
                (HopKind::Delegation, false) if has_cnf => {}
                (HopKind::Delegation, false) => {
                    return Err(Error::Chain("delegation lacks cnf".into()));
                }
                (HopKind::Delegation, true) => {
                    return Err(Error::Chain("chain ends in a delegation".into()));
                }
                _ => return Err(Error::Chain("closing hop before the end".into())),
            }
            if mandate.get("vct") != hops[0].mandate.get("vct") {
                return Err(Error::Chain("mandate type changed along the chain".into()));
            }
        } else {
            check_open_mandate(&mandate)?;
        }

        hops.push(VerifiedHop {
            id: hop_id(seg.jwt),
            kind,
            header: verified.header,
            claims,
            mandate,
        });
    }
    Ok(VerifiedChain { hops })
}

/// The open mandate must say what it is, whom it's bound to, and when it ends.
/// Without `exp` a mandate would never expire.
fn check_open_mandate(mandate: &Map<String, Value>) -> Result<(), Error> {
    if !mandate.get("vct").is_some_and(Value::is_string) {
        return Err(Error::Chain("open mandate has no vct".into()));
    }
    if !mandate
        .get("cnf")
        .and_then(|c| c.get("jwk"))
        .is_some_and(Value::is_object)
    {
        return Err(Error::Chain("open mandate has no cnf.jwk".into()));
    }
    if !mandate.get("exp").is_some_and(|e| e.as_i64().is_some()) {
        return Err(Error::Chain("open mandate has no exp".into()));
    }
    Ok(())
}

fn bound_key(prev: &VerifiedHop) -> Result<PublicJwk, Error> {
    let jwk = prev
        .mandate
        .get("cnf")
        .and_then(|c| c.get("jwk"))
        .ok_or_else(|| Error::Chain("previous hop names no cnf.jwk".into()))?;
    PublicJwk::from_value(jwk)
}

fn single_mandate(claims: &mut Map<String, Value>) -> Result<Map<String, Value>, Error> {
    match claims.remove("delegate_payload") {
        Some(Value::Array(items)) => match <[Value; 1]>::try_from(items) {
            Ok([Value::Object(m)]) => Ok(m),
            _ => Err(Error::Chain(
                "delegate_payload must disclose exactly one mandate".into(),
            )),
        },
        _ => Err(Error::Chain("missing delegate_payload".into())),
    }
}

fn check_binding(claims: &Map<String, Value>, prev: &Segment<'_>) -> Result<(), Error> {
    let (actual, expected) = match (claims.get("sd_hash"), claims.get("issuer_jwt_hash")) {
        (Some(v), None) => (v, digest(&prev.canonical)),
        (None, Some(v)) => (v, digest(prev.jwt)),
        _ => {
            return Err(Error::Binding(
                "need exactly one of sd_hash, issuer_jwt_hash".into(),
            ));
        }
    };
    if actual.as_str() != Some(expected.as_str()) {
        return Err(Error::Binding(
            "hash does not match the previous hop".into(),
        ));
    }
    Ok(())
}

fn check_closing(claims: &Map<String, Value>, opts: &VerifyOptions) -> Result<(), Error> {
    if claims.get("aud").and_then(Value::as_str) != Some(opts.aud.as_str()) {
        return Err(Error::Audience);
    }
    if claims.get("nonce").and_then(Value::as_str) != Some(opts.nonce.as_str()) {
        return Err(Error::Nonce);
    }
    let iat = claims
        .get("iat")
        .and_then(Value::as_i64)
        .unwrap_or(i64::MIN);
    if opts.now.saturating_sub(iat) > opts.max_closing_age {
        return Err(Error::Stale);
    }
    Ok(())
}

fn check_times(m: &Map<String, Value>, opts: &VerifyOptions) -> Result<(), Error> {
    let time = |name: &str| -> Result<Option<i64>, Error> {
        match m.get(name) {
            None => Ok(None),
            Some(v) => v
                .as_i64()
                .map(Some)
                .ok_or_else(|| Error::Malformed(format!("{name} must be an integer"))),
        }
    };
    if let Some(exp) = time("exp")?
        && opts.now > exp.saturating_add(opts.clock_skew)
    {
        return Err(Error::Expired);
    }
    for name in ["iat", "nbf"] {
        if let Some(t) = time(name)?
            && t > opts.now.saturating_add(opts.clock_skew)
        {
            return Err(Error::NotYetValid);
        }
    }
    Ok(())
}
