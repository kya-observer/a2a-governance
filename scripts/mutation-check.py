#!/usr/bin/env python3
"""Targeted mutation testing for every security check in this workspace.

Each mutation disables or weakens one check. The crate's tests must then fail.
A mutation that leaves the tests green means that check isn't protected by any
test, and this script exits non-zero.

    python3 scripts/mutation-check.py            # run everything
    python3 scripts/mutation-check.py --list     # only confirm every target exists
    python3 scripts/mutation-check.py pdp        # one crate

Mutations are exact text replacements, so a refactor that moves a check makes
`--list` fail loudly instead of silently skipping it. Files are restored from
git after each mutation; run it on a clean tree.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (crate, file under crates/<crate>/src, description, original text, mutated text)
MUTATIONS: list[tuple[str, str, str, str, str]] = [
    # --- a2a-gov-mandate -----------------------------------------------------------
    ("mandate", "chain.rs", "binding check disabled", "            check_binding(&claims, &segments[i - 1])?;\n", ""),
    ("mandate", "sdjwt.rs", "unreferenced disclosures allowed", "if resolver.used != disclosures.len() {", "if false {"),
    ("mandate", "sdjwt.rs", "withheld disclosures allowed", "if resolver.withheld > 0 {", "if false {"),
    ("mandate", "sdjwt.rs", "digest referenced twice allowed", "if !self.seen.insert(digest.to_owned()) {", "if false && !self.seen.insert(digest.to_owned()) {"),
    ("mandate", "sdjwt.rs", "hop id covers the signature", "let signing_input = jwt.rsplit_once('.').map_or(jwt, |(input, _)| input);", "let signing_input = jwt;"),
    ("mandate", "chain.rs", "audience not checked", 'if claims.get("aud").and_then(Value::as_str) != Some(opts.aud.as_str()) {', "if false {"),
    ("mandate", "chain.rs", "nonce not checked", 'if claims.get("nonce").and_then(Value::as_str) != Some(opts.nonce.as_str()) {', "if false {"),
    ("mandate", "chain.rs", "hop key not taken from cnf", "(kind, bound_key(&hops[i - 1])?)", "(kind, bound_key(&hops[0])?)"),
    ("mandate", "jwk.rs", "private JWK accepted", 'if obj.contains_key("d") {', "if false {"),
    ("mandate", "chain.rs", "expiry ignored", "&& opts.now > exp.saturating_add(opts.clock_skew)", "&& false"),
    ("mandate", "chain.rs", "future iat accepted", "&& t > opts.now.saturating_add(opts.clock_skew)", "&& false"),
    ("mandate", "chain.rs", "staleness ignored", "if opts.now.saturating_sub(iat) > opts.max_closing_age {", "if false {"),
    ("mandate", "chain.rs", "vct may change", 'if mandate.get("vct") != hops[0].mandate.get("vct") {', "if false {"),
    ("mandate", "chain.rs", "exp not required", 'if !mandate.get("exp").is_some_and(|e| e.as_i64().is_some()) {', "if false {"),
    ("mandate", "chain.rs", "closing hop may carry cnf", 'return Err(Error::Chain("closing hop carries cnf".into()));', "check_closing(&claims, opts)?;"),
    ("mandate", "chain.rs", "delegation may lack cnf", "(HopKind::Delegation, false) if has_cnf => {}", "(HopKind::Delegation, false) => {}"),
    ("mandate", "chain.rs", "hop typ not checked", 'other => return Err(Error::Chain(format!("hop typ {other:?}"))),', "_ => HopKind::Closing,"),
    ("mandate", "jws.rs", "alg not checked", 'other => return Err(Error::UnsupportedAlgorithm(format!("{other:?}"))),', "_ => {}"),
    ("mandate", "strict_json.rs", "duplicate keys allowed", "if !seen.insert(key.clone()) {", "if !seen.insert(key.clone()) && false {"),
    ("mandate", "chain.rs", "size limit removed", "if chain.len() > MAX_CHAIN_BYTES {", "if false {"),
    ("mandate", "chain.rs", "hop limit removed", "if raw.len() > MAX_HOPS {", "if false {"),
    ("mandate", "chain.rs", "single-segment accepted", "if raw.len() < 2 {", "if false {"),
    # --- a2a-gov-receipt -----------------------------------------------------------
    ("receipt", "lib.rs", "status and result both allowed", "(Some(Value::String(s)), None) => s.to_ascii_lowercase(),", "(Some(Value::String(s)), _) => s.to_ascii_lowercase(),"),
    ("receipt", "lib.rs", "error fields allowed on success", '"success" => return Err(Error::Malformed("error fields on a success receipt".into())),', '"success" => Outcome::Success,'),
    ("receipt", "lib.rs", "unknown status accepted", 'other => return Err(Error::Malformed(format!("unknown status {other:?}"))),', "_ => Outcome::Success,"),
    ("receipt", "lib.rs", "field-name check disabled (issue)", "if !is_field_path(f) {", "if false {"),
    ("receipt", "lib.rs", "field-name check disabled (verify)", ".map(|v| v.as_str().filter(|s| is_field_path(s)).map(str::to_owned))", ".map(|v| v.as_str().map(str::to_owned))"),
    ("receipt", "lib.rs", "iss not required", 'iss: required("iss")?,', 'iss: text("iss").unwrap_or_default(),'),
    ("receipt", "lib.rs", "reference not required", 'reference: required("reference")?,', 'reference: text("reference").unwrap_or_default(),'),
    ("receipt", "lib.rs", "matching ignores the presentation", "return presentation_id(chain).is_ok_and(|p| &p == id);", "return presentation_id(chain).is_ok();"),
    ("receipt", "lib.rs", "presentation id covers the signature", "let signing_input = jwt.rsplit_once('.').map_or(jwt, |(input, _)| input);", "let signing_input = jwt;"),
    ("receipt", "log.rs", "log sequence unchecked", "if e.seq != seq {", "if false {"),
    ("receipt", "log.rs", "log prev unchecked", "if e.prev != prev {", "if false {"),
    ("receipt", "log.rs", "log hash unchecked", "if e.hash != entry_hash(e.seq, &e.prev, &e.receipt) {", "if false {"),
    ("receipt", "log.rs", "sequence not hashed", 'format!("{seq}:{prev}:{receipt}")', 'format!("{prev}:{receipt}")'),
    # --- a2a-gov-pdp ---------------------------------------------------------------
    ("pdp", "lib.rs", "revocation ignored", "if self.revocations.is_revoked(hop.id())? {", "if self.revocations.is_revoked(hop.id())? && false {"),
    ("pdp", "lib.rs", "closed-call check skipped", "if let Some(mismatch) = describes_call(chain.closed(), call) {", "if let Some(mismatch) = None::<&str> {"),
    ("pdp", "lib.rs", "nonce not consumed", "if !self.nonces.consume(p.nonce)? {", "if false {"),
    ("pdp", "lib.rs", "uses not consumed", "if !self.uses.try_consume(&limits)? {", "if false {"),
    ("pdp", "lib.rs", "only the root checked for revocation", "chain.hops().iter().filter(|h| h.kind() != HopKind::Closing)", "chain.hops().iter().take(1)"),
    ("pdp", "lib.rs", "method unchecked", 'if closed.get("method").and_then(Value::as_str) != Some(call.method.as_str()) {', "if false {"),
    ("pdp", "lib.rs", "task unchecked", 'if closed.get("task_id").and_then(Value::as_str) != Some(call.task_id.as_str()) {', "if false {"),
    ("pdp", "lib.rs", "authorization details unchecked", "Some(Value::Array(details)) if *details == call.authorization_details => None,", "Some(Value::Array(_)) => None,"),
    ("pdp", "constraints.rs", "only root constraints", ".filter(|(_, h)| h.kind() != HopKind::Closing)", ".filter(|(i, _)| *i == 0)"),
    ("pdp", "constraints.rs", "non-array constraints ignored", 'Some(_) => return Evaluation::Refused("constraints must be an array".into()),', "Some(_) => continue,"),
    ("pdp", "constraints.rs", "untyped constraint ignored", 'return Evaluation::Refused("constraint without a type".into());', "continue;"),
    ("pdp", "constraints.rs", "max_uses not recorded", '"access.max_uses" => max_uses(c).map(|n| limits.push((hop.id().to_owned(), n))),', '"access.max_uses" => max_uses(c).map(|_| ()),'),
    ("pdp", "constraints.rs", "unknown constraint ignored", 'unknown.get_or_insert_with(|| format!("unknown constraint {other:?}"));', "let _ = other;"),
    ("pdp", "constraints.rs", "any allowance accepted", "if !allowed.iter().any(|a| covers(a, requested)) {", "if allowed.is_empty() {"),
    ("pdp", "constraints.rs", "type not compared", '|| a.get("type") != r.get("type")', "|| false"),
    ("pdp", "constraints.rs", "subset skipped", '"actions" | "fields" | "locations" => subset(r, k, v),', '"actions" | "fields" | "locations" => true,'),
    ("pdp", "constraints.rs", "other keys ignored", "_ => r.get(k) == Some(v),", "_ => true,"),
    ("pdp", "constraints.rs", "omitted dimension allowed", "        None => false,", "        None => true,"),
    ("pdp", "constraints.rs", "subset always true", "Some(Value::Array(items)) => items.iter().all(|i| allowed.contains(i)),", "Some(Value::Array(_)) => true,"),
    ("pdp", "constraints.rs", "purpose unchecked", "Some(p) if p != required =>", "Some(p) if false && p != required =>"),
    ("pdp", "constraints.rs", "release unchecked", "if call.release > cap {", "if false {"),
    ("pdp", "constraints.rs", "zero use limit allowed", "Some(n) if n >= 1 => Ok(n),", "Some(n) => Ok(n),"),
    ("pdp", "constraints.rs", "delegation depth unchecked", "if delegations_after as u64 > max {", "if false {"),
    ("pdp", "memory.rs", "use limit off by one", ">= *limit)", "> *limit)"),
    ("pdp", "memory.rs", "nonce reusable", ".remove(nonce))", ".contains(nonce))"),
    # --- a2a-gov-binding -----------------------------------------------------------
    ("binding", "lib.rs", "denied not rejected", 'AuthState::Denied { .. } => "TASK_STATE_REJECTED",', 'AuthState::Denied { .. } => "TASK_STATE_AUTH_REQUIRED",'),
    ("binding", "lib.rs", "https not required", "        require_https(&req.approval_url)?;\n", ""),
    ("binding", "lib.rs", "pending fields may be empty", "        require_nonempty(&[&req.challenge_id, &req.aud, &req.nonce])?;\n", ""),
    ("binding", "lib.rs", "presentation may be empty", "    require_nonempty(&[&p.presentation, &p.nonce])?;\n", ""),
    ("binding", "lib.rs", "extension listing not required", ".is_some_and(|exts| exts.iter().any(|e| e.as_str() == Some(EXTENSION_URI)));", ".is_none_or(|_| true);"),
    ("binding", "lib.rs", "fractions truncated", "&& f.fract() == 0.0", "&& true"),
    ("binding", "lib.rs", "arrays not normalized", "Value::Array(items) => items.iter_mut().for_each(restore_integers),", "Value::Array(_) => {}"),
    ("binding", "lib.rs", "objects not normalized", "Value::Object(m) => m.values_mut().for_each(restore_integers),", "Value::Object(_) => {}"),
    ("binding", "lib.rs", "unknown fields accepted", '#[serde(rename_all = "camelCase", deny_unknown_fields)]\npub struct PresentationMeta', '#[serde(rename_all = "camelCase")]\npub struct PresentationMeta'),
    # --- a2a-gov-extension ---------------------------------------------------------
    ("extension", "errors.rs", "challenge URL not checked", "if !is_https_url(url) {", "if false {"),
    ("extension", "lib.rs", "activation too loose", ".any(|uri| uri == EXTENSION_URI)", ".any(|uri| uri.starts_with(\"https://\"))"),
    ("extension", "errors.rs", "foreign domains accepted", '&& d.get("domain").and_then(Value::as_str) == Some(self.domain.as_str())', ""),
]


def source(crate: str, file: str) -> Path:
    return ROOT / "crates" / f"a2a-gov-{crate}" / "src" / file


def check_targets(selected: list[tuple[str, str, str, str, str]]) -> bool:
    ok = True
    for crate, file, name, old, _ in selected:
        count = source(crate, file).read_text().count(old)
        if count != 1:
            print(f"TARGET {'MISSING' if count == 0 else 'AMBIGUOUS'}: {crate}/{file}: {name}")
            ok = False
    return ok


def main() -> int:
    args = sys.argv[1:]
    list_only = "--list" in args
    crates = [a for a in args if not a.startswith("--")]
    selected = [m for m in MUTATIONS if not crates or m[0] in crates]
    if not check_targets(selected):
        return 2
    if list_only:
        print(f"{len(selected)} mutation targets found")
        return 0
    if subprocess.run(["git", "diff", "--quiet"], cwd=ROOT).returncode != 0:
        print("working tree has changes; commit or stash them first")
        return 2
    survivors = []
    for crate, file, name, old, new in selected:
        path = source(crate, file)
        original = path.read_text()
        path.write_text(original.replace(old, new, 1))
        try:
            result = subprocess.run(
                ["cargo", "test", "-q", "-p", f"a2a-gov-{crate}"],
                cwd=ROOT, capture_output=True, text=True,
            )
        finally:
            path.write_text(original)
        # A mutation that doesn't compile proves nothing about the tests.
        broken = "could not compile" in result.stderr
        caught = result.returncode != 0 and not broken
        label = "BROKEN  " if broken else ("caught  " if caught else "SURVIVED")
        print(f"{label} {crate}: {name}")
        if not caught:
            survivors.append(f"{crate}: {name}" + (" (mutation doesn't compile)" if broken else ""))
    print(f"\n{len(selected) - len(survivors)} of {len(selected)} mutations caught")
    for s in survivors:
        print(f"  survived: {s}")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
