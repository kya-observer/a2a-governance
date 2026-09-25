use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::Error;

pub(crate) fn encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn decode(s: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| Error::Malformed(format!("base64url: {e}")))
}
