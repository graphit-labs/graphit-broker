use super::{RerankHttpConfig, WireError, check};
use broker_control::RerankAdmission;
use graphit_core::file_lock::Cancellation;
use serde::{
    Deserialize,
    de::{self, DeserializeSeed, SeqAccess, Visitor},
};
use serde_json::value::RawValue;
use std::fmt;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<'a> {
    #[serde(borrow)]
    query: Option<&'a RawValue>,
    #[serde(borrow)]
    documents: Option<&'a RawValue>,
    #[serde(borrow)]
    top_n: Option<&'a RawValue>,
}
pub(super) struct Decoded {
    pub query: String,
    pub documents: Vec<String>,
    pub top_n: usize,
}
pub(super) fn decode(
    bytes: &[u8],
    config: &RerankHttpConfig,
    proof: &mut RerankAdmission<'_>,
    cancel: &Cancellation,
) -> Result<Decoded, WireError> {
    check(proof, cancel)?;
    let envelope: Envelope<'_> =
        serde_json::from_slice(bytes).map_err(|_| WireError::InvalidJson)?;
    let query: Option<String> =
        serde_json::from_str(envelope.query.ok_or(WireError::InvalidRequest)?.get())
            .map_err(|_| WireError::InvalidJson)?;
    let query = query
        .filter(|q| !q.trim().is_empty())
        .ok_or(WireError::InvalidRequest)?;
    let raw = envelope.documents.ok_or(WireError::InvalidRequest)?;
    if raw.get() == "null" {
        return Err(WireError::InvalidRequest);
    }
    let mut first = None;
    let mut parser = serde_json::Deserializer::from_str(raw.get());
    let documents = Documents {
        config,
        proof,
        cancel,
        first: &mut first,
    }
    .deserialize(&mut parser)
    .map_err(|_| first.unwrap_or(WireError::InvalidJson))?;
    parser.end().map_err(|_| WireError::InvalidJson)?;
    if documents.is_empty() {
        return Err(WireError::InvalidRequest);
    }
    let top_n: Option<i64> = match envelope.top_n {
        None => None,
        Some(raw) => serde_json::from_str(raw.get()).map_err(|_| WireError::InvalidJson)?,
    };
    let top_n = match top_n {
        None | Some(0) => documents.len(),
        Some(n) => usize::try_from(n)
            .ok()
            .filter(|&n| n > 0 && n <= documents.len())
            .ok_or(WireError::InvalidRequest)?,
    };
    check(proof, cancel)?;
    Ok(Decoded {
        query,
        documents,
        top_n,
    })
}
struct Documents<'a, 'p> {
    config: &'a RerankHttpConfig,
    proof: &'a mut RerankAdmission<'p>,
    cancel: &'a Cancellation,
    first: &'a mut Option<WireError>,
}
impl<'de> DeserializeSeed<'de> for Documents<'_, '_> {
    type Value = Vec<String>;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_seq(self)
    }
}
impl<'de> Visitor<'de> for Documents<'_, '_> {
    type Value = Vec<String>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded document list")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut documents = Vec::new();
        while let Some(value) = seq.next_element::<Option<String>>()? {
            if let Err(error) = check(self.proof, self.cancel) {
                *self.first = Some(error);
                return Err(de::Error::custom("rerank operation expired"));
            }
            let Some(value) = value else {
                *self.first = Some(WireError::InvalidRequest);
                return Err(de::Error::custom("null document"));
            };
            if documents.len() == self.config.max_documents.get()
                || value.trim().is_empty()
                || value.len() > self.config.max_document_bytes.get()
            {
                *self.first = Some(WireError::InvalidRequest);
                return Err(de::Error::custom("document limit"));
            }
            documents.try_reserve(1).map_err(|_| {
                *self.first = Some(WireError::Upstream);
                de::Error::custom("document allocation")
            })?;
            documents.push(value);
        }
        Ok(documents)
    }
}
