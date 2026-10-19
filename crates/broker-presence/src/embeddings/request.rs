use super::{EmbeddingsHttpConfig, InputType, WireError, check};
use broker_control::EmbeddingAdmission;
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
    input: Option<&'a RawValue>,
    #[serde(borrow)]
    input_type: Option<&'a RawValue>,
}
pub(super) struct Decoded {
    pub inputs: Vec<String>,
    pub input_type: InputType,
}
pub(super) fn decode(
    bytes: &[u8],
    config: &EmbeddingsHttpConfig,
    proof: &mut EmbeddingAdmission<'_>,
    cancel: &Cancellation,
) -> Result<Decoded, WireError> {
    check(proof, cancel)?;
    let envelope: Envelope<'_> =
        serde_json::from_slice(bytes).map_err(|_| WireError::InvalidJson)?;
    let input_type = match envelope.input_type {
        None => InputType::Document,
        Some(value) if value.get() == "null" => InputType::Document,
        Some(value) => {
            let value: std::borrow::Cow<'_, str> =
                serde_json::from_str(value.get()).map_err(|_| WireError::InvalidRequest)?;
            match value.trim().to_ascii_lowercase().as_str() {
                "" | "document" => InputType::Document,
                "query" => InputType::Query,
                _ => return Err(WireError::InvalidRequest),
            }
        }
    };
    let input = envelope.input.ok_or(WireError::InvalidRequest)?;
    let mut first = None;
    let mut parser = serde_json::Deserializer::from_str(input.get());
    let inputs = Inputs {
        config,
        proof,
        cancel,
        first: &mut first,
    }
    .deserialize(&mut parser)
    .map_err(|_| first.unwrap_or(WireError::InvalidRequest))?;
    parser.end().map_err(|_| WireError::InvalidRequest)?;
    check(proof, cancel)?;
    if inputs.is_empty() {
        return Err(WireError::InvalidRequest);
    }
    Ok(Decoded { inputs, input_type })
}
struct Inputs<'a, 'p> {
    config: &'a EmbeddingsHttpConfig,
    proof: &'a mut EmbeddingAdmission<'p>,
    cancel: &'a Cancellation,
    first: &'a mut Option<WireError>,
}
impl<'de> DeserializeSeed<'de> for Inputs<'_, '_> {
    type Value = Vec<String>;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}
impl Inputs<'_, '_> {
    fn text<E: de::Error>(&mut self, value: String, total: &mut usize) -> Result<String, E> {
        if let Err(error) = check(self.proof, self.cancel) {
            *self.first = Some(error);
            return Err(E::custom("embedding operation expired"));
        }
        if value.trim().is_empty() {
            return Err(E::custom("empty embedding input"));
        }
        *total = total
            .checked_add(value.len())
            .ok_or_else(|| E::custom("embedding input size overflow"))?;
        if *total > self.config.max_input_bytes.get() {
            *self.first = Some(WireError::TooLarge);
            return Err(E::custom("embedding input exceeds bound"));
        }
        Ok(value)
    }
}
impl<'de> Visitor<'de> for Inputs<'_, '_> {
    type Value = Vec<String>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string or bounded list of strings")
    }
    fn visit_str<E: de::Error>(mut self, value: &str) -> Result<Self::Value, E> {
        let mut total = 0;
        Ok(vec![self.text(value.to_owned(), &mut total)?])
    }
    fn visit_string<E: de::Error>(mut self, value: String) -> Result<Self::Value, E> {
        let mut total = 0;
        Ok(vec![self.text(value, &mut total)?])
    }
    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        let mut total = 0;
        while let Some(value) = seq.next_element::<String>()? {
            if values.len() == self.config.max_batch.get() {
                return Err(de::Error::custom("too many embedding inputs"));
            }
            let value = self.text(value, &mut total)?;
            values
                .try_reserve(1)
                .map_err(|_| de::Error::custom("embedding input allocation failed"))?;
            values.push(value);
        }
        Ok(values)
    }
}
