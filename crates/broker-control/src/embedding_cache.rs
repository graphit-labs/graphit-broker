//! Embedding cache data. This module neither authenticates nor authorizes callers.
use crate::ControlError;
use serde::de::{self, DeserializeSeed, SeqAccess, Visitor};
use std::{fmt, num::NonZeroUsize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmbeddingCacheError {
    InvalidLimits,
    InvalidInput,
    MalformedStored,
    ReadLimitExceeded,
    Control(ControlError),
}
impl fmt::Display for EmbeddingCacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "invalid embedding cache limits",
            Self::InvalidInput => "invalid embedding cache input",
            Self::MalformedStored => "invalid stored embedding",
            Self::ReadLimitExceeded => "stored embedding exceeds read limit",
            Self::Control(_) => "embedding cache persistence failed",
        })
    }
}
impl std::error::Error for EmbeddingCacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Control(error) => Some(error),
            _ => None,
        }
    }
}
impl From<ControlError> for EmbeddingCacheError {
    fn from(error: ControlError) -> Self {
        Self::Control(error)
    }
}

#[derive(Clone, Copy)]
pub struct EmbeddingCacheLimits {
    pub dimensions: NonZeroUsize,
    pub max_entries: NonZeroUsize,
    pub vector_json_bytes: NonZeroUsize,
    pub metadata_bytes: NonZeroUsize,
}
impl EmbeddingCacheLimits {
    pub(crate) fn validate(self) -> Result<Self, EmbeddingCacheError> {
        for value in [
            self.dimensions.get(),
            self.max_entries.get(),
            self.vector_json_bytes.get(),
            self.metadata_bytes.get(),
        ] {
            if value > isize::MAX as usize || i64::try_from(value).is_err() {
                return Err(EmbeddingCacheError::InvalidLimits);
            }
        }
        self.dimensions
            .get()
            .checked_mul(std::mem::size_of::<f32>())
            .filter(|bytes| *bytes <= isize::MAX as usize)
            .ok_or(EmbeddingCacheError::InvalidLimits)?;
        // Even the smallest finite JSON vector needs two delimiters and one byte per value.
        if self
            .dimensions
            .get()
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .is_none_or(|minimum| minimum > self.vector_json_bytes.get())
        {
            return Err(EmbeddingCacheError::InvalidLimits);
        }
        self.max_entries
            .get()
            .checked_mul(self.vector_json_bytes.get())
            .and_then(|n| {
                n.checked_add(
                    self.max_entries
                        .get()
                        .checked_mul(self.metadata_bytes.get())?,
                )
            })
            .filter(|n| *n <= isize::MAX as usize)
            .ok_or(EmbeddingCacheError::InvalidLimits)?;
        Ok(self)
    }
}

/// Digests only; the cache never receives or persists the original text.
#[derive(Clone, Copy)]
pub struct EmbeddingCacheKey {
    compatibility: [u8; 32],
    input: [u8; 32],
}
impl EmbeddingCacheKey {
    pub fn new(compatibility: [u8; 32], input: [u8; 32]) -> Self {
        Self {
            compatibility,
            input,
        }
    }
    pub(crate) fn sql(self) -> (String, String) {
        fn hex(bytes: &[u8; 32]) -> String {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut value = String::with_capacity(64);
            for byte in bytes {
                value.push(char::from(HEX[usize::from(byte >> 4)]));
                value.push(char::from(HEX[usize::from(byte & 15)]));
            }
            value
        }
        (hex(&self.compatibility), hex(&self.input))
    }
}

/// Public model provenance, never authentication material or an authority proof.
#[derive(Clone, Copy)]
pub struct EmbeddingCacheProvenance<'a> {
    pub provider: &'a str,
    pub revision: &'a str,
    pub model: &'a str,
    pub input_type: &'a str,
}
impl EmbeddingCacheProvenance<'_> {
    pub(crate) fn validate(self, limits: EmbeddingCacheLimits) -> Result<(), EmbeddingCacheError> {
        let mut bytes = 0usize;
        for value in [self.provider, self.revision, self.model, self.input_type] {
            bytes = bytes
                .checked_add(value.len())
                .ok_or(EmbeddingCacheError::InvalidInput)?;
            if value.trim().is_empty()
                || value.contains('\0')
                || bytes > limits.metadata_bytes.get()
            {
                return Err(EmbeddingCacheError::InvalidInput);
            }
        }
        if !matches!(self.input_type, "query" | "document") {
            return Err(EmbeddingCacheError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmbeddingCacheWrite {
    pub inserted: usize,
    pub unchanged: usize,
}

pub struct EmbeddingCacheEntry<'a> {
    pub key: EmbeddingCacheKey,
    pub provenance: EmbeddingCacheProvenance<'a>,
    pub vector: &'a [f32],
}

pub(crate) fn check_count(
    count: usize,
    limits: EmbeddingCacheLimits,
) -> Result<(), EmbeddingCacheError> {
    if count > limits.max_entries.get() {
        return Err(EmbeddingCacheError::InvalidInput);
    }
    Ok(())
}

pub(crate) struct PreparedEmbeddings {
    pub compatibility: Vec<String>,
    pub input: Vec<String>,
    pub provider: Vec<String>,
    pub revision: Vec<String>,
    pub model: Vec<String>,
    pub input_type: Vec<String>,
    pub json: Vec<String>,
}

pub(crate) fn prepare_insert(
    entries: &[EmbeddingCacheEntry<'_>],
    limits: EmbeddingCacheLimits,
    check: &mut dyn FnMut() -> Result<(), ControlError>,
) -> Result<PreparedEmbeddings, EmbeddingCacheError> {
    check_count(entries.len(), limits)?;
    let mut data = PreparedEmbeddings {
        compatibility: Vec::new(),
        input: Vec::new(),
        provider: Vec::new(),
        revision: Vec::new(),
        model: Vec::new(),
        input_type: Vec::new(),
        json: Vec::new(),
    };
    for entry in entries {
        check()?;
        entry.provenance.validate(limits)?;
        let json = encode_vector(entry.vector, limits)?;
        check()?;
        let (compatibility, input) = entry.key.sql();
        data.compatibility.push(compatibility);
        data.input.push(input);
        data.provider.push(entry.provenance.provider.to_owned());
        data.revision.push(entry.provenance.revision.to_owned());
        data.model.push(entry.provenance.model.to_owned());
        data.input_type.push(entry.provenance.input_type.to_owned());
        data.json.push(json);
    }
    Ok(data)
}

pub(crate) fn encode_vector(
    values: &[f32],
    limits: EmbeddingCacheLimits,
) -> Result<String, EmbeddingCacheError> {
    if values.len() != limits.dimensions.get() || values.iter().any(|v| !v.is_finite()) {
        return Err(EmbeddingCacheError::InvalidInput);
    }
    // A bounded writer prevents expansion past the configured SQL payload budget.
    struct Writer {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let size = self
                .bytes
                .len()
                .checked_add(bytes.len())
                .filter(|n| *n <= self.limit)
                .ok_or_else(|| std::io::Error::other("embedding cache encoding limit"))?;
            self.bytes
                .try_reserve(size - self.bytes.len())
                .map_err(|_| std::io::Error::other("embedding cache allocation failed"))?;
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer {
        bytes: Vec::new(),
        limit: limits.vector_json_bytes.get(),
    };
    serde_json::to_writer(&mut writer, values).map_err(|_| EmbeddingCacheError::InvalidInput)?;
    String::from_utf8(writer.bytes).map_err(|_| EmbeddingCacheError::InvalidInput)
}

pub(crate) fn decode_vector(
    json: &str,
    limits: EmbeddingCacheLimits,
    check: &mut dyn FnMut() -> Result<(), ControlError>,
) -> Result<Vec<f32>, EmbeddingCacheError> {
    if json.len() > limits.vector_json_bytes.get() {
        return Err(EmbeddingCacheError::ReadLimitExceeded);
    }
    struct Seed<'a> {
        count: usize,
        check: &'a mut dyn FnMut() -> Result<(), ControlError>,
    }
    impl<'de> DeserializeSeed<'de> for Seed<'_> {
        type Value = Vec<f32>;
        fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_seq(self)
        }
    }
    impl<'de> Visitor<'de> for Seed<'_> {
        type Value = Vec<f32>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("finite embedding vector")
        }
        fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
            let mut values = Vec::new();
            values
                .try_reserve_exact(self.count)
                .map_err(|_| de::Error::custom("embedding allocation failed"))?;
            while let Some(value) = seq.next_element::<f64>()? {
                (self.check)().map_err(|_| de::Error::custom("embedding operation ended"))?;
                let value = value as f32;
                if values.len() == self.count || !value.is_finite() {
                    return Err(de::Error::custom("invalid embedding vector"));
                }
                values.push(value);
            }
            if values.len() != self.count {
                return Err(de::Error::custom("invalid embedding width"));
            }
            Ok(values)
        }
    }
    check()?;
    let mut decoder = serde_json::Deserializer::from_str(json);
    let result = Seed {
        count: limits.dimensions.get(),
        check,
    }
    .deserialize(&mut decoder);
    check()?;
    let values = result.map_err(|_| EmbeddingCacheError::MalformedStored)?;
    decoder
        .end()
        .map_err(|_| EmbeddingCacheError::MalformedStored)?;
    check()?;
    Ok(values)
}
