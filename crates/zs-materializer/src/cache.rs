use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zs_credential::Credential;
use zs_policy::{CredentialSource, SourceKind};

use crate::{CredentialStore, MaterializationError, RetrieveContext};

pub const VALUE_TTL_MS: u64 = 300_000;

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    resource: String,
    grant_id: String,
    source_digest: [u8; 32],
}

struct Entry {
    value: Zeroizing<Vec<u8>>,
    until_ms: u64,
}

type Slot = Arc<tokio::sync::Mutex<Option<Entry>>>;

pub struct GrantBoundCache<S: CredentialStore> {
    inner: S,
    slots: Mutex<HashMap<Key, Slot>>,
}

fn source_digest(source: &CredentialSource) -> [u8; 32] {
    let mut out = String::new();
    let mut field = |key: &str, value: &str| {
        out.push_str(key);
        out.push('\u{1f}');
        out.push_str(value);
        out.push('\u{1e}');
    };
    match source {
        CredentialSource::File { reference } => {
            field("source.kind", SourceKind::File.as_str());
            field("source.reference", reference);
        }
        CredentialSource::AwsSsm(source) => {
            field("source.kind", SourceKind::AwsSsm.as_str());
            field("source.parameter", source.parameter.as_str());
            field("source.region", source.region.as_str());
            field("source.role_arn", source.role_arn.as_str());
        }
    }
    Sha256::digest(out.as_bytes()).into()
}

impl<S: CredentialStore> GrantBoundCache<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            slots: Mutex::default(),
        }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn entry_count(&self) -> usize {
        self.slots.lock().map_or(0, |slots| slots.len())
    }

    fn slot(&self, key: &Key, now_ms: u64) -> Result<Slot, MaterializationError> {
        let mut slots = self
            .slots
            .lock()
            .map_err(|_| MaterializationError::NoStore(self.inner.kind()))?;
        slots.retain(|k, slot| {
            k == key
                || (k.resource != key.resource
                    && slot.try_lock().map_or(true, |entry| {
                        entry.as_ref().is_some_and(|e| now_ms < e.until_ms)
                    }))
        });
        Ok(slots.entry(key.clone()).or_default().clone())
    }
}

#[async_trait::async_trait]
impl<S: CredentialStore> CredentialStore for GrantBoundCache<S> {
    fn kind(&self) -> SourceKind {
        self.inner.kind()
    }

    async fn retrieve(&self, cx: &RetrieveContext<'_>) -> Result<Credential, MaterializationError> {
        let grant = cx.grant.grant();
        let key = Key {
            resource: grant.resource.clone(),
            grant_id: grant.grant_id.clone(),
            source_digest: source_digest(&grant.source),
        };
        let slot = self.slot(&key, cx.now_ms)?;
        let mut entry = slot.lock().await;
        if let Some(cached) = entry.as_ref() {
            if cx.now_ms < cached.until_ms {
                return Credential::from_bytes(cached.value.to_vec())
                    .map_err(|_| MaterializationError::InvalidValue(self.inner.kind()));
            }
            *entry = None;
        }
        let value = self.inner.retrieve(cx).await?;
        let until_ms = grant
            .expires_at_ms
            .min(cx.now_ms.saturating_add(VALUE_TTL_MS));
        *entry = Some(Entry {
            value: Zeroizing::new(value.expose().to_vec()),
            until_ms,
        });
        let weak = Arc::downgrade(&slot);
        let lifetime = std::time::Duration::from_millis(until_ms.saturating_sub(cx.now_ms));
        tokio::spawn(async move {
            tokio::time::sleep(lifetime).await;
            if let Some(slot) = weak.upgrade() {
                let mut entry = slot.lock().await;
                if entry.as_ref().is_some_and(|e| e.until_ms == until_ms) {
                    *entry = None;
                }
            }
        });
        Ok(value)
    }

    fn forget(&self, resource: &str) {
        if let Ok(mut slots) = self.slots.lock() {
            slots.retain(|k, _| k.resource != resource);
        }
        self.inner.forget(resource);
    }
}
