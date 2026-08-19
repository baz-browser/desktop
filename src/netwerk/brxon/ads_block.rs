use adblock::lists::{FilterSet, ParseOptions};
use adblock::{Engine, request::Request};
use parking_lot::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

pub const FIRST_FETCH_DELAY_SECS: u64 = 60;
pub const PERIODIC_CHECK_INTERVAL_SECS: u64 = 6 * 60 * 60;
pub const LIST_EXPIRY_SECS: u64 = 24 * 60 * 60;
pub const EMERGENCY_THRESHOLD_SECS: u64 = 48 * 60 * 60;

/// method افتراضي مؤقت — بانتظار تمرير HTTP method الحقيقي عبر FFI/C++
/// بمرحلة لاحقة (راجع نقاش تعديل ThreatBlocker.cpp).
const DEFAULT_REQUEST_METHOD: &str = "GET";

pub mod list_names {
    pub const EASYLIST:        &str = "easylist";
    pub const EASYPRIVACY:     &str = "easyprivacy";
    pub const PETER_LOWE:      &str = "peter_lowe";
    pub const UBO_FILTERS:     &str = "ubo_filters";
    pub const UBO_BADWARE:     &str = "ubo_badware";
    pub const UBO_PRIVACY:     &str = "ubo_privacy";
    pub const UBO_UNBREAK:     &str = "ubo_unbreak";
}

#[derive(Debug, thiserror::Error)]
pub enum AdsBlockError {
    #[error("لا توجد قوائم لبنائها")]
    NoLists,

    #[error("فشل تحليل الطلب: {0}")]
    RequestParseError(String),

    #[error("فشل استعادة المحرك من التخزين المؤقت: {0}")]
    DeserializeError(String),
}

pub struct AdsBlockEngine {
    engine: RwLock<Option<Engine>>,
    last_success_unix: RwLock<Option<u64>>,
}

impl AdsBlockEngine {
    pub fn new() -> Self {
        Self {
            engine: RwLock::new(None),
            last_success_unix: RwLock::new(None),
        }
    }

    pub fn is_ready(&self) -> bool {
        self.engine.read().is_some()
    }

    pub fn needs_update(&self) -> bool {
        match *self.last_success_unix.read() {
            None => true,
            Some(last) => {
                let now = current_unix_time();
                now.saturating_sub(last) >= LIST_EXPIRY_SECS
            }
        }
    }

    pub fn is_emergency(&self) -> bool {
        match *self.last_success_unix.read() {
            None => true,
            Some(last) => {
                let now = current_unix_time();
                now.saturating_sub(last) >= EMERGENCY_THRESHOLD_SECS
            }
        }
    }

    pub fn ingest_lists(&self, lists: Vec<(&str, String)>) -> Result<(), AdsBlockError> {
        if lists.is_empty() {
            return Err(AdsBlockError::NoLists);
        }

        let mut filter_set = FilterSet::new(false);
        let mut approx_lines = 0usize;

        for (label, text) in &lists {
            let line_count = text.lines().filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('!') && !t.starts_with('#')
            }).count();

            filter_set.add_filter_list(text.clone(), ParseOptions::default());
            info!("AdsBlock: قائمة '{}' مُضافة — ~{} سطر قاعدة", label, line_count);
            approx_lines += line_count;
        }

        let new_engine = Engine::new_with_filter_set(filter_set);

        {
            let mut engine = self.engine.write();
            *engine = Some(new_engine);
        }
        {
            let mut last = self.last_success_unix.write();
            *last = Some(current_unix_time());
        }

        info!("AdsBlock: محرك جديد جاهز — ~{} سطر قاعدة من {} قائمة", approx_lines, lists.len());
        Ok(())
    }

    pub fn should_block(&self, url: &str, source_url: &str, request_type: &str) -> bool {
        let engine_guard = self.engine.read();
        let engine = match engine_guard.as_ref() {
            Some(e) => e,
            None => return false,
        };

        let request = match Request::new(url, source_url, request_type, DEFAULT_REQUEST_METHOD) {
            Ok(r) => r,
            Err(e) => {
                warn!("AdsBlock: فشل تحليل الطلب — {:?} (url={})", e, url);
                return false;
            }
        };

        let result = engine.check_network_request(&request);
        result.should_block()
    }

    pub fn serialize_for_cache(&self) -> Option<Vec<u8>> {
        self.engine.read().as_ref().map(|e| e.serialize())
    }

    pub fn load_from_cache(&self, cached_bytes: &[u8]) -> Result<(), AdsBlockError> {
        let mut new_engine = Engine::default();
        new_engine
            .deserialize(cached_bytes)
            .map_err(|e| AdsBlockError::DeserializeError(format!("{:?}", e)))?;

        let mut engine = self.engine.write();
        *engine = Some(new_engine);

        info!("AdsBlock: محرك محمّل من التخزين المؤقت للقرص");
        Ok(())
    }
}

impl Default for AdsBlockEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_not_ready_by_default() {
        let engine = AdsBlockEngine::new();
        assert!(!engine.is_ready());
        assert!(!engine.should_block("http://ads.example.com/x.js", "http://site.com", "script"));
    }

    #[test]
    fn test_ingest_and_block() {
        let engine = AdsBlockEngine::new();
        let rules = "-advertisement-icon.\n-advertisement-management/\n".to_string();
        engine.ingest_lists(vec![("test", rules)]).unwrap();
        assert!(engine.is_ready());

        let blocked = engine.should_block(
            "http://example.com/-advertisement-icon.",
            "http://example.com/",
            "image",
        );
        assert!(blocked);
    }

    #[test]
    fn test_needs_update_when_never_updated() {
        let engine = AdsBlockEngine::new();
        assert!(engine.needs_update());
        assert!(engine.is_emergency());
    }
}