// transport.rs — تحليل بيانات السيرفر (بدون أي اتصال شبكة مباشر)
//
// ⚠️  هذا الملف عمدًا لا يفتح أي اتصال شبكة (لا reqwest ولا tokio ولا
//     std::net مباشرة). الاتصال الفعلي بالسيرفر (HTTP GET + SSE) صار
//     مسؤولية C++ عبر Necko (راجع netwerk/base/ThreatBlocker.cpp)، لأن
//     Firefox يمنع مكتبات Rust داخل الشجرة من فتح سوكيت خام مباشرة
//     (فحص check_networking يفشل البناء لو لقى recv/send/connect...).
//
// وظيفتان بس هنا:
//   1. FullFilterResponse — تحليل JSON استجابة /filter/latest
//   2. SseParser          — تجميع/تقطيع دفق SSE الوارد من C++ قطعة قطعة
//      (C++ يمرر البايتات كما توصل من الشبكة، هذا الملف يبني منها
//      أحداث SSE كاملة ويطبّق كل delta عبر DeltaEngine)

use parking_lot::Mutex;
use serde::Deserialize;
use tracing::{error, info, warn};

use crate::delta::{DeltaEngine, DeltaError};
use crate::signing::SignedDelta;

// ─────────────────────────────────────────────────────────────────────────────
//  استجابة /filter/latest
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct FullFilterResponse {
    #[serde(with = "base64_bytes")]
    pub filter_bytes: Vec<u8>,
    pub sha256: String,
    pub signature: String,
    pub version: u64,
    pub m: usize, // حجم البتات (غير مستخدَم حاليًا هنا — BLOOM_M_BYTES ثابت وقت البناء)
    pub k: u32,   // عدد دوال hash
}

/// يحلّل JSON استجابة /filter/latest ويطبّقها عبر DeltaEngine.
/// `json_bytes`: المحتوى الخام (UTF-8) اللي جابه C++ عبر Necko.
pub fn ingest_full_filter_json(engine: &DeltaEngine, json_bytes: &[u8]) -> Result<(), String> {
    let full: FullFilterResponse = serde_json::from_slice(json_bytes)
        .map_err(|e| format!("خطأ في تحليل JSON للفلتر الكامل: {e}"))?;

    engine
        .load_full_filter(
            full.filter_bytes,
            full.version,
            full.k,
            &full.sha256,
            &full.signature,
        )
        .map_err(|e| format!("فشل تحميل الفلتر الكامل: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
//  SseParser — يجمّع قطع SSE الواردة من C++ ويطبّق كل delta كامل
// ─────────────────────────────────────────────────────────────────────────────

/// محلّل SSE ذو حالة (stateful) — يُستدعى من C++ في كل مرة توصل قطعة
/// بيانات جديدة من الاتصال المستمر (/filter/updates). يبني رسائل SSE
/// كاملة داخليًا (رسالة كاملة تنتهي بـ "\n\n") ويطبّق كل delta فور اكتمالها.
pub struct SseParser {
    buffer: Mutex<String>,
}

impl SseParser {
    pub fn new() -> Self {
        Self { buffer: Mutex::new(String::new()) }
    }

    /// أضف قطعة بايتات جديدة من الستريم وطبّق أي أحداث مكتملة.
    /// يُعاد استدعاؤها بأمان من نفس الخيط في كل مرة توصل بيانات (C++
    /// يضمن التسلسل — استدعاءات OnDataAvailable لنفس القناة متسلسلة أصلًا).
    pub fn feed(&self, engine: &DeltaEngine, bytes: &[u8]) {
        let text = match std::str::from_utf8(bytes) {
            Ok(t) => t,
            Err(_) => {
                warn!("Brxon: قطعة SSE ليست UTF-8 صالحة — تجاهلها");
                return;
            }
        };

        let mut buffer = self.buffer.lock();
        buffer.push_str(text);

        loop {
            let event_end = match buffer.find("\n\n") {
                Some(i) => i,
                None => break,
            };

            let event_text = buffer[..event_end].to_string();
            buffer.drain(..event_end + 2);

            Self::handle_event(engine, &event_text);
        }
    }

    fn handle_event(engine: &DeltaEngine, event_text: &str) {
        let mut event_type = String::new();
        let mut data = String::new();

        for line in event_text.lines() {
            if let Some(val) = line.strip_prefix("event: ") {
                event_type = val.trim().to_string();
            } else if let Some(val) = line.strip_prefix("data: ") {
                data = val.trim().to_string();
            }
        }

        if event_type != "filter_update" {
            return; // تجاهل أحداث أخرى (heartbeat مثلاً)
        }

        if data.is_empty() {
            warn!("Brxon: حدث filter_update بدون بيانات");
            return;
        }

        match serde_json::from_str::<SignedDelta>(&data) {
            Err(e) => {
                warn!("Brxon: خطأ في JSON delta — {}", e);
            }
            Ok(delta) => {
                let from = delta.from_version;
                let to = delta.to_version;
                match engine.apply(&delta) {
                    Ok(()) => {
                        info!("Brxon: Delta {} → {} مطبّق ✓", from, to);
                    }
                    Err(DeltaError::EngineFrozen { .. }) => {
                        warn!("Brxon: محرك مجمّد — تجاهل delta واردة");
                    }
                    Err(e) => {
                        error!("Brxon: فشل تطبيق Delta {} → {} — {}", from, to, e);
                    }
                }
            }
        }
    }
}

impl Default for SseParser {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  سيريلايزيشن مساعد — base64 ↔ Vec<u8>
// ─────────────────────────────────────────────────────────────────────────────

mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(dead_code)]
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}
