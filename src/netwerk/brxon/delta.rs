// delta.rs — تطبيق Delta XOR + إدارة الإصدارات + Rollback
//
// المنطق:
//   filter_جديد = filter_محلي XOR delta
//   العميل يحتفظ بنسختين فقط: v(n) و v(n-1)
//   عند فشل التحقق: Rollback إلى v(n-1) + Freeze

use std::sync::Arc;
use tracing::{info, warn, error};

use crate::state::{BrxonState, SecurityGuard};
use crate::signing::{verify_delta, SignedDelta, VerifyError};

// ─────────────────────────────────────────────────────────────────────────────
//  أخطاء Delta
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum DeltaError {
    #[error("التحقق فشل: {0}")]
    VerificationFailed(#[from] VerifyError),

    #[error("تسلسل الإصدار خاطئ: متوقع from={expected} مستقبَل={received}")]
    VersionMismatch { expected: u64, received: u64 },

    #[error("المحرك مجمّد بسبب: {reason}")]
    EngineFrozen { reason: String },

    #[error("حجم delta خاطئ: {0} بايت")]
    BadDeltaSize(usize),
}

// ─────────────────────────────────────────────────────────────────────────────
//  DeltaEngine
// ─────────────────────────────────────────────────────────────────────────────

pub struct DeltaEngine {
    state: Arc<BrxonState>,
}

impl DeltaEngine {
    pub fn new(state: Arc<BrxonState>) -> Self {
        Self { state }
    }

    // ── تطبيق delta واردة ────────────────────────────────────────────────────

    /// معالجة delta واردة من SSE:
    ///   1. تحقق من حالة SecurityGuard
    ///   2. تحقق من تسلسل الإصدار
    ///   3. تحقق Ed25519 + SHA256
    ///   4. طبّق XOR
    ///   5. عند أي فشل: Rollback + Freeze
    pub fn apply(&self, delta: &SignedDelta) -> Result<(), DeltaError> {
        // ── 1. هل المحرك مجمّد؟ ──────────────────────────────────────────────
        {
            let guard = self.state.guard.read();
            if let SecurityGuard::Frozen { reason } = &*guard {
                error!("Brxon: محرك مجمّد، رفض delta — السبب: {}", reason);
                return Err(DeltaError::EngineFrozen { reason: reason.clone() });
            }
        }

        // ── 2. تحقق من تسلسل الإصدار ─────────────────────────────────────────
        {
            let filter = self.state.filter.read();
            let current_version = filter.version;

            if delta.from_version != current_version {
                warn!(
                    "Brxon: تسلسل إصدار خاطئ — متوقع={} مستقبَل={}",
                    current_version, delta.from_version
                );
                return Err(DeltaError::VersionMismatch {
                    expected: current_version,
                    received: delta.from_version,
                });
            }

            // تحقق من حجم delta
            if delta.inner.payload_bytes.len() != filter.m_bytes {
                return Err(DeltaError::BadDeltaSize(delta.inner.payload_bytes.len()));
            }
        }

        // ── 3. تحقق Ed25519 + SHA256 ─────────────────────────────────────────
        if let Err(e) = verify_delta(delta, &self.state.public_key) {
            error!("Brxon: فشل التحقق من Delta — {}", e);
            self.freeze_and_rollback(format!("فشل التحقق: {e}"));
            return Err(DeltaError::VerificationFailed(e));
        }

        // ── 4. طبّق XOR ───────────────────────────────────────────────────────
        {
            let mut filter = self.state.filter.write();
            filter
                .apply_delta(&delta.inner.payload_bytes, delta.to_version)
                .map_err(|e| {
                    // هذا لا يجب أن يحدث بعد فحص الحجم أعلاه
                    error!("Brxon: خطأ داخلي في تطبيق delta — {}", e);
                    DeltaError::BadDeltaSize(0)
                })?;
        }

        info!(
            "Brxon: Delta مطبّق بنجاح — إصدار {} → {}",
            delta.from_version, delta.to_version
        );
        Ok(())
    }

    // ── Rollback + Freeze ─────────────────────────────────────────────────────

    /// العودة للنسخة السابقة وتجميد المحرك
    fn freeze_and_rollback(&self, reason: String) {
        // Rollback أولاً
        {
            let mut filter = self.state.filter.write();
            filter.rollback();
            warn!("Brxon: Rollback → إصدار {}", filter.version);
        }
        // ثم تجميد
        {
            let mut guard = self.state.guard.write();
            *guard = SecurityGuard::Frozen { reason: reason.clone() };
            error!("Brxon: SecurityGuard::Frozen — {}", reason);
        }
    }

    // ── تحميل الفلتر الكامل (عند التشغيل) ────────────────────────────────────

    /// تطبيق الفلتر الكامل الوارد عند أول تشغيل.
    /// يختلف عن delta: يستبدل الفلتر كاملاً بدل XOR.
    pub fn load_full_filter(
        &self,
        filter_bytes: Vec<u8>,
        version: u64,
        k: u32,
        sha256_hex: &str,
        signature_hex: &str,
    ) -> Result<(), DeltaError> {
        use crate::signing::{SignedPayload, verify_payload};

        // بناء SignedPayload للتحقق
        let payload = SignedPayload {
            payload_bytes: filter_bytes.clone(),
            sha256: sha256_hex.to_string(),
            signature: signature_hex.to_string(),
            version,
        };

        // تحقق Ed25519
        if let Err(e) = verify_payload(&payload, &self.state.public_key) {
            error!("Brxon: فشل التحقق من الفلتر الكامل — {}", e);
            self.freeze_and_rollback(format!("فشل التحقق من الفلتر الكامل: {e}"));
            return Err(DeltaError::VerificationFailed(e));
        }

        // تحميل مباشر
        {
            let mut filter = self.state.filter.write();
            filter.previous = filter.current.clone();
            filter.current  = filter_bytes;
            filter.version  = version;
            filter.k        = k;
        }

        // أعد تفعيل SecurityGuard إذا كان مجمّداً (فلتر نظيف جديد)
        {
            let mut guard = self.state.guard.write();
            *guard = SecurityGuard::Active;
        }

        info!("Brxon: فلتر كامل محمّل — إصدار={} k={}", version, k);
        Ok(())
    }
}
