// state.rs — الحالة المشتركة بين كل مكونات Brxon
//
// يحمل:
//   • نسختين من Bloom Filter  (current = v_n  |  previous = v_n_minus_1)
//   • رقم الإصدار الحالي
//   • المفتاح العام Ed25519 المضمّن وقت البناء
//   • حالة SecurityGuard (نشطة / مجمّدة)

use std::sync::Arc;
use parking_lot::RwLock;
use ed25519_dalek::VerifyingKey;

// ─────────────────────────────────────────────────────────────────────────────
//  SecurityGuard
// ─────────────────────────────────────────────────────────────────────────────

/// حالة أمان محرك الحجب.
/// بمجرد الانتقال إلى `Frozen` لا يُقبل أي delta جديد
/// حتى يُعاد تشغيل المتصفح أو يصل اتصال نظيف موثوق.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityGuard {
    /// الحالة الطبيعية — التحديثات مقبولة
    Active,
    /// تلاعب مكتشف — التحديثات مجمّدة، العمل على v(n-1)
    Frozen { reason: String },
}

impl SecurityGuard {
    pub fn is_active(&self) -> bool {
        matches!(self, SecurityGuard::Active)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  FilterState  (نسختا الفلتر)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FilterState {
    /// v(n)   — النسخة الحالية الفعّالة
    pub current:  Vec<u8>,
    /// v(n-1) — النسخة السابقة للـ Rollback
    pub previous: Vec<u8>,
    /// رقم الإصدار الحالي
    pub version:  u64,
    /// عدد دوال hash المستخدمة في Bloom Filter
    pub k:        u32,
    /// حجم البتات (بالبايت = m/8)
    pub m_bytes:  usize,
}

impl FilterState {
    /// حالة ابتدائية فارغة — قبل أول تحميل من السيرفر
    pub fn empty(m_bytes: usize, k: u32) -> Self {
        Self {
            current:  vec![0u8; m_bytes],
            previous: vec![0u8; m_bytes],
            version:  0,
            k,
            m_bytes,
        }
    }

    /// تطبيق delta XOR على الفلتر الحالي وترقية الإصدار
    ///
    /// يُستدعى بعد التحقق الناجح من Ed25519.
    pub fn apply_delta(&mut self, delta: &[u8], new_version: u64) -> Result<(), String> {
        if delta.len() != self.m_bytes {
            return Err(format!(
                "حجم delta ({}) لا يتطابق مع حجم الفلتر ({})",
                delta.len(), self.m_bytes
            ));
        }
        // احفظ النسخة الحالية كـ previous قبل التحديث
        self.previous = self.current.clone();
        // طبّق XOR بايت بايت
        for (cur, d) in self.current.iter_mut().zip(delta.iter()) {
            *cur ^= d;
        }
        self.version = new_version;
        Ok(())
    }

    /// Rollback — العودة للنسخة السابقة
    pub fn rollback(&mut self) {
        std::mem::swap(&mut self.current, &mut self.previous);
        if self.version > 0 { self.version -= 1; }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  BrxonState  (الحالة الكاملة)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct BrxonState {
    pub filter:        RwLock<FilterState>,
    pub guard:         RwLock<SecurityGuard>,
    /// المفتاح العام المضمّن في وقت البناء
    pub public_key:    VerifyingKey,
    /// عنوان السيرفر — يُعيَّن عند التهيئة
    pub server_base:   String,
}

impl BrxonState {
    pub fn new(
        public_key:  VerifyingKey,
        server_base: String,
        m_bytes:     usize,
        k:           u32,
    ) -> Arc<Self> {
        Arc::new(Self {
            filter:      RwLock::new(FilterState::empty(m_bytes, k)),
            guard:       RwLock::new(SecurityGuard::Active),
            public_key,
            server_base,
        })
    }

    /// هل محرك الحجب جاهز للعمل؟ (الفلتر محمّل وغير مجمّد)
    pub fn is_ready(&self) -> bool {
        let g = self.guard.read();
        let f = self.filter.read();
        g.is_active() && f.version > 0
    }
}
