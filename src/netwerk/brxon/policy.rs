// policy.rs — محرك الحجب الأساسي
//
// هذا هو قلب Brxon — يُنفَّذ قبل كل طلب شبكي في Gecko
// عبر nsIContentPolicy::ShouldLoad()
//
// ─── قاعدة الحجب الأساسية ────────────────────────────────────────────────────
//
//  نوع الطلب          | الدومين في الفلتر | القرار
//  ─────────────────────────────────────────────────────────────────────────────
//  TYPE_DOCUMENT       | إباحي             | REJECT → blockinfo.html
//  TYPE_DOCUMENT       | إعلان/تتبع        | ACCEPT  (لا يظهر في الفلتر كذلك)
//  TYPE_SUBDOCUMENT    | إباحي             | REJECT → blockinfo.html
//  أي نوع آخر          | أي دومين ضار      | REJECT صامت (لا صفحة)
//
// ─── أنواع الطلبات (Gecko constants) ─────────────────────────────────────────

/// ثوابت nsIContentPolicy (مطابقة لـ nsIContentPolicy.idl في Gecko)
pub mod content_type {
    pub const TYPE_OTHER:             u32 = 1;
    pub const TYPE_SCRIPT:            u32 = 2;
    pub const TYPE_IMAGE:             u32 = 3;
    pub const TYPE_STYLESHEET:        u32 = 4;
    pub const TYPE_OBJECT:            u32 = 5;
    pub const TYPE_DOCUMENT:          u32 = 6;   // ← تنقل كامل للصفحة
    pub const TYPE_SUBDOCUMENT:       u32 = 7;   // ← iframe
    pub const TYPE_PING:              u32 = 10;
    pub const TYPE_XMLHTTPREQUEST:    u32 = 11;
    pub const TYPE_OBJECT_SUBREQUEST: u32 = 12;
    pub const TYPE_FONT:              u32 = 14;
    pub const TYPE_MEDIA:             u32 = 15;
    pub const TYPE_WEBSOCKET:         u32 = 19;
    pub const TYPE_CSP_REPORT:        u32 = 20;
    pub const TYPE_FETCH:             u32 = 22;
    pub const TYPE_IMAGESET:          u32 = 23;
    pub const TYPE_WEB_MANIFEST:      u32 = 25;
    pub const TYPE_SPECULATIVE:       u32 = 26;
    pub const TYPE_WEB_TRANSPORT:     u32 = 31;
}

/// قرارات nsIContentPolicy
pub mod policy_decision {
    /// اقبل الطلب — ACCEPT
    pub const ACCEPT: i16 = 1;
    /// ارفض الطلب — REJECT_REQUEST
    pub const REJECT_REQUEST: i16 = -1;
    /// ارفض وأظهر صفحة بديلة — REJECT_TYPE (لـ TYPE_DOCUMENT)
    pub const REJECT_TYPE: i16 = -2;
}

use std::sync::Arc;
use tracing::{trace, debug};

use crate::state::BrxonState;
use crate::bloom::{BloomFilter, normalize_domain, normalize_full};

// ─────────────────────────────────────────────────────────────────────────────
//  نتيجة فحص الطلب
// ─────────────────────────────────────────────────────────────────────────────

/// ما يجب أن تفعله Gecko بعد استشارة Brxon
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyOutcome {
    /// الطلب مقبول — أكمل التحميل
    Accept,

    /// ارفض صامتاً — للإعلانات والتتبع والموارد الضارة
    /// لا صفحة، لا رسالة، مجرد رفض صامت
    RejectSilent,

    /// ارفض وأظهر blockinfo.html — للمواقع الإباحية (TYPE_DOCUMENT فقط)
    RejectWithBlockPage,
}

impl PolicyOutcome {
    /// تحويل إلى رقم nsIContentPolicy القرار
    pub fn to_gecko_decision(&self) -> i16 {
        match self {
            PolicyOutcome::Accept              => policy_decision::ACCEPT,
            PolicyOutcome::RejectSilent        => policy_decision::REJECT_REQUEST,
            PolicyOutcome::RejectWithBlockPage => policy_decision::REJECT_TYPE,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ContentPolicy — قلب Brxon
// ─────────────────────────────────────────────────────────────────────────────

pub struct ContentPolicy {
    state: Arc<BrxonState>,
}

impl ContentPolicy {
    pub fn new(state: Arc<BrxonState>) -> Self {
        Self { state }
    }

    // ── نقطة الدخول الرئيسية ─────────────────────────────────────────────────

    /// ShouldLoad — يُستدعى من Gecko لكل طلب شبكي
    ///
    /// `content_type` : نوع الطلب (TYPE_DOCUMENT, TYPE_SCRIPT, ...)
    /// `uri`          : الـ URI الكامل للطلب
    ///
    /// يُعيد `PolicyOutcome` الذي يُترجَم إلى قرار nsIContentPolicy
    pub fn should_load(&self, content_type: u32, uri: &str) -> PolicyOutcome {

        // ── إذا الفلتر لم يُحمَّل بعد: اقبل كل شيء (لا تعطّل المتصفح) ───────
        if !self.state.is_ready() {
            trace!("Brxon: الفلتر لم يُحمَّل — ACCEPT ({})", uri);
            return PolicyOutcome::Accept;
        }

        // ── استخرج الدومين من الـ URI ─────────────────────────────────────────
        let domain = normalize_domain(uri);

        if domain.is_empty() {
            return PolicyOutcome::Accept;
        }

        // ── ابحث في Bloom Filter ──────────────────────────────────────────────
        let filter  = self.state.filter.read();
        let bloom   = BloomFilter::from_slice(&filter.current, filter.k);
        let full    = normalize_full(uri);
        let blocked = bloom.contains_or_parent(&domain) || bloom.contains(&full);

        if !blocked {
            trace!("Brxon: ACCEPT — {}", domain);
            return PolicyOutcome::Accept;
        }

        // ── الدومين موجود في الفلتر — حدّد نوع الرفض ────────────────────────
        let outcome = self.determine_reject_type(content_type, &domain);

        debug!("Brxon: {} — {:?} (type={})", domain, outcome, content_type);
        outcome
    }

    // ── تحديد نوع الرفض ──────────────────────────────────────────────────────

    /// القرار الحاسم:
    ///
    /// • TYPE_DOCUMENT أو TYPE_SUBDOCUMENT → صفحة حجب كاملة تظهر للمستخدم
    ///   (هذا هو الحالة الوحيدة التي تظهر فيها blockinfo.html)
    ///
    /// • أي نوع آخر (سكريبت، صورة، fetch، websocket...) → رفض صامت
    ///   لأن هذه موارد فرعية — الإعلانات والتتبع دائماً هنا
    fn determine_reject_type(&self, content_type: u32, domain: &str) -> PolicyOutcome {
        use content_type::*;

        match content_type {
            // ─ تنقل كامل للصفحة أو iframe → صفحة الحجب ─────────────────────
            TYPE_DOCUMENT | TYPE_SUBDOCUMENT => {
                debug!(
                    "Brxon: موقع محجوب (تنقل كامل) → blockinfo.html — {}",
                    domain
                );
                PolicyOutcome::RejectWithBlockPage
            }

            // ─ أي مورد فرعي → رفض صامت تام ──────────────────────────────────
            // هذا يشمل:
            //   • إعلانات  (TYPE_IMAGE, TYPE_SCRIPT, TYPE_STYLESHEET)
            //   • تتبع      (TYPE_XMLHTTPREQUEST, TYPE_FETCH, TYPE_PING)
            //   • موارد أخرى (TYPE_FONT, TYPE_MEDIA, TYPE_WEBSOCKET)
            _ => {
                trace!(
                    "Brxon: مورد محجوب صامتاً (type={}) — {}",
                    content_type, domain
                );
                PolicyOutcome::RejectSilent
            }
        }
    }

    // ── فحص بالاسم المباشر (للاختبار والـ API الداخلي) ─────────────────────

    /// هل هذا الدومين في قائمة الحجب؟
    /// يُستخدم داخلياً فقط — لا يحدد نوع الرفض
    pub fn is_domain_blocked(&self, domain: &str) -> bool {
        if !self.state.is_ready() { return false; }
        let normalized = normalize_domain(domain);
        let filter     = self.state.filter.read();
        let bloom      = BloomFilter::from_slice(&filter.current, filter.k);
        bloom.contains_or_parent(&normalized)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  FFI — واجهة C للاستدعاء من Gecko (C++)
// ─────────────────────────────────────────────────────────────────────────────
//
// هذه الدوال تُصدَّر بـ `#[no_mangle]` لتُستدعى مباشرة من كود C++ في Gecko.
// Gecko يمرر:
//   - content_type : u32  ← من nsIContentPolicy
//   - uri          : *const c_char ← URI الطلب
// ويستقبل:
//   - i16 ← قرار nsIContentPolicy

use std::ffi::CStr;
use std::os::raw::c_char;

/// نتيجة الاستشارة — يُستخدم في FFI فقط لتجنب unsafe في أماكن أخرى
#[repr(C)]
pub struct BrxonDecision {
    /// القرار: 1=ACCEPT, -1=REJECT_SILENT, -2=REJECT_WITH_BLOCKPAGE
    pub decision: i16,
    /// هل يجب عرض blockinfo.html؟
    pub show_block_page: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
//  اختبارات
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// دالة مساعدة: هل هذا النوع يُفعّل صفحة الحجب؟
    fn is_navigation(content_type: u32) -> bool {
        matches!(content_type, content_type::TYPE_DOCUMENT | content_type::TYPE_SUBDOCUMENT)
    }

    #[test]
    fn test_navigation_types_trigger_block_page() {
        assert!(is_navigation(content_type::TYPE_DOCUMENT));
        assert!(is_navigation(content_type::TYPE_SUBDOCUMENT));
    }

    #[test]
    fn test_sub_resources_never_trigger_block_page() {
        let sub_resource_types = [
            content_type::TYPE_SCRIPT,
            content_type::TYPE_IMAGE,
            content_type::TYPE_STYLESHEET,
            content_type::TYPE_XMLHTTPREQUEST,
            content_type::TYPE_FETCH,
            content_type::TYPE_PING,
            content_type::TYPE_FONT,
            content_type::TYPE_MEDIA,
            content_type::TYPE_WEBSOCKET,
            content_type::TYPE_OTHER,
        ];
        for t in sub_resource_types {
            assert!(!is_navigation(t), "type={} لا يجب أن يُظهر صفحة الحجب", t);
        }
    }

    #[test]
    fn test_policy_outcome_gecko_codes() {
        assert_eq!(PolicyOutcome::Accept.to_gecko_decision(),              1);
        assert_eq!(PolicyOutcome::RejectSilent.to_gecko_decision(),       -1);
        assert_eq!(PolicyOutcome::RejectWithBlockPage.to_gecko_decision(), -2);
    }
}
