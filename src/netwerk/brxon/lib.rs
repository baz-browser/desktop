// lib.rs — نقطة دخول Brxon
//
// Brxon: درع حجب قابل للتضمين داخل Gecko
//
// يتكوّن من:
//   bloom.rs     — محرك Bloom Filter (بحث فقط)
//   signing.rs   — التحقق Ed25519 + SHA256
//   delta.rs     — تطبيق XOR delta + Rollback
//   transport.rs — HTTP GET + SSE
//   policy.rs    — nsIContentPolicy (قلب المحرك)
//   state.rs     — الحالة المشتركة
//
// دورة الحياة:
//   1. brxon_init()                     ← Gecko يُهيّئ المحرك عند التشغيل
//      (يحمّل الفلتر المضمّن فورًا — يشتغل بدون أي شبكة من أول لحظة)
//   2. brxon_start()                    ← يُعلِم المحرك إنه جاهز يستقبل بيانات
//   3. Gecko (ThreatBlocker.cpp) يجيب البيانات فعليًا عبر Necko، ثم:
//        brxon_ingest_full_filter_json()  ← فلتر كامل جديد (استجابة /filter/latest)
//        brxon_ingest_sse_chunk()         ← قطعة من دفق /filter/updates
//   4. brxon_should_load()              ← يُستدعى قبل كل طلب شبكي
//   5. brxon_shutdown()                 ← Gecko يوقف المحرك عند الإغلاق
//
// ⚠️  هذا الكريّت عمدًا لا يفتح أي اتصال شبكة بنفسه (راجع transport.rs
//     لتفاصيل السبب). كل بايت وارد من السيرفر يوصل هنا عبر FFI بعد ما
//     C++ يجيبه بطريقة تحترم إعدادات البروكسي/VPN لدى المستخدم.

pub mod bloom;
pub mod delta;
pub mod policy;
pub mod signing;
pub mod state;
pub mod transport;
pub mod initial_filter;

use std::sync::Arc;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::slice;
use tracing::info;
use ed25519_dalek::VerifyingKey;

use crate::bloom::BLOOM_M_BYTES;
use crate::bloom::BLOOM_K;
use crate::delta::DeltaEngine;
use crate::policy::ContentPolicy;
use crate::signing::EMBEDDED_PUBLIC_KEY;
use crate::state::BrxonState;
use crate::transport::SseParser;

// ─────────────────────────────────────────────────────────────────────────────
//  BrxonEngine — الكيان الرئيسي
// ─────────────────────────────────────────────────────────────────────────────

/// كائن المحرك الكامل — يُخزَّن في Gecko طوال عمر المتصفح
pub struct BrxonEngine {
    pub policy: ContentPolicy,
    pub state: Arc<BrxonState>,
    /// منطق التحقق/التطبيق (بدون أي شبكة) — تستخدمه دوال ingest
    delta_engine: DeltaEngine,
    /// يجمّع قطع SSE الواردة من C++ ويطبّق كل delta كامل
    sse_parser: SseParser,
}

impl BrxonEngine {
    /// أنشئ محرك جديد
    ///
    /// `server_base`: عنوان السيرفر مثل "https://filter.example.com"
    /// (يُخزَّن فقط ليقرأه C++ عبر واجهة لاحقة — Rust نفسه ما يتصل به)
    pub fn new(server_base: &str) -> Result<Self, String> {
        // ⚠️ لا نسجّل tracing_subscriber هنا عمدًا. بما إن brxon صار جزء
        // من نفس مكتبة gkrust (بعد الدمج)، وgkrust نفسه أصلًا يسجّل
        // logger عالمي خاص فيه وقت GkRust_Init() — وRust يسمح بـ logger
        // واحد بس لكل عملية. محاولة تسجيل واحد ثاني هنا كانت تسبب
        // panic حقيقي عند تشغيل المتصفح (SetLoggerError). استدعاءات
        // tracing::info!/warn!/error! بباقي الملف تبقى آمنة تمامًا
        // بدون تسجيل — ترجع صامتة لو ما فيه subscriber مسجّل، أو
        // تُوجَّه تلقائيًا لنظام تسجيل فايرفوكس لو gkrust سجّل واحد.

        // بناء المفتاح العام من الثابت المضمّن
        let public_key = VerifyingKey::from_bytes(&EMBEDDED_PUBLIC_KEY)
            .map_err(|e| format!("مفتاح عام غير صالح: {e}"))?;

        // بناء الحالة المشتركة
        let state = BrxonState::new(
            public_key,
            server_base.to_string(),
            BLOOM_M_BYTES,
            BLOOM_K,
        );

        // بناء سياسة الحجب
        let policy = ContentPolicy::new(Arc::clone(&state));
        let delta_engine = DeltaEngine::new(Arc::clone(&state));
        let sse_parser = SseParser::new();

        // حمّل الفلتر المضمّن فوراً — يشتغل بدون أي شبكة من أول لحظة
        if let Err(e) = crate::initial_filter::load_embedded_filter(&state) {
            eprintln!("Brxon: تحذير — فشل تحميل الفلتر المضمّن: {}", e);
        }

        info!("Brxon: محرك جاهز — سيرفر={}", server_base);

        Ok(Self { policy, state, delta_engine, sse_parser })
    }

    /// يُعلِم المحرك إنه جاهز. الجلب الفعلي مسؤولية Gecko (ThreatBlocker)
    /// عبر Necko — يستدعي brxon_ingest_full_filter_json بعد أول نجاح.
    pub fn start(&self) {
        info!("Brxon: جاهز لاستقبال بيانات من Gecko (Necko)");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  FFI — واجهة C الكاملة للاستدعاء من Gecko
// ─────────────────────────────────────────────────────────────────────────────

/// مؤشر للمحرك — يُعاد لـ Gecko ويُمرَّر في كل استدعاء لاحق
pub type BrxonHandle = *mut BrxonEngine;

/// تهيئة Brxon — يُستدعى مرة واحدة عند تشغيل Gecko
///
/// `server_base`: عنوان السيرفر (UTF-8, null-terminated)
///
/// يُعيد مؤشراً للمحرك أو NULL عند الفشل.
///
/// # Safety
/// `server_base` يجب أن يكون مؤشراً صالحاً لـ null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn brxon_init(server_base: *const c_char) -> BrxonHandle {
    if server_base.is_null() {
        return std::ptr::null_mut();
    }

    let server_str = match CStr::from_ptr(server_base).to_str() {
        Ok(s)  => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match BrxonEngine::new(server_str) {
        Ok(engine) => Box::into_raw(Box::new(engine)),
        Err(e) => {
            eprintln!("Brxon: فشل التهيئة — {}", e);
            std::ptr::null_mut()
        }
    }
}

/// تشغيل Brxon في الخلفية — يُستدعى بعد brxon_init مباشرة
///
/// # Safety
/// `handle` يجب أن يكون مؤشراً صالحاً مُعاداً من brxon_init.
#[no_mangle]
pub unsafe extern "C" fn brxon_start(handle: BrxonHandle) {
    if handle.is_null() { return; }
    (*handle).start();
}

/// فحص URI قبل تحميله — نقطة الدخول الرئيسية
///
/// `handle`       : المؤشر المُعاد من brxon_init
/// `content_type` : نوع الطلب (TYPE_DOCUMENT=6, TYPE_SCRIPT=2, ...)
/// `uri`          : الـ URI كامل (null-terminated C string)
///
/// يُعيد:
///   `BrxonDecision.decision`:
///      1  = ACCEPT
///     -1  = REJECT_REQUEST (رفض صامت — إعلانات/تتبع)
///     -2  = REJECT_TYPE    (رفض مع صفحة — مواقع إباحية)
///
/// # Safety
/// جميع المؤشرات يجب أن تكون صالحة.
#[no_mangle]
pub unsafe extern "C" fn brxon_should_load(
    handle:       BrxonHandle,
    content_type: u32,
    uri:          *const c_char,
) -> policy::BrxonDecision {
    use policy::{BrxonDecision, policy_decision};

    let null_accept = BrxonDecision {
        decision:        policy_decision::ACCEPT,
        show_block_page: false,
    };

    if handle.is_null() || uri.is_null() {
        return null_accept;
    }

    let uri_str = match CStr::from_ptr(uri).to_str() {
        Ok(s)  => s,
        Err(_) => return null_accept,
    };

    let engine  = &*handle;
    let outcome = engine.policy.should_load(content_type, uri_str);

    BrxonDecision {
        decision:        outcome.to_gecko_decision(),
        show_block_page: outcome == policy::PolicyOutcome::RejectWithBlockPage,
    }
}

/// إيقاف المحرك وتحرير الذاكرة — يُستدعى عند إغلاق Gecko
///
/// # Safety
/// `handle` يجب أن يكون مؤشراً صالحاً مُعاداً من brxon_init.
/// بعد هذه الدالة، المؤشر غير صالح ولا يجب استخدامه.
#[no_mangle]
pub unsafe extern "C" fn brxon_shutdown(handle: BrxonHandle) {
    if handle.is_null() { return; }
    info!("Brxon: إيقاف المحرك...");
    // Box::from_raw يتولى تحرير الذاكرة عند نهاية النطاق
    let _ = Box::from_raw(handle);
    info!("Brxon: تم الإيقاف");
}

/// هل الفلتر جاهز للعمل؟ (للاستعلام من Gecko)
///
/// # Safety
/// `handle` يجب أن يكون مؤشراً صالحاً.
#[no_mangle]
pub unsafe extern "C" fn brxon_is_ready(handle: BrxonHandle) -> bool {
    if handle.is_null() { return false; }
    (*handle).state.is_ready()
}

/// رقم إصدار الفلتر الحالي (للإحصاءات)
///
/// # Safety
/// `handle` يجب أن يكون مؤشراً صالحاً.
#[no_mangle]
pub unsafe extern "C" fn brxon_filter_version(handle: BrxonHandle) -> u64 {
    if handle.is_null() { return 0; }
    let h = &*handle; h.state.filter.read().version
}

/// استقبال فلتر كامل جديد — يُستدعى من Gecko بعد نجاح GET /filter/latest
/// عبر Necko. `json_bytes` هو محتوى الاستجابة الخام (UTF-8 JSON) كما وصل
/// من الشبكة، بدون أي معالجة من C++.
///
/// يُعيد `true` عند النجاح (تحقق ناجح + تطبيق)، `false` عند أي فشل
/// (خطأ تحليل JSON أو فشل تحقق التوقيع).
///
/// # Safety
/// `handle` يجب أن يكون مؤشراً صالحاً. `json_bytes` يجب أن يشير إلى
/// `json_len` بايت صالحة للقراءة.
#[no_mangle]
pub unsafe extern "C" fn brxon_ingest_full_filter_json(
    handle: BrxonHandle,
    json_bytes: *const u8,
    json_len: usize,
) -> bool {
    if handle.is_null() || json_bytes.is_null() {
        return false;
    }
    let engine = &*handle;
    let bytes = slice::from_raw_parts(json_bytes, json_len);

    match crate::transport::ingest_full_filter_json(&engine.delta_engine, bytes) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("Brxon: فشل استقبال الفلتر الكامل — {}", e);
            false
        }
    }
}

/// استقبال قطعة بايتات من دفق SSE المستمر (/filter/updates) كما توصل
/// من Necko — يُستدعى مرارًا، مرة لكل `OnDataAvailable` من جانب C++.
/// المحرك يجمّع الرسائل داخليًا ويطبّق كل delta كامل فور اكتماله.
///
/// # Safety
/// `handle` يجب أن يكون مؤشراً صالحاً. `chunk` يجب أن يشير إلى
/// `chunk_len` بايت صالحة للقراءة.
#[no_mangle]
pub unsafe extern "C" fn brxon_ingest_sse_chunk(
    handle: BrxonHandle,
    chunk: *const u8,
    chunk_len: usize,
) {
    if handle.is_null() || chunk.is_null() {
        return;
    }
    let engine = &*handle;
    let bytes = slice::from_raw_parts(chunk, chunk_len);
    engine.sse_parser.feed(&engine.delta_engine, bytes);
}

// ─────────────────────────────────────────────────────────────────────────────
//  كود C++ المرجعي لـ Gecko (تعليقات توضيحية فقط — ليس Rust)
// ─────────────────────────────────────────────────────────────────────────────
//
// // في ملف Gecko (netwerk/base/ThreatBlocker.cpp):
//
// #include "brxon.h"   // header يُنشأ من cbindgen
//
// static BrxonHandle gBrxon = nullptr;
//
// // عند تشغيل المتصفح:
// void ThreatBlocker::Init() {
//     gBrxon = brxon_init("https://filter.example.com");
//     brxon_start(gBrxon);
//     FetchFullFilterViaNecko();   // GET /filter/latest عبر nsIChannel
//     OpenSseStreamViaNecko();     // اتصال مستمر /filter/updates
// }
//
// // بعد ما Necko يجيب استجابة /filter/latest كاملة (OnStopRequest):
// void ThreatBlocker::OnFullFilterFetched(const nsACString& jsonBody) {
//     brxon_ingest_full_filter_json(
//         gBrxon,
//         reinterpret_cast<const uint8_t*>(jsonBody.BeginReading()),
//         jsonBody.Length()
//     );
// }
//
// // كل ما توصل قطعة جديدة من دفق SSE (OnDataAvailable):
// void ThreatBlocker::OnSseChunk(const char* data, uint32_t len) {
//     brxon_ingest_sse_chunk(
//         gBrxon,
//         reinterpret_cast<const uint8_t*>(data),
//         len
//     );
// }
//
// // في nsIContentPolicy::ShouldLoad():
// NS_IMETHODIMP ThreatBlocker::ShouldLoad(
//     nsIURI* aURI, uint32_t aContentType, ..., int16_t* aDecision)
// {
//     nsAutoCString uri;
//     aURI->GetSpec(uri);
//
//     BrxonDecision result = brxon_should_load(
//         gBrxon,
//         aContentType,
//         uri.get()
//     );
//
//     *aDecision = result.decision;
//
//     if (result.show_block_page) {
//         // وجّه Gecko لتحميل:
//         // chrome://browser/content/blockinfo.html
//     }
//
//     return NS_OK;
// }
//
// // عند إغلاق المتصفح:
// void ThreatBlocker::Shutdown() {
//     brxon_shutdown(gBrxon);
//     gBrxon = nullptr;
// }
