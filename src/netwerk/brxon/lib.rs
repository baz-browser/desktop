// MIT License
//
// Copyright (c) 2026 BAZ Browser
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

pub mod ads_block;
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

use crate::ads_block::AdsBlockEngine;
use crate::bloom::BLOOM_M_BYTES;
use crate::bloom::BLOOM_K;
use crate::delta::DeltaEngine;
use crate::policy::ContentPolicy;
use crate::signing::EMBEDDED_PUBLIC_KEY;
use crate::state::BrxonState;
use crate::transport::SseParser;

pub struct BrxonEngine {
    pub policy:     ContentPolicy,
    pub state:      Arc<BrxonState>,
    pub ads_engine: Arc<AdsBlockEngine>,
    delta_engine:   DeltaEngine,
    sse_parser:     SseParser,
}

impl BrxonEngine {
    pub fn new(server_base: &str) -> Result<Self, String> {
        let public_key = VerifyingKey::from_bytes(&EMBEDDED_PUBLIC_KEY)
            .map_err(|e| format!("مفتاح عام غير صالح: {e}"))?;

        let state = BrxonState::new(
            public_key,
            server_base.to_string(),
            BLOOM_M_BYTES,
            BLOOM_K,
        );

        let ads_engine = Arc::new(AdsBlockEngine::new());

        let policy = ContentPolicy::new(Arc::clone(&state), Arc::clone(&ads_engine));
        let delta_engine = DeltaEngine::new(Arc::clone(&state));
        let sse_parser = SseParser::new();

        if let Err(e) = crate::initial_filter::load_embedded_filter(&state) {
            eprintln!("Brxon: تحذير — فشل تحميل الفلتر المضمّن: {}", e);
        }

        info!("Brxon: محرك جاهز — سيرفر={}", server_base);

        Ok(Self { policy, state, ads_engine, delta_engine, sse_parser })
    }

    pub fn start(&self) {
        info!("Brxon: جاهز لاستقبال بيانات من Gecko (Necko)");
    }
}

pub type BrxonHandle = *mut BrxonEngine;

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

#[no_mangle]
pub unsafe extern "C" fn brxon_start(handle: BrxonHandle) {
    if handle.is_null() { return; }
    (*handle).start();
}

#[no_mangle]
pub unsafe extern "C" fn brxon_should_load(
    handle:       BrxonHandle,
    content_type: u32,
    uri:          *const c_char,
    source_uri:   *const c_char,   // جديد — ممكن يكون null لو ما توفر
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

    // source_uri اختياري — لو null نمرر ""
    let source_str = if source_uri.is_null() {
        ""
    } else {
        CStr::from_ptr(source_uri).to_str().unwrap_or("")
    };

    let engine  = &*handle;
    let outcome = engine.policy.should_load_with_source(content_type, uri_str, source_str);

    BrxonDecision {
        decision:        outcome.to_gecko_decision(),
        show_block_page: outcome == policy::PolicyOutcome::RejectWithBlockPage,
    }
}
#[no_mangle]
pub unsafe extern "C" fn brxon_shutdown(handle: BrxonHandle) {
    if handle.is_null() { return; }
    info!("Brxon: إيقاف المحرك...");
    let _ = Box::from_raw(handle);
    info!("Brxon: تم الإيقاف");
}

#[no_mangle]
pub unsafe extern "C" fn brxon_is_ready(handle: BrxonHandle) -> bool {
    if handle.is_null() { return false; }
    (*handle).state.is_ready()
}

#[no_mangle]
pub unsafe extern "C" fn brxon_filter_version(handle: BrxonHandle) -> u64 {
    if handle.is_null() { return 0; }
    let h = &*handle; h.state.filter.read().version
}

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

#[no_mangle]
pub unsafe extern "C" fn brxon_ads_ingest_lists_json(
    handle: BrxonHandle,
    json_bytes: *const u8,
    json_len: usize,
) -> bool {
    if handle.is_null() || json_bytes.is_null() {
        return false;
    }
    let engine = &*handle;
    let bytes = slice::from_raw_parts(json_bytes, json_len);

    let text = match std::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => return false,
    };

    #[derive(serde::Deserialize)]
    struct RawList { label: String, text: String }

    let raw_lists: Vec<RawList> = match serde_json::from_str(text) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Brxon: فشل تحليل JSON لقوائم الإعلانات — {}", e);
            return false;
        }
    };

    let lists: Vec<(&str, String)> = raw_lists.iter()
        .map(|r| (r.label.as_str(), r.text.clone()))
        .collect();

    match engine.ads_engine.ingest_lists(lists) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("Brxon: فشل تحديث محرك الإعلانات — {}", e);
            false
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn brxon_ads_is_ready(handle: BrxonHandle) -> bool {
    if handle.is_null() { return false; }
    (*handle).ads_engine.is_ready()
}

#[no_mangle]
pub unsafe extern "C" fn brxon_ads_needs_update(handle: BrxonHandle) -> bool {
    if handle.is_null() { return false; }
    (*handle).ads_engine.needs_update()
}

#[no_mangle]
pub unsafe extern "C" fn brxon_ads_cosmetic_css(
    handle: BrxonHandle,
    uri: *const c_char,
    out_len: *mut usize,
) -> *mut u8 {
    *out_len = 0;
    if handle.is_null() || uri.is_null() { return std::ptr::null_mut(); }

    let uri_str = match CStr::from_ptr(uri).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let engine = &*handle;
    match engine.ads_engine.cosmetic_css_for_url(uri_str) {
        Some(css) => {
            let mut bytes = css.into_bytes().into_boxed_slice();
            *out_len = bytes.len();
            let ptr = bytes.as_mut_ptr();
            std::mem::forget(bytes);
            ptr
        }
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn brxon_free_css_buffer(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        let _ = Vec::from_raw_parts(ptr, len, len);
    }
}
