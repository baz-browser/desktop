// MIT License
//
// Copyright (c) 2026 BAZ Browser متصفح باز
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

pub mod content_type {
    pub const TYPE_OTHER:             u32 = 1;
    pub const TYPE_SCRIPT:            u32 = 2;
    pub const TYPE_IMAGE:             u32 = 3;
    pub const TYPE_STYLESHEET:        u32 = 4;
    pub const TYPE_OBJECT:            u32 = 5;
    pub const TYPE_DOCUMENT:          u32 = 6;
    pub const TYPE_SUBDOCUMENT:       u32 = 7;
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

pub mod policy_decision {
    pub const ACCEPT: i16 = 1;
    pub const REJECT_REQUEST: i16 = -1;
    pub const REJECT_TYPE: i16 = -2;
}

use std::sync::Arc;
use tracing::{trace, debug};

use crate::ads_block::AdsBlockEngine;
use crate::bloom::{BloomFilter, normalize_domain};
use crate::state::BrxonState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyOutcome {
    Accept,
    RejectSilent,
    RejectWithBlockPage,
}

impl PolicyOutcome {
    pub fn to_gecko_decision(&self) -> i16 {
        match self {
            PolicyOutcome::Accept              => policy_decision::ACCEPT,
            PolicyOutcome::RejectSilent        => policy_decision::REJECT_REQUEST,
            PolicyOutcome::RejectWithBlockPage => policy_decision::REJECT_TYPE,
        }
    }
}

fn content_type_to_ads_str(content_type: u32) -> &'static str {
    use content_type::*;
    match content_type {
        TYPE_DOCUMENT          => "document",
        TYPE_SUBDOCUMENT       => "subdocument",
        TYPE_SCRIPT            => "script",
        TYPE_IMAGE             => "image",
        TYPE_IMAGESET          => "image",
        TYPE_STYLESHEET        => "stylesheet",
        TYPE_OBJECT            => "object",
        TYPE_OBJECT_SUBREQUEST => "object",
        TYPE_XMLHTTPREQUEST    => "xhr",
        TYPE_FETCH             => "xhr",
        TYPE_PING              => "ping",
        TYPE_FONT              => "font",
        TYPE_MEDIA             => "media",
        TYPE_WEBSOCKET         => "websocket",
        TYPE_CSP_REPORT        => "csp_report",
        TYPE_WEB_MANIFEST      => "other",
        TYPE_SPECULATIVE       => "other",
        TYPE_WEB_TRANSPORT     => "other",
        _                      => "other",
    }
}

pub struct ContentPolicy {
    state:      Arc<BrxonState>,
    ads_engine: Arc<AdsBlockEngine>,
}

impl ContentPolicy {
    pub fn new(state: Arc<BrxonState>, ads_engine: Arc<AdsBlockEngine>) -> Self {
        Self { state, ads_engine }
    }

    pub fn should_load_with_source(
        &self,
        content_type: u32,
        uri: &str,
        source_uri: &str,
    ) -> PolicyOutcome {
        if self.state.is_ready() {
            let domain = normalize_domain(uri);
            if !domain.is_empty() {
                let filter = self.state.filter.read();
                let bloom  = BloomFilter::from_slice(&filter.current, filter.k);

                if bloom.contains_or_parent(&domain) {
                    let outcome = self.determine_reject_type(content_type, &domain);
                    debug!("Brxon[NSFW]: {} — {:?} (type={})", domain, outcome, content_type);
                    return outcome;
                }
            }
        }

        if self.ads_engine.is_ready() {
            let req_type = content_type_to_ads_str(content_type);
            if self.ads_engine.should_block(uri, source_uri, req_type) {
                trace!("Brxon[Ads]: REJECT صامت — {} (type={})", uri, req_type);
                return PolicyOutcome::RejectSilent;
            }
        }

        trace!("Brxon: ACCEPT — {}", uri);
        PolicyOutcome::Accept
    }

    pub fn should_load(&self, content_type: u32, uri: &str) -> PolicyOutcome {
        self.should_load_with_source(content_type, uri, "")
    }

    fn determine_reject_type(&self, content_type: u32, domain: &str) -> PolicyOutcome {
        use content_type::*;

        match content_type {
            TYPE_DOCUMENT | TYPE_SUBDOCUMENT => {
                debug!(
                    "Brxon: موقع محجوب (تنقل كامل) → blockinfo.html — {}",
                    domain
                );
                PolicyOutcome::RejectWithBlockPage
            }
            _ => {
                trace!(
                    "Brxon: مورد محجوب صامتاً (type={}) — {}",
                    content_type, domain
                );
                PolicyOutcome::RejectSilent
            }
        }
    }

    pub fn is_domain_blocked(&self, domain: &str) -> bool {
        if !self.state.is_ready() { return false; }
        let normalized = normalize_domain(domain);
        let filter     = self.state.filter.read();
        let bloom      = BloomFilter::from_slice(&filter.current, filter.k);
        bloom.contains_or_parent(&normalized)
    }
}

#[repr(C)]
pub struct BrxonDecision {
    pub decision: i16,
    pub show_block_page: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

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