// MIT License
//
// Copyright (c) 2026 [BAZ باز] 
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


use murmur3::murmur3_x64_128;
use std::io::Cursor;

// ─────────────────────────────────────────────────────────────────────────────
//  الثوابت — مطابقة لـ build_filter.rs
// ─────────────────────────────────────────────────────────────────────────────

pub const BLOOM_M_BYTES: usize = 4_792_530;
pub const BLOOM_M_BITS:  usize = BLOOM_M_BYTES * 8;
pub const BLOOM_K:       u32   = 13;

// ─────────────────────────────────────────────────────────────────────────────
//  BloomFilter
// ─────────────────────────────────────────────────────────────────────────────

pub struct BloomFilter<'a> {
    bits:   &'a [u8],
    m_bits: usize,
    k:      u32,
}

impl<'a> BloomFilter<'a> {
    pub fn from_slice(bits: &'a [u8], k: u32) -> Self {
        Self { bits, m_bits: bits.len() * 8, k }
    }

    /// بحث مباشر — الدومين بالضبط
    pub fn contains(&self, domain: &str) -> bool {
        let (h1, h2) = self.hash_pair(domain);
        for i in 0..self.k as u64 {
            let idx     = h1.wrapping_add(i.wrapping_mul(h2)) % self.m_bits as u64;
            let byte    = (idx / 8) as usize;
            let bit     = (idx % 8) as usize;
            if byte >= self.bits.len() { return false; }
            if (self.bits[byte] >> bit) & 1 == 0 { return false; }
        }
        true
    }

    /// suffix matching — يفحص الدومين + كل parent domains
    ///
    /// مثال: "video.xvideos.com"
    ///   → فحص "video.xvideos.com"  (في الفلتر؟)
    ///   → فحص "xvideos.com"        (في الفلتر؟) ✓ محجوب
    ///
    /// هذا يتوافق مع قاعدة oisd:
    ///   "example.com تحجب example.com وكل subdomains"
    pub fn contains_or_parent(&self, domain: &str) -> bool {
        // فحص الدومين نفسه أولاً
        if self.contains(domain) { return true; }

        // فحص كل parent domain تصاعدياً
        let mut rest = domain;
        while let Some(pos) = rest.find('.') {
            rest = &rest[pos + 1..];
            // تجاهل TLD وحده (.com, .net) — يجب أن يحتوي نقطة واحدة على الأقل
            if rest.contains('.') && self.contains(rest) {
                return true;
            }
        }
        false
    }

    fn hash_pair(&self, input: &str) -> (u64, u64) {
        let b = input.as_bytes();
        let h1 = murmur3_x64_128(&mut Cursor::new(b), 0xDEAD_BEEF).unwrap_or(0) as u64;
        let h2 = murmur3_x64_128(&mut Cursor::new(b), 0xC0DE_CAFE).unwrap_or(0) as u64;
        (h1, h2)
    }

    #[inline]
    fn get_bit(&self, index: usize) -> bool {
        let byte = index / 8;
        let bit  = index % 8;
        if byte >= self.bits.len() { return false; }
        (self.bits[byte] >> bit) & 1 == 1
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  normalize_domain
// ─────────────────────────────────────────────────────────────────────────────




pub fn normalize_domain(raw: &str) -> String {
    // ① أزل البروتوكول
    let s = raw.trim();
    let s = if s.starts_with("https://") { &s[8..] }
            else if s.starts_with("http://") { &s[7..] }
            else { s };
    // ② أزل www.
    let s = if s.starts_with("www.") { &s[4..] } else { s };
    // ③ أزل المسار والـ query والـ fragment
    let s = s.split('/').next().unwrap_or(s);
    let s = s.split('?').next().unwrap_or(s);
    let s = s.split('#').next().unwrap_or(s);
    // ④ أزل رقم المنفذ
    let s = if let Some(pos) = s.rfind(':') {
        if s[pos+1..].chars().all(|c| c.is_ascii_digit()) { &s[..pos] } else { s }
    } else { s };
    // ⑤ أزل النقطة في النهاية (بعض القوائم تضيفها)
    let s = s.trim_end_matches('.');
    s.to_lowercase()
}

// ─────────────────────────────────────────────────────────────────────────────
//  اختبارات
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("https://www.Example.Com/path?q=1"), "example.com");
        assert_eq!(normalize_domain("http://ads.google.com"),            "ads.google.com");
        assert_eq!(normalize_domain("tracker.evil.net:443/js"),          "tracker.evil.net");
        // إصلاح البق الرئيسي
        assert_eq!(normalize_domain("https://doubleclick.net/ads"),      "doubleclick.net");
        assert_eq!(normalize_domain("https://www.doubleclick.net/ads"),  "doubleclick.net");
        assert_eq!(normalize_domain("https://DOUBLECLICK.NET/"),         "doubleclick.net");
        assert_eq!(normalize_domain("https://site.com:8443/path"),       "site.com");
    }

    #[test]
    fn test_suffix_matching_logic() {
        // اختبار منطق suffix matching بفلتر فارغ
        let bits = vec![0u8; BLOOM_M_BYTES];
        let bf   = BloomFilter::from_slice(&bits, BLOOM_K);
        // فلتر فارغ — كل شيء false
        assert!(!bf.contains_or_parent("sub.example.com"));
        assert!(!bf.contains_or_parent("google.com"));
    }

    #[test]
    fn test_bloom_empty() {
        let bits = vec![0u8; BLOOM_M_BYTES];
        let bf   = BloomFilter::from_slice(&bits, BLOOM_K);
        assert!(!bf.contains("google.com"));
        assert!(!bf.contains("pornhub.com"));
    }
}
