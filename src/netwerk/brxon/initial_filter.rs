// initial_filter.rs — الفلتر المضمّن وقت البناء
//
// يُحمَّل مرة واحدة عند تشغيل المتصفح.
// لا يحتاج ملف خارجي — مضمّن في libbrxon.a مباشرة.

use crate::bloom::{BLOOM_M_BYTES, BLOOM_K};
use crate::state::BrxonState;
use std::sync::Arc;
use tracing::info;

/// الفلتر المضمّن — 4.57MB داخل البايناري
static INITIAL_FILTER_BIN: &[u8] = include_bytes!("initial_filter.bin");

pub struct EmbeddedFilter {
    pub version: u64,
    pub k:       u32,
    pub m_bytes: usize,
    pub sha256:  [u8; 32],
    pub sig:     [u8; 64],
    pub bits:    &'static [u8],
}

impl EmbeddedFilter {
    pub fn parse() -> Result<Self, String> {
        let d = INITIAL_FILTER_BIN;
        if d.len() < 8 + 4 + 8 + 32 + 64 {
            return Err("initial_filter.bin أصغر من المتوقع".into());
        }

        let mut off = 0usize;
        let version = u64::from_le_bytes(d[off..off+8].try_into().unwrap()); off += 8;
        let k       = u32::from_le_bytes(d[off..off+4].try_into().unwrap()); off += 4;
        let m_bytes = u64::from_le_bytes(d[off..off+8].try_into().unwrap()) as usize; off += 8;

        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&d[off..off+32]); off += 32;

        let mut sig = [0u8; 64];
        sig.copy_from_slice(&d[off..off+64]); off += 64;

        if d.len() < off + m_bytes {
            return Err(format!("initial_filter.bin ناقص — متوقع {} بايت", m_bytes));
        }
        if m_bytes != BLOOM_M_BYTES {
            return Err(format!(
                "حجم الفلتر {} لا يتطابق مع BLOOM_M_BYTES {}",
                m_bytes, BLOOM_M_BYTES
            ));
        }

        Ok(Self { version, k, m_bytes, sha256, sig, bits: &d[off..off + m_bytes] })
    }
}

/// حمّل الفلتر المضمّن إلى BrxonState
pub fn load_embedded_filter(state: &Arc<BrxonState>) -> Result<(), String> {
    let ef = EmbeddedFilter::parse()?;

    // تحقق من التوقيع
    use crate::signing::{SignedPayload, verify_payload};
    let payload = SignedPayload {
        payload_bytes: ef.bits.to_vec(),
        sha256:    hex::encode(ef.sha256),
        signature: hex::encode(ef.sig),
        version:   ef.version,
    };

    verify_payload(&payload, &state.public_key)
        .map_err(|e| format!("فشل التحقق من الفلتر المضمّن: {e}"))?;

    {
        let mut filter  = state.filter.write();
        filter.current  = ef.bits.to_vec();
        filter.previous = ef.bits.to_vec();
        filter.version  = ef.version;
        filter.k        = ef.k;
    }

    info!(
        "Brxon: فلتر مضمّن محمّل — إصدار={} حجم={:.2}MB k={}",
        ef.version,
        ef.m_bytes as f64 / 1_048_576.0,
        ef.k
    );
    Ok(())
}
