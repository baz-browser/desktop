// signing.rs — التحقق من التوقيع الرقمي
//
// الآلية (متزامنة مع السيرفر):
//   SHA256(payload_bytes) → digest
//   Ed25519::verify(digest + version_le_bytes, signature, public_key)
//
// المفتاح العام مضمّن وقت البناء — لا يمكن تغييره من الخارج.

use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use sha2::{Sha256, Digest};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
//  المفتاح العام المضمّن — يُستبدل بالقيمة الحقيقية عند البناء
// ─────────────────────────────────────────────────────────────────────────────

/// المفتاح العام Ed25519 (32 بايت) مضمّن في وقت البناء.
///
/// ⚠️  هذه قيمة placeholder — يجب استبدالها بالمفتاح الحقيقي
///     الذي يُنشأ على السيرفر قبل البناء النهائي.
pub const EMBEDDED_PUBLIC_KEY: [u8; 32] = [
    // ← استبدل هذه القيم بالمفتاح الحقيقي المُنشأ على السيرفر
    0xB5, 0xA8, 0x84, 0x73, 0x9E, 0x68, 0xF0, 0x5B,
    0x0C, 0xF7, 0x12, 0x8F, 0x0D, 0xE2, 0x24, 0xC8,
    0x49, 0xF6, 0x86, 0x44, 0xE7, 0x8A, 0x97, 0x96,
    0x36, 0x11, 0x14, 0x53, 0x09, 0xF1, 0x06, 0xC7,
];
// ─────────────────────────────────────────────────────────────────────────────
//  أخطاء التحقق
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("SHA256 لا يتطابق: متوقع={expected} مستقبَل={received}")]
    HashMismatch { expected: String, received: String },

    #[error("توقيع Ed25519 غير صحيح: {0}")]
    BadSignature(String),

    #[error("حجم التوقيع خاطئ: {0} بايت")]
    BadSignatureSize(usize),

    #[error("بيانات الـ payload فارغة")]
    EmptyPayload,
}

// ─────────────────────────────────────────────────────────────────────────────
//  SignedPayload — البيانات الواردة من السيرفر
// ─────────────────────────────────────────────────────────────────────────────

/// حزمة البيانات الموقّعة — تصل من السيرفر عبر HTTP أو SSE
#[derive(Debug, serde::Deserialize)]
pub struct SignedPayload {
    /// البيانات الخام (bytes مُرمَّزة بـ base64 في الـ JSON)
    #[serde(with = "base64_bytes")]
    pub payload_bytes: Vec<u8>,
    /// SHA256 hash مُرمَّز hex
    pub sha256: String,
    /// التوقيع Ed25519 مُرمَّز hex (64 بايت)
    pub signature: String,
    /// رقم الإصدار الجديد
    pub version: u64,
}

/// بالنسبة للـ delta يُضاف حقلان إضافيان
#[derive(Debug, serde::Deserialize)]
pub struct SignedDelta {
    #[serde(flatten)]
    pub inner: SignedPayload,
    pub from_version: u64,
    pub to_version: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Verifier
// ─────────────────────────────────────────────────────────────────────────────

/// تحقق من حزمة بيانات موقّعة
///
/// الخطوات:
///   1. التحقق من SHA256 (تكامل البيانات)
///   2. التحقق من توقيع Ed25519 (المصادقة)
///
/// يُعيد `Ok(())` فقط إذا نجح التحققان معاً.
pub fn verify_payload(
    payload: &SignedPayload,
    public_key: &VerifyingKey,
) -> Result<(), VerifyError> {
    if payload.payload_bytes.is_empty() {
        return Err(VerifyError::EmptyPayload);
    }

    // ── 1. تحقق SHA256 ────────────────────────────────────────────────────────
    let computed_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&payload.payload_bytes);
        hex::encode(hasher.finalize())
    };

    if computed_hash != payload.sha256 {
        return Err(VerifyError::HashMismatch {
            expected: payload.sha256.clone(),
            received: computed_hash,
        });
    }

    // ── 2. تحقق Ed25519 ───────────────────────────────────────────────────────
    // الرسالة = SHA256_bytes + version_as_le_u64
    let sig_bytes = hex::decode(&payload.signature)
        .map_err(|e| VerifyError::BadSignature(e.to_string()))?;

    if sig_bytes.len() != 64 {
        return Err(VerifyError::BadSignatureSize(sig_bytes.len()));
    }

    let signature = Signature::from_bytes(
        &sig_bytes.try_into().expect("64 bytes guaranteed above")
    );

    // بناء الرسالة: digest (32 بايت) + version (8 بايت little-endian)
    let hash_bytes = hex::decode(&payload.sha256)
        .map_err(|e| VerifyError::BadSignature(format!("hex sha256: {e}")))?;

    let mut message = hash_bytes;
    message.extend_from_slice(&payload.version.to_le_bytes());

    public_key
        .verify(&message, &signature)
        .map_err(|e| VerifyError::BadSignature(e.to_string()))?;

    Ok(())
}

/// دالة مختصرة للتحقق من delta
pub fn verify_delta(
    delta: &SignedDelta,
    public_key: &VerifyingKey,
) -> Result<(), VerifyError> {
    verify_payload(&delta.inner, public_key)
}

// ─────────────────────────────────────────────────────────────────────────────
//  سيريلايزيشن مساعد — base64 ↔ Vec<u8>
// ─────────────────────────────────────────────────────────────────────────────

mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}
