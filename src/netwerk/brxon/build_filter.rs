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
// build_filter.rs
//


use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, Write, Cursor};
use std::time::Instant;
use murmur3::murmur3_x64_128;
use sha2::{Sha256, Digest};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

//  إعدادات الفلتر 

const BLOOM_M_BYTES: usize = 4_792_530;
const BLOOM_M_BITS:  usize = BLOOM_M_BYTES * 8;
const BLOOM_K:       u32   = 13;

//  Bloom Builder 
struct BloomBuilder {
    bits: Vec<u8>,
}

impl BloomBuilder {
    fn new() -> Self {
        Self { bits: vec![0u8; BLOOM_M_BYTES] }
    }

    fn add(&mut self, domain: &str) {
        let (h1, h2) = hash_pair(domain);
        for i in 0..BLOOM_K as u64 {
            let idx = h1.wrapping_add(i.wrapping_mul(h2)) % BLOOM_M_BITS as u64;
            self.bits[(idx / 8) as usize] |= 1 << (idx % 8);
        }
    }

    fn contains(&self, domain: &str) -> bool {
        let (h1, h2) = hash_pair(domain);
        for i in 0..BLOOM_K as u64 {
            let idx = h1.wrapping_add(i.wrapping_mul(h2)) % BLOOM_M_BITS as u64;
            if (self.bits[(idx / 8) as usize] >> (idx % 8)) & 1 == 0 {
                return false;
            }
        }
        true
    }

    fn count_set_bits(&self) -> u64 {
        self.bits.iter().map(|b| b.count_ones() as u64).sum()
    }
}

fn hash_pair(input: &str) -> (u64, u64) {
    let b = input.as_bytes();
    let h1 = murmur3_x64_128(&mut Cursor::new(b), 0xDEAD_BEEF).unwrap_or(0) as u64;
    let h2 = murmur3_x64_128(&mut Cursor::new(b), 0xC0DE_CAFE).unwrap_or(0) as u64;
    (h1, h2)
}

// normalize 


fn normalize_domain_only(raw: &str) -> String {
    let s = raw.trim();
    let s = if s.starts_with("https://") { &s[8..] }
            else if s.starts_with("http://") { &s[7..] }
            else { s };
    let s = if s.starts_with("www.") { &s[4..] } else { s };
    let s = s.split('/').next().unwrap_or(s);
    let s = s.split('?').next().unwrap_or(s);
    let s = s.split('#').next().unwrap_or(s);
    let s = if let Some(p) = s.rfind(':') {
        if s[p+1..].chars().all(|c| c.is_ascii_digit()) { &s[..p] } else { s }
    } else { s };
    let s = s.trim_end_matches('.');
    s.to_lowercase()
}

// ─── قراءة ملف قائمة ─────────────────────────────────────────────────────────
fn load_list(path: &str, builder: &mut BloomBuilder, label: &str) -> (usize, usize) {
    let file = match File::open(path) {
        Ok(f)  => f,
        Err(e) => { eprintln!("✗ فشل فتح {}: {}", path, e); return (0, 0); }
    };

    let mut added   = 0usize;
    let mut skipped = 0usize;

    for line in io::BufReader::new(file).lines().filter_map(|l| l.ok()) {
        let line = line.trim().to_string();

        if line.is_empty() || line.starts_with('#') {
            skipped += 1;
            continue;
        }

        let line_ref: &str = if line.starts_with("*.") { &line[2..] } else { &line };
        let entry = normalize_domain_only(line_ref);

        if entry.is_empty() || !entry.contains('.') {
            if !entry.is_empty() && entry.len() >= 2 {
                builder.add(&entry);
                added += 1;
            } else {
                skipped += 1;
            }
            continue;
        }

        builder.add(&entry);
        added += 1;
    }

    println!("   ✓ {} → {} إدخال مضاف ({} سطر متجاهل)", label, added, skipped);
    (added, skipped)
}




// ─── suffix matching check ────────────────────────────────────────────────────
fn is_blocked(builder: &BloomBuilder, domain: &str) -> bool {
    if builder.contains(domain) { return true; }
    let mut rest = domain;
    while let Some(pos) = rest.find('.') {
        rest = &rest[pos + 1..];
        if rest.contains('.') && builder.contains(rest) {
            return true;
        }
    }
    false
}

// ─── التوقيع ──────────────────────────────────────────────────────────────────
fn sign_filter(bits: &[u8], version: u64, key: &SigningKey) -> (String, String) {
    use ed25519_dalek::Signer;
    let mut hasher = Sha256::new();
    hasher.update(bits);
    let hash = hasher.finalize();
    let sha256_hex = hex::encode(&hash);
    let mut msg = hash.to_vec();
    msg.extend_from_slice(&version.to_le_bytes());
    let sig = key.sign(&msg);
    (sha256_hex, hex::encode(sig.to_bytes()))
}

// ─── main ─────────────────────────────────────────────────────────────────────
fn main() {
    let args: Vec<String> = env::args().collect();

    
    let mut lists: Vec<(String, String)> = Vec::new(); // (label, path)
    let mut output = "initial_filter.bin".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--nsfw"     => { i += 1; if i < args.len() { lists.push(("NSFW".into(),     args[i].clone())); } }
           
           
            "--list"     => { i += 1; if i < args.len() { lists.push(("Custom".into(),   args[i].clone())); } }
            "--output"   => { i += 1; if i < args.len() { output = args[i].clone(); } }
            _ => {}
        }
        i += 1;
    }

    if lists.is_empty() {
        eprintln!("الاستخدام: build_filter --nsfw <ملف> [--list <ملف>] [--output <مسار>]");
        std::process::exit(1);
    }

    println!("══════════════════════════════════════════════");
    println!("   بناء الفلتر ");
    println!("══════════════════════════════════════════════");
    println!("  الفلتر: {:.2} MB  |  k={}  |  سعة: 2M دومين", BLOOM_M_BYTES as f64 / 1_048_576.0, BLOOM_K);
    println!();

    // ─── بناء الفلتر ──────────────────────────────────────────────────────────
    println!(" تحميل القوائم...");
    let mut builder = BloomBuilder::new();
    let t0 = Instant::now();
    let mut total_added = 0usize;

 for (label, path) in &lists {
    let (added, _) = load_list(path, &mut builder, label);
    total_added += added;
}
 
    let build_time = t0.elapsed();
    let fill_ratio = builder.count_set_bits() as f64 / BLOOM_M_BITS as f64 * 100.0;
    println!("   المجموع: {} دومين في {:.2?}", total_added, build_time);
    println!("   نسبة امتلاء الفلتر: {:.1}%\n", fill_ratio);

    // ─── توليد مفاتيح ─────────────────────────────────────────────────────────
    println!("② توليد مفاتيح Ed25519...");
    let signing_key   = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let pub_hex       = hex::encode(verifying_key.as_bytes());
    println!("   ✓ المفتاح العام: {}...\n", &pub_hex[..32]);

    // ─── توقيع الفلتر ─────────────────────────────────────────────────────────
    println!("③ توقيع الفلتر...");
    let version: u64 = 1;
    let (sha256_hex, sig_hex) = sign_filter(&builder.bits, version, &signing_key);
    println!("   ✓ SHA256:    {}...", &sha256_hex[..16]);
    println!("   ✓ Signature: {}...\n", &sig_hex[..16]);

    // ─── حفظ initial_filter.bin ───────────────────────────────────────────────
    println!("④ حفظ الملفات...");
    {
        let mut f = File::create(&output).expect("فشل إنشاء الملف");
        f.write_all(&version.to_le_bytes()).unwrap();
        f.write_all(&BLOOM_K.to_le_bytes()).unwrap();
        f.write_all(&(BLOOM_M_BYTES as u64).to_le_bytes()).unwrap();
        f.write_all(&hex::decode(&sha256_hex).unwrap()).unwrap();
        f.write_all(&hex::decode(&sig_hex).unwrap()).unwrap();
        f.write_all(&builder.bits).unwrap();
    }
    let file_size = fs::metadata(&output).unwrap().len();
    println!("   ✓ {} ({:.2} MB)", output, file_size as f64 / 1_048_576.0);

    // ─── حفظ filter_keys.json ─────────────────────────────────────────────────
    let keys_path = output.replace(".bin", "_keys.json");
    let pub_array: Vec<String> = verifying_key.as_bytes().iter()
        .map(|b| format!("0x{:02X}", b)).collect();
    let pub_chunks: Vec<String> = pub_array.chunks(8)
        .map(|c| format!("    {}", c.join(", "))).collect();

    let keys_json = format!(
        r#"{{
  "note":           "احتفظ بالمفتاح الخاص في مكان آمن — لا تشاركه",
  "version":        {},
  "public_key_hex": "{}",
  "private_key_hex":"{}",
  "sha256":         "{}",
  "signature":      "{}",
  "m_bytes":        {},
  "k":              {},
  "domains_added":  {},
  "fill_ratio_pct": {:.2},
  "rust_key_array": "[\n{}\n]"
}}"#,
        version, pub_hex,
        hex::encode(signing_key.to_bytes()),
        sha256_hex, sig_hex,
        BLOOM_M_BYTES, BLOOM_K,
        total_added, fill_ratio,
        pub_chunks.join(",\n")
    );
    fs::write(&keys_path, &keys_json).unwrap();
    println!("   ✓ {} (احتفظ بالمفتاح الخاص!)\n", keys_path);

    // ─── اختبار سريع ──────────────────────────────────────────────────────────
    println!("⑤ اختبار سريع...");
    let test_blocked = ["pornhub.com", "xvideos.com", "0-0.asia", "0000xxx.com"];
    let test_clean   = ["google.com", "github.com", "mozilla.org", "rust-lang.org"];
    let test_sub     = ["sub.pornhub.com", "video.xvideos.com"];

    print!("   دومينات يجب حجبها: ");
    for d in &test_blocked {
        let hit = builder.contains(d);
        print!("{}{} ", if hit { "✓" } else { "✗!" }, d);
    }
    println!();

    print!("   suffix matching:   ");
    for d in &test_sub {
        let hit = is_blocked(&builder, d);
        print!("{}{} ", if hit { "✓" } else { "✗!" }, d);
    }
    println!();

    print!("   مواقع نظيفة:       ");
    for d in &test_clean {
        let hit = builder.contains(d);
        print!("{}{} ", if !hit { "✓" } else { "FP!" }, d);
    }
    println!("\n");

    // ─── ملخص ─────────────────────────────────────────────────────────────────
    println!("══════════════════════════════════════════════");
    println!("  الفلتر جاهز للتضمين في libbrxon.a");
    println!("══════════════════════════════════════════════");
    println!("  الخطوة التالية في signing.rs:");
    println!("  استبدل EMBEDDED_PUBLIC_KEY بـ:");
    println!("{}", pub_chunks.join(",\n").replace("    ", "  "));
    println!("══════════════════════════════════════════════");
}
