/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_net_brxon_h
#define mozilla_net_brxon_h

/* Generated with cbindgen:0.29.4 */

/* DO NOT MODIFY THIS MANUALLY! This file was generated using cbindgen. */

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

namespace mozilla {
namespace net {

constexpr static const uint64_t FIRST_FETCH_DELAY_SECS = 60;

constexpr static const uint64_t PERIODIC_CHECK_INTERVAL_SECS = ((6 * 60) * 60);

constexpr static const uint64_t LIST_EXPIRY_SECS = ((24 * 60) * 60);

constexpr static const uint64_t EMERGENCY_THRESHOLD_SECS = ((48 * 60) * 60);

constexpr static const uintptr_t BLOOM_M_BYTES = 4792530;

constexpr static const uintptr_t BLOOM_M_BITS = (BLOOM_M_BYTES * 8);

constexpr static const uint32_t BLOOM_K = 13;

constexpr static const uint32_t TYPE_OTHER = 1;

constexpr static const uint32_t TYPE_SCRIPT = 2;

constexpr static const uint32_t TYPE_IMAGE = 3;

constexpr static const uint32_t TYPE_STYLESHEET = 4;

constexpr static const uint32_t TYPE_OBJECT = 5;

constexpr static const uint32_t TYPE_DOCUMENT = 6;

constexpr static const uint32_t TYPE_SUBDOCUMENT = 7;

constexpr static const uint32_t TYPE_PING = 10;

constexpr static const uint32_t TYPE_XMLHTTPREQUEST = 11;

constexpr static const uint32_t TYPE_OBJECT_SUBREQUEST = 12;

constexpr static const uint32_t TYPE_FONT = 14;

constexpr static const uint32_t TYPE_MEDIA = 15;

constexpr static const uint32_t TYPE_WEBSOCKET = 19;

constexpr static const uint32_t TYPE_CSP_REPORT = 20;

constexpr static const uint32_t TYPE_FETCH = 22;

constexpr static const uint32_t TYPE_IMAGESET = 23;

constexpr static const uint32_t TYPE_WEB_MANIFEST = 25;

constexpr static const uint32_t TYPE_SPECULATIVE = 26;

constexpr static const uint32_t TYPE_WEB_TRANSPORT = 31;

constexpr static const int16_t ACCEPT = 1;

constexpr static const int16_t REJECT_REQUEST = -1;

constexpr static const int16_t REJECT_TYPE = -2;

struct BrxonEngine;

using BrxonHandle = BrxonEngine*;

struct BrxonDecision {
  int16_t decision;
  bool show_block_page;
};

/// المفتاح العام Ed25519 (32 بايت) مضمّن في وقت البناء.
///
/// ⚠️  هذه قيمة placeholder — يجب استبدالها بالمفتاح الحقيقي
///     الذي يُنشأ على السيرفر قبل البناء النهائي.
constexpr static const uint8_t EMBEDDED_PUBLIC_KEY[32] = { 181, 168, 132, 115, 158, 104, 240, 91, 12, 247, 18, 143, 13, 226, 36, 200, 73, 246, 134, 68, 231, 138, 151, 150, 54, 17, 20, 83, 9, 241, 6, 199, };

extern "C" {

BrxonHandle brxon_init(const char *server_base);

void brxon_start(BrxonHandle handle);

BrxonDecision brxon_should_load(BrxonHandle handle, uint32_t content_type, const char *uri);

void brxon_shutdown(BrxonHandle handle);

bool brxon_is_ready(BrxonHandle handle);

uint64_t brxon_filter_version(BrxonHandle handle);

bool brxon_ingest_full_filter_json(BrxonHandle handle,
                                   const uint8_t *json_bytes,
                                   uintptr_t json_len);

void brxon_ingest_sse_chunk(BrxonHandle handle, const uint8_t *chunk, uintptr_t chunk_len);

bool brxon_ads_ingest_lists_json(BrxonHandle handle, const uint8_t *json_bytes, uintptr_t json_len);

bool brxon_ads_is_ready(BrxonHandle handle);

bool brxon_ads_needs_update(BrxonHandle handle);

}  // extern "C"

}  // namespace net
}  // namespace mozilla

#endif  // mozilla_net_brxon_h
