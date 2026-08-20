/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
//سي++صعبه كثير ماتوقعت اني رح احتاجها فكرت رست بتكفي
#include "ThreatBlocker.h"
#include "mozilla/JSONStringWriteFuncs.h"
#include "nsIURI.h"
#include "nsILoadInfo.h"
#include "nsString.h"
#include <cstring>
#include "nsServiceManagerUtils.h"
#include "nsIObserverService.h"
#include "mozilla/Services.h"
#include "mozilla/Logging.h"
#include "mozilla/ClearOnShutdown.h"
#include "mozilla/StaticPtr.h"
#include "nsNetUtil.h"
#include "nsThreadUtils.h"
#include "nsContentUtils.h"
#include "nsDocShellLoadState.h"
#include "nsDocShellLoadTypes.h"
#include "mozilla/dom/BrowsingContext.h"
#include "nsIStreamLoader.h"
#include "nsIInputStream.h"
#include "mozilla/JSONWriter.h"

namespace mozilla::net {

static LazyLogModule sBrxonLog("Brxon");
static LazyLogModule sBrxonAdsLog("BrxonAds");
static StaticRefPtr<ThreatBlocker> sSingleton;

static const uint32_t kMaxAdsListBytes = 20 * 1024 * 1024; // 20MB

struct AdsListSpec {
  const char* label;
  const char* url;
};

static const AdsListSpec kAdsLists[] = {
    {"easylist", "https://easylist.to/easylist/easylist.txt"},
    {"easyprivacy", "https://easylist.to/easylist/easyprivacy.txt"},
    {"peter_lowe",
     "https://pgl.yoyo.org/adservers/serverlist.php?"
     "hostformat=adblockplus&mimetype=plaintext"},
    {"ubo_filters",
     "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/"
     "filters/filters.min.txt"},
    {"ubo_badware",
     "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/"
     "filters/badware.min.txt"},
    {"ubo_privacy",
     "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/"
     "filters/privacy.min.txt"},
    {"ubo_unbreak",
     "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/"
     "filters/unbreak.min.txt"},
};

static const uint32_t kAdsListCount =
    sizeof(kAdsLists) / sizeof(kAdsLists[0]);

class NsCStringJSONWriteFunc final : public JSONWriteFunc {
 public:
  explicit NsCStringJSONWriteFunc(nsACString& aBuffer) : mBuffer(aBuffer) {}
  void Write(const Span<const char>& aStr) override {
    mBuffer.Append(aStr.Elements(), aStr.Length());
  }

 private:
  nsACString& mBuffer;
};

already_AddRefed<ThreatBlocker> ThreatBlocker::GetSingleton() {
  if (!sSingleton) {
    sSingleton = new ThreatBlocker();
    sSingleton->Init();
    ClearOnShutdown(&sSingleton);
  }
  return do_AddRef(sSingleton);
}

void ThreatBlocker::Init() {
  mHandle = brxon_init("");
  if (mHandle) {
    brxon_start(mHandle);
    MOZ_LOG(sBrxonLog, LogLevel::Info, ("Brxon: محرك الحجب نشط"));
  } else {
    MOZ_LOG(sBrxonLog, LogLevel::Error, ("Brxon: فشل التهيئة"));
  }

  nsCOMPtr<nsIObserverService> obs = services::GetObserverService();
  if (obs) {
    obs->AddObserver(this, "xpcom-shutdown", false);
  }

  FetchAllAdsLists();
}

void ThreatBlocker::Shutdown() {
  if (mHandle) {
    brxon_shutdown(mHandle);
    mHandle = nullptr;
    MOZ_LOG(sBrxonLog, LogLevel::Info, ("Brxon: تم الإيقاف"));
  }
}

ThreatBlocker::~ThreatBlocker() { Shutdown(); }

NS_IMETHODIMP
ThreatBlocker::Observe(nsISupports* aSubject, const char* aTopic,
                        const char16_t* aData) {
  if (strcmp(aTopic, "xpcom-shutdown") == 0) {
    Shutdown();
  }
  return NS_OK;
}

NS_IMETHODIMP
ThreatBlocker::ShouldLoad(nsIURI* aURI, nsILoadInfo* aLoadInfo,
                           int16_t* aDecision) {
  *aDecision = nsIContentPolicy::ACCEPT;

  if (!mHandle) {
    return NS_OK;
  }

  nsAutoCString uri;
  nsresult rv = aURI->GetSpec(uri);
  if (NS_FAILED(rv)) return NS_OK;

  uint32_t contentType =
      static_cast<uint32_t>(aLoadInfo->InternalContentPolicyType());

  BrxonDecision result = brxon_should_load(mHandle, contentType, uri.get());
  *aDecision = result.decision;

  if (result.show_block_page) {
    MOZ_LOG(sBrxonLog, LogLevel::Info,
            ("Brxon: حجب موقع → about:brxon-block [%s]", uri.get()));

    *aDecision = nsIContentPolicy::REJECT_REQUEST;

    nsAutoCString blockURI("about:brxon-block?url=");
    blockURI.Append(uri);
    nsCOMPtr<nsIURI> blockPageURI;
    if (NS_FAILED(NS_NewURI(getter_AddRefs(blockPageURI), blockURI))) {
      return NS_OK;
    }

    RefPtr<dom::BrowsingContext> bc = aLoadInfo->GetBrowsingContext();
    if (!bc || bc->IsDiscarded()) {
      MOZ_LOG(sBrxonLog, LogLevel::Warning,
              ("Brxon: ما فيه BrowsingContext صالح — تعذّر التوجيه"));
      return NS_OK;
    }

    nsCOMPtr<nsIRunnable> navigateRunnable = NS_NewRunnableFunction(
        "ThreatBlocker::NavigateToBlockPage", [bc, blockPageURI]() {
          if (!bc || bc->IsDiscarded()) {
            return;
          }
          RefPtr<nsDocShellLoadState> loadState =
              new nsDocShellLoadState(blockPageURI);
          loadState->SetTriggeringPrincipal(
              nsContentUtils::GetSystemPrincipal());
          loadState->SetLoadType(LOAD_NORMAL_REPLACE);
          loadState->SetFirstParty(true);
          bc->LoadURI(loadState, /* aSetNavigating */ true);
        });
    NS_DispatchToMainThread(navigateRunnable.forget());
  }

  return NS_OK;
}

NS_IMETHODIMP
ThreatBlocker::ShouldProcess(nsIURI*, nsILoadInfo*, int16_t* aDecision) {
  *aDecision = nsIContentPolicy::ACCEPT;
  return NS_OK;
}

// ── AdsListCoordinator ─────────────────────────────────────────────────────

void AdsListCoordinator::OnListFetched(const nsACString& aJsonObjectOrEmpty) {
  if (!aJsonObjectOrEmpty.IsEmpty()) {
    mResults.AppendElement(aJsonObjectOrEmpty);
  }

  MOZ_ASSERT(mPending > 0);
  mPending--;

  if (mPending == 0) {
    Finish();
  }
}

void AdsListCoordinator::Finish() {
  MOZ_LOG(sBrxonAdsLog, LogLevel::Info,
          ("BrxonAds: اكتمل جلب كل القوائم — %u/%u نجحت",
           static_cast<uint32_t>(mResults.Length()), kAdsListCount));

  if (mResults.IsEmpty()) {
    MOZ_LOG(sBrxonAdsLog, LogLevel::Warning,
            ("BrxonAds: لا توجد قوائم صالحة — تجاهل التحديث"));
    return;
  }

  nsAutoCString json("[");
  for (uint32_t i = 0; i < mResults.Length(); ++i) {
    if (i > 0) json.AppendLiteral(",");
    json.Append(mResults[i]);
  }
  json.AppendLiteral("]");

  RefPtr<ThreatBlocker> tb = ThreatBlocker::GetSingleton();
  if (tb && tb->mHandle) {
    bool ok = brxon_ads_ingest_lists_json(
        tb->mHandle, reinterpret_cast<const uint8_t*>(json.get()),
        json.Length());
    MOZ_LOG(sBrxonAdsLog, LogLevel::Info,
            ("BrxonAds: brxon_ads_ingest_lists_json نتيجة=%s (حجم=%u بايت)",
             ok ? "نجاح" : "فشل", static_cast<uint32_t>(json.Length())));
  }
}

// ── AdsListFetchObserver ────────────────────────────────────────────────────

NS_IMPL_ISUPPORTS(AdsListFetchObserver, nsIStreamLoaderObserver)

NS_IMETHODIMP
AdsListFetchObserver::OnStreamComplete(nsIStreamLoader* aLoader,
                                        nsISupports* aContext,
                                        nsresult aStatus, uint32_t aLength,
                                        const uint8_t* aData) {
  if (NS_FAILED(aStatus)) {
    MOZ_LOG(sBrxonAdsLog, LogLevel::Warning,
            ("BrxonAds: فشل جلب '%s' — status=0x%08x", mLabel.get(),
             static_cast<uint32_t>(aStatus)));
    mCoordinator->OnListFetched(""_ns);
    return NS_OK;
  }

  if (aLength == 0 || aLength > kMaxAdsListBytes) {
    MOZ_LOG(sBrxonAdsLog, LogLevel::Warning,
            ("BrxonAds: تجاهل '%s' — حجم غير صالح (%u بايت)", mLabel.get(),
             aLength));
    mCoordinator->OnListFetched(""_ns);
    return NS_OK;
  }

  nsDependentCSubstring rawText(reinterpret_cast<const char*>(aData),
                                 aLength);

  nsAutoCString trimmed(rawText);
  trimmed.Trim(" \t\r\n");
  if (trimmed.Length() >= 1 && trimmed.CharAt(0) == '<') {
    MOZ_LOG(sBrxonAdsLog, LogLevel::Warning,
            ("BrxonAds: تجاهل '%s' — يبدو محتوى HTML وليس قائمة فلاتر",
             mLabel.get()));
    mCoordinator->OnListFetched(""_ns);
    return NS_OK;
  }

  MOZ_LOG(sBrxonAdsLog, LogLevel::Info,
          ("BrxonAds: نجح جلب '%s' — %u بايت", mLabel.get(), aLength));

  nsCString objOutput;
  NsCStringJSONWriteFunc writeFunc(objOutput);
  JSONWriter writer(writeFunc);

  writer.Start();
  writer.StringProperty("label", mLabel);
  writer.StringProperty("text", rawText);
  writer.End();

  mCoordinator->OnListFetched(objOutput);
  return NS_OK;
}

// ── ThreatBlocker::FetchAllAdsLists ─────────────────────────────────────────

void ThreatBlocker::FetchAllAdsLists() {
  RefPtr<AdsListCoordinator> coordinator =
      new AdsListCoordinator(kAdsListCount);

  for (uint32_t i = 0; i < kAdsListCount; ++i) {
    nsCOMPtr<nsIURI> uri;
    nsresult rv =
        NS_NewURI(getter_AddRefs(uri), nsDependentCString(kAdsLists[i].url));
    if (NS_FAILED(rv)) {
      coordinator->OnListFetched(""_ns);
      continue;
    }

    nsCOMPtr<nsIChannel> channel;
    rv = NS_NewChannel(getter_AddRefs(channel), uri,
                        nsContentUtils::GetSystemPrincipal(),
                        nsILoadInfo::SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL,
                        nsIContentPolicy::TYPE_OTHER);
    if (NS_FAILED(rv)) {
      coordinator->OnListFetched(""_ns);
      continue;
    }

    nsCOMPtr<nsIStreamLoader> loader;
    RefPtr<AdsListFetchObserver> observer = new AdsListFetchObserver(
        nsDependentCString(kAdsLists[i].label), coordinator);
    rv = NS_NewStreamLoader(getter_AddRefs(loader), observer);
    if (NS_FAILED(rv)) {
      coordinator->OnListFetched(""_ns);
      continue;
    }

    channel->AsyncOpen(loader);
  }
}

NS_IMPL_ISUPPORTS(ThreatBlocker, nsIContentPolicy, nsIObserver)

} // namespace mozilla::net
