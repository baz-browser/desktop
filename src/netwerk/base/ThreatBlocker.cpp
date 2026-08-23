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
#include "mozilla/Sprintf.h"

namespace mozilla::net {

static LazyLogModule sBrxonLog("Brxon");
static LazyLogModule sBrxonAdsLog("BrxonAds");
static StaticRefPtr<ThreatBlocker> sSingleton;
static const uint32_t kAdsUpdateIntervalMs = 60 * 60 * 1000; //هذه الميزة ليست مثل ادوات الحجب المشهوره بل كتجربه للنسخه التجريبيه وحدة تاريخ التحديث لكل القوائم لكن بتقدر تعمل مثل UBOبعمل تاريخ صلاحيه لكل قائمه 
static const uint32_t kMaxAdsListBytes = 20 * 1024 * 1024; 

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
     "filters/filters.txt"},
    {"ubo_badware",
     "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/"
     "filters/badware.txt"},
    {"ubo_privacy",
     "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/"
     "filters/privacy.txt"},
    {"ubo_unbreak",
     "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/"
     "filters/unbreak.txt"},
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
    obs->AddObserver(this, "document-element-inserted", false);
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
    return NS_OK;
  }

  if (strcmp(aTopic, "document-element-inserted") == 0) {
    InjectCosmeticCss(aSubject);
    return NS_OK;
  }

  return NS_OK;
}

void ThreatBlocker::InjectCosmeticCss(nsISupports* aSubject) {
  if (!mHandle) return;

  nsCOMPtr<dom::Document> doc = do_QueryInterface(aSubject);
  if (!doc) return;

  nsIURI* docURI = doc->GetDocumentURI();
  if (!docURI) return;

  bool isHttp = false, isHttps = false;
  docURI->SchemeIs("http", &isHttp);
  docURI->SchemeIs("https", &isHttps);
  if (!isHttp && !isHttps) return;

  nsAutoCString spec;
  docURI->GetSpec(spec);

  size_t cssLen = 0;
  uint8_t* cssBytes = brxon_ads_cosmetic_css(mHandle, spec.get(), &cssLen);
  if (!cssBytes || cssLen == 0) {
    return;
  }

  nsAutoCString cssText(reinterpret_cast<const char*>(cssBytes), cssLen);
  brxon_free_css_buffer(cssBytes, cssLen);

  nsAutoCString encoded;
  for (size_t i = 0; i < cssText.Length(); ++i) {
    unsigned char c = static_cast<unsigned char>(cssText[i]);
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
      encoded.Append(static_cast<char>(c));
    } else {
      char buf[4];
      SprintfLiteral(buf, "%%%02X", c);
      encoded.Append(buf);
    }
  }

  nsAutoCString dataUri("data:text/css;charset=utf-8,");
  dataUri.Append(encoded);

  nsCOMPtr<nsIURI> sheetURI;
  if (NS_FAILED(NS_NewURI(getter_AddRefs(sheetURI), dataUri))) {
    return;
  }

  nsPIDOMWindowOuter* win = doc->GetWindow();
  if (!win) return;

  nsCOMPtr<nsIDOMWindowUtils> utils = do_GetInterface(win);
  if (utils) {
    utils->LoadSheetUsingURIString(dataUri, nsIDOMWindowUtils::AGENT_SHEET);
  }

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

  
  nsAutoCString sourceSpec;  
  RefPtr<dom::BrowsingContext> bc = aLoadInfo->GetBrowsingContext();
  if (bc) {
    RefPtr<dom::BrowsingContext> top = bc->Top();
    if (top && !top->IsDiscarded()) {
      if (dom::WindowContext* wc = top->GetCurrentWindowContext()) {
        nsIURI* docURI = wc->GetDocumentURI();
        if (docURI) {
          docURI->GetSpec(sourceSpec);
        }
      }
    }
  }

  if (sourceSpec.IsEmpty()) {
    nsCOMPtr<nsIPrincipal> triggering = aLoadInfo->TriggeringPrincipal();
    if (triggering && !triggering->IsSystemPrincipal()) {
      triggering->GetAsciiSpec(sourceSpec);
    }
  }


  BrxonDecision result = brxon_should_load(
      mHandle, contentType, uri.get(),
      sourceSpec.IsEmpty() ? nullptr : sourceSpec.get());
 
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

  static const uint32_t kMinAdsListBytes = 1000;
  if (aLength < kMinAdsListBytes || aLength > kMaxAdsListBytes) {
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
            ("BrxonAds: تجاهل '%s' — يبدو محتوى وليس قائمة فلاتر",
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
