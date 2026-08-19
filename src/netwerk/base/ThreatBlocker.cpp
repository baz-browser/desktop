/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
//ياناس والله C++صعبه  انا ندمت اني تعلمت رست قبلها ماتوقعت احتاجها من مره
#include "ThreatBlocker.h"
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
#include "mozilla/dom/BrowsingContext.h"
#include "nsIStreamLoader.h"
#include "nsIInputStream.h"
#include "mozilla/JSONWriter.h"

namespace mozilla::net {

static LazyLogModule sBrxonLog("Brxon");
static StaticRefPtr<ThreatBlocker> sSingleton;



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

  //بحذفه بس اخلص اختبار
  FetchAdsListTest();
}

void ThreatBlocker::Shutdown() {
  if (mHandle) {
    brxon_shutdown(mHandle);
    mHandle = nullptr;
    MOZ_LOG(sBrxonLog, LogLevel::Info, ("Brxon: تم الإيقاف"));
  }
}

ThreatBlocker::~ThreatBlocker() {
  Shutdown();
}



NS_IMETHODIMP
ThreatBlocker::Observe(nsISupports* aSubject,
                       const char*  aTopic,
                       const char16_t* aData)
{
  if (strcmp(aTopic, "xpcom-shutdown") == 0) {
    Shutdown();
  }
  return NS_OK;
}



NS_IMETHODIMP
ThreatBlocker::ShouldLoad(nsIURI* aURI,
                           nsILoadInfo* aLoadInfo,
                           int16_t* aDecision)
{
  *aDecision = nsIContentPolicy::ACCEPT;

  if (!mHandle || !brxon_is_ready(mHandle)) {
    return NS_OK;
  }

  
  nsAutoCString uri;
  nsresult rv = aURI->GetSpec(uri);
  if (NS_FAILED(rv)) return NS_OK;

 
  uint32_t contentType = static_cast<uint32_t>(aLoadInfo->InternalContentPolicyType());

  
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
        "ThreatBlocker::NavigateToBlockPage",
        [bc, blockPageURI]() {
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
ThreatBlocker::ShouldProcess(nsIURI*, nsILoadInfo*, int16_t* aDecision)
{
  *aDecision = nsIContentPolicy::ACCEPT;
  return NS_OK;
}



NS_IMPL_ISUPPORTS(AdsListFetchObserver, nsIStreamLoaderObserver)

NS_IMETHODIMP
AdsListFetchObserver::OnStreamComplete(nsIStreamLoader* aLoader,
                                        nsISupports* aContext,
                                        nsresult aStatus,
                                        uint32_t aLength,
                                        const uint8_t* aData) {
  static LazyLogModule sBrxonAdsLog("BrxonAds");

  if (NS_FAILED(aStatus)) {
    MOZ_LOG(sBrxonAdsLog, LogLevel::Warning,
            ("BrxonAds: فشل الجلب — status=0x%08x",
             static_cast<uint32_t>(aStatus)));
    return NS_OK;
  }

  nsDependentCSubstring rawText(reinterpret_cast<const char*>(aData), aLength);

  MOZ_LOG(sBrxonAdsLog, LogLevel::Info,
          ("BrxonAds: نجح الجلب — استلمنا %u بايت", aLength));

  
  nsCString objOutput;
  JSONStringRefWriteFunc writeFunc(objOutput);
  JSONWriter writer(writeFunc);

  writer.Start();
  writer.StringProperty("label", "easylist");
  writer.StringProperty("text", rawText);
  writer.End();

  nsAutoCString json("[");
  json.Append(objOutput);
  json.AppendLiteral("]");

  RefPtr<ThreatBlocker> tb = ThreatBlocker::GetSingleton();
  if (tb && tb->mHandle) {
    bool ok = brxon_ads_ingest_lists_json(
        tb->mHandle,
        reinterpret_cast<const uint8_t*>(json.get()),
        json.Length());
    MOZ_LOG(sBrxonAdsLog, LogLevel::Info,
            ("BrxonAds: brxon_ads_ingest_lists_json نتيجة=%s (حجم=%u بايت)",
             ok ? "نجاح" : "فشل", static_cast<uint32_t>(json.Length())));
  }

  return NS_OK;
}


void ThreatBlocker::FetchAdsListTest() {
  nsCOMPtr<nsIURI> testURI;
  nsresult rv = NS_NewURI(getter_AddRefs(testURI),
                           "https://easylist.to/easylist/easylist.txt"_ns);

  if (NS_FAILED(rv)) {
    return;
  }

  nsCOMPtr<nsIChannel> channel;
  rv = NS_NewChannel(getter_AddRefs(channel), testURI,
                      nsContentUtils::GetSystemPrincipal(),
                      nsILoadInfo::SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL,
                      nsIContentPolicy::TYPE_OTHER);
  if (NS_FAILED(rv)) {
    return;
  }

  nsCOMPtr<nsIStreamLoader> loader;
  RefPtr<AdsListFetchObserver> observer = new AdsListFetchObserver();
  rv = NS_NewStreamLoader(getter_AddRefs(loader), observer);
  if (NS_FAILED(rv)) {
    return;
  }

  channel->AsyncOpen(loader);
}

NS_IMPL_ISUPPORTS(ThreatBlocker, nsIContentPolicy, nsIObserver)

} 