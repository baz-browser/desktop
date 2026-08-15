/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

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

namespace mozilla::net {

static LazyLogModule sBrxonLog("Brxon");
static StaticRefPtr<ThreatBlocker> sSingleton;

// ── Singleton ────────────────────────────────────────────────────────────────

already_AddRefed<ThreatBlocker> ThreatBlocker::GetSingleton() {
  if (!sSingleton) {
    sSingleton = new ThreatBlocker();
    sSingleton->Init();
    ClearOnShutdown(&sSingleton);
  }
  return do_AddRef(sSingleton);
}

// ── Init / Shutdown ───────────────────────────────────────────────────────────

void ThreatBlocker::Init() {
  // سيرفر فارغ في النسخة الأولى — الفلتر مضمّن في libbrxon.a
  mHandle = brxon_init("");
  if (mHandle) {
    brxon_start(mHandle);
    MOZ_LOG(sBrxonLog, LogLevel::Info, ("Brxon: محرك الحجب نشط"));
  } else {
    MOZ_LOG(sBrxonLog, LogLevel::Error, ("Brxon: فشل التهيئة"));
  }

  // استمع لحدث الإغلاق
  nsCOMPtr<nsIObserverService> obs = services::GetObserverService();
  if (obs) {
    obs->AddObserver(this, "xpcom-shutdown", false);
  }
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

// ── nsIObserver ───────────────────────────────────────────────────────────────

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

// ── nsIContentPolicy::ShouldLoad ─────────────────────────────────────────────

NS_IMETHODIMP
ThreatBlocker::ShouldLoad(nsIURI* aURI,
                           nsILoadInfo* aLoadInfo,
                           int16_t* aDecision)
{
  *aDecision = nsIContentPolicy::ACCEPT;

  if (!mHandle || !brxon_is_ready(mHandle)) {
    return NS_OK;
  }

  // استخرج URI
  nsAutoCString uri;
  nsresult rv = aURI->GetSpec(uri);
  if (NS_FAILED(rv)) return NS_OK;

  // نوع الطلب
  uint32_t contentType = static_cast<uint32_t>(aLoadInfo->InternalContentPolicyType());

  // استشر Brxon
  BrxonDecision result = brxon_should_load(mHandle, contentType, uri.get());
  *aDecision = result.decision;

  if (result.show_block_page) {
    MOZ_LOG(sBrxonLog, LogLevel::Info,
            ("Brxon: حجب موقع → about:brxon-block [%s]", uri.get()));

    // نأخذ الرجوع بالرفض حتى تنكسر القناة الأصلية فورًا
    *aDecision = nsIContentPolicy::REJECT_REQUEST;

    // نبني رابط صفحة الحجب مع تمرير الرابط الأصلي كـ query parameter
    nsAutoCString blockURI("about:brxon-block?url=");
    blockURI.Append(uri);
    nsCOMPtr<nsIURI> blockPageURI;
    if (NS_FAILED(NS_NewURI(getter_AddRefs(blockPageURI), blockURI))) {
      return NS_OK;
    }

    // نجيب BrowsingContext الخاص بهذا التحميل — بدونه ما نقدر نوجّه المتصفح
    RefPtr<dom::BrowsingContext> bc = aLoadInfo->GetBrowsingContext();
    if (!bc || bc->IsDiscarded()) {
      MOZ_LOG(sBrxonLog, LogLevel::Warning,
              ("Brxon: ما فيه BrowsingContext صالح — تعذّر التوجيه"));
      return NS_OK;
    }

    // نوجّه فعليًا لصفحة الحجب — بشكل غير متزامن (Dispatch) عشان نتجنب
    // إعادة الدخول (reentrancy) بينما إحنا لسا جوا معالجة ShouldLoad نفسها.
    // هذا هو الفرق الجوهري عن SetResultPrincipalURI: هنا نطلب التنقّل
    // بأنفسنا صراحة، بدل ما نعتمد على جيكو يفهمها تلقائيًا (ما يصير).
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

NS_IMPL_ISUPPORTS(ThreatBlocker, nsIContentPolicy, nsIObserver)

} // namespace mozilla::net
