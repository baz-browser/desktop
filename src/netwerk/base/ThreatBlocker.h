/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef ThreatBlocker_h
#define ThreatBlocker_h

#include "nsIContentPolicy.h"
#include "nsIObserver.h"
#include "mozilla/net/brxon.h"
#include "nsIStreamLoader.h"
#include "nsTArray.h"
#include "nsString.h"

namespace mozilla::net {

class AdsListCoordinator final {
 public:
  NS_INLINE_DECL_REFCOUNTING(AdsListCoordinator)

  explicit AdsListCoordinator(uint32_t aExpectedCount)
      : mPending(aExpectedCount) {}

  void OnListFetched(const nsACString& aJsonObjectOrEmpty);

 private:
  ~AdsListCoordinator() = default;
  void Finish();

  uint32_t mPending;
  nsTArray<nsCString> mResults;
};

class AdsListFetchObserver final : public nsIStreamLoaderObserver {
 public:
  NS_DECL_ISUPPORTS
  NS_DECL_NSISTREAMLOADEROBSERVER

  AdsListFetchObserver(const nsACString& aLabel,
                        AdsListCoordinator* aCoordinator)
      : mLabel(aLabel), mCoordinator(aCoordinator) {}

 private:
  ~AdsListFetchObserver() = default;

  nsCString mLabel;
  RefPtr<AdsListCoordinator> mCoordinator;
};

class ThreatBlocker final : public nsIContentPolicy
                          , public nsIObserver
{
public:
  NS_DECL_ISUPPORTS
  NS_DECL_NSICONTENTPOLICY
  NS_DECL_NSIOBSERVER

  static already_AddRefed<ThreatBlocker> GetSingleton();

  void Init();
  void Shutdown();
  void FetchAllAdsLists();

  friend class AdsListFetchObserver;
  friend class AdsListCoordinator;

private:
  ThreatBlocker() = default;
  ~ThreatBlocker();

  BrxonHandle mHandle = nullptr;
};

} 
#endif 
