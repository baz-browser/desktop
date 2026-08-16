/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef ThreatBlocker_h
#define ThreatBlocker_h

#include "nsIContentPolicy.h"
#include "nsIObserver.h"
#include "mozilla/net/brxon.h"

namespace mozilla::net {

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

private:
  ThreatBlocker() = default;
  ~ThreatBlocker();

  BrxonHandle mHandle = nullptr;
};

} // namespace mozilla::net
#endif // ThreatBlocker_h
