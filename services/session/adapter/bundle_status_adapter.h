/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef AV_SESSION_BUNDLE_STATUS_ADAPTER_H
#define AV_SESSION_BUNDLE_STATUS_ADAPTER_H

#include <mutex>

#include "bundle_mgr_proxy.h"
#include "bundle_status_callback_host.h"
#include "bundle_resource_proxy.h"

namespace OHOS::AVSession {
class BundleStatusAdapter {
public:
    static BundleStatusAdapter& GetInstance();

    static void ReleaseInstance();

    BundleStatusAdapter();

    ~BundleStatusAdapter();
    
    void Init();

    bool GetBundleIcon(const std::string bundleName, const std::string abilityName, std::string& icon);

    bool SubscribeBundleStatusEvent(const std::string bundleName,
        const std::function<void(const std::string, const int32_t userId)>& callback, int32_t userId = DEFAULT_USER_ID);

    bool IsAudioPlayback(const std::string& bundleName, const std::string& abilityName);

    std::string GetBundleNameFromUid(const int32_t uid);

    int32_t GetUidFromBundleName(const std::string bundleName, const int32_t userId);

    __attribute__((no_sanitize("cfi"))) bool IsSupportPlayIntent(const std::string& bundleName,
        std::string& supportModule, std::string& profile);

private:
    void NotifyBundleRemoved(const std::string bundleName, const int32_t userId);

    bool CheckBundleSupport(std::string& profile);

    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy;
    sptr<AppExecFwk::IBundleResource> bundleResourceProxy;

    std::map<std::pair<std::string, int32_t>, std::function<void(const std::string, const int32_t)>>
        bundleStatusListeners_;

    const int32_t backgroundModeDemand = 2;

    const int32_t getBundleInfoWithHapModule = 0x00000002;

    const int32_t startUserId = 100;

    const std::string PLAY_MUSICLIST = "PlayMusicList";

    const std::string PLAY_AUDIO = "PlayAudio";

    std::recursive_mutex bundleMgrProxyLock_;

    static const int32_t DEFAULT_USER_ID = 100;

    static std::shared_ptr<BundleStatusAdapter> instance_;

    static std::recursive_mutex instanceLock_;
};

class BundleStatusCallbackImpl : public AppExecFwk::BundleStatusCallbackHost {
public:
    explicit BundleStatusCallbackImpl(const std::function<void(const std::string, const int32_t)>& callback,
        int32_t userId);
    ~BundleStatusCallbackImpl() override;
    void OnBundleStateChanged(const uint8_t installType, const int32_t resultCode,
        const std::string &resultMsg, const std::string &bundleName) override;
    void OnBundleAdded(const std::string &bundleName, const int userId) override {};
    void OnBundleUpdated(const std::string &bundleName, const int userId) override {};
    void OnBundleRemoved(const std::string &bundleName, const int userId) override {};
private:
    DISALLOW_COPY_AND_MOVE(BundleStatusCallbackImpl);
    std::function<void(const std::string, const int32_t userId)> callback_;
    int32_t userId_ = 0;
};
}
#endif // AV_SESSION_BUNDLE_STATUS_ADAPTER_H

