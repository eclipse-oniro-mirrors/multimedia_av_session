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

#include "bundle_mgr_proxy.h"
#include "bundle_status_callback_host.h"

namespace OHOS::AVSession {
class BundleStatusAdapter {
public:
    static BundleStatusAdapter& GetInstance();
    
    ~BundleStatusAdapter();

    void Init();

    bool SubscribeBundleStatusEvent(const std::string bundleName,
        const std::function<void(const std::string)>& callback);

    bool IsAudioPlayback(const std::string& bundleName, const std::string& abilityName);

    std::string GetBundleNameFromUid(const int32_t uid);

private:
    BundleStatusAdapter();

    void NotifyBundleRemoved(const std::string bundleName);

    sptr<AppExecFwk::BundleMgrProxy> bundleMgrProxy;

    std::map<std::string, std::function<void(const std::string)>> bundleStatusListeners_;

    const int32_t BACKGROUND_MODE_DEMAND = 2;
};

class BundleStatusCallbackImpl : public AppExecFwk::BundleStatusCallbackHost {
public:
    explicit BundleStatusCallbackImpl(const std::function<void(const std::string)>& callback);
    ~BundleStatusCallbackImpl() override;
    void OnBundleStateChanged(const uint8_t installType, const int32_t resultCode,
        const std::string &resultMsg, const std::string &bundleName) override;
    void OnBundleAdded(const std::string &bundleName, const int userId) override {};
    void OnBundleUpdated(const std::string &bundleName, const int userId) override {};
    void OnBundleRemoved(const std::string &bundleName, const int userId) override {};
private:
    DISALLOW_COPY_AND_MOVE(BundleStatusCallbackImpl);
    std::function<void(std::string)> callback_;
};
}
#endif // AV_SESSION_BUNDLE_STATUS_ADAPTER_H

