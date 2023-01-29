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

#include "bundle_status_adapter.h"

#include "avsession_log.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS::AVSession {
BundleStatusAdapter::BundleStatusAdapter()
{
    SLOGI("construct");
}

BundleStatusAdapter::~BundleStatusAdapter()
{
    SLOGI("destroy");
}

BundleStatusAdapter& BundleStatusAdapter::GetInstance()
{
    static BundleStatusAdapter bundleStatusAdapter;
    return bundleStatusAdapter;
}

void BundleStatusAdapter::Init()
{
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        SLOGI("fail to get system ability mgr");
        return;
    }

    auto remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        SLOGI("fail to get bundle manager proxy");
        return;
    }

    SLOGI("get bundle manager proxy success");
    bundleMgrProxy = iface_cast<AppExecFwk::BundleMgrProxy>(remoteObject);
}

bool BundleStatusAdapter::SubscribeBundleStatusEvent(const std::string bundleName,
    const std::function<void(const std::string)>& callback)
{
    SLOGI("Bundle status adapter subscribe bundle status event, bundleName=%{public}s", bundleName.c_str());
    auto bundleStatusCallback = [this](std::string bundleName) {
        NotifyBundleRemoved(bundleName);
    };
    sptr<BundleStatusCallbackImpl> bundleStatusCallbackImpl =
            new(std::nothrow) BundleStatusCallbackImpl(bundleStatusCallback);
    if (bundleStatusCallbackImpl == nullptr) {
        SLOGE("no memory");
        return false;
    }
    bundleStatusCallbackImpl->SetBundleName(bundleName);
    if (bundleMgrProxy->RegisterBundleStatusCallback(bundleStatusCallbackImpl)) {
        bundleStatusListeners_.insert(std::pair<std::string, std::function<void(const std::string)>>(bundleName,
            callback));
        return true;
    } else {
        SLOGE("Register bundle status callback failed, bundleName=%{public}s", bundleName.c_str());
        return false;
    }
}

bool BundleStatusAdapter::IsAudioPlayback(const std::string& bundleName, const std::string& abilityName)
{
    SLOGI("Estimate bundle audio playback status, bundleName=%{public}s", bundleName.c_str());
    AppExecFwk::AbilityInfo abilityInfo;
    bool flag = false;
    if (bundleMgrProxy->GetAbilityInfo(bundleName, abilityName, abilityInfo)) {
        flag = static_cast<int32_t>(abilityInfo.backgroundModes) == BACKGROUND_MODE_DEMAND ? true : false;
    }
    return flag;
}

void BundleStatusAdapter::NotifyBundleRemoved(const std::string bundleName)
{
    auto bundleStatusListener = bundleStatusListeners_.find(bundleName);
    if (bundleStatusListener == bundleStatusListeners_.end()) {
        return;
    }
    bundleStatusListener->second(bundleName);
}

BundleStatusCallbackImpl::BundleStatusCallbackImpl(const std::function<void(const std::string)>& callback)
{
    SLOGI("Create bundle status instance");
    callback_ = callback;
}
   
BundleStatusCallbackImpl::~BundleStatusCallbackImpl()
{
    SLOGI("Destroy bundle status instance");
}

void BundleStatusCallbackImpl::OnBundleStateChanged(const uint8_t installType, const int32_t resultCode,
    const std::string &resultMsg, const std::string &bundleName)
{
    if (installType == static_cast<uint8_t>(AppExecFwk::InstallType::UNINSTALL_CALLBACK)) {
        callback_(bundleName);
    }
}
}