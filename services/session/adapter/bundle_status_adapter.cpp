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
#include "want.h"
#include "want_params_wrapper.h"
#include "string_wrapper.h"
#include "array_wrapper.h"

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

    std::lock_guard bundleMgrProxyLockGuard(bundleMgrProxyLock_);
    SLOGI("get bundle manager proxy success");
    bundleMgrProxy = iface_cast<AppExecFwk::BundleMgrProxy>(remoteObject);
}

bool BundleStatusAdapter::SubscribeBundleStatusEvent(const std::string bundleName,
    const std::function<void(const std::string, const int32_t userId)>& callback, int32_t userId)
{
    SLOGI("Bundle status adapter subscribe bundle status event, bundleName=%{public}s, userId=%{public}d",
        bundleName.c_str(), userId);
    auto bundleStatusListener = bundleStatusListeners_.find(std::make_pair(bundleName, userId));
    if (bundleStatusListener != bundleStatusListeners_.end()) {
        SLOGE("bundle status has already register");
        return false;
    }
    auto bundleStatusCallback = [this](std::string bundleName, int32_t userId) {
        NotifyBundleRemoved(bundleName, userId);
    };
    sptr<BundleStatusCallbackImpl> bundleStatusCallbackImpl =
            new(std::nothrow) BundleStatusCallbackImpl(bundleStatusCallback, userId);
    if (bundleStatusCallbackImpl == nullptr) {
        SLOGE("no memory");
        return false;
    }
    std::lock_guard bundleMgrProxyLockGuard(bundleMgrProxyLock_);
    if (bundleMgrProxy == nullptr) {
        SLOGE("SubscribeBundleStatusEvent with proxy null!");
        Init();
        if (bundleMgrProxy == nullptr) {
            SLOGE("SubscribeBundleStatusEvent with proxy null after init!");
            return false;
        }
    }
    bundleStatusCallbackImpl->SetBundleName(bundleName);
    bundleStatusCallbackImpl->SetUserId(userId);
    if (bundleMgrProxy->RegisterBundleStatusCallback(bundleStatusCallbackImpl)) {
        bundleStatusListeners_.insert(std::make_pair(std::make_pair(bundleName, userId), callback));
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
        flag = static_cast<int32_t>(abilityInfo.backgroundModes) == backgroundModeDemand ? true : false;
    }
    return flag;
}

void BundleStatusAdapter::NotifyBundleRemoved(const std::string bundleName, const int32_t userId)
{
    auto bundleStatusListener = bundleStatusListeners_.find(std::make_pair(bundleName, userId));
    if (bundleStatusListener == bundleStatusListeners_.end()) {
        return;
    }
    bundleStatusListener->second(bundleName, userId);
    // BMS will keep callbackImpl for the bundleName & userId until avsession do ClearBundleStatusCallback
    SLOGI("notify bundle status callback without erase, bundleName=%{public}s, userId=%{public}d",
        bundleName.c_str(), userId);
}

std::string BundleStatusAdapter::GetBundleNameFromUid(const int32_t uid)
{
    std::string bundleName {""};
    if (bundleMgrProxy != nullptr) {
        bundleMgrProxy->GetNameForUid(uid, bundleName);
    }
    return bundleName;
}

bool BundleStatusAdapter::CheckBundleSupport(std::string& profile)
{
    nlohmann::json profileValues = nlohmann::json::parse(profile, nullptr, false);
    CHECK_AND_RETURN_RET_LOG(!profileValues.is_discarded(), false, "json object is null");
    CHECK_AND_RETURN_RET_LOG(profileValues.contains("insightIntents"), false, "json do not contains insightIntents");
    for (const auto& value : profileValues["insightIntents"]) {
        std::string insightName = value["intentName"];
        CHECK_AND_RETURN_RET_LOG(value.contains("uiAbility"), false, "json do not contains uiAbility");
        nlohmann::json abilityValue = value["uiAbility"];
        if (insightName != PLAY_MUSICLIST && insightName != PLAY_AUDIO) {
            continue;
        }
        if (abilityValue.is_discarded()) {
            SLOGE("uiability discarded=%{public}d", abilityValue.is_discarded());
            return false;
        }
        CHECK_AND_RETURN_RET_LOG(abilityValue.contains("executeMode"), false, "json do not contains executeMode");
        auto modeValues = abilityValue["executeMode"];
        if (modeValues.is_discarded()) {
            SLOGE("executeMode discarded=%{public}d", modeValues.is_discarded());
            return false;
        }
        auto mode = std::find(modeValues.begin(), modeValues.end(), "background");
        return (mode != modeValues.end());
    }
    return false;
}

__attribute__((no_sanitize("cfi"))) bool BundleStatusAdapter::IsSupportPlayIntent(const std::string& bundleName,
    std::string& supportModule, std::string& profile)
{
    if (bundleMgrProxy == nullptr) {
        return false;
    }
    AppExecFwk::BundleInfo bundleInfo;
    if (!bundleMgrProxy->GetBundleInfo(bundleName, getBundleInfoWithHapModule, bundleInfo, startUserId)) {
        SLOGE("GetBundleInfo=%{public}s fail", bundleName.c_str());
        return false;
    }
    bool isSupportIntent = false;
    for (std::string module : bundleInfo.moduleNames) {
        auto ret = bundleMgrProxy->GetJsonProfile(AppExecFwk::ProfileType::INTENT_PROFILE, bundleName, module,
            profile, startUserId);
        if (ret == 0) {
            SLOGI("GetJsonProfile success, profile=%{public}s", profile.c_str());
            isSupportIntent = true;
            supportModule = module;
            break;
        }
    }
    if (!isSupportIntent) {
        SLOGE("Bundle=%{public}s does not support insight", bundleName.c_str());
        return false;
    }
    return CheckBundleSupport(profile);
}

BundleStatusCallbackImpl::BundleStatusCallbackImpl(
    const std::function<void(const std::string, const int32_t userId)>& callback, int32_t userId)
{
    SLOGI("Create bundle status instance with userId %{public}d", userId);
    callback_ = callback;
    userId_ = userId;
}

BundleStatusCallbackImpl::~BundleStatusCallbackImpl()
{
    SLOGI("Destroy bundle status instance");
}

void BundleStatusCallbackImpl::OnBundleStateChanged(const uint8_t installType, const int32_t resultCode,
    const std::string &resultMsg, const std::string &bundleName)
{
    if (installType == static_cast<uint8_t>(AppExecFwk::InstallType::UNINSTALL_CALLBACK)) {
        callback_(bundleName, userId_);
    }
}
}
