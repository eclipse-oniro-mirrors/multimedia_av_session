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
#include "cJSON.h"
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
    bundleResourceProxy = bundleMgrProxy->GetBundleResourceProxy();
}

bool BundleStatusAdapter::GetBundleIcon(const std::string bundleName, const std::string abilityName, std::string& icon)
{
    SLOGI("GetBundleIcon with bundleName:%{public}s", bundleName.c_str());
    
    if (bundleMgrProxy == nullptr || bundleResourceProxy == nullptr) {
        SLOGE("GetBundleIcon with bundleMgrProxy:%{public}d, bundleResourceProxy:%{public}d",
            static_cast<int>(bundleMgrProxy != nullptr), static_cast<int>(bundleResourceProxy != nullptr));
        return false;
    }
    AppExecFwk::BundleInfo bundleInfo;
    if (!bundleMgrProxy->GetBundleInfo(bundleName, getBundleInfoWithHapModule, bundleInfo, startUserId)) {
        SLOGE("GetBundleInfo of bundleName:%{public}s fail!", bundleName.c_str());
        return false;
    }
    std::vector<AppExecFwk::LauncherAbilityResourceInfo> LauncherAbilityResourceInfoList;
    ErrCode ret = bundleResourceProxy->GetLauncherAbilityResourceInfo(bundleName, 0, LauncherAbilityResourceInfoList);
    if (ret != ERR_OK) {
        SLOGE("GetLauncherAbilityResourceInfo of bundleName:%{public}s fail for errCode:%{public}d",
            bundleName.c_str(), ret);
        return false;
    }
    for (const auto& resourceInfo : LauncherAbilityResourceInfoList) {
        if (abilityName == resourceInfo.abilityName) {
            icon = resourceInfo.icon;
            break;
        }
    }
    if (icon.empty() && LauncherAbilityResourceInfoList.size() > 0) {
        icon = LauncherAbilityResourceInfoList[LauncherAbilityResourceInfoList.size() - 1].icon;
    }

    return true;
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

int32_t BundleStatusAdapter::GetUidFromBundleName(const std::string bundleName, const int32_t userId)
{
    int32_t uid = 0;
    if (bundleMgrProxy != nullptr) {
        uid = bundleMgrProxy->GetUidByBundleName(bundleName, userId);
    }
    return uid;
}

bool BundleStatusAdapter::CheckBundleSupport(std::string& profile)
{
    // check bundle support background mode & playmusiclist intent
    cJSON* profileValues = cJSON_Parse(profile.c_str());
    CHECK_AND_RETURN_RET_LOG(profileValues != nullptr, false, "parse profile fail");
    if (cJSON_IsInvalid(profileValues)) {
        SLOGE("CheckBundleSupport parse profile not valid json");
        cJSON_Delete(profileValues);
        return false;
    }
    cJSON* insightIntentsArray = cJSON_GetObjectItem(profileValues, "insightIntents");
    if (insightIntentsArray == nullptr || !cJSON_IsArray(insightIntentsArray)) {
        SLOGE("CheckBundleSupport json do not contain insightIntentsArray");
        cJSON_Delete(profileValues);
        return false;
    }
    cJSON* insightIntentsItem = nullptr;
    cJSON_ArrayForEach(insightIntentsItem, insightIntentsArray) {
        cJSON* intentNameItem = cJSON_GetObjectItem(insightIntentsItem, "intentName");
        if (intentNameItem == nullptr || !cJSON_IsString(intentNameItem)) {
            SLOGE("CheckBundleSupport json do not contain intentName");
            continue;
        }
        const char* insightName = intentNameItem->valuestring;
        if (insightName != nullptr &&
            strcmp(insightName, PLAY_MUSICLIST.c_str()) != 0 && strcmp(insightName, PLAY_AUDIO.c_str()) != 0) {
            continue;
        }

        cJSON* uiAbilityItem = cJSON_GetObjectItem(insightIntentsItem, "uiAbility");
        if (uiAbilityItem == nullptr) {
            SLOGE("CheckBundleSupport json do not contain uiAbility");
            cJSON_Delete(profileValues);
            return false;
        }
        cJSON* executeModeArray = cJSON_GetObjectItem(uiAbilityItem, "executeMode");
        if (executeModeArray == nullptr || !cJSON_IsArray(executeModeArray)) {
            SLOGE("CheckBundleSupport json do not contain executeMode");
            cJSON_Delete(profileValues);
            return false;
        }
        cJSON* modeItem = nullptr;
        cJSON_ArrayForEach(modeItem, executeModeArray) {
            if (cJSON_IsString(modeItem) && modeItem->valuestring != nullptr &&
                strcmp(modeItem->valuestring, "background") == 0) {
                cJSON_Delete(profileValues);
                return true;
            }
        }
    }
    cJSON_Delete(profileValues);
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
