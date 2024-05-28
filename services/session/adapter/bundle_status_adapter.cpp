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
    if (bundleMgrProxy == nullptr) {
        SLOGE("SubscribeBundleStatusEvent with proxy null!");
        Init();
        if (bundleMgrProxy == nullptr) {
            SLOGE("SubscribeBundleStatusEvent with proxy null after init!");
            return false;
        }
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
        flag = static_cast<int32_t>(abilityInfo.backgroundModes) == backgroundModeDemand ? true : false;
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
    SLOGI("erase bundle status callback, bundleName=%{public}s", bundleName.c_str());
    bundleStatusListeners_.erase(bundleName);
}

std::string BundleStatusAdapter::GetBundleNameFromUid(const int32_t uid)
{
    std::string bundleName {""};
    if (bundleMgrProxy != nullptr) {
        bundleMgrProxy->GetNameForUid(uid, bundleName);
    }
    return bundleName;
}

bool BundleStatusAdapter::CheckBundleSurpport(std::string& profile)
{
    // check bundle support background mode & playmusiclist intent
    nlohmann::json profileValues = nlohmann::json::parse(profile, nullptr, false);
    CHECK_AND_RETURN_RET_LOG(!profileValues.is_discarded(), false, "json object is null");
    for (const auto& value : profileValues["insightIntents"]) {
        std::string insightName = value["intentName"];
        if (!value.contains("uiAbility")) {
            SLOGE("value contains is null");
            return false;
        }
        nlohmann::json abilityValue = value["uiAbility"];
        if (insightName != PLAY_MUSICLIST) {
            continue;
        }
        if (abilityValue.is_discarded()) {
            SLOGE("PLAY_MUSICLIST uiability discarded=%{public}d", abilityValue.is_discarded());
            return false;
        }
        if (!abilityValue.contains("executeMode")) {
            SLOGE("abilityValue contains is null");
            return false;
        }
        auto modeValues = abilityValue["executeMode"];
        if (modeValues.is_discarded()) {
            SLOGE("PLAY_MUSICLIST executeMode discarded=%{public}d", modeValues.is_discarded());
            return false;
        }
        auto mode = std::find(modeValues.begin(), modeValues.end(), "background");
        return (mode != modeValues.end());
    }
    return false;
}

bool BundleStatusAdapter::IsSupportPlayIntent(const std::string& bundleName, std::string& supportModule,
                                              std::string& profile)
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
    reutrn CheckBundleSurpport(profile);
}

bool BundleStatusAdapter::GetPlayIntentParam(const std::string& bundleName, const std::string& assetId,
                                             AppExecFwk::InsightIntentExecuteParam &executeParam)
{
    if (bundleMgrProxy == nullptr) {
        return false;
    }
    std::string supportModule;
    std::string profile;
    if (!IsSupportPlayIntent(bundleName, supportModule, profile)) {
        SLOGE("bundle=%{public}s does not support play insights", bundleName.c_str());
        return false;
    }
    SLOGD("GetJsonProfile profile=%{public}s", profile.c_str());
    nlohmann::json profileValues = nlohmann::json::parse(profile, nullptr, false);
    CHECK_AND_RETURN_RET_LOG(!profileValues.is_discarded(), false, "json object is null");
    for (const auto& value : profileValues["insightIntents"]) {
        std::string insightName = value["intentName"];
        nlohmann::json abilityValue = value["uiAbility"];
        SLOGD(" insightName=%{public}s", insightName.c_str());
        if (insightName == PLAY_MUSICLIST) {
            if (!value.contains("uiAbility") || abilityValue.is_discarded()) {
                SLOGE("PLAY_MUSICLIST uiability discarded=%{public}d", abilityValue.is_discarded());
                return false;
            }
            executeParam.bundleName_ = bundleName;
            executeParam.moduleName_ = supportModule;
            executeParam.abilityName_ = abilityValue["ability"];
            executeParam.insightIntentName_ = insightName;
            executeParam.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_BACKGROUND;
            // construct items array
            AppExecFwk::WantParams innerParams;
            innerParams.SetParam("entityId", OHOS::AAFwk::String::Box(assetId));
            sptr<OHOS::AAFwk::IArray> array = new (std::nothrow) OHOS::AAFwk::Array(1, OHOS::AAFwk::g_IID_IWantParams);
            array->Set(0, OHOS::AAFwk::WantParamWrapper::Box(innerParams));
            std::shared_ptr<AppExecFwk::WantParams> wantParam = std::make_shared<AppExecFwk::WantParams>();
            wantParam->SetParam("items", array);
            executeParam.insightIntentParam_ = wantParam;
            return true;
        }
    }

    return false;
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