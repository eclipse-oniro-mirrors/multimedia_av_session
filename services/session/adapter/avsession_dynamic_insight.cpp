/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ability_manager_interface.h"
#include "ability_manager_client.h"
#include "bundle_mgr_proxy.h"
#include "iremote_stub.h"
#include "iservice_registry.h"
#include "array_wrapper.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"
#include "system_ability_definition.h"

#include "avsession_dynamic_insight.h"
#include "avsession_errors.h"
#include "avsession_log.h"

namespace OHOS::AVSession {

InsightAdapter::InsightAdapter()
{
    SLOGI("construct");
}

InsightAdapter::~InsightAdapter()
{
    SLOGI("destroy");
}

InsightAdapter& InsightAdapter::GetInsightAdapterInstance()
{
    static InsightAdapter insightAdapter;
    return insightAdapter;
}

bool InsightAdapter::CheckBundleSupport(std::string& profile)
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

__attribute__((no_sanitize("cfi"))) bool InsightAdapter::IsSupportPlayIntent(const std::string& bundleName,
    std::string& supportModule, std::string& profile)
{
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        SLOGI("fail to get system ability mgr");
        return false;
    }

    auto remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        SLOGI("fail to get bundle manager proxy");
        return false;
    }

    sptr<AppExecFwk::BundleMgrProxy> bundleMgrProxy = iface_cast<AppExecFwk::BundleMgrProxy>(remoteObject);
    if (bundleMgrProxy == nullptr) {
        return false;
    }
    SLOGI("get bundle manager proxy success");

    AppExecFwk::BundleInfo bundleInfo;
    if (!bundleMgrProxy->GetBundleInfo(bundleName, getBundleInfoWithHapModule, bundleInfo, startUserId)) {
        SLOGE("GetBundleInfo=%{public}s fail", bundleName.c_str());
        return false;
    }
    bool isSupportIntent = false;
    for (const std::string& module : bundleInfo.moduleNames) {
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

bool InsightAdapter::GetPlayIntentParam(const std::string& bundleName, const std::string& assetId,
    AppExecFwk::InsightIntentExecuteParam &executeParam)
{
    std::string supportModule;
    std::string profile;
    if (!IsSupportPlayIntent(bundleName, supportModule, profile)) {
        SLOGE("bundle=%{public}s does not support play insights", bundleName.c_str());
        return false;
    }
    SLOGD("GetJsonProfile profile=%{public}s", profile.c_str());
    nlohmann::json profileValues = nlohmann::json::parse(profile, nullptr, false);
    CHECK_AND_RETURN_RET_LOG(!profileValues.is_discarded(), false, "json object is null");
    CHECK_AND_RETURN_RET_LOG(profileValues.contains("insightIntents"), false, "json do not contains insightIntents");
    auto res = false;
    for (const auto& value : profileValues["insightIntents"]) {
        std::string insightName = value["intentName"];
        nlohmann::json abilityValue = value["uiAbility"];
        SLOGD(" insightName=%{public}s", insightName.c_str());
        if (insightName != PLAY_MUSICLIST && insightName != PLAY_AUDIO) {
            continue;
        }
        if (!value.contains("uiAbility") || abilityValue.is_discarded()) {
            SLOGE("uiability discarded=%{public}d", abilityValue.is_discarded());
            continue;
        }
        SLOGD("insightName=%{public}s", insightName.c_str());
        executeParam.bundleName_ = bundleName;
        executeParam.moduleName_ = supportModule;
        executeParam.abilityName_ = abilityValue["ability"];
        executeParam.insightIntentName_ = insightName;
        executeParam.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_BACKGROUND;
        std::shared_ptr<AppExecFwk::WantParams> wantParam = std::make_shared<AppExecFwk::WantParams>();
        if (insightName == PLAY_MUSICLIST) {
            // construct items array
            AppExecFwk::WantParams innerParams;
            innerParams.SetParam("entityId", OHOS::AAFwk::String::Box(assetId));
            sptr<OHOS::AAFwk::IArray> array = new (std::nothrow) OHOS::AAFwk::Array(1, OHOS::AAFwk::g_IID_IWantParams);
            array->Set(0, OHOS::AAFwk::WantParamWrapper::Box(innerParams));
            wantParam->SetParam("items", array);
            res = true;
        }
        if (insightName == PLAY_AUDIO) {
            wantParam->SetParam("entityId", AppExecFwk::WantParams::GetInterfaceByType(interfaceType, assetId));
            res = true;
        }
        executeParam.insightIntentParam_ = wantParam;
    }
    return res;
}

int32_t InsightAdapter::StartAVPlayback(AppExecFwk::InsightIntentExecuteParam &executeParam)
{
    SLOGI("bundleName=%{public}s abilityName=%{public}s moduleName=%{public}s IntentName=%{public}s",
        executeParam.bundleName_.c_str(), executeParam.abilityName_.c_str(),
        executeParam.moduleName_.c_str(), executeParam.insightIntentName_.c_str());

    sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemManager == nullptr) {
        SLOGE("Fail to get registry");
        return AVSESSION_ERROR;
    }
    sptr<IRemoteObject> remote = systemManager->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
    if (remote == nullptr) {
        SLOGE("Fail to connect ability manager service");
        return AVSESSION_ERROR;
    }
    
    auto ret = AAFwk::AbilityManagerClient::GetInstance()->ExecuteIntent((uint64_t) AVSESSION_SERVICE_ID,
        remote, executeParam);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("ExecuteIntent insightIntent=%{public}s fail", executeParam.insightIntentName_.c_str());
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

extern "C" bool IsSupportPlayIntent(const std::string& bundleName, const std::string& assetId)
{
    AppExecFwk::InsightIntentExecuteParam executeParam;
    return InsightAdapter::GetInsightAdapterInstance().GetPlayIntentParam(bundleName, assetId, executeParam);
}

extern "C" int32_t StartAVPlayback(const std::string& bundleName, const std::string& assetId)
{
    AppExecFwk::InsightIntentExecuteParam executeParam;
    bool isSupport = InsightAdapter::GetInsightAdapterInstance().GetPlayIntentParam(bundleName, assetId, executeParam);
    if (isSupport) {
        return InsightAdapter::GetInsightAdapterInstance().StartAVPlayback(executeParam);
    }
    return AVSESSION_SUCCESS;
}
}
