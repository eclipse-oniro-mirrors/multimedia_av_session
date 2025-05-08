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
    cJSON* profileValues = cJSON_Parse(profile.c_str());
    CHECK_AND_RETURN_RET_LOG(profileValues != nullptr, false, "parse profile fail");
    if (cJSON_IsInvalid(profileValues)) {
        SLOGE("parse profile not valid json");
        cJSON_Delete(profileValues);
        return false;
    }
    cJSON* insightIntentsArray = cJSON_GetObjectItem(profileValues, "insightIntents");
    if (insightIntentsArray == nullptr || !cJSON_IsArray(insightIntentsArray)) {
        SLOGE("json do not contain insightIntentsArray");
        cJSON_Delete(profileValues);
        return false;
    }

    cJSON* insightIntentsItem = nullptr;
    cJSON_ArrayForEach(insightIntentsItem, insightIntentsArray) {
        cJSON* intentNameItem = cJSON_GetObjectItem(insightIntentsItem, "intentName");
        if (intentNameItem == nullptr || !cJSON_IsString(intentNameItem)) {
            SLOGE("json do not contain intentName");
            continue;
        }
        const char* insightName = intentNameItem->valuestring;
        if (insightName != nullptr &&
            strcmp(insightName, PLAY_MUSICLIST.c_str()) != 0 && strcmp(insightName, PLAY_AUDIO.c_str()) != 0) {
            continue;
        }

        cJSON* uiAbilityItem = cJSON_GetObjectItem(insightIntentsItem, "uiAbility");
        if (uiAbilityItem == nullptr) {
            SLOGE("json do not contain uiAbility");
            cJSON_Delete(profileValues);
            return false;
        }
        cJSON* executeModeArray = cJSON_GetObjectItem(uiAbilityItem, "executeMode");
        if (executeModeArray == nullptr || !cJSON_IsArray(executeModeArray)) {
            SLOGE("json do not contain executeMode");
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

void InsightAdapter::SetStartPlayInfoToParam(const StartPlayInfo startPlayInfo, StartPlayType startPlayType,
    std::shared_ptr<AppExecFwk::WantParams> &wantParam)
{
    AppExecFwk::WantParams startPlayInfoParam;
    startPlayInfoParam.SetParam("startPlayBundleName", OHOS::AAFwk::String::Box(startPlayInfo.getBundleName()));
    startPlayInfoParam.SetParam("deviceId", OHOS::AAFwk::String::Box(startPlayInfo.getDeviceId()));
        
    if (wantParam == nullptr) {
        SLOGE("wantParam is null when SetStartPlayInfoToParam");
        return;
    }
    wantParam->SetParam("startPlayInfo", OHOS::AAFwk::WantParamWrapper::Box(startPlayInfoParam));
    wantParam->SetParam("startPlayType", OHOS::AAFwk::String::Box(StartPlayTypeToString.at(startPlayType)));
}

std::shared_ptr<AppExecFwk::WantParams> InsightAdapter::GetPlayIntentParamWithWantProcess(std::string& insightName,
    const std::string& assetId, const StartPlayInfo startPlayInfo, StartPlayType startPlayType, bool& res)
{
    std::shared_ptr<AppExecFwk::WantParams> wantParam = std::make_shared<AppExecFwk::WantParams>();
    if (insightName == PLAY_MUSICLIST) {
        AppExecFwk::WantParams innerParams; // construct items array
        innerParams.SetParam("entityId", OHOS::AAFwk::String::Box(assetId));
        sptr<OHOS::AAFwk::IArray> array = new (std::nothrow) OHOS::AAFwk::Array(1, OHOS::AAFwk::g_IID_IWantParams);
        CHECK_AND_RETURN_RET_LOG(array != nullptr, wantParam, "new Array is null");
        array->Set(0, OHOS::AAFwk::WantParamWrapper::Box(innerParams));
        wantParam->SetParam("items", array);
        SetStartPlayInfoToParam(startPlayInfo, startPlayType, wantParam);
        res = true;
    }
    if (insightName == PLAY_AUDIO) {
        wantParam->SetParam("entityId", AppExecFwk::WantParams::GetInterfaceByType(interfaceType, assetId));
        SetStartPlayInfoToParam(startPlayInfo, startPlayType, wantParam);
        res = true;
    }
    return wantParam;
}

bool InsightAdapter::GetPlayIntentParam(const std::string& bundleName, const std::string& assetId,
    AppExecFwk::InsightIntentExecuteParam &executeParam, const StartPlayInfo startPlayInfo, StartPlayType startPlayType)
{
    std::string supportModule;
    std::string profile;
    if (!IsSupportPlayIntent(bundleName, supportModule, profile)) {
        SLOGE("bundle=%{public}s does not support play insights", bundleName.c_str());
        return false;
    }
    SLOGD("GetJsonProfile profile=%{public}s", profile.c_str());
    cJSON* profileValues = cJSON_Parse(profile.c_str());
    CHECK_AND_RETURN_RET_LOG(profileValues != nullptr && !cJSON_IsInvalid(profileValues), false, "parse profile fail");
    cJSON* insightIntentsArray = cJSON_GetObjectItem(profileValues, "insightIntents");
    if (insightIntentsArray == nullptr || !cJSON_IsArray(insightIntentsArray)) {
        SLOGE("json do not contain insightIntentsArray");
        cJSON_Delete(profileValues);
        return false;
    }
    bool res = false;
    cJSON* insightIntentsItem = nullptr;
    cJSON_ArrayForEach(insightIntentsItem, insightIntentsArray) {
        cJSON* intentNameItem = cJSON_GetObjectItem(insightIntentsItem, "intentName");
        if (intentNameItem == nullptr || !cJSON_IsString(intentNameItem)) {
            SLOGE("json do not contain intentName");
            continue;
        }
        std::string insightName(intentNameItem->valuestring);
        if (insightName != PLAY_MUSICLIST && insightName != PLAY_AUDIO) {
            continue;
        }
        cJSON* uiAbilityItem = cJSON_GetObjectItem(insightIntentsItem, "uiAbility");
        if (uiAbilityItem == nullptr) {
            SLOGE("json do not contain uiAbility");
            continue;
        }
        cJSON* abilityItem = cJSON_GetObjectItem(uiAbilityItem, "ability");
        if (abilityItem == nullptr || !cJSON_IsString(abilityItem)) {
            SLOGE("json do not contain ability");
            continue;
        }
        executeParam.bundleName_ = bundleName;
        executeParam.moduleName_ = supportModule;
        executeParam.abilityName_.assign(abilityItem->valuestring);
        executeParam.insightIntentName_ = insightName;
        executeParam.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_BACKGROUND;
        std::shared_ptr<AppExecFwk::WantParams> wantParam =
            GetPlayIntentParamWithWantProcess(insightName, assetId, startPlayInfo, startPlayType, res);
        executeParam.insightIntentParam_ = wantParam;
    }
    cJSON_Delete(profileValues);
    return res;
}

bool InsightAdapter::ExecuteIntentFromAVSession(uint64_t key, const sptr<IRemoteObject> &callerToken,
    AppExecFwk::InsightIntentExecuteParam &param)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(ABILITY_MANAGER_INTERFACE_TOKEN)) {
        SLOGE("write interface token failed");
        return false;
    }
    if (!data.WriteUint64(key)) {
        SLOGE("write key fail");
        return false;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        SLOGE("write callerToken fail");
        return false;
    }
    if (!data.WriteParcelable(&param)) {
        SLOGE("write param fail");
        return false;
    }

    sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemManager == nullptr) {
        SLOGE("Fail to get registry");
        return false;
    }
    sptr<IRemoteObject> remote = systemManager->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
    if (remote == nullptr) {
        SLOGE("Fail to connect ability manager service");
        return false;
    }
    SLOGI("Connect ability manager service success");

    if (remote->SendRequest(static_cast<uint32_t>(AVSESSION_EXECUTE_INTENT_CODE),
        data, reply, option) != 0) {
        SLOGE("Send request error");
        return false;
    }
    return reply.ReadInt32() == ERR_OK;
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
    
    bool ret = ExecuteIntentFromAVSession((uint64_t) AVSESSION_SERVICE_ID, remote, executeParam);
    if (!ret) {
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

extern "C" int32_t StartAVPlaybackWithId(const std::string& bundleName, const std::string& assetId,
    const StartPlayInfo startPlayInfo, StartPlayType startPlayType)
{
    AppExecFwk::InsightIntentExecuteParam executeParam;
    bool isSupport = InsightAdapter::GetInsightAdapterInstance().GetPlayIntentParam(bundleName, assetId,
        executeParam, startPlayInfo, startPlayType);
    if (isSupport) {
        return InsightAdapter::GetInsightAdapterInstance().StartAVPlayback(executeParam);
    }
    return AVSESSION_SUCCESS;
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
