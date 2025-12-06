/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "avsession_whitelist_config_manager.h"

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "avsession_log.h"
#include "cJSON.h"
#include "iservice_registry.h"
#include "rdb_errno.h"
#include "system_ability_definition.h"

namespace OHOS::AVSession {

#ifdef INPUT_REDISTRIBUTE_ENABLE
constexpr const char *SETTING_URI_PROXY =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
constexpr const char *SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
constexpr const char *SETTINGS_DATA_KEY_URI = "&key=";
constexpr const char *SETTINGS_DATA_COLUMN_VALUE = "VALUE";
constexpr const char *SETTINGS_DATA_COLUMN_KEYWORD = "KEYWORD";
constexpr const char *WHITELIST_AVSESSION_STRATEGY = "WHITELIST_AVSESSION_STRATEGY";
#endif

bool AVSessionWhitelistConfigManager::IsKeyEventSupported(const std::string &bundleName)
{
    if (bundleName.empty()) {
        SLOGI("bundleName empty");
        return false;
    }
    if (IsSystemApp()) {
        SLOGI("isSystemApp bundleName: %{public}s", bundleName.c_str());
        return false;
    }
    bool supportKeyEvent = false;
#ifdef INPUT_REDISTRIBUTE_ENABLE
    supportKeyEvent = GetSupportKeyEventFromSettings(bundleName);
#endif
    SLOGI("supportKeyEvent:%{public}d, bundleName: %{public}s", supportKeyEvent, bundleName.c_str());
    return supportKeyEvent;
}

#ifdef INPUT_REDISTRIBUTE_ENABLE
bool AVSessionWhitelistConfigManager::GetSupportKeyEventFromSettings(const std::string &bundleName)
{
    if (bundleName.empty()) {
        SLOGI("bundleName empty");
        return false;
    }
    std::call_once(settingsDataLoadFlag_, [this]() {
        SLOGI("load settings data start");
        std::string jsonStr = GetSettingsDataStringValue();
        if (!ParseJsonToMap(jsonStr, compatibleInfoMap_)) {
            SLOGI("parse json fail");
        } else {
            isSettingsDataLoaded_.store(true, std::memory_order_release);
        }
        SLOGI("load settings data end");
    });
    bool supportKeyEvent = false;
    if (isSettingsDataLoaded_.load(std::memory_order_acquire)) {
        auto iter = compatibleInfoMap_.find(bundleName);
        if (iter != compatibleInfoMap_.end()) {
            supportKeyEvent = iter->second;
        }
    }
    return supportKeyEvent;
}

std::string AVSessionWhitelistConfigManager::GetSettingsDataStringValue()
{
    auto helper = CreateDataShareHelper();
    if (helper == nullptr) {
        SLOGW("helper nullptr");
        return "";
    }
    std::vector<std::string> columns = {SETTINGS_DATA_COLUMN_VALUE};
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_COLUMN_KEYWORD, WHITELIST_AVSESSION_STRATEGY);
    std::string uriString = SETTING_URI_PROXY;
    Uri uri(uriString + SETTINGS_DATA_KEY_URI + WHITELIST_AVSESSION_STRATEGY);
    auto resultSet = helper->Query(uri, predicates, columns);
    ReleaseDataShareHelper(helper);
    if (resultSet == nullptr) {
        SLOGW("helper->Query return nullptr");
        return "";
    }
    int32_t count = 0;
    resultSet->GetRowCount(count);
    if (count == 0) {
        SLOGW("not found value, count=%{public}d", count);
        resultSet->Close();
        return "";
    }
    const int32_t index = 0;
    resultSet->GoToRow(index);
    std::string value;
    int32_t ret = resultSet->GetString(index, value);
    if (ret != NativeRdb::E_OK) {
        SLOGW("resultSet->GetString return not ok, ret=%{public}d", ret);
        resultSet->Close();
        return "";
    }
    resultSet->Close();
    return value;
}

bool AVSessionWhitelistConfigManager::ParseJsonToMap(
    const std::string &jsonStr, std::map<std::string, bool> &compatibleMap)
{
    if (jsonStr.empty()) {
        SLOGW("json str is empty.");
        return false;
    }
    SLOGI("jsonStr : %{public}s", jsonStr.c_str());
    cJSON *root = cJSON_Parse(jsonStr.c_str());
    if (root == nullptr || !cJSON_IsObject(root)) {
        cJSON_Delete(root);
        SLOGW("root is not object.");
        return false;
    }
    cJSON* item = root->child;
    while (item != nullptr) {
        if (!cJSON_IsInvalid(item) && cJSON_IsBool(item)) {
            const char* key = item->string;
            bool value = cJSON_IsTrue(item);
            compatibleMap[key] = value;
            item = item->next;
        }
    }
    cJSON_Delete(root);
    return true;
}

std::shared_ptr<DataShare::DataShareHelper> AVSessionWhitelistConfigManager::CreateDataShareHelper()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        SLOGW("GetSystemAbilityManager return nullptr");
        return nullptr;
    }
    auto remoteObj = sam->GetSystemAbility(AVSESSION_SERVICE_ID);
    if (remoteObj == nullptr) {
        SLOGW("GetSystemAbility return nullptr");
        return nullptr;
    }
    auto helper = DataShare::DataShareHelper::Creator(remoteObj, SETTING_URI_PROXY, SETTINGS_DATA_EXT_URI);
    if (helper == nullptr) {
        SLOGW("helper is nullptr");
        return nullptr;
    }
    return helper;
}

bool AVSessionWhitelistConfigManager::ReleaseDataShareHelper(std::shared_ptr<DataShare::DataShareHelper> &helper)
{
    if (helper == nullptr) {
        SLOGW("helper is null");
        return false;
    }
    if (!helper->Release()) {
        SLOGW("release helper fail");
        return false;
    }
    helper = nullptr;
    return true;
}
#endif
bool AVSessionWhitelistConfigManager::IsSystemApp()
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingFullTokenID();
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(callingTokenId);
}
} // namespace OHOS::AVSession