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

#include "params_config_operator.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "file_ex.h"
#include "cJSON.h"

namespace OHOS::AVSession {
// LCOV_EXCL_START
ParamsConfigOperator::ParamsConfigOperator()
{
    SLOGI("construct");
}
// LCOV_EXCL_STOP

ParamsConfigOperator::~ParamsConfigOperator()
{
    SLOGI("destroy");
}

ParamsConfigOperator& ParamsConfigOperator::GetInstance()
{
    static ParamsConfigOperator paramsConfigOperator;
    return paramsConfigOperator;
}

void ParamsConfigOperator::InitConfig()
{
    SLOGI("Init configuration params");
    std::string content;
    if (!LoadStringFromFile(avsessionFileDir + PARAMS_FILE_NAME, content)) {
        SLOGE("LoadStringFromFile failed, filename=%{public}s", PARAMS_FILE_NAME);
        return;
    }
    // LCOV_EXCL_START
    cJSON* configsArray = cJSON_Parse(content.c_str());
    CHECK_AND_RETURN_LOG(configsArray != nullptr, "configs is invalid");
    if (cJSON_IsInvalid(configsArray) || !cJSON_IsArray(configsArray)) {
        SLOGE("CheckBundleSupport parse profile not valid json");
        cJSON_Delete(configsArray);
        return;
    }
    SLOGD("InitConfig::parse json object finished");

    cJSON* configItem = nullptr;
    cJSON_ArrayForEach(configItem, configsArray) {
        if (configItem == nullptr || cJSON_IsInvalid(configItem)) {
            SLOGE("get config item null");
            continue;
        }
        cJSON* propItem = configItem->child;
        while (propItem != nullptr) {
            std::string keyStr = propItem->string;
            cJSON* valueItem = cJSON_GetObjectItem(propItem, propItem->string);
            if (valueItem == nullptr) {
                propItem = propItem->next;
                continue;
            }
            if (cJSON_IsNumber(valueItem)) {
                configIntParams.insert(std::pair<std::string, int32_t>(keyStr, valueItem->valueint));
            } else if (cJSON_IsString(valueItem)) {
                configStringParams.insert(std::pair<std::string, std::string>(keyStr,
                    std::string(valueItem->valuestring)));
            }
            propItem = propItem->next;
        }
    }
    cJSON_Delete(configsArray);
    // LCOV_EXCL_STOP
}

int32_t ParamsConfigOperator::GetValueIntByKey(const std::string& key, int32_t *value)
{
    auto param = configIntParams.find(key);
    if (param == configIntParams.end()) {
        SLOGE("GetValueIntByKey failed, key=%{public}s", key.c_str());
        return AVSESSION_ERROR;
    }
    *value = static_cast<int>(param->second);
    return AVSESSION_SUCCESS;
}
}