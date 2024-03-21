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
#include "nlohmann/json.hpp"

namespace OHOS::AVSession {
ParamsConfigOperator::ParamsConfigOperator()
{
    SLOGI("construct");
}

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
    nlohmann::json configs = nlohmann::json::parse(content, nullptr, false);
    CHECK_AND_RETURN_LOG(configs.is_discarded(), "configs is invalid");
    SLOGD("InitConfig::parse json object finished");
    for (auto config : configs.items()) {
        if (config.value().is_number()) {
            configIntParams.insert(std::pair<std::string, int32_t>(config.key(), config.value()));
        }
        if (config.value().is_string()) {
            configStringParams.insert(std::pair<std::string, std::string>(config.key(), config.value()));
        }
    }
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