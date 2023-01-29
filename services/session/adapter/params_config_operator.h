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

#ifndef AV_SESSION_PARAMS_CONFIGZ_OPERATOR_H
#define AV_SESSION_PARAMS_CONFIGZ_OPERATOR_H

#include <string>
#include <map>

namespace OHOS::AVSession {
class ParamsConfigOperator {
public:
    static ParamsConfigOperator& GetInstance();
    ~ParamsConfigOperator();

    void InitConfig();

    int32_t GetValueIntByKey(const std::string& key, int32_t *value);
    int32_t GetValueStringByKey(const std::string& key, std::string& value);
private:
    ParamsConfigOperator();
    bool IsExistDir(const std::string& path);
    bool IsExistFile(const std::string& path);
    bool IsExistFormat(const std::string& path);

    std::map<std::string, int32_t> configIntParams = {{"historicalRecordMaxNum", HISTORY_RECORD_MAX_NUM}};
    std::map<std::string, std::string> configStringParams = {};

    static constexpr size_t HISTORY_RECORD_MAX_NUM = 10;
    static constexpr const char *PARAMS_FILE_NAME = "av_session_params_cfg";

    const std::string avsessionFileDir = "/system/etc";
};
}
#endif // AV_SESSION_PARAMS_CONFIGZ_OPERATOR_H