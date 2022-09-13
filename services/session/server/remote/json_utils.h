/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_JSON_UTILS_H
#define OHOS_JSON_UTILS_H

#include <algorithm>
#include <iterator>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "avsession_info.h"
#include "avsession_errors.h"

namespace OHOS::AVSession {
using json = nlohmann::json;
class JsonUtils {
public:
    static int32_t GetJsonCapability(const std::vector<std::vector<int32_t>>& capability, std::string& jsonCapability);
    static int32_t GetVectorCapability(const std::string& jsonCapability,
                                       std::vector<std::vector<int32_t>>& vectorCapability);
    static int32_t GetAllCapability(const std::string& sessionInfo, std::string& jsonCapability);

    static int32_t SetSessionBasicInfo(std::string& sessionInfo, const AVSessionBasicInfo& basicInfo);
    static int32_t GetSessionBasicInfo(const std::string& sessionInfo, AVSessionBasicInfo& basicInfo);

    static int32_t SetSessionDescriptors(std::string& sessionInfo, const std::vector<AVSessionDescriptor>& descriptors);
    static int32_t GetSessionDescriptors(const std::string& sessionInfo, std::vector<AVSessionDescriptor>& descriptors);

    static int32_t SetSessionDescriptor(std::string& sessionInfo, const AVSessionDescriptor& descriptor);
    static int32_t GetSessionDescriptor(const std::string& sessionInfo, AVSessionDescriptor& descriptor);

private:
    static int32_t JsonToVector(json object, std::vector<int32_t>& out);
    static int32_t ConvertSessionType(const std::string& typeString);
    static std::string ConvertSessionType(int32_t type);
};
} // namespace OHOS::AVSession
#endif // OHOS_JSON_UTILS_H