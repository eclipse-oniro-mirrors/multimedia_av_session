/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVSESSION_CLI_UTILS_H
#define OHOS_AVSESSION_CLI_UTILS_H

#include <string>
#include "nlohmann/json.hpp"
#include "avsession_info.h"
#include "avplayback_state.h"
#include "avmeta_data.h"
#include "avqueue_info.h"
#include "avqueue_item.h"
#include "avsession_descriptor.h"

namespace OHOS::AVSession::Cli {

void CLI_LOG(const std::string& message);
void CLI_ERROR(const std::string& message);

void OutputSuccess(const nlohmann::json& data);
void OutputError(int32_t errCode, const std::string& errMsg, const std::string& suggestion);

std::string GetErrorString(int32_t errCode);
std::string GetPlaybackStateString(int32_t state);
std::string GetLoopModeString(int32_t loopMode);
std::string GetControlCommandString(int32_t cmd);

nlohmann::json AVSessionDescriptorToJson(const AVSessionDescriptor& descriptor);
nlohmann::json AVQueueInfoToJson(const AVQueueInfo& info);
nlohmann::json AVPlaybackStateToJson(const AVPlaybackState& state);
nlohmann::json AVMetaDataToJson(const AVMetaData& meta);
nlohmann::json AVQueueItemToJson(const AVQueueItem& item);
nlohmann::json OutputDeviceInfoToJson(const OutputDeviceInfo& info);

}

#endif // OHOS_AVSESSION_CLI_UTILS_H