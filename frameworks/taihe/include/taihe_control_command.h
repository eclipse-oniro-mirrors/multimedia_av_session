/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef TAIHE_CONTROL_COMMAND_H
#define TAIHE_CONTROL_COMMAND_H

#include <map>
#include <functional>

#include "avcontrol_command.h"
#include "taihe_headers.h"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;

class TaiheControlCommand {
public:
    using GetterType = std::function<int32_t(AVControlCommand, OHOS::AVSession::AVControlCommand&)>;
    using SetterType = std::function<int32_t(OHOS::AVSession::AVControlCommand&, AVControlCommand&)>;

    static std::string ConvertCommand(int32_t cmd);
    static int32_t ConvertCommand(const std::string &cmd);
    static std::vector<std::string> ConvertCommands(const std::vector<int32_t> &cmds);

    static int32_t GetValue(AVControlCommand in, OHOS::AVSession::AVControlCommand &out);
    static int32_t SetValue(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out);

    static int32_t GetNoneParam(AVControlCommand in, OHOS::AVSession::AVControlCommand &out);
    static int32_t GetSpeed(AVControlCommand in, OHOS::AVSession::AVControlCommand &out);
    static int32_t GetForwardTime(AVControlCommand in, OHOS::AVSession::AVControlCommand &out);
    static int32_t GetRewindTime(AVControlCommand in, OHOS::AVSession::AVControlCommand &out);
    static int32_t GetSeekTime(AVControlCommand in, OHOS::AVSession::AVControlCommand &out);
    static int32_t GetLoopMode(AVControlCommand in, OHOS::AVSession::AVControlCommand &out);
    static int32_t GetTargetLoopMode(AVControlCommand in, OHOS::AVSession::AVControlCommand &out);
    static int32_t GetAssetId(AVControlCommand in, OHOS::AVSession::AVControlCommand &out);
    static int32_t GetPlayFromAssetId(AVControlCommand in, OHOS::AVSession::AVControlCommand &out);

    static int32_t SetNoneParam(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out);
    static int32_t SetSpeed(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out);
    static int32_t SetForwardTime(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out);
    static int32_t SetRewindTime(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out);
    static int32_t SetSeekTime(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out);
    static int32_t SetLoopMode(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out);
    static int32_t SetTargetLoopMode(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out);
    static int32_t SetAssetId(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out);
    static int32_t SetPlayFromAssetId(OHOS::AVSession::AVControlCommand &in, AVControlCommand &out);

private:
    static std::map<std::string, std::tuple<GetterType, SetterType, int32_t>> commandMap_;
    static constexpr int GETTER_INDEX = 0;
    static constexpr int SETTER_INDEX = 1;
    static constexpr int ENUM_INDEX = 2;
};
} // namespace ANI::AVSession
#endif // TAIHE_CONTROL_COMMAND_H