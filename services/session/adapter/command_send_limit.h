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

#ifndef OHOS_COMMAND_SEND_LIMIT_H
#define OHOS_COMMAND_SEND_LIMIT_H

#include <string>
#include <memory>
#include <mutex>
#include <functional>
#include "timer.h"

namespace OHOS::AVSession {
class CommandSendLimit : public std::enable_shared_from_this<CommandSendLimit> {
public:
    static CommandSendLimit& GetInstance();

    CommandSendLimit();
    ~CommandSendLimit();

    bool IsCommandSendEnable(pid_t pid);
    void StartTimer();
    void StopTimer();
private:
    std::recursive_mutex commandLimitLock_;
    void ClearCommandLimits();
    static std::shared_ptr<CommandSendLimit> instance_;
    static std::once_flag onceFlag_;
    std::map<pid_t, int32_t> commandLimits_;
    std::unique_ptr<Utils::Timer> timer_;
    uint32_t timerId_;
    static constexpr int32_t COMMAND_SEND_NUM_MAX = 10;
    static constexpr int32_t COMMAND_SEND_TIME = 1000;
};
} // namespace OHOS::AVSession
#endif // OHOS_COMMAND_SEND_LIMIT_H