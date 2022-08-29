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

#include "command_send_limit.h"
#include "avsession_errors.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
std::shared_ptr<CommandSendLimit> CommandSendLimit::instance_;
std::once_flag CommandSendLimit::onceFlag_;

CommandSendLimit& CommandSendLimit::GetInstance()
{
    std::call_once(onceFlag_, [] {
        instance_ = std::make_shared<CommandSendLimit>();
    });
    return *instance_;
}

CommandSendLimit::CommandSendLimit()
{
    SLOGD("CommandSendLimit construct");
}

CommandSendLimit::~CommandSendLimit()
{
    SLOGD("CommandSendLimit destroy");
}

bool CommandSendLimit::IsCommandSendEnable(pid_t pid)
{
    std::lock_guard lockGuard(commandLimitLock_);
    if (timer_ == nullptr) {
        return true;
    }
    if (commandLimits_.find(pid) != commandLimits_.end()) {
        if (commandLimits_[pid] >= COMMAND_SEND_NUM_MAX) {
            SLOGD("commandSendTime=%{public}d", commandLimits_[pid]);
            return false;
        }
        SLOGD("commandSendTime=%{public}d", commandLimits_[pid]);
        commandLimits_[pid] += 1;
    } else {
        SLOGD("commandSendTime=0");
        commandLimits_.insert(std::make_pair(pid, 1));
    }
    return true;
}

void CommandSendLimit::ClearCommandLimits()
{
    std::lock_guard lockGuard(commandLimitLock_);
    commandLimits_.clear();
}
void CommandSendLimit::StartTimer()
{
    SLOGD("CommandSendLimit StartTimer");
    std::lock_guard lockGuard(commandLimitLock_);
    if (!timer_) {
        timer_ = std::make_unique<OHOS::Utils::Timer>("CommandLimitTimer");
        CHECK_AND_RETURN_LOG(timer_ != nullptr, "create Timer failed");
        Utils::Timer::TimerCallback timerCallback = [this]() {
            ClearCommandLimits();
        };
        timerId_ = timer_->Register(timerCallback, COMMAND_SEND_TIME, false);
        timer_->Setup();
    }
}

void CommandSendLimit::StopTimer()
{
    SLOGD("CommandSendLimit StopTimer");
    std::lock_guard lockGuard(commandLimitLock_);
    if (timer_) {
        timer_->Shutdown();
        timer_->Unregister(timerId_);
        timer_ = nullptr;
    }
    commandLimits_.clear();
}
} // namespace OHOS::AVSession