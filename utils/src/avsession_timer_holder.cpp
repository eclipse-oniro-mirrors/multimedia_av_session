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

#include "avsession_timer_holder.h"

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
#include "avsession_log.h"
#endif

namespace OHOS::AVSession {
#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
AVSessionTimerHolder& AVSessionTimerHolder::GetInstance()
{
    static AVSessionTimerHolder instance;
    return instance;
}

AVSessionTimerHolder::AVSessionTimerHolder() : timer_(nullptr) {}

AVSessionTimerHolder::~AVSessionTimerHolder()
{
    Shutdown();
}

uint32_t AVSessionTimerHolder::Register(const Utils::Timer::TimerCallback& callback, uint32_t intervalMs)
{
    // interval 0 makes the underlying timerfd expire immediately
    if (intervalMs == 0) {
        SLOGE("AVSessionTimerHolder invalid interval 0");
        return 0;
    }
    std::lock_guard<std::mutex> lockGuard(lock_);
    if (timer_ == nullptr) {
        timer_ = std::make_unique<Utils::Timer>("EventStatisticTimer");
        if (timer_->Setup() != 0) {
            SLOGE("AVSessionTimerHolder Setup failed");
            timer_ = nullptr;
            return 0;
        }
    }
    uint32_t timerId = timer_->Register(callback, intervalMs, false);
    if (timerId == 0 || timerId == TIMER_REGISTER_FAILED) {
        SLOGE("AVSessionTimerHolder Register failed ret=%{public}u interval=%{public}ums", timerId, intervalMs);
        return 0;
    }
    SLOGI("AVSessionTimerHolder register task id=%{public}u interval=%{public}ums", timerId, intervalMs);
    return timerId;
}

void AVSessionTimerHolder::Unregister(uint32_t timerId)
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    CHECK_AND_RETURN_LOG(timer_ != nullptr, "AVSessionTimerHolder timer not running");
    CHECK_AND_RETURN_LOG(timerId != 0, "AVSessionTimerHolder invalid timerId 0");
    timer_->Unregister(timerId);
    SLOGI("AVSessionTimerHolder unregister task id=%{public}u", timerId);
}

void AVSessionTimerHolder::Shutdown()
{
    std::lock_guard<std::mutex> lockGuard(lock_);
    CHECK_AND_RETURN_LOG(timer_ != nullptr, "AVSessionTimerHolder already shutdown");
    timer_->Shutdown();
    timer_ = nullptr;
    SLOGI("AVSessionTimerHolder shutdown");
}
#endif
} // namespace OHOS::AVSession
