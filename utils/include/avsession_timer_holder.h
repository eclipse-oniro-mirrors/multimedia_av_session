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

#ifndef OHOS_AVSESSION_TIMER_HOLDER_H
#define OHOS_AVSESSION_TIMER_HOLDER_H

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
#include <memory>
#include <mutex>
#include "timer.h"
#endif

namespace OHOS::AVSession {
#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
// Shared Utils::Timer so multiple periodic tasks reuse one thread.
class AVSessionTimerHolder {
public:
    static AVSessionTimerHolder& GetInstance();

    // Returns timerId (>0) for Unregister, or 0 on failure. intervalMs must be > 0.
    uint32_t Register(const Utils::Timer::TimerCallback& callback, uint32_t intervalMs);
    void Unregister(uint32_t timerId);
    void Shutdown();

private:
    AVSessionTimerHolder();
    ~AVSessionTimerHolder();
    AVSessionTimerHolder(const AVSessionTimerHolder&) = delete;
    AVSessionTimerHolder& operator=(const AVSessionTimerHolder&) = delete;

    std::unique_ptr<Utils::Timer> timer_;
    std::mutex lock_;

    static constexpr uint32_t TIMER_REGISTER_FAILED = 65547;
};
#else
class AVSessionTimerHolder {};
#endif
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_TIMER_HOLDER_H
