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

#ifndef SCHEDULED_TASK_H
#define SCHEDULED_TASK_H

#include "avsession_timer_info.h"

namespace OHOS::AVSession {
class AVSessionTimerTask {
public:
    AVSessionTimerTask(const std::function<void()>& callback);
    ~AVSessionTimerTask();

    AVSessionTimerTask(AVSessionTimerTask &other) = delete;
    AVSessionTimerTask& operator = (const AVSessionTimerTask &other) = delete;

    bool StartTimer(int32_t delayTime);
    void StopTimer();
    void CreateTimer();
    void DestroyTimer();

private:
    uint64_t timerId_ = 0;
    bool isCreated_ = false;
    std::shared_ptr<AVSessionTimerInfo> timerInfo_;
};
} // namespace OHOS::AVSession

#endif // SCHEDULED_TASK_H