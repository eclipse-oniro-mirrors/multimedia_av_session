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

#include "avsession_timer_task.h"
#include "avsession_log.h"

namespace OHOS::AVSession {

constexpr uint32_t TIMER_TYPE_WAKEUP = (1 << 1);
constexpr uint32_t TIMER_TYPE_REALTIME = (1);

AVSessionTimerTask::AVSessionTimerTask(const std::function<void()>& callback)
{
    timerInfo_ = std::make_shared<AVSessionTimerInfo>();
    timerInfo_->SetType(TIMER_TYPE_WAKEUP|TIMER_TYPE_REALTIME);
    timerInfo_->SetRepeat(false);
    timerInfo_->SetCallbackInfo(callback);
}

AVSessionTimerTask::~AVSessionTimerTask()
{
    DestroyTimer();
}

void AVSessionTimerTask::CreateTimer()
{
    auto errCode = OHOS::MiscServices::TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo_, timerId_);
    if (errCode == 0) {
        isCreated_ = true;
        SLOGI("Create Timer success, timerId %{public}" PRIu64 "", timerId_);
        return;
    }

    SLOGE("Create Timer failed, errCode %{public}d", errCode);
}

void AVSessionTimerTask::DestroyTimer()
{
    if (!isCreated_) {
        return;
    }

    SLOGI("Destroy timer, timerId %{public}" PRIu64 "", timerId_);
    OHOS::MiscServices::TimeServiceClient::GetInstance()->DestroyTimerV9(timerId_);
    timerId_ = 0;
    isCreated_ = false;
    timerInfo_ = NULL;
}

bool AVSessionTimerTask::StartTimer(int32_t delayTime)
{
    if (!isCreated_ || delayTime <= 0) {
        SLOGE("create timer first");
        return false;
    }

    int64_t time = 0;
    OHOS::MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs(time);
    time += delayTime;
    auto errCode = OHOS::MiscServices::TimeServiceClient::GetInstance()->StartTimerV9(timerId_, time);
    if (errCode == 0) {
        SLOGI("start timer success, delay time %{public}d", delayTime);
        return true;
    }

    SLOGE("start timer failed");
    return false;
}

void AVSessionTimerTask::StopTimer()
{
    if (!isCreated_) {
        return;
    }
    auto errCode = OHOS::MiscServices::TimeServiceClient::GetInstance()->StopTimerV9(timerId_);
    if (errCode != 0) {
        SLOGE("stop timer failed");
    }
}
} // namespace OHOS::AVSession