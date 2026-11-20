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

#include "avsession_timer_info.h"
#include "avsession_log.h"

namespace OHOS::AVSession {

/**
* When timing is up, this function will execute as call back.
*/
void AVSessionTimerInfo::OnTrigger()
{
    SLOGI("timeout");
    if (callBack_ != nullptr) {
        callBack_();
    }
}

void AVSessionTimerInfo::SetCallbackInfo(const std::function<void()> &callBack)
{
    callBack_ = callBack;
}

/**
* SetType set timer type
* @para: type: TIMER_TYPE_REALTIME | TIMER_TYPE_WAKEUP
*
*/
void AVSessionTimerInfo::SetType(const int &_type)
{
    type = _type;
}

/**
* SetRepeat set timer repeat or not
* @para: repeat: bool
*
*/
void AVSessionTimerInfo::SetRepeat(bool _repeat)
{
    repeat = _repeat;
}

/**
* SetInterval set timer repeat interval
* @para: repeat: uint64_t >= 5000ms
*
*/
void AVSessionTimerInfo::SetInterval(const uint64_t &_interval)
{
    interval = _interval;
}

void AVSessionTimerInfo::SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> _wantAgent)
{
    wantAgent = _wantAgent;
}

/**
* SetDisposable set timer disposable or not
* @para: _disposable bool
*        true: the timer will be destroyed automaticly when it is triggered.
*              But do not take effect for repeat timer.
*        false: the timer need to be destroyed by client
*/
void AVSessionTimerInfo::SetDisposable(const bool &_disposable)
{
    disposable = _disposable;
}

} // namespace OHOS::AVSession