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

#ifndef OHOS_AVSESSION_H
#define OHOS_AVSESSION_H

#include <string>
#include <memory>

#include "avsession_info.h"
#include "want_agent.h"
#include "want_params.h"
#include "avsession_controller.h"

namespace OHOS::AVSession {
class AVSession {
public:
    enum {
        SESSION_TYPE_INVALID = -1,
        SESSION_TYPE_AUDIO = 0,
        SESSION_TYPE_VIDEO = 1
    };

    virtual std::string GetSessionId() = 0;

    virtual int32_t GetAVMetaData(AVMetaData& meta) = 0;

    virtual int32_t SetAVMetaData(const AVMetaData& meta) = 0;

    virtual int32_t GetAVPlaybackState(AVPlaybackState& state) = 0;

    virtual int32_t SetAVPlaybackState(const AVPlaybackState& state) = 0;

    virtual int32_t SetLaunchAbility(const AbilityRuntime::WantAgent::WantAgent& ability) = 0;

    virtual std::shared_ptr<AVSessionController> GetController() = 0;

    virtual int32_t RegisterCallback(const std::shared_ptr<AVSessionCallback>& callback) = 0;

    virtual int32_t Activate() = 0;

    virtual int32_t Deactivate() = 0;

    virtual bool IsActive() = 0;

    virtual int32_t Destroy() = 0;

    virtual int32_t AddSupportCommand(const int32_t cmd) = 0;

    virtual int32_t DeleteSupportCommand(const int32_t cmd) = 0;

    virtual int32_t SetSessionEvent(const std::string& event, const AAFwk::WantParams& args) = 0;

    virtual ~AVSession() = default;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_H