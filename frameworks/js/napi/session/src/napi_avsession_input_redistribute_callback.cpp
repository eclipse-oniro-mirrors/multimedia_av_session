/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "napi_avsession_input_redistribute_callback.h"
#include "int_wrapper.h"
#include "avsession_log.h"

namespace OHOS::AVSession {

Rosen::InputAfterRedistributeBehavior NapiAVSessionInputRedistributeCallback::OnInputEvent(
    const std::shared_ptr<MMI::KeyEvent>& keyEvent)
{
    if (keyEvent == nullptr) {
        return Rosen::InputAfterRedistributeBehavior::BEHAVIOR_NORMAL;
    }
    int32_t keyAction = keyEvent->GetKeyAction();
    if (keyAction == MMI::KeyEvent::KEY_ACTION_DOWN) {
        std::string event = "InputRedistributeEvent";
        int32_t keyCode = keyEvent->GetKeyCode();
        AAFwk::WantParams args;
        args.SetParam("keyCode", AAFwk::Integer::Box(static_cast<int32_t>(keyCode)));
        int32_t result = nativeSession->SetSessionEvent(event, args);
        SLOGI("InputRedistributeCallback keyCode %{public}d result %{public}d", keyEvent->GetKeyCode(), result);
        return result == 0 ? Rosen::InputAfterRedistributeBehavior::BEHAVIOR_INTERCEPT :
                            Rosen::InputAfterRedistributeBehavior::BEHAVIOR_NORMAL;
    }
    return Rosen::InputAfterRedistributeBehavior::BEHAVIOR_NORMAL;
}

Rosen::InputAfterRedistributeBehavior NapiAVSessionInputRedistributeCallback::OnInputEvent(
    const std::shared_ptr<MMI::PointerEvent>& keyEvent)
{
    return Rosen::InputAfterRedistributeBehavior::BEHAVIOR_NORMAL;
}

}
