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

#include "key_event_adapter.h"
#include "input_manager.h"
#include "key_option.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
KeyEventAdapter& KeyEventAdapter::GetInstance()
{
    static KeyEventAdapter keyEventAdapter;
    return keyEventAdapter;
}

void KeyEventAdapter::SubscribeKeyEvent(const std::vector<int32_t>& keyCodes,
                                        const std::function<void(std::shared_ptr<MMI::KeyEvent>)>& callback)
{
    SLOGI("enter");
    auto* inputManager = MMI::InputManager::GetInstance();
    CHECK_AND_RETURN_LOG(inputManager != nullptr, "failed to get input manager");

    for (auto keyCode : keyCodes) {
        auto keyOption = std::make_shared<MMI::KeyOption>();
        CHECK_AND_RETURN_LOG(keyOption != nullptr, "no memory");
        keyOption->SetFinalKey(keyCode);
        keyOption->SetFinalKeyDown(true);
        keyOption->SetFinalKeyDownDuration(0);
        if ((keyCode == MMI::KeyEvent::KEYCODE_HEADSETHOOK) ||
            (keyCode == MMI::KeyEvent::KEYCODE_MEDIA_PLAY_PAUSE)) {
            keyOption->SetRepeat(false);
        }
        if (inputManager->SubscribeKeyEvent(keyOption, callback) < 0) {
            SLOGE("keyCode=%{public}d failed", keyCode);
        }
    }
}
}