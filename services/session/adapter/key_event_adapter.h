/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#ifndef AVSESSION_KEY_EVENT_ADAPTER_H
#define AVSESSION_KEY_EVENT_ADAPTER_H

#include "key_event.h"
#include "avsession_errors.h"

namespace OHOS::AVSession {
class KeyEventAdapter {
public:
    static KeyEventAdapter& GetInstance();

    void SubscribeKeyEvent(const std::vector<int32_t>& keyCodes,
                           const std::function<void(std::shared_ptr<MMI::KeyEvent>)>& callback);
};
}
#endif // AVSESSION_KEY_EVENT_ADAPTER_H