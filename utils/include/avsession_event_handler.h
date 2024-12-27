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

#ifndef AV_SESSION_AVSESSION_EVENT_HANDLER_H
#define AV_SESSION_AVSESSION_EVENT_HANDLER_H

#include "event_handler.h"

namespace OHOS::AVSession {
class AVSessionEventHandler : public AppExecFwk::EventHandler {
public:
    static AVSessionEventHandler& GetInstance();

    AVSessionEventHandler();
    ~AVSessionEventHandler() override;

    bool AVSessionPostTask(const Callback &callback, const std::string &name = std::string(), int64_t delayTime = 0);

    void AVSessionRemoveTask(const std::string &name);

    void AVSessionRemoveHandler();
    
private:
    std::shared_ptr<AppExecFwk::EventHandler> handler_;
    std::mutex handlerLock_;
};
}
#endif // AV_SESSION_AVSESSION_EVENT_HANDLER_H