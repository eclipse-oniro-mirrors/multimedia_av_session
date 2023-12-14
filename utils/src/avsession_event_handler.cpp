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

#include "avsession_event_handler.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
AVSessionEventHandler &AVSessionEventHandler::GetInstance()
{
    static AVSessionEventHandler avSessionEventHandler;
    return avSessionEventHandler;
}

AVSessionEventHandler::AVSessionEventHandler()
{
    SLOGI("construct");
}

AVSessionEventHandler::~AVSessionEventHandler()
{
    SLOGI("destroy");
}

bool AVSessionEventHandler::AVSessionPostTask(const Callback &callback, const std::string &name, int64_t delayTime)
{
    SLOGI("AVSessionEventHandler ProxyPostTask");

    if (!handler_) {
        auto runner = AppExecFwk::EventRunner::Create("OS_AVSessionHdl");
        handler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    return handler_->PostTask(callback, name, delayTime);
}

void AVSessionEventHandler::AVSessionRemoveTask(const std::string &name)
{
    SLOGI("AVSessionEventHandler ProxyRemoveTask");

    if (handler_) {
        handler_->RemoveTask(name);
    }
}
}