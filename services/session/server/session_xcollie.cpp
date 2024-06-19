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

#include "session_xcollie.h"

#include "avsession_log.h"

#ifdef HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#endif

namespace OHOS::AVSession {
SessionXCollie::SessionXCollie(const std::string& tag, uint32_t timeoutSeconds,
    std::function<void(void *)> func, void *arg, uint32_t flag)
{
    tag_ = tag;
    #ifdef HICOLLIE_ENABLE
    id_ = HiviewDFX::XCollie::GetInstance().SetTimer(tag_, timeoutSeconds, func, arg, flag);
    #else
    id_ = -1;
    #endif
    isCanceled_ = false;
    SLOGD("start SessionXCollie, tag:%{public}s, timeout:%{public}u, flag:%{public}u, id:%{public}d",
        tag_.c_str(), timeoutSeconds, flag, id_);
}

SessionXCollie::~SessionXCollie()
{
    CancelSessionXCollie();
}

void SessionXCollie::CancelSessionXCollie()
{
    if (!isCanceled_) {
        #ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(id_);
        #endif
        isCanceled_ = true;
        SLOGD("cancel SessionXCollie, tag:%{public}s,id:%{public}d", tag_.c_str(), id_);
    }
}
}   // namespace OHOS::AVSession