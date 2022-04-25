/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "avsession_proxy.h"
#include "avsession_log.h"
#include "avsession_errors.h"

namespace OHOS::AVSession {
AVSessionProxy::AVSessionProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IAVSession>(impl)
{
    SLOGD("construct");
}

int32_t AVSessionProxy::GetSessionId()
{
    return 0;
}

int32_t AVSessionProxy::RegisterCallback(std::shared_ptr<AVSessionCallback> &callback)
{
    sptr<IRemoteObject> object;
    RegisterCallbackInner(object);
    return AVSESSION_SUCCESS;
}

int32_t AVSessionProxy::RegisterCallbackInner(sptr<IRemoteObject> &callback)
{
    return AVSESSION_SUCCESS;
}
void AVSessionProxy::Release()
{
    SLOGD("enter");
}
}