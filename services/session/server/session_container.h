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

#ifndef OHOS_SESSION_CONTAINER_H
#define OHOS_SESSION_CONTAINER_H

#include <string>
#include <vector>
#include "avsession_item.h"

namespace OHOS::AVSession {
class SessionContainer {
public:
    virtual int32_t AddSession(pid_t pid, sptr<AVSessionItem>& item) = 0;

    virtual sptr<AVSessionItem> RemoveSession(pid_t pid) = 0;

    virtual sptr<AVSessionItem> GetSession(pid_t pid) = 0;

    virtual std::vector<sptr<AVSessionItem>> GetAllSessions() = 0;

    virtual ~SessionContainer() = default;

    static constexpr int32_t SESSION_NUM_MAX = 20;
};
} // namespace OHOS::AVSession
#endif // OHOS_SESSION_CONTAINER_H