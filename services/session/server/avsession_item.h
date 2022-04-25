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

#ifndef OHOS_AVSESSION_ITEM_H
#define OHOS_AVSESSION_ITEM_H

#include <string>
#include "avsession_stub.h"

namespace OHOS::AVSession {
class AVSessionItem : public AVSessionStub {
public:
    AVSessionItem(const std::string& tag, int32_t id);

    ~AVSessionItem() override;

    int32_t GetSessionId() override;

    void Release() override;

protected:
    int32_t RegisterCallbackInner(sptr<IRemoteObject>& callback) override;

private:
    std::string tag_;
    int32_t sessionId_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_ITEM_H