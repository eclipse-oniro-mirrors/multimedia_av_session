
/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVSESSION_ITEM_EXTENSION_H
#define OHOS_AVSESSION_ITEM_EXTENSION_H

#include <string>
#include <cstdint>

namespace OHOS::AVSession {

class AVSessionItemExtension {
public:
    virtual ~AVSessionItemExtension() = default;

    virtual int32_t StartDesktopLyricAbility(const std::string &sessionId, const std::string &handler) = 0;

    virtual int32_t UploadDesktopLyricOperationInfo(const std::string &sessionId,
        const std::string &handler, uint32_t sceneCode) = 0;
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_ITEM_EXTENSION_H
