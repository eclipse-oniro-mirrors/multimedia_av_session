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

#ifndef AV_CAST_INFO_H
#define AV_CAST_INFO_H

#include <sys/types.h>

namespace OHOS::AVSession {
class AVCastInfo {
public:
    AVCastInfo() = default;
    ~AVCastInfo() = default;

    void SetAppUid(uid_t appUid);
    uid_t GetAppUid();

private:
    uid_t appUid_ = 0;
};
} // namespace OHOS::AVSession

#endif // AV_CAST_INFO_H