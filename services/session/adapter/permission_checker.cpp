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

#include "permission_checker.h"

#include "accesstoken_kit.h"
#include "avsession_log.h"
#include "ipc_skeleton.h"

namespace OHOS::AVSession {
using namespace Security::AccessToken;
PermissionChecker& PermissionChecker::GetInstance()
{
    static PermissionChecker permissionChecker;
    return permissionChecker;
}

bool PermissionChecker::CheckSystemPermission()
{
    AccessTokenID callerToken = OHOS::IPCSkeleton::GetCallingTokenID();
    if (AccessTokenKit::GetTokenTypeFlag(callerToken) == TOKEN_NATIVE) {
        return true;
    }

    int32_t res = AccessTokenKit::VerifyAccessToken(callerToken, MANAGE_MEDIA_RESOURCES);
    if (res == PERMISSION_GRANTED) {
        return true;
    }
    SLOGI("permission reject tokenid=%{public}u", callerToken);
    return false;
}
} // namespace OHOS::AVSession