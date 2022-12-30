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
#include "bundle_mgr_client.h"
#include "tokenid_kit.h"

namespace OHOS::AVSession {
using namespace Security::AccessToken;
using AppExecFwk::BundleMgrClient;
PermissionChecker& PermissionChecker::GetInstance()
{
    static PermissionChecker permissionChecker;
    return permissionChecker;
}

bool PermissionChecker::CheckSystemPermission(Security::AccessToken::AccessTokenID tokenId)
{
    if (AccessTokenKit::GetTokenTypeFlag(tokenId) == TOKEN_NATIVE) {
        return true;
    }

    if (AccessTokenKit::GetTokenTypeFlag(tokenId) == TOKEN_SHELL) {
        return true;
    }

    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    bool isSystemApp = TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
    if (!isSystemApp) {
        SLOGI("Not system app, permission reject tokenid=%{public}u", tokenId);
        return false;
    }

    SLOGI("Check system permission finished");
    return true;
}

bool PermissionChecker::CheckSystemPermission()
{
    AccessTokenID callerToken = OHOS::IPCSkeleton::GetCallingTokenID();
    return CheckSystemPermission(callerToken);
}

bool PermissionChecker::CheckSystemPermissionByUid(int uid)
{
    BundleMgrClient client;
    std::string bundleName;
    if (!client.GetBundleNameForUid(uid, bundleName)) {
        return true;
    }

    auto tokenId = AccessTokenKit::GetHapTokenID(uid / UID_TRANSFORM_DIVISOR, bundleName, 0);
    if (tokenId == INVALID_TOKENID) {
        SLOGE("get token id failed");
        return false;
    }

    return CheckSystemPermission(tokenId);
}
} // namespace OHOS::AVSession
