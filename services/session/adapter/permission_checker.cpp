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

    if (!IsSystemApp()) {
        SLOGE("Check system permission failed, is not a system app");
        return false;
    }

    SLOGD("Check system permission finished");
    return true;
}

bool PermissionChecker::CheckPermission(int32_t checkPermissionType)
{
    Security::AccessToken::AccessTokenID callerToken = OHOS::IPCSkeleton::GetCallingTokenID();
    if (AccessTokenKit::GetTokenTypeFlag(callerToken) == TOKEN_SHELL) {
        return true;
    }
    switch (checkPermissionType) {
        case CHECK_SYSTEM_PERMISSION:
            return CheckSystemPermission(callerToken);
        case CHECK_MEDIA_RESOURCES_PERMISSION:
            return CheckMediaResourcePermission(callerToken, std::string(MANAGE_MEDIA_RESOURCES)) &&
                CheckSystemPermission(callerToken);
        default:
            return false;
    }
}

bool PermissionChecker::CheckMediaResourcePermission(
    Security::AccessToken::AccessTokenID callerToken, std::string permissionName)
{
    const std::string &permission = permissionName;
    int32_t ret = AccessTokenKit::VerifyAccessToken(callerToken, permission);
    if (ret == PermissionState::PERMISSION_DENIED) {
        SLOGE("Check media resources permission failed.");
        return false;
    }
    return true;
}

bool PermissionChecker::IsSystemApp()
{
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    return TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
}

bool PermissionChecker::CheckSystemPermissionByUid(int uid)
{
    BundleMgrClient client;
    std::string bundleName;
    std::string identity = OHOS::IPCSkeleton::ResetCallingIdentity();
    if (client.GetNameForUid(uid, bundleName) != OHOS::ERR_OK) {
        return true;
    }
    OHOS::IPCSkeleton::SetCallingIdentity(identity);

    AccessTokenIDEx accessTokenIdEx = AccessTokenKit::GetHapTokenIDEx(uid / UID_TRANSFORM_DIVISOR, bundleName, 0);
    auto tokenId = accessTokenIdEx.tokenIdExStruct.tokenID;
    if (tokenId == INVALID_TOKENID) {
        SLOGE("get token id failed");
        return false;
    }
    if (AccessTokenKit::GetTokenTypeFlag(tokenId) == TOKEN_NATIVE) {
        return true;
    }

    if (AccessTokenKit::GetTokenTypeFlag(tokenId) == TOKEN_SHELL) {
        return true;
    }
    bool isSystemApp = TokenIdKit::IsSystemAppByFullTokenID(accessTokenIdEx.tokenIDEx);
    if (!isSystemApp) {
        SLOGI("CheckSystemPermissionByUid Not system app");
        return false;
    }
    SLOGD("CheckSystemPermissionByUid is system app done");
    return true;
}
} // namespace OHOS::AVSession
