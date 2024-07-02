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
    auto tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    const std::string &permissionName = std::string(MANAGE_MEDIA_RESOURCES);
    if ((tokenType == TOKEN_NATIVE || tokenType == TOKEN_SHELL) && CheckPermission(tokenId, permissionName)) {
        return true;
    }

    if (!CheckPermission(tokenId, permissionName)) {
        SLOGI("CheckSystemPermission permission reject for MANAGE_MEDIA_RESOURCES");
        return false;
    }

    SLOGI("Check system permission finished");
    return true;
}

bool PermissionChecker::CheckPermission(uint32_t tokenId, const std::string &permissionName)
{
    int32_t ret = AccessTokenKit::VerifyAccessToken(tokenId, permissionName);
    if (ret == PermissionState::PERMISSION_DENIED) {
        return false;
    }
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

    auto tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    const std::string &permissionName = std::string(MANAGE_MEDIA_RESOURCES);
    if ((tokenType == TOKEN_NATIVE || tokenType == TOKEN_SHELL) && CheckPermission(tokenId, permissionName)) {
        return true;
    }

    if (!CheckPermission(tokenId, permissionName)) {
        SLOGI("CheckSystemPermissionByUid permission reject for MANAGE_MEDIA_RESOURCES");
        return false;
    }

    SLOGD("CheckSystemPermissionByUid is system app done");
    return true;
}
} // namespace OHOS::AVSession
