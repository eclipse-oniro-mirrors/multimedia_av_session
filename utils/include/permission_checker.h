/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef PERMISSION_CHECKER_H
#define PERMISSION_CHECKER_H
#include "access_token.h"

namespace OHOS::AVSession {

class PermissionChecker {
public:
    static const int32_t CHECK_SYSTEM_PERMISSION = 0;
    static const int32_t CHECK_MEDIA_RESOURCES_PERMISSION = 1;

    static PermissionChecker& GetInstance();

    int32_t CheckSystemPermission(Security::AccessToken::AccessTokenID tokenId);

    int32_t CheckPermission(int32_t checkPermissionType);

    static bool CheckSystemPermissionByUid(int uid);

private:
    static constexpr const char* MANAGE_MEDIA_RESOURCES = "ohos.permission.MANAGE_MEDIA_RESOURCES";
    static constexpr int UID_TRANSFORM_DIVISOR = 200000;

    bool IsSystemApp();
    int32_t CheckMediaResourcePermission(
        Security::AccessToken::AccessTokenID callerToken, std::string permissionName);
};
} // namespace OHOS::AVSession
#endif // PERMISSION_CHECKER_H