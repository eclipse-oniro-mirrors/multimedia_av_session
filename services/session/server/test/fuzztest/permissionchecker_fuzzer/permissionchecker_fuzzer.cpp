/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "avsession_log.h"
#include "permissionchecker_fuzzer.h"
#include "ipc_skeleton.h"
#include "permission_checker.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

static const int32_t MAX_CODE_LEN  = 512;
static const int32_t MIN_SIZE_NUM = 4;

void OHOS::AVSession::CheckPermissionTest001(uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }

    PermissionChecker permissionChecker;
    permissionChecker.CheckPermission(PermissionChecker::CHECK_SYSTEM_PERMISSION);
}

void OHOS::AVSession::CheckPermissionTest002(uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }

    PermissionChecker permissionChecker;
    permissionChecker.CheckPermission(PermissionChecker::CHECK_MEDIA_RESOURCES_PERMISSION);
}

void OHOS::AVSession::CheckPermissionTest003(uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }

    int32_t CHECK_PERMISSION = 6;
    PermissionChecker permissionChecker;
    permissionChecker.CheckPermission(CHECK_PERMISSION);
}

void OHOS::AVSession::CheckSystemPermissionTest001(uint8_t *data, size_t size)
{
    PermissionChecker permissionChecker;
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    permissionChecker.CheckSystemPermission(tokenId);
}

void OHOS::AVSession::CheckMediaResourcePermissionTest001(uint8_t *data, size_t size)
{
    PermissionChecker permissionChecker;
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    std::string permissionName = "permissionName";
    permissionChecker.IsSystemApp();
    permissionChecker.CheckMediaResourcePermission(tokenId, permissionName);
}

void OHOS::AVSession::CheckSystemPermissionByUidTest001(uint8_t *data, size_t size)
{
    PermissionChecker permissionChecker;
    int uid = *(reinterpret_cast<const int*>(data));
    permissionChecker.CheckSystemPermissionByUid(uid);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::CheckPermissionTest001(data, size);
    OHOS::AVSession::CheckPermissionTest002(data, size);
    OHOS::AVSession::CheckPermissionTest003(data, size);
    OHOS::AVSession::CheckSystemPermissionTest001(data, size);
    OHOS::AVSession::CheckMediaResourcePermissionTest001(data, size);
    CheckSystemPermissionByUidTest001(data, size);
    return 0;
}