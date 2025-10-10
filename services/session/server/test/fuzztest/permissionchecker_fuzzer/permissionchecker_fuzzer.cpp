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
#include "mock_token_flag.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

static const int32_t MIN_SIZE_NUM = 4;

void OHOS::AVSession::CheckPermissionTest001()
{
    PermissionChecker::GetInstance().CheckPermission(PermissionChecker::CHECK_SYSTEM_PERMISSION);
}

void OHOS::AVSession::CheckPermissionTest002()
{
    PermissionChecker::GetInstance().CheckPermission(PermissionChecker::CHECK_MEDIA_RESOURCES_PERMISSION);
}

void OHOS::AVSession::CheckPermissionTest003()
{
    int32_t CHECK_PERMISSION = 6;
    PermissionChecker::GetInstance().CheckPermission(CHECK_PERMISSION);
}

void OHOS::AVSession::CheckPermissionTest004(uint8_t* data, size_t size)
{
    Notification::MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    int32_t invalidType = *reinterpret_cast<const int32_t*>(data);
    PermissionChecker::GetInstance().CheckPermission(invalidType);
}

void OHOS::AVSession::CheckSystemPermissionTest001()
{
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    PermissionChecker::GetInstance().CheckSystemPermission(tokenId);
}

void OHOS::AVSession::CheckSystemPermissionTest002(uint8_t* data, size_t size)
{
    Notification::MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    uint32_t tokenId = *reinterpret_cast<const uint32_t*>(data);
    PermissionChecker::GetInstance().CheckSystemPermission(tokenId);
    OHOS::Notification::MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_INVALID);
}

void OHOS::AVSession::CheckMediaResourcePermissionTest001(uint8_t* data, size_t size)
{
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    std::string permissionName(reinterpret_cast<const char*>(data), size);
    PermissionChecker::GetInstance().IsSystemApp();
    PermissionChecker::GetInstance().CheckMediaResourcePermission(tokenId, permissionName);
}

void OHOS::AVSession::CheckSystemPermissionByUidTest001()
{
    PermissionChecker::GetInstance().CheckSystemPermissionByUid(-1);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    SLOGI("the maximum length of size should not be verified");
    if ((data == nullptr) || (size < MIN_SIZE_NUM)) {
        return 0;
    }
    OHOS::AVSession::CheckPermissionTest001();
    OHOS::AVSession::CheckPermissionTest002();
    OHOS::AVSession::CheckPermissionTest003();
    OHOS::AVSession::CheckSystemPermissionTest001();
    OHOS::AVSession::CheckMediaResourcePermissionTest001(data, size);
    OHOS::AVSession::CheckSystemPermissionByUidTest001();
    return 0;
}