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

#ifndef ANI_UTILS_H
#define ANI_UTILS_H

#include <chrono>
#include <cstdint>
#include <map>
#include <list>

#include "ani.h"
#include "avsession_log.h"
#include "ani_av_session_enum.h"

#define CHECK_ARGS_RETURN_VOID(context, condition, message, code)               \
    do {                                                                        \
        if (!(condition)) {                                                     \
            (context)->status = ANI_INVALID_ARGS;                               \
            (context)->errMessage = std::string(message);                       \
            (context)->errCode = code;                                          \
            SLOGE("test (" #condition ") failed: " message);                    \
            return;                                                             \
        }                                                                       \
    } while (0)

#define CHECK_STATUS_RETURN_VOID(context, message, code)                        \
    do {                                                                        \
        if ((context)->status != ANI_OK) {                                      \
            (context)->errMessage = std::string(message);                       \
            (context)->errCode = code;                                          \
            SLOGE("test (context->status == ANI_OK) failed: " message);         \
            return;                                                             \
        }                                                                       \
    } while (0)

#define CHECK_RETURN(condition, message, retVal)                                \
    do {                                                                        \
        if (!(condition)) {                                                     \
            SLOGE("test (" #condition ") failed: " message);                    \
            return retVal;                                                      \
        }                                                                       \
    } while (0)

#define CHECK_RETURN_VOID(condition, message)                                   \
    do {                                                                        \
        if (!(condition)) {                                                     \
            SLOGE("test (" #condition ") failed: " message);                    \
            return;                                                             \
        }                                                                       \
    } while (0)

namespace OHOS::AVSession {
class AniUtils {
public:
    static int32_t ConvertSessionType(const std::string& typeString);
    static ani_status GetString(ani_env *env, ani_string arg, std::string &str);
    static ani_status GetValue(ani_env *env, ani_object object, AppExecFwk::ElementName& out);

    static ani_boolean Equals(ani_env *env, ani_ref value, ani_ref copy);
    static ani_status GetRefByCallback(ani_env *env, std::list<ani_ref> callbackList, ani_ref callback,
        ani_ref& callbackRef);
    static ani_status GetStageElementName(ani_env *env, ani_object object, AppExecFwk::ElementName& out);
    static ani_status GetFaElementName(ani_env *env, AppExecFwk::ElementName& out);

    static ani_status SetValue(ani_env *env, const double& in, ani_object& object);
    static ani_status SetValue(ani_env *env, const int32_t& in, ani_object &object);
    static ani_status SetValue(ani_env *env, const int64_t& in, ani_object &object);
    static ani_status SetValue(ani_env *env, const std::string& in, ani_object& object);
    static ani_status SetValue(ani_env *env, const CastDisplayInfo& in, ani_object &object);
    static ani_status SetValue(ani_env *env, const std::vector<CastDisplayInfo>& in, ani_object &aniArray);

    static ani_status ToAniString(ani_env *env, const std::string &str, ani_string &aniStr);
    static ani_status ToAniBooleanObject(ani_env *env, bool src, ani_object &aniObj);
    static ani_status ToAniIntObject(ani_env *env, int32_t src, ani_object &aniObj);
    static ani_status ToAniLongObject(ani_env *env, int64_t src, ani_object &aniObj);

    static ani_status ThrowError(ani_env *env, const char *aniMessage, int32_t aniCode);
    static ani_ref GetUndefinedValue(ani_env *env);
    static ani_object CreateCastDisplayInfoAniObject(ani_env *env);
    static ani_object CreateCastDisplayInfoAniObject(ani_env *env, ani_ref ref);
};
}
#endif // ANI_UTILS_H
