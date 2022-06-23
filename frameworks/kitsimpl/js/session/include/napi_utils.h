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

#ifndef NAPI_UTILS_H
#define NAPI_UTILS_H

#include <cstdint>
#include <map>
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "avsession_log.h"
#include "avsession_descriptor.h"
#include "avmeta_data.h"
#include "avcontrol_command.h"
#include "avplayback_state.h"
#include "key_event.h"
#include "want_agent.h"

/* check condition related to argc/argv, return and logging. */
#define CHECK_ARGS_RETURN_VOID(context, condition, message)               \
    do {                                                               \
        if (!(condition)) {                                            \
            (context)->status = napi_invalid_arg;                         \
            (context)->error = std::string(message);                      \
            SLOGE("test (" #condition ") failed: " message);           \
            return;                                                    \
        }                                                              \
    } while (0)

#define CHECK_STATUS_RETURN_VOID(context, message)                        \
    do {                                                               \
        if ((context)->status != napi_ok) {                               \
            (context)->error = std::string(message);                      \
            SLOGE("test (context->status == napi_ok) failed: " message);  \
            return;                                                    \
        }                                                              \
    } while (0)

/* check condition, return and logging if condition not true. */
#define CHECK_RETURN(condition, message, retVal)             \
    do {                                                     \
        if (!(condition)) {                                  \
            SLOGE("test (" #condition ") failed: " message); \
            return retVal;                                   \
        }                                                    \
    } while (0)

#define CHECK_RETURN_VOID(condition, message)                \
    do {                                                     \
        if (!(condition)) {                                  \
            SLOGE("test (" #condition ") failed: " message); \
            return;                                          \
        }                                                    \
    } while (0)

namespace OHOS::AVSession {
class NapiUtils {
public:
    static int32_t ConvertSessionType(const std::string& typeString);
    static std::string ConvertSessionType(int32_t type);

    /* napi_value <-> bool */
    static napi_status GetValue(napi_env env, napi_value in, bool& out);
    static napi_status SetValue(napi_env env, const bool& in, napi_value& out);

    /* napi_value <-> int32_t */
    static napi_status GetValue(napi_env env, napi_value in, int32_t& out);
    static napi_status SetValue(napi_env env, const int32_t& in, napi_value& out);

    /* napi_value <-> uint32_t */
    static napi_status GetValue(napi_env env, napi_value in, uint32_t& out);
    static napi_status SetValue(napi_env env, const uint32_t& in, napi_value& out);

    /* napi_value <-> int64_t */
    static napi_status GetValue(napi_env env, napi_value in, int64_t& out);
    static napi_status SetValue(napi_env env, const int64_t& in, napi_value& out);

    /* napi_value <-> double */
    static napi_status GetValue(napi_env env, napi_value in, double& out);
    static napi_status SetValue(napi_env env, const double& in, napi_value& out);

    /* napi_value <-> std::string */
    static napi_status GetValue(napi_env env, napi_value in, std::string& out);
    static napi_status SetValue(napi_env env, const std::string& in, napi_value& out);

    /* napi_value <-> AppExecFwk::ElementName */
    static napi_status SetValue(napi_env env, const AppExecFwk::ElementName& in, napi_value& out);

    /* napi_value <-> OutputDeviceInfo */
    static napi_status SetValue(napi_env env, const OutputDeviceInfo& in, napi_value& out);

    /* napi_value <-> AVSessionDescriptor */
    static napi_status SetValue(napi_env env, const AVSessionDescriptor& in, napi_value& out);

    /* napi_value <-> MMI::KeyEvent::KeyItem */
    static napi_status GetValue(napi_env env, napi_value in, MMI::KeyEvent::KeyItem& out);
    static napi_status SetValue(napi_env env, const MMI::KeyEvent::KeyItem& in, napi_value& out);

    /* napi_value <-> MMI::KeyEvent */
    static napi_status GetValue(napi_env env, napi_value in, std::shared_ptr<MMI::KeyEvent>& out);
    static napi_status SetValue(napi_env env, const std::shared_ptr<MMI::KeyEvent>& in, napi_value& out);

    /* napi_value <-> AbilityRuntime::WantAgent::WantAgent */
    static napi_status GetValue(napi_env env, napi_value in, AbilityRuntime::WantAgent::WantAgent*& out);
    static napi_status SetValue(napi_env env, const AbilityRuntime::WantAgent::WantAgent& in, napi_value& out);

    /* napi_value <-> AVMetaData */
    static napi_status GetValue(napi_env env, napi_value in, AVMetaData& out);
    static napi_status SetValue(napi_env env, const AVMetaData& in, napi_value& out);

    /* napi_value <-> AVPlaybackState */
    static napi_status GetValue(napi_env env, napi_value in, AVPlaybackState& out);
    static napi_status SetValue(napi_env env, const AVPlaybackState& in, napi_value& out);

    /* napi_value <-> std::vector<std::string> */
    static napi_status GetValue(napi_env env, napi_value in, std::vector<std::string>& out);
    static napi_status SetValue(napi_env env, const std::vector<std::string>& in, napi_value& out);

    /* napi_value <-> std::vector<uint8_t> */
    static napi_status GetValue(napi_env env, napi_value in, std::vector<uint8_t>& out);
    static napi_status SetValue(napi_env env, const std::vector<uint8_t>& in, napi_value& out);

    /* napi_value <-> std::vector<int32_t> */
    static napi_status GetValue(napi_env env, napi_value in, std::vector<int32_t>& out);
    static napi_status SetValue(napi_env env, const std::vector<int32_t>& in, napi_value& out);

    /* napi_value <-> std::vector<uint32_t> */
    static napi_status GetValue(napi_env env, napi_value in, std::vector<uint32_t>& out);
    static napi_status SetValue(napi_env env, const std::vector<uint32_t>& in, napi_value& out);

    /* napi_value <-> std::vector<int64_t> */
    static napi_status GetValue(napi_env env, napi_value in, std::vector<int64_t>& out);
    static napi_status SetValue(napi_env env, const std::vector<int64_t>& in, napi_value& out);

    /* napi_value <-> std::vector<double> */
    static napi_status GetValue(napi_env env, napi_value in, std::vector<double>& out);
    static napi_status SetValue(napi_env env, const std::vector<double>& in, napi_value& out);

    /* std::vector<AVSessionDescriptor> <-> napi_value */
    static napi_status SetValue(napi_env env, const std::vector<AVSessionDescriptor>& in, napi_value& out);

    /* napi_get_named_property wrapper */
    template <typename T>
    static inline napi_status GetNamedProperty(napi_env env, napi_value in, const std::string& prop, T& value)
    {
        bool hasProp = false;
        napi_status status = napi_has_named_property(env, in, prop.c_str(), &hasProp);
        if ((status == napi_ok) && hasProp) {
            napi_value inner = nullptr;
            status = napi_get_named_property(env, in, prop.c_str(), &inner);
            if ((status == napi_ok) && (inner != nullptr)) {
                return GetValue(env, inner, value);
            }
        }
        return napi_invalid_arg;
    };

    /* napi_unwrap with napi_instanceof */
    static napi_status Unwrap(napi_env env, napi_value in, void** out, napi_value constructor);

    static bool Equals(napi_env env, napi_value value, napi_ref copy);

    static napi_value GetUndefinedValue(napi_env env);

    static napi_status GetPropertyNames(napi_env env, napi_value in, std::vector<std::string>& out);
};
}
#endif // NAPI_UTILS_H