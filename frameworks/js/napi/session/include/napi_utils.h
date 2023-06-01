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
#include <list>
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "avsession_log.h"
#include "audio_system_manager.h"
#include "avsession_info.h"
#include "want_agent.h"
#include "napi_base_context.h"
#include "ability.h"

/* check condition related to argc/argv, return and logging. */
#define CHECK_ARGS_RETURN_VOID(context, condition, message, code)               \
    do {                                                               \
        if (!(condition)) {                                            \
            (context)->status = napi_invalid_arg;                         \
            (context)->errMessage = std::string(message);                      \
            (context)->errCode = code;                      \
            SLOGE("test (" #condition ") failed: " message);           \
            return;                                                    \
        }                                                              \
    } while (0)

#define CHECK_STATUS_RETURN_VOID(context, message, code)                        \
    do {                                                               \
        if ((context)->status != napi_ok) {                               \
            (context)->errMessage = std::string(message);                      \
            (context)->errCode = code;                      \
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
    static napi_status SetValue(napi_env env, const std::optional<MMI::KeyEvent::KeyItem> in, napi_value& out);

    /* napi_value <-> MMI::KeyEvent */
    static napi_status GetValue(napi_env env, napi_value in, std::shared_ptr<MMI::KeyEvent>& out);
    static napi_status SetValue(napi_env env, const std::shared_ptr<MMI::KeyEvent>& in, napi_value& out);

    /* napi_value <-> AbilityRuntime::WantAgent::WantAgent */
    static napi_status GetValue(napi_env env, napi_value in, AbilityRuntime::WantAgent::WantAgent*& out);
    static napi_status SetValue(napi_env env, AbilityRuntime::WantAgent::WantAgent& in, napi_value& out);

    /* napi_value <-> AAFwk::WantParams */
    static napi_status GetValue(napi_env env, napi_value in, AAFwk::WantParams& out);
    static napi_status SetValue(napi_env env, const AAFwk::WantParams& in, napi_value& out);

    /* napi_value <-> AVMetaData */
    static napi_status GetValue(napi_env env, napi_value in, AVMetaData& out);
    static napi_status SetValue(napi_env env, const AVMetaData& in, napi_value& out);

    /* napi_value <-> AVMediaDescription */
    static napi_status GetValue(napi_env env, napi_value in, AVMediaDescription& out);
    static napi_status SetValue(napi_env env, const AVMediaDescription& in, napi_value& out);

    /* napi_value <-> AVQueueItem */
    static napi_status GetValue(napi_env env, napi_value in, AVQueueItem& out);
    static napi_status SetValue(napi_env env, const AVQueueItem& in, napi_value& out);

    /* napi_value <-> std::vector<AVQueueItem> */
    static napi_status GetValue(napi_env env, napi_value in, std::vector<AVQueueItem>& out);
    static napi_status SetValue(napi_env env, const std::vector<AVQueueItem>& in, napi_value& out);

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
    static bool TypeCheck(napi_env env, napi_value value, napi_valuetype expectType);

    static napi_value GetUndefinedValue(napi_env env);

    static napi_status GetPropertyNames(napi_env env, napi_value in, std::vector<std::string>& out);

    static napi_status GetDateValue(napi_env env, napi_value value, double& result);
    static napi_status SetDateValue(napi_env env, double time, napi_value& result);
    static napi_status GetRefByCallback(napi_env env, std::list<napi_ref> callbackList, napi_value callback,
        napi_ref& callbackRef);

    static napi_status GetStageElementName(napi_env env, napi_value in, AppExecFwk::ElementName& out);
    static napi_status GetFaElementName(napi_env env, AppExecFwk::ElementName& out);
    static napi_status GetValue(napi_env env, napi_value in, AppExecFwk::ElementName& out);
    static napi_status GetValue(napi_env env, napi_value in, SessionToken& out);
    static napi_status GetValue(napi_env env, napi_value in, AudioStandard::DeviceRole& out);
    static napi_status GetValue(napi_env env, napi_value in, AudioStandard::DeviceType& out);
    static napi_status GetValue(napi_env env, napi_value in, AudioStandard::AudioDeviceDescriptor& out);
    static napi_status GetValue(napi_env env, napi_value in, std::vector<AudioStandard::AudioDeviceDescriptor>& out);
    static napi_status GetSampleRate(napi_env env, napi_value in, AudioStandard::AudioSamplingRate& out);
    static napi_status GetChannels(napi_env env, napi_value in, AudioStandard::AudioChannel& out);
    static napi_status GetChannelMasks(napi_env env, napi_value in, int32_t& out);
    static napi_status SetOutPutDeviceIdValue(napi_env env, const std::vector<std::string>& in, napi_value& out);

    static constexpr int KEYEVENT_ACTION_JS_NATIVE_DELTA = 1;

    static napi_status ThrowError(napi_env env, const char* napiMessage, int32_t napiCode);

    static constexpr size_t ARGC_ONE = 1;
    static constexpr size_t ARGC_TWO = 2;
    static constexpr size_t ARGC_THERE = 3;

    static constexpr size_t ARGV_FIRST = 0;
    static constexpr size_t ARGV_SECOND = 1;
    static constexpr size_t ARGV_THIRD = 2;
};
}
#endif // NAPI_UTILS_H
