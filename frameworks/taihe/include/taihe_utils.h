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

#ifndef TAIHE_UTILS_H
#define TAIHE_UTILS_H

#include <chrono>
#include <cstdint>
#include <map>
#include <list>
#include <algorithm>

#include "avsession_log.h"
#include "audio_system_manager.h"
#include "avsession_info.h"
#include "want_agent.h"
#include "ability.h"
#include "media_info_holder.h"
#include "media_info.h"
#include "av_file_descriptor.h"
#include "avqueue_info.h"
#include "avsession_controller.h"
#include "av_data_src_descriptor.h"
#include "taihe_avsession_enum.h"
#include "taihe_headers.h"

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

#define CHECK_ERROR_RETURN_RET_LOG(cond, ret, fmt, ...)  \
    do {                                                 \
        if (cond) {                                      \
            SLOGE(fmt, ##__VA_ARGS__);           \
            return ret;                                  \
        }                                                \
    } while (0)

#define CHECK_RETURN_VOID_THROW_ON_ERR(condition, message)   \
    do {                                                     \
        if (!(condition)) {                                  \
            SLOGE("test (" #condition ") failed: " message); \
            TaiheUtils::ThrowAddCallbackError();             \
            return;                                          \
        }                                                    \
    } while (0)

#define CHECK_RETURN_VOID_THROW_OFF_ERR(condition, message)  \
    do {                                                     \
        if (!(condition)) {                                  \
            SLOGE("test (" #condition ") failed: " message); \
            TaiheUtils::ThrowRemoveCallbackError();          \
            return;                                          \
        }                                                    \
    } while (0)

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;
using namespace ohos::multimodalInput;
class TaiheUtils {
public:
    static constexpr int COAP = 2;
    static constexpr int TIME_OUT_SECOND = 5;
    static constexpr int HTTP_ERROR_CODE = 400;
    static constexpr int KEYEVENT_ACTION_JS_NATIVE_DELTA = 1;
    static constexpr char CLASS_NAME_BUSINESSERROR[] = "@ohos.base.BusinessError";

    static void ThrowError(int32_t errCode, const std::string &errMsg = "");
    static void ThrowAddCallbackError();
    static void ThrowRemoveCallbackError();
    static int32_t ConvertSessionType(const std::string& typeString);
    static std::string ConvertSessionType(int32_t type);

    static ani_object CreateAniEmptyRecord();
    static bool IsAniUndefined(ani_env *env, ani_object obj);
    static bool IsAniArray(ani_env *env, ani_object obj);
    static int32_t GetAniPropertyObject(ani_env *env, ani_object obj, const std::string &name, ani_object &value);
    static int32_t GetAniPropertyInt32(ani_env *env, ani_object obj, const std::string &name, int32_t &value);
    static int32_t GetAniOptionalPropertyInt32(ani_env *env, ani_object obj, const std::string &name, int32_t &value);
    static int32_t GetAniPropertyInt32Array(ani_env *env, ani_object obj, const std::string &name,
        std::vector<int32_t> &array);
    static int32_t GetAniPropertyInt64(ani_env *env, ani_object obj, const std::string &name, int64_t &value);
    static int32_t GetAniOptionalPropertyInt64(ani_env *env, ani_object obj, const std::string &name, int64_t &value);
    static int32_t GetAniPropertyString(ani_env *env, ani_object obj, const std::string &name, std::string &value);
    static int32_t GetAniOptionalPropertyString(ani_env *env, ani_object obj, const std::string &name,
        std::string &value);
    static int32_t GetAniPropertyEnumInt32(ani_env *env, ani_object obj, const std::string &name, int32_t &value);

    static int32_t GetStageElementName(uintptr_t context, OHOS::AppExecFwk::ElementName &out);
    static int32_t GetString(string_view in, std::string &out);
    static int32_t GetString(string in, std::string &out);
    static int32_t GetOptionalString(optional<string> in, std::string &out);
    static int32_t GetStringArray(const array<string> &in, std::vector<std::string> &out);
    static int32_t GetUIntArray(const array<uint32_t> &in, std::vector<uint32_t> &out);
    static int32_t GetSessionToken(SessionToken const &in, OHOS::AVSession::SessionToken &out);
    static int32_t GetDeviceInfo(DeviceInfo const &in, OHOS::AVSession::DeviceInfo &out);
    static int32_t GetOutputDeviceInfo(ohos::multimedia::avsession::avSession::OutputDeviceInfo const &in,
        OHOS::AVSession::OutputDeviceInfo &out);
    static int32_t GetWantParams(uintptr_t in, OHOS::AAFwk::WantParams &out);
    static int32_t GetWantAgent(uintptr_t in, OHOS::AbilityRuntime::WantAgent::WantAgent* &out);
    static int32_t GetAVFileDescriptor(uintptr_t in, OHOS::AVSession::AVFileDescriptor &out);
    static int32_t GetAVDataSrcDescriptor(uintptr_t in, OHOS::AVSession::AVDataSrcDescriptor &out);
    static std::shared_ptr<OHOS::Media::PixelMap> GetImagePixelMap(uintptr_t in);
    static int32_t GetAudioDeviceDescriptor(uintptr_t in, OHOS::AudioStandard::AudioDeviceDescriptor &out);
    static int32_t GetAudioDeviceDescriptors(array_view<uintptr_t> in,
        std::vector<OHOS::AudioStandard::AudioDeviceDescriptor> &out);
    static int32_t GetAudioCapabilities(AudioCapabilities const &in, OHOS::AVSession::AudioCapabilities &out);
    static int32_t GetKeyEvent(keyEvent::KeyEvent const &in, OHOS::MMI::KeyEvent &out);
    static int32_t GetAVCallState(const ohos::multimedia::avsession::avSession::AVCallState &in,
        OHOS::AVSession::AVCallState &out);
    static int32_t GetAVQueueItem(const ohos::multimedia::avsession::avSession::AVQueueItem &in,
        OHOS::AVSession::AVQueueItem &out);
    static int32_t GetAVQueueItemArray(const array<ohos::multimedia::avsession::avSession::AVQueueItem> &in,
        std::vector<OHOS::AVSession::AVQueueItem> &out);
    static int32_t GetAVCallMetaData(const CallMetadata &in, OHOS::AVSession::AVCallMetaData &out);

    static int32_t ToAniDoubleObject(ani_env *env, double in, ani_object &out);
    static ani_object ToAniElementName(const OHOS::AppExecFwk::ElementName &in);
    static ani_object ToAniWantParams(const OHOS::AAFwk::WantParams &in);
    static ani_object ToAniWantAgent(OHOS::AbilityRuntime::WantAgent::WantAgent* &in);
    static ani_object ToAniAVFileDescriptor(const OHOS::AVSession::AVFileDescriptor &in);
    static ani_object ToAniAVDataSrcDescriptor(const OHOS::AVSession::AVDataSrcDescriptor &in);
    static ani_object ToAniAudioStreamInfo(const OHOS::AVSession::AudioStreamInfo &in);
    static ani_object ToAniImagePixelMap(std::shared_ptr<OHOS::Media::PixelMap> &in);
    static ani_object ToAniKeyEvent(const OHOS::MMI::KeyEvent &in);

    static DeviceInfo ToTaiheDeviceInfo(const OHOS::AVSession::DeviceInfo &in);
    static ohos::multimedia::avsession::avSession::OutputDeviceInfo ToTaiheOutputDeviceInfo(
        const OHOS::AVSession::OutputDeviceInfo &in);
    static DeviceState ToTaiheDeviceState(const OHOS::AVSession::DeviceState &in);
    static AVSessionDescriptor ToTaiheAVSessionDescriptor(const OHOS::AVSession::AVSessionDescriptor &in);
    static taihe::array<AVSessionDescriptor> ToTaiheAVSessionDescriptorArray(
        const std::vector<OHOS::AVSession::AVSessionDescriptor> &in);
    static AVImageType ToTaiheAVImageType(const std::shared_ptr<OHOS::AVSession::AVSessionPixelMap> &avPixelMap,
        const std::string &uri);
    static AVQueueInfo ToTaiheAVQueueInfo(const OHOS::AVSession::AVQueueInfo &in);
    static taihe::array<AVQueueInfo> ToTaiheAVQueueInfoArray(const std::vector<OHOS::AVSession::AVQueueInfo> &in);
    static CastDisplayInfo ToTaiheCastDisplayInfo(const OHOS::AVSession::CastDisplayInfo &in);
    static taihe::array<CastDisplayInfo> ToTaiheCastDisplayInfoArray(
        const std::vector<OHOS::AVSession::CastDisplayInfo> &in);
    static AVMediaDescription ToTaiheAVMediaDescription(const std::shared_ptr<OHOS::AVSession::AVMediaDescription> &in);
    static ohos::multimedia::avsession::avSession::AVQueueItem ToTaiheAVQueueItem(
        const OHOS::AVSession::AVQueueItem &in);
    static taihe::array<ohos::multimedia::avsession::avSession::AVQueueItem> ToTaiheAVQueueItemArray(
        const std::vector<OHOS::AVSession::AVQueueItem> &in);
    static AVMetadata ToTaiheAVMetaData(const OHOS::AVSession::AVMetaData &in);
    static PlaybackPosition ToTaihePlaybackPosition(const OHOS::AVSession::AVPlaybackState::Position &in);
    static ohos::multimedia::avsession::avSession::AVPlaybackState ToTaiheAVPlaybackState(
        const OHOS::AVSession::AVPlaybackState &in);
    static CallMetadata ToTaiheAVCallMetaData(const OHOS::AVSession::AVCallMetaData &in);
    static ohos::multimedia::avsession::avSession::AVCallState ToTaiheAVCallState(
        const OHOS::AVSession::AVCallState &in);
    static taihe::array<string> ToTaiheStringArray(const std::vector<std::string> &in);
    static taihe::array<uint8_t> ToTaiheUint8Array(const std::vector<uint8_t> &in);
    static ani_object ToBusinessError(ani_env *env, int32_t code, const std::string &message);
    static taihe::array<AVSessionController> ToTaiheAVSessionControllerArray(
        const std::vector<std::shared_ptr<OHOS::AVSession::AVSessionController>> &in);
    static taihe::array<DecoderType> ToTaiheDecoderTypeArray(const std::vector<std::string> &in);
    static keyEvent::KeyEvent ToTaiheKeyEvent(const OHOS::MMI::KeyEvent &in);
    static AudioCapabilities ToTaiheAudioCapabilities(const OHOS::AVSession::AudioCapabilities &in);

    static ohos::multimedia::avsession::avSession::OutputDeviceInfo CreateUndefinedOutputDeviceInfo();

    static size_t WriteCallback(std::uint8_t *ptr, size_t size, size_t nmemb, std::vector<std::uint8_t> *imgBuffer);
    static bool CurlSetRequestOptions(std::vector<std::uint8_t> &imgBuffer, const std::string &uri);
    static bool DoDownloadInCommon(std::shared_ptr<OHOS::Media::PixelMap> &pixelMap, const std::string &uri);
    static int32_t GetRefByCallback(std::list<std::shared_ptr<uintptr_t>> callbackList,
        std::shared_ptr<uintptr_t> callback, std::shared_ptr<uintptr_t> &targetCb);
    static bool Equals(std::shared_ptr<uintptr_t> src, std::shared_ptr<uintptr_t> dst);

    template<typename... Params>
    static std::shared_ptr<uintptr_t> TypeCallback(callback_view<void(Params...)> callback)
    {
        std::shared_ptr<taihe::callback<void(Params...)>> taiheCallback =
            std::make_shared<taihe::callback<void(Params...)>>(callback);
        return std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    }

    static std::shared_ptr<uintptr_t> TypeCallback(callback_view<void()> callback)
    {
        std::shared_ptr<taihe::callback<void()>> taiheCallback =
            std::make_shared<taihe::callback<void()>>(callback);
        return std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);
    }
};
} // namespace ANI::AVSession
#endif // TAIHE_UTILS_H
