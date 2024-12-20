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

#ifndef OHOS_CJ_AVSESSION_UTILS_H
#define OHOS_CJ_AVSESSION_UTILS_H

#include "want_agent.h"
#include "avcall_state.h"
#include "avmeta_data.h"
#include "avcall_meta_data.h"
#include "avsession_pixel_map.h"
#include "avsession_descriptor.h"
#include "avqueue_item.h"
#include "avmedia_description.h"
#include "avplayback_state.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avcast_control_command.h"
#include "avcontrol_command.h"
#include "cj_avsession_prototypes.h"
#include "key_event.h"

namespace OHOS::AVSession {
constexpr int32_t CJNO_ERROR = 0;

constexpr int32_t STR_TYPE = 0;
constexpr int32_t I32_TYPE = 1;
constexpr int32_t BOOL_TYPE = 3;
constexpr int32_t FD_TYPE = 4;
constexpr int32_t STR_PTR_TYPE = 5;
constexpr int32_t I32_PTR_TYPE = 6;
constexpr int32_t I64_PTR_TYPE = 7;
constexpr int32_t BOOL_PTR_TYPE = 8;
constexpr int32_t DOUBLE_PTR_TYPE = 9;
constexpr int32_t FD_PTR_TYPE = 10;
constexpr int32_t DOUBLE_TYPE = 11;
constexpr int32_t PIXEL_MAP_TYPE = 13;
constexpr int32_t NONE_VALUE = -1;

/* Native => Cangjie FFI Object*/
/*Primitive Type*/
int32_t convertNativeToCJStruct(const std::string& native, char*& cj);
int32_t convertNativeToCJStruct(const std::vector<std::string>& native, CArray& cj);
int32_t convertNativeToCJStruct(const int32_t& native, int32_t& cj);
int32_t convertNativeToCJStruct(const int64_t& native, int64_t& cj);
int32_t convertNativeToCJStruct(const bool& native, bool& cj);
int32_t convertNativeToCJStruct(const std::vector<int32_t>& native, CArray& cj);
int32_t convertNativeToCJStruct(const std::vector<uint8_t>& native, CArray& cj);
int32_t convertNativeToCJStruct(const AAFwk::WantParams& native, CArray& cj);

/* String | PixelMap*/
int32_t convertNativeToCJStruct(const std::shared_ptr<AVSessionPixelMap>& native, int64_t& cj);
int32_t convertNativeToCJStruct(const std::shared_ptr<AVSessionPixelMap>& native, StringPixelMapParameter& cj);
int32_t convertNativeToCJStruct(const std::string& native, StringPixelMapParameter& cj);

int32_t convertNativeToCJStruct(const AVCallState& native, CAVCallState& cj);
int32_t convertNativeToCJStruct(const AVCallMetaData& native, CAVCallMetaData& cj);
int32_t convertNativeToCJStruct(const AVPlaybackState::Position& native, CPlaybackPosition& cj);
int32_t convertNativeToCJStruct(const AVPlaybackState& native, CAVPlaybackState& cj);
int32_t convertNativeToCJStruct(const AVMetaData& native, CAVMetaData& cj);

int32_t convertNativeToCJStruct(const DeviceInfo& native, CDeviceInfo& cj);
int32_t convertNativeToCJStruct(const OutputDeviceInfo& native, COutputDeviceInfo& cj);

int32_t convertNativeToCJStruct(const AVQueueItem& native, CAVQueueItem& cj);
int32_t convertNativeToCJStruct(const std::vector<AVQueueItem>& native, CArray& cj);
int32_t convertNativeToCJStruct(const AVMediaDescription& native, CAVMediaDescription& cj);
int32_t convertNativeToCJStruct(const AVFileDescriptor& native, CAVFileDescriptor& cj);

int32_t convertNativeToCJStruct(const std::vector<CastDisplayInfo>& native, CArray& cj);
int32_t convertNativeToCJStruct(const CastDisplayInfo& native, CCastDisplayInfo& cj);

int32_t convertNativeToCJStruct(const MMI::KeyEvent::KeyItem& native, CKey& cj);
int32_t convertNativeToCJStruct(const std::vector<MMI::KeyEvent::KeyItem>& native, CKey*& cj);
int32_t convertNativeToCJStruct(const MMI::KeyEvent& native, CInputEvent& cj);
int32_t convertNativeToCJStruct(const MMI::KeyEvent& native, CKeyEvent& cj);

int32_t convertNativeToCJStruct(const AbilityRuntime::WantAgent::WantAgent& native, int64_t& cj);

/* Canjie FFI Object => Native*/
int32_t convertCJStructToNative(const int32_t& cj, int32_t& native);
int32_t convertCJStructToNative(const CKeyEvent& cj, MMI::KeyEvent& native);
int32_t convertCJStructToNative(const CKey& cj, MMI::KeyEvent::KeyItem& native);

int32_t convertCJStructToNative(const CArray& cj, AAFwk::WantParams& native);
int32_t convertCJStructToNative(const CAVMetaData& cj, AVMetaData &native);
int32_t convertCJStructToNative(const CArray& cj, std::vector<std::string>& native);
int32_t convertCJStructToNative(const CAVCallMetaData& cj, AVCallMetaData& native);
int32_t convertCJStructToNative(const CAVCallState& cj, AVCallState& native);
int32_t convertCJStructToNative(const CAVPlaybackState& cj, AVPlaybackState& native);
int32_t convertCJStructToNative(const CArray& cj, std::vector<AVQueueItem>& native);
int32_t convertCJStructToNative(const CAVQueueItem& cj, AVQueueItem& native);
int32_t convertCJStructToNative(const CAVMediaDescription& cj, AVMediaDescription& native);
int32_t convertCJStructToNative(const CAVSessionCommand& cj, AVControlCommand& native);
int32_t convertCJStructToNative(const CAVSessionCommand& cj, AVCastControlCommand& native);
int32_t convertCJStructToNative(const CArray& cj, std::vector<uint8_t>& native);
int32_t convertCJStructToNative(const int64_t& cj, std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>& native);

/* Free cjObject */
void cjStructHeapFree(COutputDeviceInfo& cj);
void cjStructHeapFree(CArray& cj);
void cjStructHeapFree(CCastDisplayInfo& cj);


/* Common Methods */
int32_t CJExecMethod(std::function<int32_t()> method, std::string methodName);

template<class NT, class CJT>
int32_t CJControllerGetterCStruct(
    std::function<int32_t(NT&)> method, CJT& cj, std::string method_name)
{
    NT native;
    int32_t ret = method(native);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("%{public}s failed:%{public}d", method_name.c_str(), ret);
    } else {
        ret = convertNativeToCJStruct(native, cj);
        if (ret != CJNO_ERROR) {
            SLOGE("%{public}s failed:%{public}d", method_name.c_str(), ret);
        }
    }
    return ret;
}

template<class NT, class CJT>
int32_t CJAVSessionSetterCStruct(
    std::function<int32_t(NT&)> method, CJT& cj, std::string method_name)
{
    NT native;
    int32_t ret = convertCJStructToNative(cj, native);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("%{public}s failed:%{public}d", method_name.c_str(), ret);
    } else {
        ret = method(native);
        if (ret != CJNO_ERROR) {
            SLOGE("%{public}s failed:%{public}d", method_name.c_str(), ret);
        }
    }
    return ret;
}
} // namespace AVSession::OHOS

#endif // OHOS_CJ_AVSESSION_UTILS_H