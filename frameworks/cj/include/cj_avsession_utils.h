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

#include "avcall_state.h"
#include "avmeta_data.h"
#include "avcall_meta_data.h"
#include "avsession_pixel_map.h"
#include "avsession_descriptor.h"
#include "avqueue_item.h"
#include "avmedia_description.h"
#include "avplayback_state.h"
#include "avsession_errors.h"
#include "cj_avsession_prototypes.h"

namespace OHOS::AVSession {
const int32_t CJNO_ERROR = 0;

/* Native => Cangjie FFI Object*/
/*Primitive Type*/
int32_t convertNativeToCJStruct(const std::string& native, char*& cj);
int32_t convertNativeToCJStruct(const std::vector<std::string>& native, CArray& cj);
int32_t convertNativeToCJStruct(const int64_t& native, int64_t& cj);
int32_t convertNativeToCJStruct(const bool& native, bool& cj);
int32_t convertNativeToCJStruct(const std::vector<int32_t>& native, CArray& cj);
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

/* Canjie FFI Object => Native*/
int32_t convertCJStructToNative(const CArray& cj, AAFwk::WantParams& native);
int32_t convertCJStructToNative(const CAVMetaData& cj, AVMetaData &native);
int32_t convertCJStructToNative(const CArray& cj, std::vector<std::string>& native);
int32_t convertCJStructToNative(const CAVCallMetaData& cj, AVCallMetaData& native);
int32_t convertCJStructToNative(const CAVCallState& cj, AVCallState& native);
int32_t convertCJStructToNative(const CAVPlaybackState& cj, AVPlaybackState& native);
int32_t convertCJStructToNative(const CArray& cj, std::vector<AVQueueItem>& native);
int32_t convertCJStructToNative(const CAVQueueItem& cj, AVQueueItem& native);
int32_t convertCJStructToNative(const CAVMediaDescription& cj, AVMediaDescription& native);

} // namespace AVSession::OHOS

#endif // OHOS_CJ_AVSESSION_UTILS_H