/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_CJ_AVSESSION_IMPL_H
#define OHOS_CJ_AVSESSION_IMPL_H

#include "av_session.h"
#include "ffi_remote_data.h"
#include "cj_avsession_prototypes.h"

namespace OHOS::AVSession {

class CJAVSessionImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(CJAVSessionImpl, OHOS::FFI::FFIData)
public:
    CJAVSessionImpl(std::shared_ptr<AVSession> session);
    int32_t SetAVMetaData(CAVMetaData& data);
    int32_t SetAVCallMetaData(CAVCallMetaData& dat);
    int32_t SetAVCallState(CAVCallState& state);
    int32_t SetAVPlaybackState(CAVPlaybackState& state);
    int32_t SetAVQueueItems(CArray& items);
    int32_t SetAVQueueTitle(char*& title);
    int32_t SetExtras(CArray& extras);
    int32_t GetController();
    int32_t GetOutputDevice(COutputDeviceInfo& outputDeviceInfo);
    int32_t Activate();
    int32_t Deactivate();
    int32_t Destroy();
    int32_t StopCasting();

    std::string GetSessionId() { return sessionId_; }
private:
    std::string sessionId_;
    std::string sessionType_;
    std::shared_ptr<AVSession> session_;
};

}  // namespace AVSession::OHOS

#endif // OHOS_CJ_AVSESSION_IMPL_H