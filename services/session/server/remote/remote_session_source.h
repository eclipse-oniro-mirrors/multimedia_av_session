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

#ifndef OHOS_REMOTE_SESSION_SOURCE_H
#define OHOS_REMOTE_SESSION_SOURCE_H

#include "avsession_info.h"
#include "avsession_item.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avmedia_description.h"
#include "avqueue_item.h"

namespace OHOS::AVSession {
class RemoteSessionSource {
public:
    virtual int32_t CastSessionToRemote(const sptr<AVSessionItem>& session, const std::string& sourceDevice,
                                        const std::string& sinkDevice, const std::string& sinkCapability) = 0;
    virtual int32_t CancelCastAudio(const std::string& sinkDevice) = 0;
    virtual int32_t SetAVMetaData(const AVMetaData& metaData) = 0;
    virtual int32_t SetAVPlaybackState(const AVPlaybackState& state) = 0;
    virtual int32_t SetSessionEventRemote(const std::string& event, const AAFwk::WantParams& args) = 0;
    virtual int32_t SetAVQueueItems(const std::vector<AVQueueItem>& itemId) = 0;
    virtual int32_t SetAVQueueTitle(const std::string& title) = 0;
    virtual ~RemoteSessionSource() = default;
};
} // namespace OHOS::AVSession
#endif // OHOS_REMOTE_SESSION_SOURCE_H