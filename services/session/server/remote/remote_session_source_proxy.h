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

#ifndef OHOS_REMOTE_SESSION_SOURCE_PROXY_H
#define OHOS_REMOTE_SESSION_SOURCE_PROXY_H

#include "avsession_info.h"
#include "avsession_item.h"
#include "remote_session_source.h"
#include "remote_session_source_impl.h"

namespace OHOS::AVSession {
class RemoteSessionSourceProxy : public RemoteSessionSource {
public:
    int32_t CastSessionToRemote(const sptr <AVSessionItem>& session, const std::string& sourceDevice,
                                const std::string& sinkDevice, const std::string& sinkCapability) override;

    int32_t CancelCastAudio(const std::string& sinkDevice) override;

    int32_t SetAVMetaData(const AVMetaData& metaData) override;

    int32_t SetSessionEventRemote(const std::string& event, const AAFwk::WantParams& args) override;

    int32_t SetAVPlaybackState(const AVPlaybackState& state) override;

    int32_t SetAVQueueItems(const std::vector<AVQueueItem>& items) override;

    int32_t SetAVQueueTitle(const std::string& title) override;

    int32_t SetExtrasRemote(const AAFwk::WantParams& extras) override;

    RemoteSessionSourceProxy();
    ~RemoteSessionSourceProxy() override;

private:
    int32_t LoadSourceImplement();

    int32_t UnLoadSourceImplement();

    void *handle_ = nullptr;
    RemoteSessionSourceImpl *sourceImpl_ = nullptr;
};
} // namespace OHOS::AVSession
#endif // OHOS_REMOTE_SESSION_SOURCE_PROXY_H