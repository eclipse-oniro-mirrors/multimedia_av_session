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

#ifndef OHOS_REMOTE_SESSION_SYNCER_H
#define OHOS_REMOTE_SESSION_SYNCER_H

#include "avsession_info.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avmedia_description.h"
#include "avqueue_item.h"
#include "avcontrol_command.h"

namespace OHOS::AVSession {
class RemoteSessionSyncer {
public:
    using ObjectDataNotifier = std::function<void(const SessionDataCategory category, const std::string& deviceId)>;
    using ObjectDisconnectNotifier = std::function<void(const std::string& deviceId)>;

    virtual int32_t Init() = 0;

    virtual int32_t PutAVMetaData(const AVMetaData& metaData) = 0;

    virtual int32_t GetAVMetaData(AVMetaData& metaData) = 0;

    virtual int32_t PutAVPlaybackState(const AVPlaybackState& state) = 0;

    virtual int32_t GetAVPlaybackState(AVPlaybackState& state) = 0;

    virtual int32_t PutControlCommand(const AVControlCommand& command) = 0;

    virtual int32_t GetControlCommand(AVControlCommand& command) = 0;

    virtual int32_t PutCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs) = 0;

    virtual int32_t GetCommonCommand(std::string& commonCommand, AAFwk::WantParams& commandArgs) = 0;

    virtual int32_t PutSessionEvent(const std::string& event, const AAFwk::WantParams& args) = 0;

    virtual int32_t GetSessionEvent(std::string& event, AAFwk::WantParams& args) = 0;

    virtual int32_t PutAVQueueItems(const std::vector<AVQueueItem>& items) = 0;

    virtual int32_t GetAVQueueItems(std::vector<AVQueueItem>& items) = 0;
    
    virtual int32_t PutAVQueueTitle(const std::string& items) = 0;

    virtual int32_t GetAVQueueTitle(std::string& items) = 0;

    virtual int32_t PutExtras(const AAFwk::WantParams& extras) = 0;

    virtual int32_t GetExtras(AAFwk::WantParams& extras) = 0;

    virtual int32_t RegisterDataNotifier(const ObjectDataNotifier& notifier) = 0;

    virtual int32_t RegisterDisconnectNotifier(const ObjectDisconnectNotifier& notifier) = 0;

    virtual void Destroy() = 0;

    virtual ~RemoteSessionSyncer() = default;
};
} // namespace OHOS::AVSession
#endif // OHOS_REMOTE_SESSION_SYNCER_H