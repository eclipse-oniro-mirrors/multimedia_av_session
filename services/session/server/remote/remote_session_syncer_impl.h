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

#ifndef OHOS_REMOTE_SESSION_SYNCER_IMPL_H
#define OHOS_REMOTE_SESSION_SYNCER_IMPL_H

#include "avsession_info.h"
#include "avmeta_data.h"
#include "avplayback_state.h"
#include "avmedia_description.h"
#include "avqueue_item.h"
#include "avcontrol_command.h"
#include "remote_session_syncer.h"
#include "distributed_object.h"
#include "distributed_objectstore.h"
#include "objectstore_errors.h"
#include "avsession_errors.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
using namespace ObjectStore;
class RemoteSessionSyncerImpl : public RemoteSessionSyncer, public ObjectWatcher, public StatusNotifier,
    public std::enable_shared_from_this<RemoteSessionSyncerImpl> {
public:
    RemoteSessionSyncerImpl(const std::string& sourceSessionId, const std::string& sourceDevice,
                            const std::string& sinkDevice);

    int32_t Init() override;

    int32_t PutAVMetaData(const AVMetaData& metaData) override;

    int32_t GetAVMetaData(AVMetaData& metaData) override;

    int32_t PutAVPlaybackState(const AVPlaybackState& state) override;

    int32_t GetAVPlaybackState(AVPlaybackState& state) override;

    int32_t PutControlCommand(const AVControlCommand& command) override;

    int32_t GetControlCommand(AVControlCommand& command) override;

    int32_t PutSessionEvent(const std::string& event, const AAFwk::WantParams& args) override;

    int32_t GetSessionEvent(std::string& event, AAFwk::WantParams& args) override;

    int32_t PutCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs) override;

    int32_t GetCommonCommand(std::string& commonCommand, AAFwk::WantParams& commandArgs) override;

    int32_t PutAVQueueItems(const std::vector<AVQueueItem>& items) override;

    int32_t GetAVQueueItems(std::vector<AVQueueItem>& items) override;
    
    int32_t PutAVQueueTitle(const std::string& items) override;

    int32_t GetAVQueueTitle(std::string& items) override;

    int32_t RegisterDataNotifier(const ObjectDataNotifier& notifier) override;

    int32_t RegisterDisconnectNotifier(const ObjectDisconnectNotifier& notifier) override;

    void OnChanged(const std::string &sessionId, const std::vector<std::string> &keys) override;

    void OnChanged(const std::string &name, const std::string &networkId, const std::string &onlineStatus) override;

    void Destroy() override;

    ~RemoteSessionSyncerImpl() override;

    static constexpr char METADATA_KEY[] = "metaData";
    static constexpr char PLAYBACK_STATE_KEY[] = "playbackState";
    static constexpr char CONTROL_COMMAND_KEY[] = "controlCommand";
    static constexpr char COMMON_COMMAND_KEY[] = "commonCommand";
    static constexpr char SESSION_EVENT_KEY[] = "sessionEvent";
    static constexpr char QUEUE_ITEMS_KEY[] = "queueItems";
    static constexpr char QUEUE_TITLE_KEY[] = "queueTitle";
    static constexpr int RECEIVE_DATA_SIZE_MAX = 500 * 1024;
    const std::map<std::string, SessionDataCategory> categoryMap {
            {METADATA_KEY, SESSION_DATA_META},
            {PLAYBACK_STATE_KEY, SESSION_DATA_PLAYBACK_STATE},
            {CONTROL_COMMAND_KEY, SESSION_DATA_CONTROL_COMMAND},
            {COMMON_COMMAND_KEY, SESSION_DATA_COMMON_COMMAND},
            {SESSION_EVENT_KEY, SESSION_DATA_SET_EVENT},
            {QUEUE_ITEMS_KEY, SESSION_DATA_QUEUE_ITEMS},
            {QUEUE_TITLE_KEY, SESSION_DATA_QUEUE_TITLE},
    };

private:
    int32_t PutData(const std::string &key, std::vector<uint8_t> &data);

    int32_t GetData(const std::string &key, std::vector<uint8_t> &data);

    std::string objectName_;
    DistributedObject *object_;
    DistributedObjectStore *objectStore_;
    ObjectDataNotifier objectDataNotifier_;
    ObjectDisconnectNotifier objectDisconnectNotifier_;
    std::string sourceSessionId_;
    std::string sourceDevice_;
    std::string sinkDevice_;
};
} // namespace OHOS::AVSession
#endif // OHOS_REMOTE_SESSION_SYNCER_IMPL_H