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

#include "remote_session_sink_impl.h"

#include "avsession_sysevent.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
RemoteSessionSinkImpl::RemoteSessionSinkImpl()
{
}

// LCOV_EXCL_START
extern "C" RemoteSessionSinkImpl* CreateRemoteSessionSinkImpl()
{
    return new(std::nothrow) RemoteSessionSinkImpl();
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
extern "C" void DestroyRemoteSessionSinkImpl(RemoteSessionSinkImpl* impl)
{
    delete(impl);
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
int32_t RemoteSessionSinkImpl::CastSessionFromRemote(const sptr <AVSessionItem>& session,
                                                     const std::string& sourceSessionId,
                                                     const std::string& sourceDevice,
                                                     const std::string& sinkDevice,
                                                     const std::string& sourceCap)
{
#ifdef DATA_OBJECT_ENABLE
    auto syncer = std::make_shared<RemoteSessionSyncerImpl>(sourceSessionId, sourceDevice, sinkDevice);
#endif
    CHECK_AND_RETURN_RET_LOG(syncer != nullptr, AVSESSION_ERROR, "syncer is nullptr");
    int32_t ret = syncer->Init();
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "syncer init failed");

    {
        std::lock_guard<std::mutex> lock(mutex_);
        syncer_ = syncer;
        session_ = session;
    }
    sourceDevice_ = sourceDevice;
    RemoteSessionCapabilitySet::GetInstance().AddRemoteCapability(session->GetSessionId(), sourceDevice, sourceCap);

    ret = syncer_->RegisterDisconnectNotifier([this](const std::string& deviceId) {
        sptr<AVSessionItem> session;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            session = session_;
        }
        if (session == nullptr) {
            SLOGE("session is nullptr in disconnect notifier");
            return AVSESSION_ERROR;
        }
        SLOGE("device disconnected, sessionId is %{public}s",
              session->GetSessionId().c_str());
        HISYSEVENT_FAULT("REMOTE_CONTROL_FAILED",
            "BUNDLE_NAME", session->GetDescriptor().elementName_.GetBundleName(),
            "SESSION_TYPE", session->GetDescriptor().sessionType_,
            "AUDIO_STATUS", HISYSEVENT_GET_AUDIO_STATUS(session->GetUid()),
            "ERROR_TYPE", "REMOTE_DISCONNECTED",
            "ERROR_INFO", "remote disconnected");
        return AVSESSION_SUCCESS;
    });

    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "AddDisconnectNotifier failed");

    ret = syncer_->RegisterDataNotifier([this](const SessionDataCategory category, const std::string& deviceId) {
        SLOGI("device category %{public}d changed", category);
        std::shared_ptr<RemoteSessionSyncer> syncer;
        sptr<AVSessionItem> session;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            syncer = syncer_;
            session = session_;
        }
        CHECK_AND_RETURN_RET_LOG(session != nullptr && syncer != nullptr, AVSESSION_ERROR, "session_ is nullptr");

        return HandleSessionDataCategory(category, syncer, session);
    });
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "AddDataNotifier failed");
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
int32_t RemoteSessionSinkImpl::HandleSessionDataCategory(const SessionDataCategory category,
    const std::shared_ptr<RemoteSessionSyncer>& syncer, const sptr<AVSessionItem>& session)
{
    if (category == SESSION_DATA_META) {
        AVMetaData metaData;
        AVSESSION_TRACE_SYNC_START("RemoteSessionSinkImpl::GetAVMetaData");
        CHECK_AND_RETURN_RET_LOG(syncer->GetAVMetaData(metaData) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "GetAVMetaData failed");
        CHECK_AND_RETURN_RET_LOG(session->SetAVMetaData(metaData) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "SetAVMetaData failed");
    } else if (category == SESSION_DATA_PLAYBACK_STATE) {
        AVPlaybackState playbackState;
        AVSESSION_TRACE_SYNC_START("RemoteSessionSinkImpl::GetAVPlaybackState");
        CHECK_AND_RETURN_RET_LOG(syncer->GetAVPlaybackState(playbackState) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "GetAVPlaybackState failed");
        CHECK_AND_RETURN_RET_LOG(session->SetAVPlaybackState(playbackState) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "SetAVPlaybackState failed");
    } else if (category == SESSION_DATA_SET_EVENT) {
        std::string event;
        AAFwk::WantParams args;
        AVSESSION_TRACE_SYNC_START("RemoteSessionSinkImpl::SetSessionEvent");
        CHECK_AND_RETURN_RET_LOG(syncer->GetSessionEvent(event, args) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "GetSessionEvent failed");
        CHECK_AND_RETURN_RET_LOG(session->SetSessionEvent(event, args) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "SetSessionEvent failed");
    } else if (category == SESSION_DATA_QUEUE_ITEMS) {
        std::vector<AVQueueItem> items;
        AVSESSION_TRACE_SYNC_START("RemoteSessionSinkImpl::Get & Set QueueItems");
        CHECK_AND_RETURN_RET_LOG(syncer->GetAVQueueItems(items) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "GetAVQueueItems failed");
        CHECK_AND_RETURN_RET_LOG(session->SetAVQueueItems(items) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "SetAVQueueItems failed");
    } else if (category == SESSION_DATA_QUEUE_TITLE) {
        std::string title;
        AVSESSION_TRACE_SYNC_START("RemoteSessionSinkImpl::Get & Set QueueTitle");
        CHECK_AND_RETURN_RET_LOG(syncer->GetAVQueueTitle(title) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "GetAVQueueTitle failed");
        CHECK_AND_RETURN_RET_LOG(session->SetAVQueueTitle(title) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "SetAVQueueTitle failed");
    } else if (category == SESSION_DATA_EXTRAS) {
        AAFwk::WantParams extras;
        AVSESSION_TRACE_SYNC_START("RemoteSessionSinkImpl::Get & Set Extras");
        CHECK_AND_RETURN_RET_LOG(syncer->GetExtras(extras) == AVSESSION_SUCCESS, AVSESSION_ERROR, "GetExtras failed");
        CHECK_AND_RETURN_RET_LOG(session->SetExtras(extras) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "SetExtras failed");
    } else {
        SLOGE("category is illegal");
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
int32_t RemoteSessionSinkImpl::CancelCastSession()
{
    sptr<AVSessionItem> session;
    std::shared_ptr<RemoteSessionSyncer> syncer;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        session = session_;
        syncer = syncer_;
        syncer_ = nullptr;
        session_ = nullptr;
    }
    CHECK_AND_RETURN_RET_LOG(session != nullptr, AVSESSION_ERROR, "session is nullptr");
    RemoteSessionCapabilitySet::GetInstance().RemoveRemoteCapability(session->GetSessionId(), sourceDevice_);
    if (syncer) {
        syncer->Destroy();
    }
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
int32_t RemoteSessionSinkImpl::SetControlCommand(const AVControlCommand& command)
{
    std::shared_ptr<RemoteSessionSyncer> syncer;
    sptr<AVSessionItem> session;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        syncer = syncer_;
        session = session_;
    }
    CHECK_AND_RETURN_RET_LOG(syncer != nullptr, AVSESSION_ERROR, "syncer is nullptr");
    auto ret = syncer->PutControlCommand(command);
    if (ret != AVSESSION_SUCCESS && session != nullptr) {
        HISYSEVENT_FAULT("REMOTE_CONTROL_FAILED",
            "BUNDLE_NAME", session->GetDescriptor().elementName_.GetBundleName(),
            "SESSION_TYPE", session->GetDescriptor().sessionType_,
            "AUDIO_STATUS", HISYSEVENT_GET_AUDIO_STATUS(session->GetUid()),
            "ERROR_TYPE", "TIME_OUT",
            "ERROR_INFO", "SetControlCommand time out");
    }
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
int32_t RemoteSessionSinkImpl::SetCommonCommand(const std::string& commonCommand,
    const AAFwk::WantParams& commandArgs)
{
    std::shared_ptr<RemoteSessionSyncer> syncer;
    sptr<AVSessionItem> session;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        syncer = syncer_;
        session = session_;
    }
    CHECK_AND_RETURN_RET_LOG(syncer != nullptr, AVSESSION_ERROR, "syncer is nullptr");
    auto ret = syncer->PutCommonCommand(commonCommand, commandArgs);
    if (ret != AVSESSION_SUCCESS && session != nullptr) {
        HISYSEVENT_FAULT("REMOTE_CONTROL_FAILED",
            "BUNDLE_NAME", session->GetDescriptor().elementName_.GetBundleName(),
            "SESSION_TYPE", session->GetDescriptor().sessionType_,
            "AUDIO_STATUS", HISYSEVENT_GET_AUDIO_STATUS(session->GetUid()),
            "ERROR_TYPE", "TIME_OUT",
            "ERROR_INFO", "SetCommonCommand time out");
    }
return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP
} // namespace OHOS::AVSession
