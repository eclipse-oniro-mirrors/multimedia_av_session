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

extern "C" RemoteSessionSinkImpl* CreateRemoteSessionSinkImpl()
{
    return new(std::nothrow) RemoteSessionSinkImpl();
}

extern "C" void DestroyRemoteSessionSinkImpl(RemoteSessionSinkImpl* impl)
{
    delete(impl);
}

int32_t RemoteSessionSinkImpl::CastSessionFromRemote(const sptr <AVSessionItem>& session,
                                                     const std::string& sourceSessionId,
                                                     const std::string& sourceDevice,
                                                     const std::string& sinkDevice,
                                                     const std::string& sourceCap)
{
    syncer_ = std::make_shared<RemoteSessionSyncerImpl>(sourceSessionId, sourceDevice, sinkDevice);
    CHECK_AND_RETURN_RET_LOG(syncer_ != nullptr, AVSESSION_ERROR, "syncer_ is nullptr");
    int32_t ret = syncer_->Init();
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "syncer init failed");
    session_ = session;
    sourceDevice_ = sourceDevice;
    RemoteSessionCapabilitySet::GetInstance().AddRemoteCapability(session->GetSessionId(), sourceDevice, sourceCap);

    ret = syncer_->RegisterDisconnectNotifier([this](const std::string& deviceId) {
        SLOGE("device %{public}s disconnected, sessionId is %{public}s", deviceId.c_str(),
              session_->GetSessionId().c_str());
        HISYSEVENT_FAULT("REMOTE_CONTROL_FAILED",
            "BUNDLE_NAME", session_->GetDescriptor().elementName_.GetBundleName(),
            "SESSION_TYPE", session_->GetDescriptor().sessionType_,
            "AUDIO_STATUS", HISYSEVENT_GET_AUDIO_STATUS(session_->GetUid()),
            "ERROR_TYPE", "REMOTE_DISCONNECTED",
            "ERROR_INFO", "remote disconnected");
        return AVSESSION_SUCCESS;
    });

    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "AddDisconnectNotifier failed");

    ret = syncer_->RegisterDataNotifier([this](const SessionDataCategory category, const std::string& deviceId) {
        SLOGI("device %{public}s category %{public}d changed", deviceId.c_str(), category);
        CHECK_AND_RETURN_RET_LOG(session_ != nullptr && syncer_ != nullptr, AVSESSION_ERROR, "session_ is nullptr");

        return HandleSessionDataCategory(category);
    });
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "AddDataNotifier failed");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSinkImpl::HandleSessionDataCategory(const SessionDataCategory category)
{
    if (category == SESSION_DATA_META) {
        AVMetaData metaData;
        AVSESSION_TRACE_SYNC_START("RemoteSessionSinkImpl::GetAVMetaData");
        CHECK_AND_RETURN_RET_LOG(syncer_->GetAVMetaData(metaData) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "GetAVMetaData failed");
        CHECK_AND_RETURN_RET_LOG(session_->SetAVMetaData(metaData) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "SetAVMetaData failed");
    } else if (category == SESSION_DATA_PLAYBACK_STATE) {
        AVPlaybackState playbackState;
        AVSESSION_TRACE_SYNC_START("RemoteSessionSinkImpl::GetAVPlaybackState");
        CHECK_AND_RETURN_RET_LOG(syncer_->GetAVPlaybackState(playbackState) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "GetAVPlaybackState failed");
        CHECK_AND_RETURN_RET_LOG(session_->SetAVPlaybackState(playbackState) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "SetAVPlaybackState failed");
    } else if (category == SESSION_DATA_SET_EVENT) {
        std::string event;
        AAFwk::WantParams args;
        AVSESSION_TRACE_SYNC_START("RemoteSessionSinkImpl::SetSessionEvent");
        CHECK_AND_RETURN_RET_LOG(syncer_->GetSessionEvent(event, args) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "GetSessionEvent failed");
        CHECK_AND_RETURN_RET_LOG(session_->SetSessionEvent(event, args) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "SetSessionEvent failed");
    } else if (category == SESSION_DATA_QUEUE_ITEMS) {
        std::vector<AVQueueItem> items;
        AVSESSION_TRACE_SYNC_START("RemoteSessionSinkImpl::Get & Set QueueItems");
        CHECK_AND_RETURN_RET_LOG(syncer_->GetAVQueueItems(items) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "GetAVQueueItems failed");
        CHECK_AND_RETURN_RET_LOG(session_->SetAVQueueItems(items) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "SetAVQueueItems failed");
    } else if (category == SESSION_DATA_QUEUE_TITLE) {
        std::string title;
        AVSESSION_TRACE_SYNC_START("RemoteSessionSinkImpl::Get & Set QueueTitle");
        CHECK_AND_RETURN_RET_LOG(syncer_->GetAVQueueTitle(title) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "GetAVQueueTitle failed");
        CHECK_AND_RETURN_RET_LOG(session_->GetAVQueueTitle(title) == AVSESSION_SUCCESS, AVSESSION_ERROR,
            "GetAVQueueTitle failed");
    } else {
        SLOGE("category is illegal");
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSinkImpl::CancelCastSession()
{
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, AVSESSION_ERROR, "session is nullptr");
    RemoteSessionCapabilitySet::GetInstance().RemoveRemoteCapability(session_->GetSessionId(), sourceDevice_);
    syncer_->Destroy();
    syncer_ = nullptr;
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSinkImpl::SetControlCommand(const AVControlCommand& command)
{
    CHECK_AND_RETURN_RET_LOG(syncer_ != nullptr, AVSESSION_ERROR, "syncer is nullptr");
    auto ret = syncer_->PutControlCommand(command);
    if (ret != AVSESSION_SUCCESS && session_ != nullptr) {
        HISYSEVENT_FAULT("REMOTE_CONTROL_FAILED",
            "BUNDLE_NAME", session_->GetDescriptor().elementName_.GetBundleName(),
            "SESSION_TYPE", session_->GetDescriptor().sessionType_,
            "AUDIO_STATUS", HISYSEVENT_GET_AUDIO_STATUS(session_->GetUid()),
            "ERROR_TYPE", "TIME_OUT",
            "ERROR_INFO", "SetControlCommand time out");
    }
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSinkImpl::SetCommonCommand(const std::string& commonCommand,
    const AAFwk::WantParams& commandArgs)
{
    CHECK_AND_RETURN_RET_LOG(syncer_ != nullptr, AVSESSION_ERROR, "syncer is nullptr");
    auto ret = syncer_->PutCommonCommand(commonCommand, commandArgs);
    if (ret != AVSESSION_SUCCESS && session_ != nullptr) {
        HISYSEVENT_FAULT("REMOTE_CONTROL_FAILED",
            "BUNDLE_NAME", session_->GetDescriptor().elementName_.GetBundleName(),
            "SESSION_TYPE", session_->GetDescriptor().sessionType_,
            "AUDIO_STATUS", HISYSEVENT_GET_AUDIO_STATUS(session_->GetUid()),
            "ERROR_TYPE", "TIME_OUT",
            "ERROR_INFO", "SetCommonCommand time out");
    }
    return AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession
