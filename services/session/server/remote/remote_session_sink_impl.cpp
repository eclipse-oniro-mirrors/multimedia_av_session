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
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "syncer_ init failed");
    session_ = session;
    sourceDevice_ = sourceDevice;
    SessionCapabilitySet::GetInstance().AddRemoteCapability(session->GetSessionId(), sourceDevice, sourceCap);

    ret = syncer_->RegisterDisconnectNotifier([this](const std::string& deviceId) {
        SLOGE("device %{public}s disconnected, sessionId is %{public}s", deviceId.c_str(),
              session_->GetSessionId().c_str());
        return AVSESSION_SUCCESS;
    });
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "AddDisconnectNotifier failed");

    ret = syncer_->RegisterDataNotifier([this](const SessionDataCategory category, const std::string& deviceId) {
        SLOGE("device %{public}s category %{public}d changed", deviceId.c_str(), category);
        CHECK_AND_RETURN_RET_LOG(session_ != nullptr && syncer_ != nullptr, AVSESSION_ERROR, "session_ is nullptr");
        if (category == SESSION_DATA_META) {
            AVMetaData metaData;
            CHECK_AND_RETURN_RET_LOG(syncer_->GetAVMetaData(metaData) == AVSESSION_SUCCESS, AVSESSION_ERROR,
                                     "GetAVMetaData failed");
            CHECK_AND_RETURN_RET_LOG(session_->SetAVMetaData(metaData) == AVSESSION_SUCCESS, AVSESSION_ERROR,
                                     "SetAVMetaData failed");
            return AVSESSION_SUCCESS;
        }

        if (category == SESSION_DATA_PLAYBACK_STATE) {
            AVPlaybackState playbackState;
            CHECK_AND_RETURN_RET_LOG(syncer_->GetAVPlaybackState(playbackState) == AVSESSION_SUCCESS, AVSESSION_ERROR,
                                     "GetAVPlaybackState failed");
            CHECK_AND_RETURN_RET_LOG(session_->SetAVPlaybackState(playbackState) == AVSESSION_SUCCESS, AVSESSION_ERROR,
                                     "SetAVPlaybackState failed");
            return AVSESSION_SUCCESS;
        }
        SLOGE("category is illegal");
        return AVSESSION_ERROR;
    });
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "AddDataNotifier failed");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSinkImpl::CancelCastSession()
{
    CHECK_AND_RETURN_RET_LOG(session_ != nullptr, AVSESSION_ERROR, "session is nullptr");
    SessionCapabilitySet::GetInstance().RemoveRemoteCapability(session_->GetSessionId(), sourceDevice_);
    syncer_->Destroy();
    syncer_ = nullptr;
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSinkImpl::SetControlCommand(const AVControlCommand &command)
{
    CHECK_AND_RETURN_RET_LOG(syncer_ != nullptr, AVSESSION_ERROR, "syncer is nullptr");
    syncer_->PutControlCommand(command);
    return AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession