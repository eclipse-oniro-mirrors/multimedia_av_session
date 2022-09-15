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

#include "remote_session_source_impl.h"

#include "json_utils.h"
#include "avsession_trace.h"
#include "avsession_sysevent.h"

namespace OHOS::AVSession {
RemoteSessionSourceImpl::RemoteSessionSourceImpl()
{
}

extern "C" RemoteSessionSourceImpl* CreateRemoteSessionSourceImpl()
{
    return new(std::nothrow) RemoteSessionSourceImpl();
}

extern "C" void DestroyRemoteSessionSourceImpl(RemoteSessionSourceImpl* impl)
{
    delete(impl);
}

int32_t RemoteSessionSourceImpl::CastSessionToRemote(const sptr <AVSessionItem>& session,
                                                     const std::string& sourceDevice,
                                                     const std::string& sinkDevice,
                                                     const std::string& sinkCapability)
{
    session_ = session;
    auto syncer = std::make_shared<RemoteSessionSyncerImpl>(session->GetSessionId(), sourceDevice, sinkDevice);
    CHECK_AND_RETURN_RET_LOG(syncer != nullptr, AVSESSION_ERROR, "syncer is nullptr");
    int32_t ret = syncer->Init();
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "syncer init failed");
    syncers_[sinkDevice] = syncer;
    SLOGE("sinkDevice is %{public}s", sinkDevice.c_str());

    SessionCapabilitySet::GetInstance().AddRemoteCapability(session->GetSessionId(), sinkDevice, sinkCapability);

    CHECK_AND_RETURN_RET_LOG(!syncers_.empty(), AVSESSION_ERROR, "syncers size is empty");

    for (auto iter = syncers_.rbegin(); iter != syncers_.rend(); iter++) {
        auto syncer = iter->second;
        ret = syncer->RegisterDisconnectNotifier([this](const std::string& deviceId) {
            CHECK_AND_RETURN_RET_LOG(!syncers_.empty() && syncers_[deviceId] != nullptr, AVSESSION_ERROR,
                                     "syncer is not exist");
            SLOGE("device %{public}s is disconnected", deviceId.c_str());
            if (session_ != nullptr) {
                HISYSEVENT_FAULT("REMOTE_CONTROL_FAILED",
                    "BUNDLE_NAME", session_->GetDescriptor().elementName_.GetBundleName(),
                    "SESSION_TYPE", session_->GetDescriptor().sessionType_,
                    "AUDIO_STATUS", HISYSEVENT_GET_AUDIO_STATUS(session_->GetUid()),
                    "ERROR_TYPE", "REMOTE_DISCONNECTED",
                    "ERROR_INFO", "remote disconnected");
            }
            return AVSESSION_SUCCESS;
        });
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "AddDisconnectNotifier failed");

        ret = syncer->RegisterDataNotifier([this](const SessionDataCategory category, const std::string& deviceId) {
			AVSESSION_TRACE_SYNC_START("RemoteSessionSourceImpl::DataNotifier");
            SLOGI("device %{public}s category %{public}d changed", deviceId.c_str(), category);
            CHECK_AND_RETURN_RET_LOG(session_ != nullptr, AVSESSION_ERROR, "session_ is nullptr");
            CHECK_AND_RETURN_RET_LOG(!syncers_.empty() && syncers_[deviceId] != nullptr, AVSESSION_ERROR,
                                     "syncer is not exist");
            CHECK_AND_RETURN_RET_LOG(category == SESSION_DATA_CONTROL_COMMAND, AVSESSION_ERROR, "category is error");
            AVControlCommand command;
            CHECK_AND_RETURN_RET_LOG(syncers_[deviceId]->GetControlCommand(command) == AVSESSION_SUCCESS,
                                     AVSESSION_ERROR, "GetControlCommand failed");
            session_->ExecuteControllerCommand(command);
            return AVSESSION_SUCCESS;
        });
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "AddDataNotifier failed");
    }
    return AVSESSION_SUCCESS;
}

int32_t  RemoteSessionSourceImpl::CancelCastAudio(const std::string& sinkDevice)
{
    SLOGI("start");
    SessionCapabilitySet::GetInstance().RemoveRemoteCapability(session_->GetSessionId(), sinkDevice);
    CHECK_AND_RETURN_RET_LOG(!syncers_.empty(), AVSESSION_SUCCESS, "syncer is empty");
    auto iter = syncers_.begin();
    while (iter != syncers_.end()) {
        if (iter->first == sinkDevice) {
            SLOGI("cancel sinkDevice %{public}s cast audio", sinkDevice.c_str());
            iter->second->Destroy();
            iter->second = nullptr;
            iter = syncers_.erase(iter);
        }
    }
    SLOGI("success");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSourceImpl::SetAVMetaData(const AVMetaData& metaData)
{
    SLOGI("start");
    CHECK_AND_RETURN_RET_LOG(!syncers_.empty() && session_ != nullptr, AVSESSION_ERROR, "syncer size is zero");
    for (auto iter = syncers_.rbegin(); iter != syncers_.rend(); iter++) {
        SLOGI("iter %{public}s", iter->first.c_str());
        AVMetaData sinkMetaData;
        auto mask = GetSinkMetaMaskType(iter->first);
        metaData.CopyToByMask(mask, sinkMetaData);
        auto ret = iter->second->PutAVMetaData(sinkMetaData);
        if (ret != AVSESSION_SUCCESS) {
            HISYSEVENT_FAULT("REMOTE_CONTROL_FAILED",
                "BUNDLE_NAME", session_->GetDescriptor().elementName_.GetBundleName(),
                "SESSION_TYPE", session_->GetDescriptor().sessionType_,
                "AUDIO_STATUS", HISYSEVENT_GET_AUDIO_STATUS(session_->GetUid()),
                "ERROR_TYPE", "TIME_OUT",
                "ERROR_INFO", "SetAVMetaData time out");
        }
    }
    SLOGI("success");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSourceImpl::SetAVPlaybackState(const AVPlaybackState& state)
{
    SLOGI("start");
    CHECK_AND_RETURN_RET_LOG(!syncers_.empty() && session_ != nullptr, AVSESSION_ERROR, "syncer size is zero");
    for (auto iter = syncers_.rbegin(); iter != syncers_.rend(); iter++) {
        SLOGI("syncer %{public}s", iter->first.c_str());
        AVPlaybackState sinkState;
        auto mask = GetSinkPlaybackStateMaskType(iter->first);
        state.CopyToByMask(mask, sinkState);
        auto ret = iter->second->PutAVPlaybackState(sinkState);
        if (ret != AVSESSION_SUCCESS) {
            HISYSEVENT_FAULT("REMOTE_CONTROL_FAILED",
                "BUNDLE_NAME", session_->GetDescriptor().elementName_.GetBundleName(),
                "SESSION_TYPE", session_->GetDescriptor().sessionType_,
                "AUDIO_STATUS", HISYSEVENT_GET_AUDIO_STATUS(session_->GetUid()),
                "ERROR_TYPE", "TIME_OUT",
                "ERROR_INFO", "SetAVPlaybackState time out");
        }
    }
    SLOGI("success");
    return AVSESSION_SUCCESS;
}

AVMetaData::MetaMaskType RemoteSessionSourceImpl::GetSinkMetaMaskType(const std::string& sinkDevice)
{
    std::vector<int32_t> capability = AVMetaData::localCapability;
    AVMetaData::MetaMaskType mask;
    for (const auto& key : capability) {
        bool hasCapability = SessionCapabilitySet::GetInstance().HasCapability(session_->GetSessionId(), sinkDevice,
                                                                               SESSION_DATA_META, key);
        if (hasCapability) {
            mask.set(key);
        }
    }
    return mask;
}

AVPlaybackState::PlaybackStateMaskType RemoteSessionSourceImpl::GetSinkPlaybackStateMaskType(
    const std::string &sinkDevice)
{
    std::vector<int32_t> capability = AVPlaybackState::localCapability;
    AVPlaybackState::PlaybackStateMaskType mask;
    for (const auto& key : capability) {
        bool hasCapability = SessionCapabilitySet::GetInstance().HasCapability(session_->GetSessionId(), sinkDevice,
                                                                               SESSION_DATA_PLAYBACK_STATE, key);
        if (hasCapability) {
            mask.set(key);
        }
    }
    return mask;
}
} // namespace OHOS::AVSession