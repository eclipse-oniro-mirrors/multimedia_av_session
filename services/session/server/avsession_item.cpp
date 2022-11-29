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

#include "avsession_item.h"
#include "avsession_service.h"
#include "avcontroller_item.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_descriptor.h"
#include "avsession_trace.h"
#include "avsession_sysevent.h"
#include "avsession_utils.h"
#include "remote_session_sink.h"
#include "remote_session_source.h"
#include "remote_session_source_proxy.h"
#include "remote_session_sink_proxy.h"

#if !defined(WINDOWS_PLATFORM) and !defined(MAC_PLATFORM) and !defined(IOS_PLATFORM)
#include <malloc.h>
#endif

namespace OHOS::AVSession {
AVSessionItem::AVSessionItem(const AVSessionDescriptor& descriptor)
    : descriptor_(descriptor)
{
    SLOGD("constructor id=%{public}s", descriptor_.sessionId_.c_str());
}

AVSessionItem::~AVSessionItem()
{
    SLOGD("destroy id=%{public}s", descriptor_.sessionId_.c_str());
#if !defined(WINDOWS_PLATFORM) and !defined(MAC_PLATFORM) and !defined(IOS_PLATFORM)
#if defined(__BIONIC__)
    mallopt(M_PURGE, 0);
#endif
#endif
}

std::string AVSessionItem::GetSessionId()
{
    return descriptor_.sessionId_;
}

int32_t AVSessionItem::Destroy()
{
    if (callback_) {
        callback_.clear();
    }
    std::string sessionId = descriptor_.sessionId_;
    std::string fileName = AVSessionUtils::GetCachePathName() + sessionId + AVSessionUtils::GetFileSuffix();
    AVSessionUtils::DeleteFile(fileName);

    SLOGI("size=%{public}d", static_cast<int>(controllers_.size()));
    {
        std::lock_guard lockGuard(lock_);
        for (auto it = controllers_.begin(); it != controllers_.end();) {
            SLOGI("pid=%{public}d", it->first);
            it->second->HandleSessionDestroy();
            controllers_.erase(it++);
        }
    }

    if (serviceCallback_) {
        serviceCallback_(*this);
    }
    SLOGI("Destroy success");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::GetAVMetaData(AVMetaData& meta)
{
    std::string sessionId = GetSessionId();
    std::string fileName = AVSessionUtils::GetCachePathName() + sessionId + AVSessionUtils::GetFileSuffix();
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = metaData_.GetMediaImage();
    AVSessionUtils::ReadImageFromFile(innerPixelMap, fileName);
    meta = metaData_;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetAVMetaData(const AVMetaData& meta)
{
    CHECK_AND_RETURN_RET_LOG(metaData_.CopyFrom(meta), AVSESSION_ERROR, "AVMetaData set error");
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = metaData_.GetMediaImage();
    if (innerPixelMap != nullptr) {
        std::string sessionId = GetSessionId();
        std::string fileName = AVSessionUtils::GetCachePathName() + sessionId + AVSessionUtils::GetFileSuffix();
        AVSessionUtils::WriteImageToFile(innerPixelMap, fileName);
        innerPixelMap->Clear();
        metaData_.SetMediaImage(innerPixelMap);
    }
    std::lock_guard lockGuard(lock_);
    for (const auto& [pid, controller] : controllers_) {
        controller->HandleMetaDataChange(meta);
    }

    if (remoteSource_ != nullptr) {
        SLOGI("set remote AVMetaData");
        auto ret = remoteSource_->SetAVMetaData(meta);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetAVMetaData failed");
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetAVPlaybackState(const AVPlaybackState& state)
{
    CHECK_AND_RETURN_RET_LOG(playbackState_.CopyFrom(state), AVSESSION_ERROR, "AVPlaybackState set error");
    std::lock_guard lockGuard(lock_);
    for (const auto& [pid, controller] : controllers_) {
        SLOGI("pid=%{public}d", pid);
        controller->HandlePlaybackStateChange(state);
    }

    if (remoteSource_ != nullptr) {
        SLOGI("set remote AVPlaybackState");
        remoteSource_->SetAVPlaybackState(state);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::GetAVPlaybackState(AVPlaybackState& state)
{
    state = playbackState_;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetLaunchAbility(const AbilityRuntime::WantAgent::WantAgent& ability)
{
    launchAbility_ = ability;
    return AVSESSION_SUCCESS;
}

sptr<IRemoteObject> AVSessionItem::GetControllerInner()
{
    std::lock_guard lockGuard(lock_);
    auto iter = controllers_.find(GetPid());
    if (iter != controllers_.end()) {
        return iter->second;
    }

    sptr<AVSessionItem> session(this);
    sptr<AVControllerItem> result = new(std::nothrow) AVControllerItem(GetPid(), session);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "malloc controller failed");
    controllers_.insert({GetPid(), result});
    return result;
}

int32_t AVSessionItem::RegisterCallbackInner(const sptr<IAVSessionCallback>& callback)
{
    callback_ = callback;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::Activate()
{
    descriptor_.isActive_ = true;
    std::lock_guard lockGuard(lock_);
    for (const auto& [pid, controller] : controllers_) {
        SLOGI("pid=%{pubic}d", pid);
        controller->HandleActiveStateChange(true);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::Deactivate()
{
    descriptor_.isActive_ = false;
    std::lock_guard lockGuard(lock_);
    for (const auto& [pid, controller] : controllers_) {
        SLOGI("pid=%{pubic}d", pid);
        controller->HandleActiveStateChange(false);
    }
    return AVSESSION_SUCCESS;
}

bool AVSessionItem::IsActive()
{
    return descriptor_.isActive_;
}

int32_t AVSessionItem::AddSupportCommand(int32_t cmd)
{
    CHECK_AND_RETURN_RET_LOG(cmd > AVControlCommand::SESSION_CMD_INVALID, AVSESSION_ERROR, "invalid cmd");
    CHECK_AND_RETURN_RET_LOG(cmd < AVControlCommand::SESSION_CMD_MAX, AVSESSION_ERROR, "invalid cmd");
    auto iter = std::find(supportedCmd_.begin(), supportedCmd_.end(), cmd);
    CHECK_AND_RETURN_RET_LOG(iter == supportedCmd_.end(), AVSESSION_SUCCESS, "cmd already been added");
    supportedCmd_.push_back(cmd);
    std::lock_guard lockGuard(lock_);
    for (const auto& [pid, controller] : controllers_) {
        SLOGI("pid=%{pubic}d", pid);
        controller->HandleValidCommandChange(supportedCmd_);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::DeleteSupportCommand(int32_t cmd)
{
    CHECK_AND_RETURN_RET_LOG(cmd > AVControlCommand::SESSION_CMD_INVALID, AVSESSION_ERROR, "invalid cmd");
    CHECK_AND_RETURN_RET_LOG(cmd < AVControlCommand::SESSION_CMD_MAX, AVSESSION_ERROR, "invalid cmd");
    auto iter = std::remove(supportedCmd_.begin(), supportedCmd_.end(), cmd);
    supportedCmd_.erase(iter, supportedCmd_.end());
    std::lock_guard lockGuard(lock_);
    for (const auto& [pid, controller] : controllers_) {
        SLOGI("pid=%{pubic}d", pid);
        controller->HandleValidCommandChange(supportedCmd_);
    }
    return AVSESSION_SUCCESS;
}

AVSessionDescriptor AVSessionItem::GetDescriptor()
{
    return descriptor_;
}

AVPlaybackState AVSessionItem::GetPlaybackState()
{
    return playbackState_;
}

AVMetaData AVSessionItem::GetMetaData()
{
    std::string sessionId = GetSessionId();
    std::string fileName = AVSessionUtils::GetCachePathName() + sessionId + AVSessionUtils::GetFileSuffix();
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = metaData_.GetMediaImage();
    AVSessionUtils::ReadImageFromFile(innerPixelMap, fileName);
    return metaData_;
}

std::vector<int32_t> AVSessionItem::GetSupportCommand()
{
    return supportedCmd_;
}

AbilityRuntime::WantAgent::WantAgent AVSessionItem::GetLaunchAbility()
{
    return launchAbility_;
}

void AVSessionItem::HandleMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnMediaKeyEvent");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    CHECK_AND_RETURN_LOG(descriptor_.isActive_, "session is deactive");
    callback_->OnMediaKeyEvent(keyEvent);
}

void AVSessionItem::ExecuteControllerCommand(const AVControlCommand& cmd)
{
    HISYSEVENT_ADD_OPERATION_COUNT(Operation::OPT_ALL_CTRL_COMMAND);
    int32_t code = cmd.GetCommand();
    if (code < 0 || code >= SESSION_CMD_MAX) {
        SLOGE("controlCommand invalid");
        return;
    }

    if (remoteSink_ != nullptr) {
        SLOGI("set remote ControlCommand");
        CHECK_AND_RETURN_LOG(remoteSink_->SetControlCommand(cmd) == AVSESSION_SUCCESS, "SetControlCommand failed");
    }
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    CHECK_AND_RETURN_LOG(descriptor_.isActive_, "session is deactivate");

    HISYSEVENT_ADD_OPERATION_COUNT(static_cast<Operation>(cmd.GetCommand()));
    HISYSEVENT_ADD_OPERATION_COUNT(Operation::OPT_SUCCESS_CTRL_COMMAND);
    HISYSEVENT_ADD_CONTROLLER_COMMAND_INFO(descriptor_.elementName_.GetBundleName(), GetPid(),
        cmd.GetCommand(), descriptor_.sessionType_);
    return (this->*cmdHandlers[code])(cmd);

    HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "ERROR_TYPE", "INVALID_COMMAND", "CMD", code,
        "ERROR_INFO", "avsessionitem executecontrollercommand, invaild command");
}

void AVSessionItem::HandleOnPlay(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnPlay");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPlay();
}

void AVSessionItem::HandleOnPause(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnPause");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPause();
}

void AVSessionItem::HandleOnStop(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnStop");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnStop();
}

void AVSessionItem::HandleOnPlayNext(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnPlayNext");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPlayNext();
}

void AVSessionItem::HandleOnPlayPrevious(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnPlayPrevious");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPlayPrevious();
}

void AVSessionItem::HandleOnFastForward(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnFastForward");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnFastForward();
}

void AVSessionItem::HandleOnRewind(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnRewind");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnRewind();
}

void AVSessionItem::HandleOnSeek(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnSeek");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    int64_t time = 0;
    CHECK_AND_RETURN_LOG(cmd.GetSeekTime(time) == AVSESSION_SUCCESS, "GetSeekTime failed");
    callback_->OnSeek(time);
}

void AVSessionItem::HandleOnSetSpeed(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnSetSpeed");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    double speed = 0.0;
    CHECK_AND_RETURN_LOG(cmd.GetSpeed(speed) == AVSESSION_SUCCESS, "GetSpeed failed");
    callback_->OnSetSpeed(speed);
}

void AVSessionItem::HandleOnSetLoopMode(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnSetLoopMode");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    int32_t loopMode = AVSESSION_ERROR;
    CHECK_AND_RETURN_LOG(cmd.GetLoopMode(loopMode) == AVSESSION_SUCCESS, "GetLoopMode failed");
    callback_->OnSetLoopMode(loopMode);
}

void AVSessionItem::HandleOnToggleFavorite(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnToggleFavorite");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    std::string assetId;
    CHECK_AND_RETURN_LOG(cmd.GetAssetId(assetId) == AVSESSION_SUCCESS, "GetMediaId failed");
    callback_->OnToggleFavorite(assetId);
}

int32_t AVSessionItem::AddController(pid_t pid, sptr<AVControllerItem>& controller)
{
    std::lock_guard lockGuard(lock_);
    controllers_.insert({pid, controller});
    return AVSESSION_SUCCESS;
}

void AVSessionItem::SetPid(pid_t pid)
{
    descriptor_.pid_ = pid;
}

void AVSessionItem::SetUid(pid_t uid)
{
    descriptor_.uid_ = uid;
}

pid_t AVSessionItem::GetPid() const
{
    return descriptor_.pid_;
}

pid_t AVSessionItem::GetUid() const
{
    return descriptor_.uid_;
}

std::string AVSessionItem::GetAbilityName() const
{
    return descriptor_.elementName_.GetAbilityName();
}

void AVSessionItem::SetTop(bool top)
{
    descriptor_.isTopSession_ = top;
}

std::shared_ptr<RemoteSessionSource> AVSessionItem::GetRemoteSource()
{
    return remoteSource_;
}

void AVSessionItem::HandleControllerRelease(pid_t pid)
{
    std::lock_guard lockGuard(lock_);
    controllers_.erase(pid);
}

void AVSessionItem::SetServiceCallbackForRelease(const std::function<void(AVSessionItem&)>& callback)
{
    serviceCallback_ = callback;
}

void AVSessionItem::HandleOutputDeviceChange(const OutputDeviceInfo& outputDeviceInfo)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnOutputDeviceChange");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnOutputDeviceChange(outputDeviceInfo);
}

void AVSessionItem::SetOutputDevice(const OutputDeviceInfo& info)
{
    descriptor_.outputDeviceInfo_.isRemote_ = info.isRemote_;
    descriptor_.outputDeviceInfo_.deviceIds_ = info.deviceIds_;
    descriptor_.outputDeviceInfo_.deviceNames_ = info.deviceNames_;
    HandleOutputDeviceChange(descriptor_.outputDeviceInfo_);
    for (const auto& controller : controllers_) {
        controller.second->HandleOutputDeviceChange(descriptor_.outputDeviceInfo_);
    }
    SLOGI("OutputDeviceInfo device size is %{public}d", static_cast<int32_t>(info.deviceIds_.size()));
}

void AVSessionItem::GetOutputDevice(OutputDeviceInfo& info)
{
    info = GetDescriptor().outputDeviceInfo_;
}

int32_t AVSessionItem::CastAudioToRemote(const std::string& sourceDevice, const std::string& sinkDevice,
                                         const std::string& sinkCapability)
{
    SLOGI("start");
    remoteSource_ = std::make_shared<RemoteSessionSourceProxy>();
    CHECK_AND_RETURN_RET_LOG(remoteSource_ != nullptr, AVSESSION_ERROR, "remoteSource_ is nullptr");
    int32_t ret = remoteSource_->CastSessionToRemote(this, sourceDevice, sinkDevice, sinkCapability);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CastSessionToRemote failed");
    ret = remoteSource_->SetAVMetaData(GetMetaData());
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetAVMetaData failed");
    ret = remoteSource_->SetAVPlaybackState(GetPlaybackState());
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetAVPlaybackState failed");
    SLOGI("success");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SourceCancelCastAudio(const std::string& sinkDevice)
{
    SLOGI("start");
    CHECK_AND_RETURN_RET_LOG(remoteSource_ != nullptr, AVSESSION_ERROR, "remoteSource_ is nullptr");
    int32_t ret = remoteSource_->CancelCastAudio(sinkDevice);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CastAudioToLocal failed");
    SLOGI("success");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::CastAudioFromRemote(const std::string& sourceSessionId, const std::string& sourceDevice,
                                           const std::string& sinkDevice, const std::string& sourceCapability)
{
    SLOGI("start");
    remoteSink_ = std::make_shared<RemoteSessionSinkProxy>();
    CHECK_AND_RETURN_RET_LOG(remoteSink_ != nullptr, AVSESSION_ERROR, "remoteSink_ is nullptr");
    int32_t ret = remoteSink_->CastSessionFromRemote(this, sourceSessionId, sourceDevice, sinkDevice,
                                                     sourceCapability);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CastSessionFromRemote failed");

    OutputDeviceInfo deviceInfo;
    GetOutputDevice(deviceInfo);
    deviceInfo.isRemote_ = true;
    SetOutputDevice(deviceInfo);

    CHECK_AND_RETURN_RET_LOG(Activate() == AVSESSION_SUCCESS, AVSESSION_ERROR, "Activate failed");

    std::vector<std::vector<int32_t>> value(SESSION_DATA_CATEGORY_MAX);
    ret = JsonUtils::GetVectorCapability(sourceCapability, value);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "GetVectorCapability error");
    for (auto cmd : value[SESSION_DATA_CONTROL_COMMAND]) {
        SLOGI("add support cmd : %{public}d", cmd);
        ret = AddSupportCommand(cmd);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "AddSupportCommand failed");
    }
    SLOGI("success");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SinkCancelCastAudio()
{
    CHECK_AND_RETURN_RET_LOG(remoteSink_ != nullptr, AVSESSION_ERROR, "remoteSink_ is nullptr");
    int32_t ret = remoteSink_->CancelCastSession();
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CancelCastSession failed");
    GetDescriptor().outputDeviceInfo_.deviceIds_.clear();
    GetDescriptor().outputDeviceInfo_.deviceNames_.clear();
    SLOGI("SinkCancelCastAudio");
    return AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession