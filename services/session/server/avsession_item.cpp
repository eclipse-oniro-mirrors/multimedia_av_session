/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "av_router.h"
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
#include "permission_checker.h"
#include "avsession_item.h"

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include "avcast_controller_proxy.h"
#include "avcast_controller_item.h"
#endif

#if !defined(WINDOWS_PLATFORM) and !defined(MAC_PLATFORM) and !defined(IOS_PLATFORM)
#include <malloc.h>
#endif

namespace OHOS::AVSession {
AVSessionItem::AVSessionItem(const AVSessionDescriptor& descriptor)
    : descriptor_(descriptor)
{
    SLOGD("constructor id=%{public}s", descriptor_.sessionId_.c_str());
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    cssListener_ = std::make_shared<CssListener>(this);
#endif
}

AVSessionItem::~AVSessionItem()
{
    SLOGD("destroy id=%{public}s", descriptor_.sessionId_.c_str());
}

std::string AVSessionItem::GetSessionId()
{
    return descriptor_.sessionId_;
}

std::string AVSessionItem::GetSessionType()
{
    if (descriptor_.sessionType_ == AVSession::SESSION_TYPE_VIDEO) {
        return "video";
    }
    return "audio";
}

int32_t AVSessionItem::Destroy()
{
    {
        std::lock_guard lockGuard(callbackLock_);
        if (callback_) {
            callback_.clear();
        }
    }
    std::string sessionId = descriptor_.sessionId_;
    std::string fileName = AVSessionUtils::GetCachePathName() + sessionId + AVSessionUtils::GetFileSuffix();
    AVSessionUtils::DeleteFile(fileName);

    {
        std::lock_guard controllerLockGuard(controllersLock_);
        SLOGI("size=%{public}d", static_cast<int>(controllers_.size()));
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

    {
        std::lock_guard controllerLockGuard(controllersLock_);
        for (const auto& [pid, controller] : controllers_) {
            controller->HandleMetaDataChange(meta);
        }
    }
    std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
    if (remoteSource_ != nullptr) {
        SLOGI("set remote AVMetaData");
        auto ret = remoteSource_->SetAVMetaData(meta);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetAVMetaData failed");
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::GetAVQueueItems(std::vector<AVQueueItem>& items)
{
    std::lock_guard queueItemsLockGuard(queueItemsLock_);
    items = queueItems_;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetAVQueueItems(const std::vector<AVQueueItem>& items)
{
    {
        std::lock_guard queueItemsLockGuard(queueItemsLock_);
        queueItems_ = items;
    }
    {
        std::lock_guard controllerLockGuard(controllersLock_);
        for (const auto& [pid, controller] : controllers_) {
            controller->HandleQueueItemsChange(items);
        }
    }
    std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
    if (remoteSource_ != nullptr) {
        SLOGI("set remote AVQueueItems");
        auto ret = remoteSource_->SetAVQueueItems(items);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetAVQueueItems failed");
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::GetAVQueueTitle(std::string& title)
{
    title = queueTitle_;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetAVQueueTitle(const std::string& title)
{
    queueTitle_ = title;

    {
        std::lock_guard controllerLockGuard(controllersLock_);
        for (const auto& [pid, controller] : controllers_) {
            controller->HandleQueueTitleChange(title);
        }
    }
    std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
    if (remoteSource_ != nullptr) {
        SLOGI("set remote AVQueueTitle");
        auto ret = remoteSource_->SetAVQueueTitle(title);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetAVQueueTitle failed");
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetAVPlaybackState(const AVPlaybackState& state)
{
    CHECK_AND_RETURN_RET_LOG(playbackState_.CopyFrom(state), AVSESSION_ERROR, "AVPlaybackState set error");

    {
        std::lock_guard controllerLockGuard(controllersLock_);
        for (const auto& [pid, controller] : controllers_) {
            SLOGI("pid=%{public}d", pid);
            controller->HandlePlaybackStateChange(state);
        }
    }
    std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
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

int32_t AVSessionItem::GetExtras(AAFwk::WantParams& extras)
{
    extras = extras_;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetExtras(const AAFwk::WantParams& extras)
{
    extras_ = extras;

    {
        std::lock_guard controllerLockGuard(controllersLock_);
        for (const auto& [pid, controller] : controllers_) {
            controller->HandleExtrasChange(extras);
        }
    }
    std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
    if (remoteSource_ != nullptr) {
        SLOGI("Set remote session extras");
        auto ret = remoteSource_->SetExtrasRemote(extras);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetRemoteExtras failed");
    }
    return AVSESSION_SUCCESS;
}

sptr<IRemoteObject> AVSessionItem::GetControllerInner()
{
    std::lock_guard controllerLockGuard(controllersLock_);
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

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
sptr<IRemoteObject> AVSessionItem::GetAVCastControllerInner()
{
    if (castControllerProxy_ == nullptr) {
        SLOGI("CastControllerProxy is null, start get new proxy");
        {
            std::lock_guard lockGuard(castHandleLock_);
            castControllerProxy_ = AVRouter::GetInstance().GetRemoteController(castHandle_);
        }
    }
    CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, nullptr, "Get castController proxy failed");

    sptr<AVCastControllerItem> castController = new (std::nothrow) AVCastControllerItem();
    CHECK_AND_RETURN_RET_LOG(castController != nullptr, nullptr, "malloc AVCastController failed");
    std::shared_ptr<AVCastControllerItem> sharedPtr = std::shared_ptr<AVCastControllerItem>(castController.GetRefPtr(),
        [holder = castController](const auto*) {});

    sharedPtr->Init(castControllerProxy_);
    castControllers_.emplace_back(sharedPtr);
    
    sptr<IRemoteObject> remoteObject = castController;

    return remoteObject;
}
#endif

int32_t AVSessionItem::RegisterCallbackInner(const sptr<IAVSessionCallback>& callback)
{
    std::lock_guard callbackLockGuard(callbackLock_);
    callback_ = callback;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::Activate()
{
    descriptor_.isActive_ = true;
    std::lock_guard controllerLockGuard(controllersLock_);
    for (const auto& [pid, controller] : controllers_) {
        SLOGI("pid=%{pubic}d", pid);
        controller->HandleActiveStateChange(true);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::Deactivate()
{
    descriptor_.isActive_ = false;
    std::lock_guard controllerLockGuard(controllersLock_);
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
    std::lock_guard controllerLockGuard(controllersLock_);
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
    std::lock_guard controllerLockGuard(controllersLock_);
    for (const auto& [pid, controller] : controllers_) {
        SLOGI("pid=%{pubic}d", pid);
        controller->HandleValidCommandChange(supportedCmd_);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetSessionEvent(const std::string& event, const AAFwk::WantParams& args)
{
    {
        std::lock_guard controllerLockGuard(controllersLock_);
        for (const auto& [pid, controller] : controllers_) {
            controller->HandleSetSessionEvent(event, args);
        }
    }
    std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
    if (remoteSource_ != nullptr) {
        SLOGI("Set remote session event");
        auto ret = remoteSource_->SetSessionEventRemote(event, args);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetSessionEvent failed");
    }
    return AVSESSION_SUCCESS;
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
int32_t AVSessionItem::ReleaseCast()
{
    SLOGI("Release cast process");
    return StopCast();
}

int32_t AVSessionItem::StartCast(const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("Start cast process");
    std::lock_guard castHandleLockGuard(castHandleLock_);

    int64_t castHandle = AVRouter::GetInstance().StartCast(outputDeviceInfo);
    CHECK_AND_RETURN_RET_LOG(castHandle != AVSESSION_ERROR, AVSESSION_ERROR, "StartCast failed");

    std::lock_guard lockGuard(castHandleLock_);
    castHandle_ = castHandle;

    AddDevice(static_cast<int32_t>(castHandle), outputDeviceInfo);

    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::AddDevice(const int64_t castHandle, const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("Add device process");
    std::lock_guard lockGuard(castHandleLock_);
    AVRouter::GetInstance().RegisterCallback(castHandle_, cssListener_);
    int32_t castId = static_cast<int32_t>(castHandle_);
    AVRouter::GetInstance().AddDevice(castId, outputDeviceInfo);
    return AVSESSION_SUCCESS;
}

void AVSessionItem::OnCastStateChange(int32_t castState, DeviceInfo deviceInfo)
{
    SLOGI("OnCastStateChange");
    OutputDeviceInfo outputDeviceInfo;
    if (castDeviceInfoMap_.count(deviceInfo.deviceId_) > 0) {
        outputDeviceInfo.deviceInfos_.emplace_back(castDeviceInfoMap_[deviceInfo.deviceId_]);
    } else {
        outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
    }
    if (castState == 6) { // 6 is connected status
        descriptor_.outputDeviceInfo_ = outputDeviceInfo;
    }

    if (castState == 5) { // 5 is disconnected status
        AVRouter::GetInstance().UnRegisterCallback(castHandle_, cssListener_);
        AVRouter::GetInstance().StopCastSession(castHandle_);
        castControllerProxy_ = nullptr;
    }

    HandleOutputDeviceChange(castState, outputDeviceInfo);
    std::lock_guard controllersLockGuard(controllersLock_);
    for (const auto& controller : controllers_) {
        controller.second->HandleOutputDeviceChange(castState, outputDeviceInfo);
    }
}

int32_t AVSessionItem::StopCast()
{
    SLOGI("Stop cast process");
    {
        std::lock_guard lockGuard(castHandleLock_);
        int64_t ret = AVRouter::GetInstance().StopCast(castHandle_);
        CHECK_AND_RETURN_RET_LOG(ret != AVSESSION_ERROR, AVSESSION_ERROR, "StartCast failed");
    }

    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = AVCastCategory::CATEGORY_LOCAL;
    deviceInfo.deviceId_ = "0";
    deviceInfo.deviceName_ = "LocalDevice";
    outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
    SetOutputDevice(outputDeviceInfo);
    return AVSESSION_SUCCESS;
}
#endif

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

std::vector<AVQueueItem> AVSessionItem::GetQueueItems()
{
    return queueItems_;
}

std::string AVSessionItem::GetQueueTitle()
{
    return queueTitle_;
}

std::vector<int32_t> AVSessionItem::GetSupportCommand()
{
    return supportedCmd_;
}

AbilityRuntime::WantAgent::WantAgent AVSessionItem::GetLaunchAbility()
{
    return launchAbility_;
}

AAFwk::WantParams AVSessionItem::GetExtras()
{
    return extras_;
}

void AVSessionItem::HandleMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnMediaKeyEvent");
    std::lock_guard callbackLockGuard(callbackLock_);
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

    {
        std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
        if (remoteSink_ != nullptr) {
            SLOGI("set remote ControlCommand");
            CHECK_AND_RETURN_LOG(remoteSink_->SetControlCommand(cmd) == AVSESSION_SUCCESS, "SetControlCommand failed");
        }
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

void AVSessionItem::ExecueCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::ExecueCommonCommand");

    {
        std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
        if (remoteSink_ != nullptr) {
            SLOGI("Send remote CommonCommand");
            CHECK_AND_RETURN_LOG(remoteSink_->SetCommonCommand(commonCommand, commandArgs) == AVSESSION_SUCCESS,
                "SetCommonCommand failed");
        }
    }
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnCommonCommand(commonCommand, commandArgs);
}

void AVSessionItem::HandleSkipToQueueItem(const int32_t& itemId)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnSkipToQueueItem");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnSkipToQueueItem(itemId);
}

void AVSessionItem::HandleOnPlay(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnPlay");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPlay();
}

void AVSessionItem::HandleOnPause(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnPause");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPause();
}

void AVSessionItem::HandleOnStop(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnStop");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnStop();
}

void AVSessionItem::HandleOnPlayNext(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnPlayNext");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPlayNext();
}

void AVSessionItem::HandleOnPlayPrevious(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnPlayPrevious");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPlayPrevious();
}

void AVSessionItem::HandleOnFastForward(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnFastForward");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnFastForward();
}

void AVSessionItem::HandleOnRewind(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnRewind");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnRewind();
}

void AVSessionItem::HandleOnSeek(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnSeek");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    int64_t time = 0;
    CHECK_AND_RETURN_LOG(cmd.GetSeekTime(time) == AVSESSION_SUCCESS, "GetSeekTime failed");
    callback_->OnSeek(time);
}

void AVSessionItem::HandleOnSetSpeed(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnSetSpeed");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    double speed = 0.0;
    CHECK_AND_RETURN_LOG(cmd.GetSpeed(speed) == AVSESSION_SUCCESS, "GetSpeed failed");
    callback_->OnSetSpeed(speed);
}

void AVSessionItem::HandleOnSetLoopMode(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnSetLoopMode");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    int32_t loopMode = AVSESSION_ERROR;
    CHECK_AND_RETURN_LOG(cmd.GetLoopMode(loopMode) == AVSESSION_SUCCESS, "GetLoopMode failed");
    callback_->OnSetLoopMode(loopMode);
}

void AVSessionItem::HandleOnToggleFavorite(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnToggleFavorite");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    std::string assetId;
    CHECK_AND_RETURN_LOG(cmd.GetAssetId(assetId) == AVSESSION_SUCCESS, "GetMediaId failed");
    callback_->OnToggleFavorite(assetId);
}

int32_t AVSessionItem::AddController(pid_t pid, sptr<AVControllerItem>& controller)
{
    std::lock_guard controllersLockGuard(controllersLock_);
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

std::string AVSessionItem::GetBundleName() const
{
    return descriptor_.elementName_.GetBundleName();
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
    std::lock_guard controllersLockGuard(controllersLock_);
    controllers_.erase(pid);
}

void AVSessionItem::SetServiceCallbackForRelease(const std::function<void(AVSessionItem&)>& callback)
{
    serviceCallback_ = callback;
}

void AVSessionItem::HandleOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnOutputDeviceChange");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnOutputDeviceChange(connectionState, outputDeviceInfo);
}

void AVSessionItem::SetOutputDevice(const OutputDeviceInfo& info)
{
    descriptor_.outputDeviceInfo_ = info;
    int32_t connectionStateConnected = 1;
    HandleOutputDeviceChange(connectionStateConnected, descriptor_.outputDeviceInfo_);
    std::lock_guard controllersLockGuard(controllersLock_);
    for (const auto& controller : controllers_) {
        controller.second->HandleOutputDeviceChange(connectionStateConnected, descriptor_.outputDeviceInfo_);
    }
    SLOGI("OutputDeviceInfo device size is %{public}d", static_cast<int32_t>(info.deviceInfos_.size()));
}

void AVSessionItem::GetOutputDevice(OutputDeviceInfo& info)
{
    info = GetDescriptor().outputDeviceInfo_;
}

int32_t AVSessionItem::CastAudioToRemote(const std::string& sourceDevice, const std::string& sinkDevice,
                                         const std::string& sinkCapability)
{
    SLOGI("start cast audio to remote");
    std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
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
    SLOGI("start cancel cast audio");
    std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
    CHECK_AND_RETURN_RET_LOG(remoteSource_ != nullptr, AVSESSION_ERROR, "remoteSource_ is nullptr");
    int32_t ret = remoteSource_->CancelCastAudio(sinkDevice);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CastAudioToLocal failed");
    SLOGI("success");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::CastAudioFromRemote(const std::string& sourceSessionId, const std::string& sourceDevice,
                                           const std::string& sinkDevice, const std::string& sourceCapability)
{
    SLOGI("start cast audio from remote");

    std::lock_guard remoteSinkLockGuard(remoteSinkLock_);
    remoteSink_ = std::make_shared<RemoteSessionSinkProxy>();
    CHECK_AND_RETURN_RET_LOG(remoteSink_ != nullptr, AVSESSION_ERROR, "remoteSink_ is nullptr");
    int32_t ret = remoteSink_->CastSessionFromRemote(this, sourceSessionId, sourceDevice, sinkDevice,
        sourceCapability);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CastSessionFromRemote failed");

    OutputDeviceInfo outputDeviceInfo;
    GetOutputDevice(outputDeviceInfo);
    int32_t castCategoryStreaming = ProtocolType::TYPE_CAST_PLUS_STREAM;
    for (int32_t i = 0; i < outputDeviceInfo.deviceInfos_.size(); i++) {
        outputDeviceInfo.deviceInfos_[i].castCategory_ = castCategoryStreaming;
    }
    SetOutputDevice(outputDeviceInfo);

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
    std::lock_guard remoteSinkLockGuard(remoteSinkLock_);
    CHECK_AND_RETURN_RET_LOG(remoteSink_ != nullptr, AVSESSION_ERROR, "remoteSink_ is nullptr");
    int32_t ret = remoteSink_->CancelCastSession();
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CancelCastSession failed");
    GetDescriptor().outputDeviceInfo_.deviceInfos_.clear();
    DeviceInfo deviceInfo;
    GetDescriptor().outputDeviceInfo_.deviceInfos_.emplace_back(deviceInfo);
    SLOGI("SinkCancelCastAudio");
    return AVSESSION_SUCCESS;
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
void AVSessionItem::UpdateCastDeviceMap(DeviceInfo deviceInfo)
{
    castDeviceInfoMap_[deviceInfo.deviceId_] = deviceInfo;
}
#endif
} // namespace OHOS::AVSession
