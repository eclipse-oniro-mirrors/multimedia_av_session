/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "audio_manager_proxy.h"
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
#include "session_xcollie.h"
#include "avsession_item.h"
#include "avsession_radar.h"
#include "avsession_event_handler.h"
#include "bundle_status_adapter.h"
#include "want_agent_helper.h"
#include "array_wrapper.h"
#include "string_wrapper.h"

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include "avcast_controller_proxy.h"
#include "avcast_controller_item.h"
#include "collaboration_manager.h"
#endif

#if !defined(WINDOWS_PLATFORM) and !defined(MAC_PLATFORM) and !defined(IOS_PLATFORM)
#include <malloc.h>
#include <string>
#include <openssl/crypto.h>
#endif

using namespace OHOS::AudioStandard;

namespace OHOS::AVSession {

static const std::string AVSESSION_DYNAMIC_DISPLAY_LIBRARY_PATH = std::string("libavsession_dynamic_display.z.so");

AVSessionItem::AVSessionItem(const AVSessionDescriptor& descriptor, int32_t userId)
    : descriptor_(descriptor), userId_(userId)
{
    SLOGI("constructor session id=%{public}s, userId=%{public}d",
        AVSessionUtils::GetAnonySessionId(descriptor_.sessionId_).c_str(), userId_);
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    cssListener_ = std::make_shared<CssListener>(this);
#endif
    dynamicLoader_ = std::make_unique<AVSessionDynamicLoader>();
    avsessionDisaplayIntf_ = nullptr;
}

AVSessionItem::~AVSessionItem()
{
    SLOGI("destroy with activeCheck session id=%{public}s, userId=%{public}d",
        AVSessionUtils::GetAnonySessionId(descriptor_.sessionId_).c_str(), userId_);
    if (IsActive()) {
        SLOGI("destroy with activate session, try deactivate it");
        Deactivate();
    }
}

// LCOV_EXCL_START
std::string AVSessionItem::GetSessionId()
{
    return descriptor_.sessionId_;
}

std::string AVSessionItem::GetSessionType()
{
    if (descriptor_.sessionType_ == AVSession::SESSION_TYPE_VIDEO) {
        return "video";
    }
    if (descriptor_.sessionType_ == AVSession::SESSION_TYPE_VOICE_CALL) {
        return "voice_call";
    }
    if (descriptor_.sessionType_ == AVSession::SESSION_TYPE_VIDEO_CALL) {
        return "video_call";
    }
    return "audio";
}
// LCOV_EXCL_STOP

int32_t AVSessionItem::Destroy()
{
    SLOGI("AVSessionItem send service destroy event to service, check serviceCallback exist");
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "Destroy",
        "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(),
        "ERROR_CODE", AVSESSION_SUCCESS,
        "ERROR_MSG", "SUCCESS");
    if (serviceCallback_) {
        SLOGI("AVSessionItem send service destroy event to service");
        serviceCallback_(*this);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::DestroyTask()
{
    {
        std::lock_guard lockGuard(callbackLock_);
        if (callback_) {
            callback_.clear();
        }
    }
    std::lock_guard lockGuard(destroyLock_);
    if (isDestroyed_) {
        SLOGE("return for already in destroy");
        return AVSESSION_SUCCESS;
    }
    isDestroyed_ = true;
    std::string sessionId = descriptor_.sessionId_;
    SLOGI("session destroy for:%{public}s", AVSessionUtils::GetAnonySessionId(sessionId).c_str());
    std::string fileName = AVSessionUtils::GetCachePathName(userId_) + sessionId + AVSessionUtils::GetFileSuffix();
    AVSessionUtils::DeleteFile(fileName);
    std::list<sptr<AVControllerItem>> controllerList;
    {
        std::lock_guard controllerLockGuard(controllersLock_);
        SLOGI("to release controller list size: %{public}d", static_cast<int>(controllers_.size()));
        for (auto it = controllers_.begin(); it != controllers_.end();) {
            SLOGI("controller for pid: %{public}d", it->first);
            controllerList.push_back(it->second);
            controllers_.erase(it++);
        }
    }
    SLOGD("Send session destroy event to controller");
    for (auto& controller : controllerList) {
        controller->HandleSessionDestroy();
    }
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("Session destroy with castHandle: %{public}ld", castHandle_);
    ReleaseAVCastControllerInner();
    if (descriptor_.sessionTag_ != "RemoteCast" && castHandle_ > 0) {
        SLOGW("Session destroy at source, release cast");
        AVRouter::GetInstance().UnRegisterCallback(castHandle_, cssListener_);
        ReleaseCast();
    }
    StopCastDisplayListener();
#endif
    SLOGI("session destroy success");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetAVCallMetaData(const AVCallMetaData& avCallMetaData)
{
    CHECK_AND_RETURN_RET_LOG(avCallMetaData_.CopyFrom(avCallMetaData), AVSESSION_ERROR, "AVCallMetaData set error");
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = avCallMetaData_.GetMediaImage();
    if (innerPixelMap != nullptr) {
        std::string sessionId = GetSessionId();
        std::string fileDir = AVSessionUtils::GetCachePathName(userId_);
        AVSessionUtils::WriteImageToFile(innerPixelMap, fileDir, sessionId + AVSessionUtils::GetFileSuffix());
        innerPixelMap->Clear();
        avCallMetaData_.SetMediaImage(innerPixelMap);
    }

    {
        std::lock_guard controllerLockGuard(controllersLock_);
        for (const auto& [pid, controller] : controllers_) {
            controller->HandleAVCallMetaDataChange(avCallMetaData);
        }
    }
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVSessionItem::SetAVCallState(const AVCallState& avCallState)
{
    CHECK_AND_RETURN_RET_LOG(avCallState_.CopyFrom(avCallState), AVSESSION_ERROR, "AVCallState set error");
    {
        std::lock_guard controllerLockGuard(controllersLock_);
        for (const auto& [pid, controller] : controllers_) {
            SLOGI("pid=%{public}d", pid);
            controller->HandleAVCallStateChange(avCallState);
        }
    }
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVSessionItem::GetAVMetaData(AVMetaData& meta)
{
    std::lock_guard lockGuard(metaDataLock_);
    SessionXCollie sessionXCollie("avsession::GetAVMetaData");
    std::string sessionId = GetSessionId();
    std::string fileDir = AVSessionUtils::GetCachePathName(userId_);
    std::string fileName = sessionId + AVSessionUtils::GetFileSuffix();
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = metaData_.GetMediaImage();
    AVSessionUtils::ReadImageFromFile(innerPixelMap, fileDir, fileName);

    std::string avQueueFileDir = AVSessionUtils::GetFixedPathName();
    std::string avQueueFileName = GetBundleName() + "_" + metaData_.GetAVQueueId() + AVSessionUtils::GetFileSuffix();
    std::shared_ptr<AVSessionPixelMap> avQueuePixelMap = metaData_.GetAVQueueImage();
    AVSessionUtils::ReadImageFromFile(avQueuePixelMap, avQueueFileDir, avQueueFileName);

    meta = metaData_;
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVSessionItem::ProcessFrontSession(const std::string& source)
{
    SLOGI("ProcessFrontSession with directly handle %{public}s ", source.c_str());
    HandleFrontSession();
    return AVSESSION_SUCCESS;
}

void AVSessionItem::HandleFrontSession()
{
    bool isMetaEmpty;
    {
        std::lock_guard lockGuard(metaDataLock_);
        isMetaEmpty = metaData_.GetTitle().empty() && metaData_.GetMediaImage() == nullptr &&
            metaData_.GetMediaImageUri().empty();
    }
    SLOGI("frontSession bundle=%{public}s metaEmpty=%{public}d Cmd=%{public}d castCmd=%{public}d firstAdd=%{public}d",
        GetBundleName().c_str(), isMetaEmpty, static_cast<int32_t>(supportedCmd_.size()),
        static_cast<int32_t>(supportedCastCmds_.size()), isFirstAddToFront_);
    if (isMetaEmpty || (supportedCmd_.size() == 0 && supportedCastCmds_.size() == 0)) {
        if (!isFirstAddToFront_ && serviceCallbackForUpdateSession_) {
            serviceCallbackForUpdateSession_(GetSessionId(), false);
            isFirstAddToFront_ = true;
        }
    } else {
        if (isFirstAddToFront_ && serviceCallbackForUpdateSession_) {
            serviceCallbackForUpdateSession_(GetSessionId(), true);
            isFirstAddToFront_ = false;
        }
    }
}

bool AVSessionItem::HasAvQueueInfo()
{
    std::lock_guard lockGuard(metaDataLock_);
    SLOGD("check HasAvQueueInfo in");
    if (metaData_.GetAVQueueName().empty()) {
        SLOGD("no avqueueinfo as avqueuename empty");
        return false;
    }
    if (metaData_.GetAVQueueId().empty()) {
        SLOGD("no avqueueinfo as avqueueid empty");
        return false;
    }
    if (metaData_.GetAVQueueImage() == nullptr && metaData_.GetAVQueueImageUri().empty()) {
        SLOGD("no avqueueinfo as avqueueimg empty");
        return false;
    }
    if (playbackState_.GetState() != AVPlaybackState::PLAYBACK_STATE_PLAY) {
        SLOGD("no avqueueinfo as not play");
        return false;
    }
    SLOGI("check HasAvQueueInfo %{public}s", metaData_.GetAVQueueName().c_str());
    return true;
}

void AVSessionItem::ReportSetAVMetaDataInfo(const AVMetaData& meta)
{
    std::string mediaImage = "false";
    std::string avQueueImage = "false";
    if (meta.GetMediaImage() != nullptr || !(meta.GetMediaImageUri().empty())) {
        mediaImage = "true";
    }
    if (meta.GetAVQueueImage() != nullptr || !(meta.GetAVQueueImageUri().empty())) {
        avQueueImage = "true";
    }
    std::string API_PARAM_STRING = "assetId: " + meta.GetAssetId() + ", "
                                    + "artist: " + meta.GetArtist() + ", "
                                    + "title: " + meta.GetTitle() + ", "
                                    + "subtitle: " + meta.GetSubTitle() + ", "
                                    + "avQueueId: " + meta.GetAVQueueId() + ", "
                                    + "duration: " + std::to_string(meta.GetDuration()) + ", "
                                    + "avQueueName: " + meta.GetAVQueueName() + ", "
                                    + "mediaImage: " + mediaImage + ", "
                                    + "avqueueImage: " + avQueueImage;
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR", "API_NAME", "SetAVMetaData",
        "BUNDLE_NAME", GetBundleName(), "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_, "SESSION_TYPE", GetSessionType(), "API_PARAM", API_PARAM_STRING,
        "ERROR_CODE", AVSESSION_SUCCESS, "ERROR_MSG", "SUCCESS");
}

int32_t AVSessionItem::SetAVMetaData(const AVMetaData& meta)
{
    bool hasAvQueueInfo = false;
    {
        SLOGD("limit metaDataLock range to split with sessionAndControllerLock");
        std::lock_guard lockGuard(metaDataLock_);
        SessionXCollie sessionXCollie("avsession::SetAVMetaData");
        ReportSetAVMetaDataInfo(meta);
        CHECK_AND_RETURN_RET_LOG(metaData_.CopyFrom(meta), AVSESSION_ERROR, "AVMetaData set error");
        std::shared_ptr<AVSessionPixelMap> innerPixelMap = metaData_.GetMediaImage();
        if (innerPixelMap != nullptr) {
            std::string sessionId = GetSessionId();
            std::string fileDir = AVSessionUtils::GetCachePathName(userId_);
            AVSessionUtils::WriteImageToFile(innerPixelMap, fileDir, sessionId + AVSessionUtils::GetFileSuffix());
            innerPixelMap->Clear();
            metaData_.SetMediaImage(innerPixelMap);
        }
        hasAvQueueInfo = HasAvQueueInfo();
        SLOGI(" SetAVMetaData AVQueueName: %{public}s AVQueueId: %{public}s hasAvQueueInfo: %{public}d",
            metaData_.GetAVQueueName().c_str(), metaData_.GetAVQueueId().c_str(), static_cast<int>(hasAvQueueInfo));
    }
    ProcessFrontSession("SetAVMetaData");
    if (hasAvQueueInfo && serviceCallbackForAddAVQueueInfo_) {
        serviceCallbackForAddAVQueueInfo_(*this);
    }
    SLOGI("send metadata change event to controllers with title %{public}s", meta.GetTitle().c_str());
    AVSessionEventHandler::GetInstance().AVSessionPostTask([this, meta]() {
        SLOGI("HandleMetaDataChange in postTask with title %{public}s and size %{public}d",
            meta.GetTitle().c_str(), static_cast<int>(controllers_.size()));
        std::lock_guard controllerLockGuard(controllersLock_);
        CHECK_AND_RETURN_LOG(controllers_.size() > 0, "handle with no controller, return");
        for (const auto& [pid, controller] : controllers_) {
            SLOGI("HandleMetaDataChange for controller pid=%{public}d", pid);
            controller->HandleMetaDataChange(meta);
        }
        }, "HandleMetaDataChange", 0);

    SLOGI("send metadata change event to controllers done");
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

    if (HasAvQueueInfo() && serviceCallbackForAddAVQueueInfo_) {
        SLOGD(" SetAVPlaybackState AVQueueName: %{public}s AVQueueId: %{public}s", metaData_.GetAVQueueName().c_str(),
            metaData_.GetAVQueueId().c_str());
        SLOGD("reduce metaDataLock for split metaDataLock & sessionAndControllerLock");
        serviceCallbackForAddAVQueueInfo_(*this);
    }

    {
        std::lock_guard controllerLockGuard(controllersLock_);
        SLOGI("send HandlePlaybackStateChange in postTask with state %{public}d and controller size %{public}d",
            state.GetState(), static_cast<int>(controllers_.size()));
        if (controllers_.size() > 0) {
            for (const auto& [pid, controller] : controllers_) {
                SLOGD("HandlePlaybackStateChange for controller pid=%{public}d", pid);
                controller->HandlePlaybackStateChange(state);
            }
        }
    }

    SLOGD("send playbackstate change event to controllers done");
    std::string isFavor = state.GetFavorite()? "true" : "false";
    std::string API_PARAM_STRING = "state: " + std::to_string(state.GetState()) + ", "
                                    + "elapsedTime: " + std::to_string(state.GetPosition().elapsedTime_) + ", "
                                    + "updateTime: " + std::to_string(state.GetPosition().updateTime_) + ", "
                                    + "loopMode: " + std::to_string(state.GetLoopMode()) + ", "
                                    + "isFavorite: " + isFavor;
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "SetAVPlaybackState",
        "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(),
        "API_PARAM", API_PARAM_STRING,
        "ERROR_CODE", AVSESSION_SUCCESS,
        "ERROR_MSG", "SUCCESS");
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
// LCOV_EXCL_STOP

int32_t AVSessionItem::SetLaunchAbility(const AbilityRuntime::WantAgent::WantAgent& ability)
{
    launchAbility_ = ability;
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> launWantAgent =
        std::make_shared<AbilityRuntime::WantAgent::WantAgent>(ability);
    int res = AVSESSION_SUCCESS;
    if (want != nullptr && launWantAgent != nullptr) {
        res = AbilityRuntime::WantAgent::WantAgentHelper::GetWant(launWantAgent, want);
    }
    std::string errMsg = "Get want failed.";
    std::string bundleName = "";
    std::string abilityName = "";
    std::string moduleName = "";
    if (res == AVSESSION_SUCCESS) {
        bundleName = want->GetElement().GetBundleName().c_str();
        abilityName = want->GetElement().GetAbilityName().c_str();
        moduleName = want->GetElement().GetModuleName().c_str();
        errMsg = "SUCCESS";
    }
    std::string API_PARAM_STRING = "bundleName: " + bundleName + ", "
                                    + "moduleName: " + moduleName + ", "
                                    + "abilityName: " + abilityName;
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "SetLaunchAbility",
        "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(),
        "API_PARAM", API_PARAM_STRING,
        "ERROR_CODE", res,
        "ERROR_MSG", errMsg);
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVSessionItem::GetExtras(AAFwk::WantParams& extras)
{
    std::lock_guard lockGuard(wantParamLock_);
    SLOGI("getextras lock pass");
    extras = extras_;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetExtras(const AAFwk::WantParams& extras)
{
    std::lock_guard lockGuard(wantParamLock_);
    SLOGI("set extras pass lock");
    extras_ = extras;

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    if (extras.HasParam("requireAbilityList")) {
        auto value = extras.GetParam("requireAbilityList");
        AAFwk::IArray* list = AAFwk::IArray::Query(value);
        if (list != nullptr && AAFwk::Array::IsStringArray(list)) {
            SetExtrasInner(list);
        }
    }
#endif

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
    sptr<AVControllerItem> result = new(std::nothrow) AVControllerItem(GetPid(), session, userId_);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "malloc controller failed");
    result->isFromSession_ = true;
    SLOGI("ImgSetLoop get controller set from session");
    controllers_.insert({GetPid(), result});
    return result;
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
void AVSessionItem::GetAVCastControllerProxy()
{
    if (castControllerProxy_ == nullptr) {
        SLOGI("CastControllerProxy is null, start get new proxy");
        {
            std::lock_guard lockGuard(castHandleLock_);
            castControllerProxy_ = AVRouter::GetInstance().GetRemoteController(castHandle_);
        }
    }
}

void AVSessionItem::ReportAVCastControllerInfo()
{
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "getAVCastController",
        "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(),
        "ERROR_CODE", AVSESSION_SUCCESS,
        "ERROR_MSG", "SUCCESS");
}

sptr<IRemoteObject> AVSessionItem::GetAVCastControllerInner()
{
    SLOGI("Start get avcast controller inner");
    GetAVCastControllerProxy();
    CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, nullptr, "Get castController proxy failed");

    sptr<AVCastControllerItem> castController = new (std::nothrow) AVCastControllerItem();
    CHECK_AND_RETURN_RET_LOG(castController != nullptr, nullptr, "malloc AVCastController failed");
    std::shared_ptr<AVCastControllerItem> sharedPtr = std::shared_ptr<AVCastControllerItem>(castController.GetRefPtr(),
        [holder = castController](const auto*) {});
    ReportAVCastControllerInfo();
    auto callback = [this](int32_t cmd, std::vector<int32_t>& supportedCastCmds) {
        SLOGI("add cast valid command %{public}d", cmd);
        if (cmd == AVCastControlCommand::CAST_CONTROL_CMD_INVALID) {
            supportedCastCmds_.clear();
            supportedCastCmds = supportedCastCmds_;
            HandleCastValidCommandChange(supportedCastCmds_);
            return;
        }
        if (cmd == AVCastControlCommand::CAST_CONTROL_CMD_MAX) {
            supportedCastCmds = supportedCastCmds_;
            return;
        }
        if (descriptor_.sessionTag_ == "RemoteCast") {
            SLOGE("sink session should not modify valid cmds");
            supportedCastCmds = {};
            return;
        }
        if (cmd > removeCmdStep_) {
            DeleteSupportCastCommand(cmd - removeCmdStep_);
        } else {
            AddSupportCastCommand(cmd);
        }
        supportedCastCmds = supportedCastCmds_;
        return;
    }

    sharedPtr->Init(castControllerProxy_, callback);
    {
        std::lock_guard lockGuard(castControllersLock_);
        castControllers_.emplace_back(sharedPtr);
    }
    sptr<IRemoteObject> remoteObject = castController;

    sharedPtr->SetSessionTag(descriptor_.sessionTag_);
    InitializeCastCommands();
    return remoteObject;
}

void AVSessionItem::ReleaseAVCastControllerInner()
{
    SLOGI("Release AVCastControllerInner");
    std::lock_guard lockGuard(castControllersLock_);
    for (auto controller : castControllers_) {
        controller->Destroy();
    }
    castControllerProxy_ = nullptr;
}
#endif

int32_t AVSessionItem::RegisterCallbackInner(const sptr<IAVSessionCallback>& callback)
{
    std::lock_guard callbackLockGuard(callbackLock_);
    callback_ = callback;
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVSessionItem::Activate()
{
    descriptor_.isActive_ = true;
    std::lock_guard controllerLockGuard(controllersLock_);
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "Activate",
        "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(),
        "ERROR_CODE", AVSESSION_SUCCESS,
        "ERROR_MSG", "SUCCESS");
    for (const auto& [pid, controller] : controllers_) {
        SLOGI("pid=%{public}d", pid);
        controller->HandleActiveStateChange(true);
    }
    if (descriptor_.sessionType_ == AVSession::SESSION_TYPE_VOICE_CALL ||
        descriptor_.sessionType_ == AVSession::SESSION_TYPE_VIDEO_CALL) {
        SLOGI("set audio scene for phone chat start");
        AudioSystemManager *audioManager = AudioSystemManager::GetInstance();
        AudioScene audioScene = AudioScene::AUDIO_SCENE_CALL_START;
        if (audioManager != nullptr) {
            audioManager->SetAudioScene(audioScene);
        }
    }
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVSessionItem::Deactivate()
{
    descriptor_.isActive_ = false;
    SLOGI("Deactivate in");
    std::lock_guard controllerLockGuard(controllersLock_);
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "Deactivate",
        "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(),
        "ERROR_CODE", AVSESSION_SUCCESS,
        "ERROR_MSG", "SUCCESS");
    for (const auto& [pid, controller] : controllers_) {
        SLOGI("pid=%{public}d", pid);
        controller->HandleActiveStateChange(false);
    }
    if (descriptor_.sessionType_ == AVSession::SESSION_TYPE_VOICE_CALL ||
        descriptor_.sessionType_ == AVSession::SESSION_TYPE_VIDEO_CALL) {
        SLOGI("set audio scene for phone chat end");
        AudioSystemManager *audioManager = AudioSystemManager::GetInstance();
        AudioScene audioScene = AudioScene::AUDIO_SCENE_CALL_END;
        if (audioManager != nullptr) {
            audioManager->SetAudioScene(audioScene);
        }
    }
    SLOGI("Deactivate done");
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

bool AVSessionItem::IsActive()
{
    return descriptor_.isActive_;
}

// LCOV_EXCL_START
int32_t AVSessionItem::AddSupportCommand(int32_t cmd)
{
    CHECK_AND_RETURN_RET_LOG(cmd > AVControlCommand::SESSION_CMD_INVALID, AVSESSION_ERROR, "invalid cmd");
    CHECK_AND_RETURN_RET_LOG(cmd < AVControlCommand::SESSION_CMD_MAX, AVSESSION_ERROR, "invalid cmd");
    SLOGD("AddSupportCommand=%{public}d", cmd);
    if (cmd == AVControlCommand::SESSION_CMD_MEDIA_KEY_SUPPORT) {
        SLOGI("enable media key event listen");
        isMediaKeySupport = true;
        return AVSESSION_SUCCESS;
    }
    auto iter = std::find(supportedCmd_.begin(), supportedCmd_.end(), cmd);
    CHECK_AND_RETURN_RET_LOG(iter == supportedCmd_.end(), AVSESSION_SUCCESS, "cmd already been added");
    supportedCmd_.push_back(cmd);
    std::string API_PARAM_STRING = "cmd :" + std::to_string(cmd);
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "OnEvent",
        "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(),
        "API_PARAM", API_PARAM_STRING,
        "ERROR_CODE", AVSESSION_SUCCESS,
        "ERROR_MSG", "SUCCESS");
    ProcessFrontSession("AddSupportCommand");

    {
        std::lock_guard controllerLockGuard(controllersLock_);
        SLOGI("send HandleValidCommandChange check number %{public}d", static_cast<int>(controllers_.size()));
        for (const auto& [pid, controller] : controllers_) {
            SLOGI("HandleValidCommandChange add for controller pid=%{public}d with num %{public}d",
                pid, static_cast<int>(supportedCmd_.size()));
            controller->HandleValidCommandChange(supportedCmd_);
        }
    }

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AddSessionCommandToCast(cmd);
#endif
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::DeleteSupportCommand(int32_t cmd)
{
    CHECK_AND_RETURN_RET_LOG(cmd > AVControlCommand::SESSION_CMD_INVALID, AVSESSION_ERROR, "invalid cmd");
    CHECK_AND_RETURN_RET_LOG(cmd < AVControlCommand::SESSION_CMD_MAX, AVSESSION_ERROR, "invalid cmd");
    SLOGD("DeleteSupportCommand=%{public}d", cmd);
    if (cmd == AVControlCommand::SESSION_CMD_MEDIA_KEY_SUPPORT) {
        SLOGI("disable media key event listen");
        isMediaKeySupport = false;
        return AVSESSION_SUCCESS;
    }
    auto iter = std::remove(supportedCmd_.begin(), supportedCmd_.end(), cmd);
    supportedCmd_.erase(iter, supportedCmd_.end());
    std::string API_PARAM_STRING = "cmd :" + std::to_string(cmd);
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "OffEvent",
        "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(),
        "API_PARAM", API_PARAM_STRING,
        "ERROR_CODE", AVSESSION_SUCCESS,
        "ERROR_MSG", "SUCCESS");
    ProcessFrontSession("DeleteSupportCommand");

    SLOGD("send validCommand change event to controllers with num %{public}d DEL %{public}d",
        static_cast<int>(supportedCmd_.size()), cmd);
    std::lock_guard controllerLockGuard(controllersLock_);
    for (const auto& [pid, controller] : controllers_) {
        SLOGI("HandleValidCommandChange del for controller pid=%{public}d with num %{public}d",
            pid, static_cast<int>(supportedCmd_.size()));
        controller->HandleValidCommandChange(supportedCmd_);
    }

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    RemoveSessionCommandFromCast(cmd);
#endif
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

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

std::string AVSessionItem::GetAnonymousDeviceId(std::string deviceId)
{
    if (deviceId.empty() || deviceId.length() < DEVICE_ID_MIN_LEN) {
        return "unknown";
    }
    const uint32_t half = DEVICE_ID_MIN_LEN / 2;
    return deviceId.substr(0, half) + "**" + deviceId.substr(deviceId.length() - half);
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
int32_t AVSessionItem::RegisterListenerStreamToCast(const std::map<std::string, std::string>& serviceNameMapState,
    DeviceInfo deviceInfo)
{
    std::lock_guard displayListenerLockGuard(mirrorToStreamLock_);
    if (castHandle_ > 0) {
        return AVSESSION_ERROR;
    }
    castServiceNameMapState_ = serviceNameMapState;
    OutputDeviceInfo outputDeviceInfo;
    outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
    int64_t castHandle = AVRouter::GetInstance().StartCast(outputDeviceInfo, castServiceNameMapState_);
    castHandle_ = castHandle;
    castHandleDeviceId_ = deviceInfo.deviceId_;
    SLOGI("RegisterListenerStreamToCast check handle set to %{public}ld", castHandle_);
    CHECK_AND_RETURN_RET_LOG(castHandle != AVSESSION_ERROR, AVSESSION_ERROR, "StartCast failed");
    counter_ = firstStep;
    AVRouter::GetInstance().RegisterCallback(castHandle, cssListener_);
    AVRouter::GetInstance().SetServiceAllConnectState(castHandle, deviceInfo);
    counter_ = secondStep;
    UpdateCastDeviceMap(deviceInfo);

    doContinuousTaskRegister();
    HISYSEVENT_BEHAVIOR("SESSION_CAST_CONTROL",
        "CONTROL_TYPE", "MirrorTostreamCast",
        "PEER_DEVICE_ID", GetAnonymousDeviceId(deviceInfo.deviceId_),
        "PEER_DEVICE_NAME", deviceInfo.deviceName_,
        "PEER_DEVICE_TYPE", deviceInfo.deviceType_,
        "PEER_NETWORK_ID", GetAnonymousDeviceId(deviceInfo.networkId_),
        "PEER_SUPPORTED_PROTOCOL", deviceInfo.supportedProtocols_,
        "BUNDLE_NAME", GetBundleName());
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
void AVSessionItem::InitializeCastCommands()
{
    // always support setVolume command
    auto iter = std::find(supportedCastCmds_.begin(), supportedCastCmds_.end(),
        AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME);
    if (iter == supportedCastCmds_.end()) {
        supportedCastCmds_.push_back(AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME);
    }

    iter = std::find(supportedCastCmds_.begin(), supportedCastCmds_.end(),
        AVCastControlCommand::CAST_CONTROL_CMD_SET_SPEED);
    if (iter == supportedCastCmds_.end()) {
        supportedCastCmds_.push_back(AVCastControlCommand::CAST_CONTROL_CMD_SET_SPEED);
    }

    iter = std::find(supportedCastCmds_.begin(), supportedCastCmds_.end(),
        AVCastControlCommand::CAST_CONTROL_CMD_SEEK);
    if (iter == supportedCastCmds_.end()) {
        supportedCastCmds_.push_back(AVCastControlCommand::CAST_CONTROL_CMD_SEEK);
        supportedCastCmds_.push_back(AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD);
        supportedCastCmds_.push_back(AVCastControlCommand::CAST_CONTROL_CMD_REWIND);
    }

    iter = std::find(supportedCmd_.begin(), supportedCmd_.end(), AVControlCommand::SESSION_CMD_SET_LOOP_MODE);
    if (iter != supportedCmd_.end()) {
        AddSessionCommandToCast(AVControlCommand::SESSION_CMD_SET_LOOP_MODE);
    }
}

bool AVSessionItem::IsCastRelevancyCommand(int32_t cmd)
{
    if (cmd == AVControlCommand::SESSION_CMD_SET_LOOP_MODE) {
        return true;
    }
    return false;
}

int32_t AVSessionItem::SessionCommandToCastCommand(int32_t cmd)
{
    if (cmd == AVControlCommand::SESSION_CMD_SET_LOOP_MODE) {
        return AVCastControlCommand::CAST_CONTROL_CMD_SET_LOOP_MODE;
    }
    return AVCastControlCommand::CAST_CONTROL_CMD_INVALID;
}

void AVSessionItem::AddSessionCommandToCast(int32_t cmd)
{
    if (!IsCastRelevancyCommand(cmd)) {
        return;
    }

    if (castControllerProxy_ != nullptr) {
        int32_t castCmd = SessionCommandToCastCommand(cmd);
        auto iter = std::find(supportedCastCmds_.begin(), supportedCastCmds_.end(), castCmd);
        if (iter != supportedCastCmds_.end()) {
            SLOGI("castCmd have already been added. cmd:%{public}d", castCmd);
            return;
        }
        supportedCastCmds_.push_back(castCmd);
        HandleCastValidCommandChange(supportedCastCmds_);
    }
}

void AVSessionItem::RemoveSessionCommandFromCast(int32_t cmd)
{
    if (!IsCastRelevancyCommand(cmd)) {
        return;
    }

    if (castControllerProxy_ != nullptr) {
        int32_t castCmd = SessionCommandToCastCommand(cmd);
        SLOGI("remove castcmd:%{public}d", castCmd);
        auto iter = std::remove(supportedCastCmds_.begin(), supportedCastCmds_.end(), castCmd);
        supportedCastCmds_.erase(iter, supportedCastCmds_.end());
        HandleCastValidCommandChange(supportedCastCmds_);
    }
}

int32_t AVSessionItem::AddSupportCastCommand(int32_t cmd)
{
    CHECK_AND_RETURN_RET_LOG(cmd > AVCastControlCommand::CAST_CONTROL_CMD_INVALID, AVSESSION_ERROR, "invalid cmd");
    CHECK_AND_RETURN_RET_LOG(cmd < AVCastControlCommand::CAST_CONTROL_CMD_MAX, AVSESSION_ERROR, "invalid cmd");
    if (cmd == AVCastControlCommand::CAST_CONTROL_CMD_PLAY_STATE_CHANGE) {
        auto iter = std::find(
            supportedCastCmds_.begin(), supportedCastCmds_.end(), AVCastControlCommand::CAST_CONTROL_CMD_PLAY);
        CHECK_AND_RETURN_RET_LOG(iter == supportedCastCmds_.end(), AVSESSION_SUCCESS, "cmd already been added");
        supportedCastCmds_.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PLAY);
        supportedCastCmds_.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PAUSE);
        supportedCastCmds_.push_back(AVCastControlCommand::CAST_CONTROL_CMD_STOP);
    } else if (cmd == AVCastControlCommand::CAST_CONTROL_CMD_SEEK) {
        auto iter = std::find(supportedCastCmds_.begin(), supportedCastCmds_.end(), cmd);
        CHECK_AND_RETURN_RET_LOG(iter == supportedCastCmds_.end(), AVSESSION_SUCCESS, "cmd already been added");
        supportedCastCmds_.push_back(cmd);
        supportedCastCmds_.push_back(AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD);
        supportedCastCmds_.push_back(AVCastControlCommand::CAST_CONTROL_CMD_REWIND);
    } else {
        auto iter = std::find(supportedCastCmds_.begin(), supportedCastCmds_.end(), cmd);
        CHECK_AND_RETURN_RET_LOG(iter == supportedCastCmds_.end(), AVSESSION_SUCCESS, "cmd already been added");
        supportedCastCmds_.push_back(cmd);
    }
    ProcessFrontSession("AddSupportCastCommand");
    HandleCastValidCommandChange(supportedCastCmds_);
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::DeleteSupportCastCommand(int32_t cmd)
{
    CHECK_AND_RETURN_RET_LOG(cmd > AVCastControlCommand::CAST_CONTROL_CMD_INVALID, AVSESSION_ERROR, "invalid cmd");
    CHECK_AND_RETURN_RET_LOG(cmd < AVCastControlCommand::CAST_CONTROL_CMD_MAX, AVSESSION_ERROR, "invalid cmd");

    if (cmd == AVCastControlCommand::CAST_CONTROL_CMD_PLAY_STATE_CHANGE) {
        auto iter = std::remove(
            supportedCastCmds_.begin(), supportedCastCmds_.end(), AVCastControlCommand::CAST_CONTROL_CMD_PLAY);
        supportedCastCmds_.erase(iter, supportedCastCmds_.end());

        iter = std::remove(
            supportedCastCmds_.begin(), supportedCastCmds_.end(), AVCastControlCommand::CAST_CONTROL_CMD_PAUSE);
        supportedCastCmds_.erase(iter, supportedCastCmds_.end());

        iter = std::remove(
            supportedCastCmds_.begin(), supportedCastCmds_.end(), AVCastControlCommand::CAST_CONTROL_CMD_STOP);
        supportedCastCmds_.erase(iter, supportedCastCmds_.end());
    } else if (cmd == AVCastControlCommand::CAST_CONTROL_CMD_SEEK) {
        auto iter = std::remove(supportedCastCmds_.begin(), supportedCastCmds_.end(), cmd);
        supportedCastCmds_.erase(iter, supportedCastCmds_.end());

        iter = std::remove(
            supportedCastCmds_.begin(), supportedCastCmds_.end(), AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD);
        supportedCastCmds_.erase(iter, supportedCastCmds_.end());

        iter = std::remove(
            supportedCastCmds_.begin(), supportedCastCmds_.end(), AVCastControlCommand::CAST_CONTROL_CMD_REWIND);
        supportedCastCmds_.erase(iter, supportedCastCmds_.end());
    } else {
        auto iter = std::remove(supportedCastCmds_.begin(), supportedCastCmds_.end(), cmd);
        supportedCastCmds_.erase(iter, supportedCastCmds_.end());
    }
    ProcessFrontSession("DeleteSupportCastCommand");
    HandleCastValidCommandChange(supportedCastCmds_);
    return AVSESSION_SUCCESS;
}

void AVSessionItem::HandleCastValidCommandChange(std::vector<int32_t> &cmds)
{
    std::lock_guard lockGuard(castControllersLock_);
    SLOGI("HandleCastValidCommandChange with castControllerNum %{public}d", static_cast<int>(castControllers_.size()));
    for (auto controller : castControllers_) {
        if (controller != nullptr) {
            SLOGI("HandleCastValidCommandChange size:%{public}zd", cmds.size());
            controller->HandleCastValidCommandChange(cmds);
        }
    }
}

int32_t AVSessionItem::ReleaseCast()
{
    SLOGI("Release cast process");
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "StopCasting",
        "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(),
        "ERROR_CODE", AVSESSION_SUCCESS,
        "ERROR_MSG", "SUCCESS");
    return StopCast();
}

int32_t AVSessionItem::CastAddToCollaboration(const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("enter CastAddToCollaboration");
    if (castDeviceInfoMap_.count(outputDeviceInfo.deviceInfos_[0].deviceId_) != 1) {
        SLOGE("deviceId map deviceinfo is not exit");
        return AVSESSION_ERROR;
    }
    ListenCollaborationRejectToStopCast();
    DeviceInfo cacheDeviceInfo = castDeviceInfoMap_[outputDeviceInfo.deviceInfos_[0].deviceId_];
    if (cacheDeviceInfo.networkId_.empty()) {
        SLOGI("untrusted device, networkId is empty, then input deviceId to ApplyAdvancedResource");
        collaborationNeedNetworkId_ = cacheDeviceInfo.deviceId_;
        networkIdIsEmpty_ = true;
    } else {
        collaborationNeedNetworkId_= cacheDeviceInfo.networkId_;
    }
    CollaborationManager::GetInstance().ApplyAdvancedResource(collaborationNeedNetworkId_.c_str());
    //wait collaboration callback 10s
    std::unique_lock <std::mutex> applyResultLock(collaborationApplyResultMutex_);
    bool flag = connectWaitCallbackCond_.wait_for(applyResultLock, std::chrono::seconds(collaborationCallbackTimeOut_),
        [this]() {
            return applyResultFlag_;
    });
    //wait user decision collaboration callback 60s
    if (waitUserDecisionFlag_) {
        flag = connectWaitCallbackCond_.wait_for(applyResultLock, std::chrono::seconds(collaborationUserCallbackTimeOut_),
        [this]() {
            return applyUserResultFlag_;
        });
    }
    applyResultFlag_ = false;
    applyUserResultFlag_ = false;
    waitUserDecisionFlag_ = false;
    CHECK_AND_RETURN_RET_LOG(flag, ERR_WAIT_ALLCONNECT_TIMEOUT, "collaboration callback timeout");
    if (collaborationRejectFlag_) {
        collaborationRejectFlag_ = false;
        SLOGE("collaboration callback reject");
        return ERR_ALLCONNECT_CAST_REJECT;
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::StartCast(const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("Start cast process");
    std::lock_guard castHandleLockGuard(castHandleLock_);

    // unregister pre castSession callback to avoid previous session timeout disconnect influence current session
    if (castHandle_ > 0) {
        if (castHandleDeviceId_ == outputDeviceInfo.deviceInfos_[0].deviceId_) {
            SLOGI("repeat startcast %{public}ld", castHandle_);
            return AVSESSION_ERROR;
        } else {
            SLOGI("cast check with pre cast alive %{public}ld, unregister callback", castHandle_);
            AVRouter::GetInstance().UnRegisterCallback(castHandle_, cssListener_);
        }
    }
    int32_t flag = CastAddToCollaboration(outputDeviceInfo);
    CHECK_AND_RETURN_RET_LOG(flag == AVSESSION_SUCCESS, AVSESSION_ERROR, "collaboration to start cast fail");
    int64_t castHandle = AVRouter::GetInstance().StartCast(outputDeviceInfo, castServiceNameMapState_);
    CHECK_AND_RETURN_RET_LOG(castHandle != AVSESSION_ERROR, AVSESSION_ERROR, "StartCast failed");
    std::lock_guard lockGuard(castHandleLock_);
    castHandle_ = castHandle;
    SLOGI("start cast check handle set to %{public}ld", castHandle_);

    int32_t ret = AddDevice(static_cast<int32_t>(castHandle), outputDeviceInfo);
    if (ret == AVSESSION_SUCCESS) {
        castHandleDeviceId_ = outputDeviceInfo.deviceInfos_[0].deviceId_;
    }

    doContinuousTaskRegister();
    return ret;
}

int32_t AVSessionItem::AddDevice(const int64_t castHandle, const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("Add device process");
    std::lock_guard lockGuard(castHandleLock_);
    AVRouter::GetInstance().RegisterCallback(castHandle_, cssListener_);
    int32_t castId = static_cast<int32_t>(castHandle_);
    int32_t ret = AVRouter::GetInstance().AddDevice(castId, outputDeviceInfo);
    SLOGI("Add device process with ret %{public}d", ret);
    return ret;
}

bool AVSessionItem::IsCastSinkSession(int32_t castState)
{
    SLOGI("IsCastSinkSession for castState %{public}d, sessionTag is %{public}s", castState,
        descriptor_.sessionTag_.c_str());
    if (castState == ConnectionState::STATE_DISCONNECTED && descriptor_.sessionTag_ == "RemoteCast") {
        SLOGI("A cast sink session is being disconnected, call destroy with service");
        if (isDestroyed_) {
            SLOGE("return for already in destroy");
            return true;
        }
        return Destroy() == true;
    }
    return false;
}

void AVSessionItem::DealCastState(int32_t castState)
{
    if (newCastState == castState) {
        isUpdate = false;
    } else {
        if (counter_ == firstStep) {
            newCastState = virtualDeviceStateConnection;
        } else {
            newCastState = castState;
        }
        isUpdate = true;
    }
}

void AVSessionItem::DealDisconnect(DeviceInfo deviceInfo)
{
    SLOGI("Is remotecast, received disconnect event for castHandle_: %{public}ld", castHandle_);
    AVRouter::GetInstance().UnRegisterCallback(castHandle_, cssListener_);
    AVRouter::GetInstance().StopCastSession(castHandle_);
    castHandle_ = -1;
    castHandleDeviceId_ = "-100";
    doContinuousTaskUnregister();
    castControllerProxy_ = nullptr;
    supportedCastCmds_.clear();
    SaveLocalDeviceInfo();
    ReportStopCastFinish("AVSessionItem::OnCastStateChange", deviceInfo);
}

void AVSessionItem::DealCollaborationPublishState(int32_t castState, DeviceInfo deviceInfo)
{
    SLOGI("enter DealCollaborationPublishState");
    if (castState == castConnectStateForConnected_) { // 6 is connected status (stream)
        if (networkIdIsEmpty_) {
            SLOGI("untrusted device, networkId is empty, get netwokId from castplus");
            AVRouter::GetInstance().GetRemoteNetWorkId(
                castHandle_, deviceInfo.deviceId_, collaborationNeedNetworkId_);
            networkIdIsEmpty_ = false;
        }
        if (collaborationNeedNetworkId_.empty()) {
            SLOGI("cast add to collaboration in peer, get netwokId from castplus");
            AVRouter::GetInstance().GetRemoteNetWorkId(
                castHandle_, deviceInfo.deviceId_, collaborationNeedNetworkId_);
        }
        CollaborationManager::GetInstance().PublishServiceState(collaborationNeedNetworkId_.c_str(),
            ServiceCollaborationManagerBussinessStatus::SCM_CONNECTED);
    }
    if (castState == castConnectStateForDisconnect_) { // 5 is disconnected status
        CollaborationManager::GetInstance().PublishServiceState(collaborationNeedNetworkId_.c_str(),
            ServiceCollaborationManagerBussinessStatus::SCM_IDLE);
    }
}

void AVSessionItem::OnCastStateChange(int32_t castState, DeviceInfo deviceInfo)
{
    SLOGI("OnCastStateChange in with state: %{public}d | id: %{public}s", static_cast<int32_t>(castState),
        deviceInfo.deviceId_.c_str());
    DealCollaborationPublishState(castState, deviceInfo);
    DealCastState(castState);
    if (castState == streamStateConnection && counter_ == secondStep) {
        SLOGI("interception of one devicestate=6 transmission");
        counter_ = 0;
        return;
    }
    OutputDeviceInfo outputDeviceInfo;
    if (castDeviceInfoMap_.count(deviceInfo.deviceId_) > 0) {
        outputDeviceInfo.deviceInfos_.emplace_back(castDeviceInfoMap_[deviceInfo.deviceId_]);
    } else {
        outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
    }
    if (castState == castConnectStateForConnected_) { // 6 is connected status (stream)
        castState = 1; // 1 is connected status (local)
        descriptor_.outputDeviceInfo_ = outputDeviceInfo;
        ReportConnectFinish("AVSessionItem::OnCastStateChange", deviceInfo);
        if (callStartCallback_) {
            SLOGI("AVSessionItem send callStart event to service for connected");
            callStartCallback_(*this);
        }
    }
    if (castState == castConnectStateForDisconnect_) { // 5 is disconnected status
        castState = 6; // 6 is disconnected status of AVSession
        DealDisconnect(deviceInfo);
    }
    HandleOutputDeviceChange(castState, outputDeviceInfo);
    {
        std::lock_guard controllersLockGuard(controllersLock_);
        SLOGD("AVCastController map size is %{public}zu", controllers_.size());
        for (const auto& controller : controllers_) {
            if (controllers_.size() <= 0) {
                SLOGE("lopp in empty controllers, break");
                break;
            }
            CHECK_AND_RETURN_LOG(controller.second != nullptr, "Controller is nullptr, return");
            controller.second->HandleOutputDeviceChange(castState, outputDeviceInfo);
        }
    }
    if (IsCastSinkSession(castState)) {
        SLOGE("Cast sink session start to disconnect");
        return;
    }
}

void AVSessionItem::OnCastEventRecv(int32_t errorCode, std::string& errorMsg)
{
    SLOGI("OnCastEventRecv in with code and msg %{public}dm %{public}s", errorCode, errorMsg.c_str());
    for (auto controller : castControllers_) {
        SLOGI("pass error to cast controller with code %{public}d", errorCode);
        controller->OnPlayerError(errorCode, errorMsg);
    }
}

void AVSessionItem::ListenCollaborationRejectToStopCast()
{
    CollaborationManager::GetInstance().SendRejectStateToStopCast([this](const int32_t code) {
        std::unique_lock <std::mutex> applyResultLock(collaborationApplyResultMutex_);
        if (code == ServiceCollaborationManagerResultCode::ONSTOP && newCastState == castConnectStateForConnected_) {
            SLOGI("onstop to stop cast");
            StopCast();
        }
        if (code == ServiceCollaborationManagerResultCode::PASS && newCastState != castConnectStateForConnected_) {
            SLOGI("ApplyResult can cast");
            applyResultFlag_ = true;
            applyUserResultFlag_ = true;
            connectWaitCallbackCond_.notify_one();
        }
        if (code == ServiceCollaborationManagerResultCode::REJECT && newCastState != castConnectStateForConnected_) {
            SLOGI("ApplyResult can not cast");
            collaborationRejectFlag_ = true;
            applyResultFlag_ = true;
            applyUserResultFlag_ = true;
            connectWaitCallbackCond_.notify_one();
        }
        if (code == ServiceCollaborationManagerResultCode::USERTIP && newCastState != castConnectStateForConnected_) {
            SLOGI("ApplyResult user tip");
            applyResultFlag_ = true;
            waitUserDecisionFlag_ = true;
            connectWaitCallbackCond_.notify_one();
        }
        if (code == ServiceCollaborationManagerResultCode::USERAGREE && newCastState != castConnectStateForConnected_) {
            SLOGI("ApplyResult user agree cast");
        }
    });
}

int32_t AVSessionItem::StopCast()
{
    if (descriptor_.sessionTag_ == "RemoteCast") {
        AVRouter::GetInstance().UnRegisterCallback(castHandle_, cssListener_);
        int32_t ret = AVRouter::GetInstance().StopCastSession(castHandle_);
        castHandle_ = -1;
        castHandleDeviceId_ = "-100";
        SLOGI("Unregister and Stop cast process for sink with ret %{public}d", ret);
        return ret;
    }
    SLOGI("Stop cast process");
    removeTimes = 1;
    if (isUpdate && newCastState == streamStateConnection) {
        SLOGE("removeTimes = 0");
        removeTimes = 0;
    }
    {
        std::lock_guard lockGuard(castHandleLock_);
        CHECK_AND_RETURN_RET_LOG(castHandle_ != 0, AVSESSION_SUCCESS, "Not cast session, return");
        AVSessionRadarInfo info("AVSessionItem::StopCast");
        AVSessionRadar::GetInstance().StopCastBegin(descriptor_.outputDeviceInfo_, info);
        int64_t ret = AVRouter::GetInstance().StopCast(castHandle_, removeTimes);
        AVSessionRadar::GetInstance().StopCastEnd(descriptor_.outputDeviceInfo_, info);
        SLOGI("StopCast with unchange castHandle is %{public}ld", castHandle_);
        CHECK_AND_RETURN_RET_LOG(ret != AVSESSION_ERROR, AVSESSION_ERROR, "StopCast failed");
        removeTimes = 1;
    }

    if (castServiceNameMapState_["HuaweiCast"] != deviceStateConnection &&
        castServiceNameMapState_["HuaweiCast-Dual"] != deviceStateConnection) {
        OutputDeviceInfo outputDeviceInfo;
        DeviceInfo deviceInfo;
        deviceInfo.castCategory_ = AVCastCategory::CATEGORY_LOCAL;
        deviceInfo.deviceId_ = "0";
        deviceInfo.deviceName_ = "LocalDevice";
        outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
        SetOutputDevice(outputDeviceInfo);
    }

    return AVSESSION_SUCCESS;
}

void AVSessionItem::SetCastHandle(const int64_t castHandle)
{
    castHandle_ = castHandle;
    SLOGI("set cast handle is %{public}ld", castHandle_);
}

void AVSessionItem::RegisterDeviceStateCallback()
{
    SLOGI("Start register callback for device state change");
    OutputDeviceInfo localDevice;
    DeviceInfo localInfo;
    localInfo.castCategory_ = AVCastCategory::CATEGORY_LOCAL;
    localInfo.deviceId_ = "0";
    localInfo.deviceName_ = "LocalDevice";
    localDevice.deviceInfos_.emplace_back(localInfo);
    descriptor_.outputDeviceInfo_ = localDevice;
    AVRouter::GetInstance().RegisterCallback(castHandle_, cssListener_);
    SLOGI("register callback for device state change done");
}

void AVSessionItem::UnRegisterDeviceStateCallback()
{
    SLOGI("Stop unregister callback for device state change");
    AVRouter::GetInstance().UnRegisterCallback(castHandle_, cssListener_);
}

void AVSessionItem::StopCastSession()
{
    SLOGI("Stop cast session process with castHandle: %{public}ld", castHandle_);
    int64_t ret = AVRouter::GetInstance().StopCastSession(castHandle_);
    doContinuousTaskUnregister();
    if (ret != AVSESSION_ERROR) {
        castHandle_ = -1;
        castHandleDeviceId_ = "-100";
    } else {
        SLOGE("Stop cast session process error");
    }
}

AVSessionDisplayIntf* AVSessionItem::GetAVSessionDisplayIntf()
{
    if (avsessionDisaplayIntf_ == nullptr) {
        typedef AVSessionDisplayIntf *(*CreateAVSessionDisplayIntfFunc)();
        CreateAVSessionDisplayIntfFunc createAVSessionDisplayIntf =
            reinterpret_cast<CreateAVSessionDisplayIntfFunc>(dynamicLoader_->GetFuntion(
                AVSESSION_DYNAMIC_DISPLAY_LIBRARY_PATH, "createAVSessionDisplayIntf"));
        if (createAVSessionDisplayIntf) {
            avsessionDisaplayIntf_ = (*createAVSessionDisplayIntf)();
        }
    }
    return avsessionDisaplayIntf_;
}

int32_t AVSessionItem::StartCastDisplayListener()
{
    SLOGI("StartCastDisplayListener in");
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "onCastDisplayChange",
        "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(),
        "ERROR_CODE", AVSESSION_SUCCESS,
        "ERROR_MSG", "SUCCESS");
    sptr<IAVSessionCallback> callback;
    {
        std::lock_guard callbackLockGuard(callbackLock_);
        CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, AVSESSION_ERROR, "callback_ is nullptr");
        callback = callback_;
    }
    GetDisplayListener(callback);
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::StopCastDisplayListener()
{
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "offCastDisplayChange",
        "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(),
        "ERROR_CODE", AVSESSION_SUCCESS,
        "ERROR_MSG", "SUCCESS");
    SLOGI("StopCastDisplayListener in");
    std::lock_guard displayListenerLockGuard(displayListenerLock_);
    CHECK_AND_RETURN_RET_LOG(displayListener_ != nullptr, AVSESSION_ERROR, "displayListener_ is nullptr");
    Rosen::DMError ret = Rosen::ScreenManager::GetInstance().UnregisterScreenListener(displayListener_);
    if (ret != Rosen::DMError::DM_OK) {
        SLOGE("UnregisterScreenListener failed, ret: %{public}d.", ret);
    }
    displayListener_ = nullptr;
    return AVSESSION_SUCCESS;
}

void AVSessionItem::GetDisplayListener(sptr<IAVSessionCallback> callback)
{
    SLOGI("GetDisplayListener in");
    std::lock_guard displayListenerLockGuard(displayListenerLock_);
    if (displayListener_ == nullptr) {
        SLOGI("displayListener_ is null, try to create new listener");
        displayListener_ = new HwCastDisplayListener(callback);
        if (displayListener_ == nullptr) {
            SLOGI("Create displayListener failed");
            return;
        }
        SLOGI("Start to register display listener");
        Rosen::DMError ret = Rosen::ScreenManager::GetInstance().RegisterScreenListener(displayListener_);
        if (ret != Rosen::DMError::DM_OK) {
            SLOGE("UnregisterScreenListener failed, ret: %{public}d.", ret);
        }
    }
    return;
}

int32_t AVSessionItem::GetAllCastDisplays(std::vector<CastDisplayInfo>& castDisplays)
{
    SLOGI("GetAllCastDisplays in");
    std::vector<sptr<Rosen::Screen>> allDisplays;
    Rosen::ScreenManager::GetInstance().GetAllScreens(allDisplays);
    std::vector<CastDisplayInfo> displays;
    for (auto &display : allDisplays) {
        SLOGI("GetAllCastDisplays name: %{public}s, id: %{public}lu", display->GetName().c_str(), display->GetId());
        auto flag = Rosen::ScreenManager::GetInstance().GetVirtualScreenFlag(display->GetId());
        if (flag == Rosen::VirtualScreenFlag::CAST) {
            SLOGI("ReportCastDisplay start in");
            CastDisplayInfo castDisplayInfo;
            castDisplayInfo.displayState = CastDisplayState::STATE_ON;
            castDisplayInfo.displayId = display->GetId();
            castDisplayInfo.name = display->GetName();
            castDisplayInfo.width = display->GetWidth();
            castDisplayInfo.height = display->GetHeight();
            displays.push_back(castDisplayInfo);
            std::lock_guard displayListenerLockGuard(displayListenerLock_);
            if (displayListener_ != nullptr) {
                displayListener_->SetDisplayInfo(display);
            }
        }
    }
    castDisplays = displays;
    SLOGI("GetAllCastDisplays out");
    return AVSESSION_SUCCESS;
}

void AVSessionItem::SetExtrasInner(AAFwk::IArray* list)
{
    auto func = [&](AAFwk::IInterface* object) {
        if (object != nullptr) {
            AAFwk::IString* stringValue = AAFwk::IString::Query(object);
            if (stringValue != nullptr && AAFwk::String::Unbox(stringValue) == "url-cast" &&
                descriptor_.sessionType_ == AVSession::SESSION_TYPE_VIDEO && serviceCallbackForStream_) {
                SLOGI("AVSessionItem send mirrortostream event to service");
                serviceCallbackForStream_(GetSessionId());
            }
        }
    };
    AAFwk::Array::ForEach(list, func);
}

void AVSessionItem::SetServiceCallbackForStream(const std::function<void(std::string)>& callback)
{
    SLOGI("SetServiceCallbackForStream in");
    serviceCallbackForStream_ = callback;
}
#endif

AVSessionDescriptor AVSessionItem::GetDescriptor()
{
    return descriptor_;
}

AVCallState AVSessionItem::GetAVCallState()
{
    return avCallState_;
}

AVCallMetaData AVSessionItem::GetAVCallMetaData()
{
    std::string sessionId = GetSessionId();
    std::string fileDir = AVSessionUtils::GetCachePathName(userId_);
    std::string fileName = sessionId + AVSessionUtils::GetFileSuffix();
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = avCallMetaData_.GetMediaImage();
    AVSessionUtils::ReadImageFromFile(innerPixelMap, fileDir, fileName);
    return avCallMetaData_;
}


AVPlaybackState AVSessionItem::GetPlaybackState()
{
    return playbackState_;
}

AVMetaData AVSessionItem::GetMetaData()
{
    std::lock_guard lockGuard(metaDataLock_);
    std::string sessionId = GetSessionId();
    std::string fileDir = AVSessionUtils::GetCachePathName(userId_);
    std::string fileName = sessionId + AVSessionUtils::GetFileSuffix();
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = metaData_.GetMediaImage();
    AVSessionUtils::ReadImageFromFile(innerPixelMap, fileDir, fileName);

    std::string avQueueFileDir = AVSessionUtils::GetFixedPathName();
    std::string avQueueFileName = GetBundleName() + "_" + metaData_.GetAVQueueId() + AVSessionUtils::GetFileSuffix();
    std::shared_ptr<AVSessionPixelMap> avQueuePixelMap = metaData_.GetAVQueueImage();
    AVSessionUtils::ReadImageFromFile(avQueuePixelMap, avQueueFileDir, avQueueFileName);
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
    if (descriptor_.elementName_.GetBundleName() == "castBundleName"
        && descriptor_.elementName_.GetAbilityName() == "castAbilityName") {
        SLOGI("GetSupportCommand when cast session");
        std::vector<int32_t> supportedCmdForCastSession {
            AVControlCommand::SESSION_CMD_PLAY,
            AVControlCommand::SESSION_CMD_PAUSE,
            AVControlCommand::SESSION_CMD_STOP,
            AVControlCommand::SESSION_CMD_PLAY_NEXT,
            AVControlCommand::SESSION_CMD_PLAY_PREVIOUS,
            AVControlCommand::SESSION_CMD_SEEK
        };
        return supportedCmdForCastSession;
    }
    return supportedCmd_;
}

AbilityRuntime::WantAgent::WantAgent AVSessionItem::GetLaunchAbility()
{
    return launchAbility_;
}

AAFwk::WantParams AVSessionItem::GetExtras()
{
    std::lock_guard lockGuard(wantParamLock_);
    SLOGI("GetExtras pass lock");
    return extras_;
}

void AVSessionItem::HandleMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnMediaKeyEvent");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    CHECK_AND_RETURN_LOG(descriptor_.isActive_, "session is deactive");
    SLOGI("HandleMediaKeyEvent check isMediaKeySupport %{public}d for %{public}d",
        static_cast<int>(isMediaKeySupport), static_cast<int>(keyEvent.GetKeyCode()));
    if (!isMediaKeySupport && keyEventCaller_.count(keyEvent.GetKeyCode()) > 0) {
        SLOGD("auto set controller command for %{public}d", static_cast<int>(keyEvent.GetKeyCode()));
        AVControlCommand cmd;
        cmd.SetRewindTime(metaData_.GetSkipIntervals());
        cmd.SetForwardTime(metaData_.GetSkipIntervals());
        keyEventCaller_[keyEvent.GetKeyCode()](cmd);
    } else {
        callback_->OnMediaKeyEvent(keyEvent);
    }
}

void AVSessionItem::ExecuteControllerCommand(const AVControlCommand& cmd)
{
    HISYSEVENT_ADD_OPERATION_COUNT(Operation::OPT_ALL_CTRL_COMMAND);
    int32_t code = cmd.GetCommand();
    if (code < 0 || code >= SESSION_CMD_MAX) {
        SLOGE("controlCommand invalid");
        return;
    }
    SLOGI("ExecuteControllerCommand code %{public}d for pid %{public}d", code, static_cast<int>(GetCallingPid()));
    {
        std::lock_guard remoteSinkLockGuard(remoteSinkLock_);
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
    return cmdHandlers[code](cmd);

    HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "ERROR_TYPE", "INVALID_COMMAND", "CMD", code,
        "ERROR_INFO", "avsessionitem executecontrollercommand, invaild command");
}
// LCOV_EXCL_STOP

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

// LCOV_EXCL_START
void AVSessionItem::HandleSkipToQueueItem(const int32_t& itemId)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnSkipToQueueItem");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnSkipToQueueItem(itemId);
}

void AVSessionItem::HandleOnAVCallAnswer(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnAVCallAnswer");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnAVCallAnswer();
}

void AVSessionItem::HandleOnAVCallHangUp(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnAVCallHangUp");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnAVCallHangUp();
}

void AVSessionItem::HandleOnAVCallToggleCallMute(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnAVCallToggleCallMute");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnAVCallToggleCallMute();
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

void AVSessionItem::HandleOnPlayOrPause(const AVControlCommand& cmd)
{
    std::lock_guard lockGuard(metaDataLock_);
    SLOGI("check current playstate : %{public}d", playbackState_.GetState());
    if (playbackState_.GetState() == AVPlaybackState::PLAYBACK_STATE_PLAY) {
        HandleOnPause(cmd);
    } else {
        HandleOnPlay(cmd);
    }
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
    int64_t time = 0;
    CHECK_AND_RETURN_LOG(cmd.GetForwardTime(time) == AVSESSION_SUCCESS, "GetForwardTime failed");
    callback_->OnFastForward(time);
}

void AVSessionItem::HandleOnRewind(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnRewind");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    int64_t time = 0;
    CHECK_AND_RETURN_LOG(cmd.GetRewindTime(time) == AVSESSION_SUCCESS, "GetForwardTime failed");
    callback_->OnRewind(time);
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

void AVSessionItem::HandleOnPlayFromAssetId(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnPlayFromAssetId");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    int64_t assetId = 0;
    CHECK_AND_RETURN_LOG(cmd.GetPlayFromAssetId(assetId) == AVSESSION_SUCCESS, "Get playFromAssetId failed");
    callback_->OnPlayFromAssetId(assetId);
}
// LCOV_EXCL_STOP

int32_t AVSessionItem::AddController(pid_t pid, sptr<AVControllerItem>& controller)
{
    std::lock_guard controllersLockGuard(controllersLock_);
    SLOGI("handle controller newup for pid: %{public}d", static_cast<int>(pid));
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

int32_t AVSessionItem::GetUserId() const
{
    return userId_;
}

std::string AVSessionItem::GetAbilityName() const
{
    return descriptor_.elementName_.GetAbilityName();
}

// LCOV_EXCL_START
std::string AVSessionItem::GetBundleName() const
{
    return descriptor_.elementName_.GetBundleName();
}
// LCOV_EXCL_STOP

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
    SLOGI("handle controller release for pid: %{public}d", static_cast<int>(pid));
    controllers_.erase(pid);
}

void AVSessionItem::SetServiceCallbackForRelease(const std::function<void(AVSessionItem&)>& callback)
{
    SLOGI("SetServiceCallbackForRelease in");
    serviceCallback_ = callback;
}

void AVSessionItem::SetServiceCallbackForAVQueueInfo(const std::function<void(AVSessionItem&)>& callback)
{
    SLOGI("SetServiceCallbackForAVQueueInfo in");
    serviceCallbackForAddAVQueueInfo_ = callback;
}

void AVSessionItem::SetServiceCallbackForCallStart(const std::function<void(AVSessionItem&)>& callback)
{
    SLOGI("SetServiceCallbackForCallStart in");
    callStartCallback_ = callback;
}

void AVSessionItem::SetServiceCallbackForUpdateSession(const std::function<void(std::string, bool)>& callback)
{
    SLOGI("SetServiceCallbackForUpdateSession in");
    serviceCallbackForUpdateSession_ = callback;
}

void AVSessionItem::HandleOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("Connection state %{public}d", connectionState);
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

// LCOV_EXCL_START
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
    for (size_t i = 0; i < outputDeviceInfo.deviceInfos_.size(); i++) {
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
    SLOGI("UpdateCastDeviceMap with id: %{public}s", deviceInfo.deviceid_.c_str());
    castDeviceInfoMap_[deviceInfo.deviceId_] = deviceInfo;
}
#endif

void AVSessionItem::ReportConnectFinish(const std::string func, const DeviceInfo &deviceInfo)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSessionRadarInfo info(func);
    if (castDeviceInfoMap_.count(deviceInfo.deviceId_) > 0) {
        DeviceInfo cacheDeviceInfo = castDeviceInfoMap_[deviceInfo.deviceId_];
        AVSessionRadar::GetInstance().ConnectFinish(cacheDeviceInfo, info);
    } else {
        AVSessionRadar::GetInstance().ConnectFinish(deviceInfo, info);
    }
#endif
}

void AVSessionItem::ReportStopCastFinish(const std::string func, const DeviceInfo &deviceInfo)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSessionRadarInfo info(func);
    if (castDeviceInfoMap_.count(deviceInfo.deviceId_) > 0) {
        DeviceInfo cacheDeviceInfo = castDeviceInfoMap_[deviceInfo.deviceId_];
        AVSessionRadar::GetInstance().StopCastFinish(cacheDeviceInfo, info);
    } else {
        AVSessionRadar::GetInstance().StopCastFinish(deviceInfo, info);
    }
#endif
}

void AVSessionItem::SaveLocalDeviceInfo()
{
    OutputDeviceInfo localDevice;
    DeviceInfo localInfo;
    localInfo.castCategory_ = AVCastCategory::CATEGORY_LOCAL;
    localInfo.deviceId_ = "0";
    localInfo.deviceName_ = "LocalDevice";
    localDevice.deviceInfos_.emplace_back(localInfo);
    descriptor_.outputDeviceInfo_ = localDevice;
}

int32_t AVSessionItem::doContinuousTaskRegister()
{
#ifdef EFFICIENCY_MANAGER_ENABLE
    SLOGI("Start register continuous task");
    if (descriptor_.sessionTag_ == "RemoteCast") {
        SLOGI("sink session should not register ContinuousTask");
        return AVSESSION_SUCCESS;
    }
    int32_t uid = GetUid();
    int32_t pid = GetPid();
    std::string bundleName = BundleStatusAdapter::GetInstance().GetBundleNameFromUid(uid);
    CHECK_AND_RETURN_RET_LOG(bundleName != "", AVSESSION_ERROR, "GetBundleNameFromUid failed");

    void *handle_ = dlopen("libsuspend_manager_client.z.so", RTLD_NOW);
    if (handle_ == nullptr) {
        SLOGE("failed to open library libsuspend_manager_client reaseon %{public}s", dlerror());
        return AVSESSION_ERROR;
    }
    SLOGI("open library libsuspend_manager_client success");
    typedef ErrCode (*handler) (int32_t eventType, int32_t uid, int32_t pid,
        const std::string bundleName, int32_t taskState, int32_t serviceId);
    handler reportContinuousTaskEventEx = reinterpret_cast<handler>(dlsym(handle_, "ReportContinuousTaskEventEx"));
    ErrCode errCode = reportContinuousTaskEventEx(0, uid, pid, bundleName, 1, AVSESSION_SERVICE_ID);
    SLOGI("reportContinuousTaskEventEx done, result: %{public}d", errCode);
#ifndef TEST_COVERAGE
    OPENSSL_thread_stop();
    dlclose(handle_);
#endif
#endif
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::doContinuousTaskUnregister()
{
#ifdef EFFICIENCY_MANAGER_ENABLE
    SLOGI("Stop register continuous task");
    if (descriptor_.sessionTag_ == "RemoteCast") {
        SLOGI("sink session should not unregister ContinuousTask");
        return AVSESSION_SUCCESS;
    }
    int32_t uid = GetUid();
    int32_t pid = GetPid();
    std::string bundleName = BundleStatusAdapter::GetInstance().GetBundleNameFromUid(uid);
    CHECK_AND_RETURN_RET_LOG(bundleName != "", AVSESSION_ERROR, "GetBundleNameFromUid failed");

    void *handle_ = dlopen("libsuspend_manager_client.z.so", RTLD_NOW);
    if (handle_ == nullptr) {
        SLOGE("failed to open library libsuspend_manager_client when stop cast, reaseon %{public}s", dlerror());
        return AVSESSION_ERROR;
    }
    SLOGI("open library libsuspend_manager_client success when stop cast");
    typedef ErrCode (*handler) (int32_t eventType, int32_t uid, int32_t pid,
        const std::string bundleName, int32_t taskState, int32_t serviceId);
    handler reportContinuousTaskEventEx = reinterpret_cast<handler>(dlsym(handle_, "ReportContinuousTaskEventEx"));
    ErrCode errCode = reportContinuousTaskEventEx(0, uid, pid, bundleName, 2, AVSESSION_SERVICE_ID);
    SLOGI("reportContinuousTaskEventEx done when stop cast, result: %{public}d", errCode);
#ifndef TEST_COVERAGE
    OPENSSL_thread_stop();
    dlclose(handle_);
#endif
#endif
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP
} // namespace OHOS::AVSession
