/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "array_wrapper.h"
#include "bool_wrapper.h"
#include "string_wrapper.h"
#include "avsession_hianalytics_report.h"
#include "want_agent_helper.h"

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

const std::map<int32_t, std::string> sessionTypeMap_ = {
    {AVSession::SESSION_TYPE_VIDEO, "video"},
    {AVSession::SESSION_TYPE_VOICE_CALL, "voice_call"},
    {AVSession::SESSION_TYPE_VIDEO_CALL, "video_call"},
};

const std::map<int32_t, int32_t> g_cmdToOffsetMap = {
    {AVControlCommand::SESSION_CMD_SET_TARGET_LOOP_MODE, 9},
    {AVControlCommand::SESSION_CMD_PLAY, 8},
    {AVControlCommand::SESSION_CMD_PAUSE, 7},
    {AVControlCommand::SESSION_CMD_PLAY_NEXT, 6},
    {AVControlCommand::SESSION_CMD_PLAY_PREVIOUS, 5},
    {AVControlCommand::SESSION_CMD_FAST_FORWARD, 4},
    {AVControlCommand::SESSION_CMD_REWIND, 3},
    {AVControlCommand::SESSION_CMD_SEEK, 2},
    {AVControlCommand::SESSION_CMD_SET_LOOP_MODE, 1},
    {AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE, 0}
};

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
static const int32_t CONTROL_COLD_START = 2;
#endif

AVSessionItem::AVSessionItem(const AVSessionDescriptor& descriptor, int32_t userId)
    : descriptor_(descriptor), userId_(userId)
{
    SLOGI("constructor session id=%{public}s, userId=%{public}d",
        AVSessionUtils::GetAnonySessionId(descriptor_.sessionId_).c_str(), userId_);
    {
        std::lock_guard aliveLockGuard(isAliveLock_);
        isAlivePtr_ = std::make_shared<bool>(true);
    }
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    cssListener_ = std::make_shared<CssListener>(this);
#endif
}

AVSessionItem::~AVSessionItem()
{
    SLOGI("destroy with aliveLock session id=%{public}s, userId=%{public}d",
        AVSessionUtils::GetAnonySessionId(descriptor_.sessionId_).c_str(), userId_);
    if (IsActive()) {
        Deactivate();
    }
    {
        std::lock_guard callbackForCastCapLockGuard(callbackForCastCapLock_);
        if (castControllerProxy_ != nullptr) {
            castControllerProxy_->SetSessionCallbackForCastCap(nullptr);
        }
    }
    {
        std::lock_guard aliveLockGuard(isAliveLock_);
        if (isAlivePtr_ != nullptr) {
            *isAlivePtr_ = false;
        }
    }
}

// LCOV_EXCL_START
std::string AVSessionItem::GetSessionId()
{
    return descriptor_.sessionId_;
}

std::string AVSessionItem::GetSessionType()
{
    auto iter = sessionTypeMap_.find(descriptor_.sessionType_);
    if (iter != sessionTypeMap_.end()) {
        return iter->second;
    } else {
        return "audio";
    }
}
// LCOV_EXCL_STOP

void AVSessionItem::UpdateSessionElement(const AppExecFwk::ElementName& elementName)
{
    descriptor_.elementName_ = elementName;
}

int32_t AVSessionItem::Destroy()
{
    SLOGI("AVSessionItem %{public}d check service destroy event with service, check serviceCallback exist",
        static_cast<int>(GetPid()));
    {
        std::lock_guard lockGuard(destroyLock_);
        if (isDestroyed_) {
            SLOGE("AVSessionItem Destroy process but check already destroyed");
            return AVSESSION_SUCCESS;
        }
    }
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "Destroy", "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_, "SESSION_TYPE", GetSessionType(),
        "ERROR_CODE", AVSESSION_SUCCESS, "ERROR_MSG", "SUCCESS");
    if (serviceCallback_) {
        SLOGI("AVSessionItem send service destroy event to service");
        serviceCallback_(*this);
    }
    return AVSESSION_SUCCESS;
}

void AVSessionItem::DelRecommend()
{
    CHECK_AND_RETURN_LOG(descriptor_.sessionTag_ != "RemoteCast", "remote cast session, return");
    if (isRecommend_) {
        AVSessionHiAnalyticsReport::PublishRecommendInfo(GetBundleName(), "", "", "", -1);
        isRecommend_ = false;
    }
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    CHECK_AND_RETURN_LOG(castHandle_ > 0, "delete recommend without casthandler");
    PublishAVCastHa(disconnectStateFromCast_, GetDescriptor().outputDeviceInfo_.deviceInfos_[0]);
#endif
}

int32_t AVSessionItem::DestroyTask(bool continuePlay)
{
    {
        std::lock_guard lockGuard(destroyLock_);
        if (isDestroyed_) {
            SLOGI("session is already destroyed");
            return AVSESSION_SUCCESS;
        }
        isDestroyed_ = true;
    }

    std::string sessionId = descriptor_.sessionId_;
    std::string fileName = AVSessionUtils::GetCachePathName(userId_) + sessionId + AVSessionUtils::GetFileSuffix();
    AVSessionUtils::DeleteFile(fileName);
    DelRecommend();
    std::list<sptr<AVControllerItem>> controllerList;
    {
        std::lock_guard controllerLockGuard(controllersLock_);
        for (auto it = controllers_.begin(); it != controllers_.end();) {
            if (it->second) {
                controllerList.push_back(it->second);
            }
            it = controllers_.erase(it);
        }
    }
    for (auto& controller : controllerList) {
        controller->HandleSessionDestroy();
    }
    {
        std::lock_guard lockGuard(callbackLock_);
        if (callback_) {
            callback_.clear();
        }
    }

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("Session destroy with castHandle: %{public}lld", (long long)castHandle_);
    if (descriptor_.sessionTag_ != "RemoteCast" && castHandle_ > 0) {
        if (!collaborationNeedNetworkId_.empty()) {
            CollaborationManager::GetInstance().PublishServiceState(collaborationNeedDeviceId_.c_str(),
                ServiceCollaborationManagerBussinessStatus::SCM_IDLE);
            CollaborationManager::GetInstance().PublishServiceState(collaborationNeedNetworkId_.c_str(),
                ServiceCollaborationManagerBussinessStatus::SCM_IDLE);
        }
        AVRouter::GetInstance().UnRegisterCallback(castHandle_, cssListener_, GetSessionId());
        ReleaseCast(continuePlay);
        StopCastSession();
    }
    ReleaseAVCastControllerInner();
    StopCastDisplayListener();
#endif
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetAVCallMetaData(const AVCallMetaData& avCallMetaData)
{
    std::lock_guard lockGuard(avsessionItemLock_);
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
            if (controller != nullptr) {
                controller->HandleAVCallMetaDataChange(avCallMetaData);
            }
        }
    }
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVSessionItem::SetAVCallState(const AVCallState& avCallState)
{
    {
        std::lock_guard lockGuard(avsessionItemLock_);
        CHECK_AND_RETURN_RET_LOG(avCallState_.CopyFrom(avCallState), AVSESSION_ERROR, "AVCallState set error");
    }

    {
        std::lock_guard controllerLockGuard(controllersLock_);
        for (const auto& [pid, controller] : controllers_) {
            if (controller != nullptr) {
                controller->HandleAVCallStateChange(avCallState);
            }
        }
    }
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVSessionItem::GetAVMetaData(AVMetaData& meta)
{
    std::lock_guard lockGuard(avsessionItemLock_);
    SessionXCollie sessionXCollie("avsession::GetAVMetaData");
    std::string sessionId = GetSessionId();
    std::string fileDir = AVSessionUtils::GetCachePathName(userId_);
    std::string fileName = sessionId + AVSessionUtils::GetFileSuffix();
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = metaData_.GetMediaImage();
    AVSessionUtils::ReadImageFromFile(innerPixelMap, fileDir, fileName);

    std::string avQueueFileDir = AVSessionUtils::GetFixedPathName(userId_);
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

void AVSessionItem::UpdateRecommendInfo(bool needRecommend)
{
    if (descriptor_.sessionTag_ == "RemoteCast") {
        return;
    }
    AVMetaData meta;
    AAFwk::WantParams extra;
    {
        std::lock_guard lockGuard(avsessionItemLock_);
        meta = metaData_;
        extra = extras_;
    }
    SLOGI("assetChange:%{public}d AddFront:%{public}d supportCast:%{public}d filter:%{public}d duration:%{public}d",
        isAssetChange_, isFirstAddToFront_, extra.HasParam("requireAbilityList"), meta.GetFilter(),
        static_cast<int>(meta.GetDuration()));
    if (needRecommend) {
        if (isAssetChange_ && !isFirstAddToFront_ && extra.HasParam("requireAbilityList") &&
            meta.GetFilter() !=0 && meta.GetDuration() != 0) {
            isAssetChange_ = false;
            isRecommend_ = true;
            AVSessionHiAnalyticsReport::PublishRecommendInfo(GetBundleName(), GetSessionId(),
                GetSessionType(), meta.GetAssetId(), meta.GetDuration());
        }
    } else {
        if (isRecommend_) {
            isAssetChange_ = true;
            AVSessionHiAnalyticsReport::PublishRecommendInfo(GetBundleName(), GetSessionId(), GetSessionType(),
                metaData_.GetAssetId(), -1);
        }
    }

}

void AVSessionItem::HandleFrontSession()
{
    bool isMetaEmpty;
    bool isCastMetaEmpty;
    {
        std::lock_guard lockGuard(avsessionItemLock_);
        isMetaEmpty = (metaData_.GetTitle().empty() && metaData_.GetMediaImage() == nullptr);
        AVQueueItem item;
        GetCurrentCastItem(item);
        isCastMetaEmpty = (item.GetDescription() == nullptr ||
            (item.GetDescription()->GetTitle().empty() && item.GetDescription()->GetIconUri().empty()));
        SLOGI("frontSession bundle=%{public}s isMetaEmpty=%{public}d isCastMetaEmpty=%{public}d Cmd=%{public}d "
            "castCmd=%{public}d firstAdd=%{public}d",
            GetBundleName().c_str(), isMetaEmpty, isCastMetaEmpty, static_cast<int32_t>(supportedCmd_.size()),
            static_cast<int32_t>(supportedCastCmds_.size()), isFirstAddToFront_);
    }
    if ((isMetaEmpty && isCastMetaEmpty) || (supportedCmd_.size() == 0 && supportedCastCmds_.size() == 0)) {
        if (!isFirstAddToFront_ && serviceCallbackForUpdateSession_) {
            serviceCallbackForUpdateSession_(GetSessionId(), false);
            isFirstAddToFront_ = true;
            UpdateRecommendInfo(false);
        }
    } else {
        if (isFirstAddToFront_ && serviceCallbackForUpdateSession_) {
            serviceCallbackForUpdateSession_(GetSessionId(), true);
            isFirstAddToFront_ = false;
            UpdateRecommendInfo(true);
        }
    }
}

bool AVSessionItem::HasAvQueueInfo()
{
    std::lock_guard lockGuard(avsessionItemLock_);
    if (metaData_.GetAVQueueName().empty() || metaData_.GetAVQueueId().empty()) {
        SLOGD("avqueuename or avqueueid is empty");
        return false;
    }
    if (metaData_.GetAVQueueImage() == nullptr && metaData_.GetAVQueueImageUri().empty()) {
        SLOGD("avqueue img is empty");
        return false;
    }
    if (playbackState_.GetState() != AVPlaybackState::PLAYBACK_STATE_PLAY) {
        SLOGD("current avqueueinfo is not playing");
        return false;
    }

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
    std::string apiParamString = "assetId: " + meta.GetAssetId() + ", "
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
        "SESSION_TAG", descriptor_.sessionTag_, "SESSION_TYPE", GetSessionType(), "API_PARAM", apiParamString,
        "ERROR_CODE", AVSESSION_SUCCESS, "ERROR_MSG", "SUCCESS");
}

bool AVSessionItem::CheckTitleChange(const AVMetaData& meta)
{
    bool isTitleLyric = (GetBundleName() == defaultBundleName) && !meta.GetDescription().empty();
    bool isTitleChange = metaData_.GetTitle() != meta.GetTitle();
    SLOGI("CheckTitleChange isTitleLyric:%{public}d isTitleChange:%{public}d", isTitleLyric, isTitleChange);
    return isTitleChange && !isTitleLyric;
}

void AVSessionItem::CheckUseAVMetaData(const AVMetaData& meta)
{
    bool hasPixelMap = (meta.GetMediaImage() != nullptr);
    SLOGI("MediaCapsule addLocalCapsule hasImage_:%{public}d isMediaChange_:%{public}d", hasPixelMap, isMediaChange_);
    if (serviceCallbackForNtf_ && hasPixelMap && isMediaChange_) {
        serviceCallbackForNtf_(GetSessionId(), isMediaChange_);
        isMediaChange_ = false;
    }
    ProcessFrontSession("SetAVMetaData");
    if (HasAvQueueInfo() && serviceCallbackForAddAVQueueInfo_) {
        serviceCallbackForAddAVQueueInfo_(*this);
    }

    UpdateRecommendInfo(true);
}

int32_t AVSessionItem::UpdateAVQueueInfo(const AVQueueInfo& info)
{
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = info.GetAVQueueImage();
    if (innerPixelMap != nullptr) {
        std::string fileDir = AVSessionUtils::GetFixedPathName(userId_);
        std::string fileName = GetBundleName() + "_" + info.GetAVQueueId() + AVSessionUtils::GetFileSuffix();
        SLOGI("write image to file for %{public}s", info.GetAVQueueId().c_str());
        AVSessionUtils::WriteImageToFile(innerPixelMap, fileDir, fileName);
        innerPixelMap->Clear();
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetAVMetaData(const AVMetaData& meta)
{
    {
        std::lock_guard lockGuard(avsessionItemLock_);
        SessionXCollie sessionXCollie("avsession::SetAVMetaData");
        ReportSetAVMetaDataInfo(meta);
        if ((metaData_.GetAssetId() != meta.GetAssetId()) || CheckTitleChange(meta)) {
            isMediaChange_ = true;
            isAssetChange_ = true;
        }
        CHECK_AND_RETURN_RET_LOG(metaData_.CopyFrom(meta), AVSESSION_ERROR, "AVMetaData set error");
        std::shared_ptr<AVSessionPixelMap> innerPixelMap = metaData_.GetMediaImage();
        if (innerPixelMap != nullptr) {
            std::string fileDir = AVSessionUtils::GetCachePathName(userId_);
            AVSessionUtils::WriteImageToFile(innerPixelMap, fileDir, GetSessionId() + AVSessionUtils::GetFileSuffix());
            innerPixelMap->Clear();
            metaData_.SetMediaImage(innerPixelMap);
        }
    }
    CheckUseAVMetaData(meta);
    SLOGI("send metadata change event to controllers with title %{public}s from pid:%{public}d, isAlive:%{public}d",
        meta.GetTitle().c_str(), static_cast<int>(GetPid()), (isAlivePtr_ == nullptr) ? -1 : *isAlivePtr_);
    AVSessionEventHandler::GetInstance().AVSessionPostTask([this, meta, isAlivePtr = isAlivePtr_]() {
        std::lock_guard aliveLockGuard(isAliveLock_);
        CHECK_AND_RETURN_LOG(isAlivePtr != nullptr && *isAlivePtr, "handle metadatachange with session gone, return");
        SLOGI("HandleMetaDataChange in postTask with title %{public}s and size %{public}d",
            meta.GetTitle().c_str(), static_cast<int>(controllers_.size()));
        std::lock_guard controllerLockGuard(controllersLock_);
        CHECK_AND_RETURN_LOG(controllers_.size() > 0, "handle with no controller, return");
        for (const auto& [pid, controller] : controllers_) {
            if (controller != nullptr) {
                controller->HandleMetaDataChange(meta);
            }
        }
        }, "HandleMetaDataChange", 0);

    std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
    if (remoteSource_ != nullptr) {
        SLOGI("set remote AVMetaData");
        auto ret = remoteSource_->SetAVMetaData(meta);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetAVMetaData failed");
    }
#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
    ReportMetadataChange(meta);
#endif
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::GetAVQueueItems(std::vector<AVQueueItem>& items)
{
    std::lock_guard lock_guard(avsessionItemLock_);
    items = queueItems_;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetAVQueueItems(const std::vector<AVQueueItem>& items)
{
    {
        std::lock_guard lock_guard(avsessionItemLock_);
        queueItems_ = items;
    }

    {
        std::lock_guard controllerLockGuard(controllersLock_);
        for (const auto& [pid, controller] : controllers_) {
            if (controller != nullptr) {
                controller->HandleQueueItemsChange(items);
            }
        }
    }

    std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
    if (remoteSource_ != nullptr) {
        auto ret = remoteSource_->SetAVQueueItems(items);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetAVQueueItems failed");
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::GetAVQueueTitle(std::string& title)
{
    std::lock_guard lockGuard(avsessionItemLock_);
    title = queueTitle_;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetAVQueueTitle(const std::string& title)
{
    {
        std::lock_guard lockGuard(avsessionItemLock_);
        queueTitle_ = title;
    }

    {
        std::lock_guard controllerLockGuard(controllersLock_);
        for (const auto& [pid, controller] : controllers_) {
            if (controller != nullptr) {
                controller->HandleQueueTitleChange(title);
            }
        }
    }
    std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
    if (remoteSource_ != nullptr) {
        auto ret = remoteSource_->SetAVQueueTitle(title);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetAVQueueTitle failed");
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetAVPlaybackState(const AVPlaybackState& state)
{
    {
        std::lock_guard lockGuard(avsessionItemLock_);
        CHECK_AND_RETURN_RET_LOG(playbackState_.CopyFrom(state), AVSESSION_ERROR, "AVPlaybackState set error");
    }
    if (HasAvQueueInfo() && serviceCallbackForAddAVQueueInfo_) {
        serviceCallbackForAddAVQueueInfo_(*this);
    }
    if (GetUid() == audioBrokerUid && state.GetState() == AVPlaybackState::PLAYBACK_STATE_PLAY &&
        serviceCallbackForMediaSession_) {
        SLOGI("addAncoCapsule");
        serviceCallbackForMediaSession_(GetSessionId(), true);
    }
    {
        std::lock_guard controllerLockGuard(controllersLock_);
        SLOGD("send HandlePlaybackStateChange in postTask with state %{public}d and controller size %{public}d",
            state.GetState(), static_cast<int>(controllers_.size()));
        if (controllers_.size() > 0) {
            for (const auto& [pid, controller] : controllers_) {
                if (controller != nullptr) {
                    controller->HandlePlaybackStateChange(state);
                }
            }
        }
    }

    std::string isFavor = state.GetFavorite()? "true" : "false";
    std::string apiParamString = "state: " + std::to_string(state.GetState()) + ", "
                                    + "elapsedTime: " + std::to_string(state.GetPosition().elapsedTime_) + ", "
                                    + "updateTime: " + std::to_string(state.GetPosition().updateTime_) + ", "
                                    + "loopMode: " + std::to_string(state.GetLoopMode()) + ", "
                                    + "isFavorite: " + isFavor;
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "SetAVPlaybackState", "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(), "API_PARAM", apiParamString,
        "ERROR_CODE", AVSESSION_SUCCESS, "ERROR_MSG", "SUCCESS");
    std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
    if (remoteSource_ != nullptr) {
        remoteSource_->SetAVPlaybackState(state);
    }
#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
    ReportPlaybackState(state);
#endif
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::GetAVPlaybackState(AVPlaybackState& state)
{
    std::lock_guard lockGuard(avsessionItemLock_);
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
    std::string apiParamString = "bundleName: " + bundleName + ", " +
        "moduleName: " + moduleName + ", " + "abilityName: " + abilityName;
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "SetLaunchAbility", "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(), "API_PARAM", apiParamString,
        "ERROR_CODE", res, "ERROR_MSG", errMsg);
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVSessionItem::GetExtras(AAFwk::WantParams& extras)
{
    std::lock_guard lockGuard(avsessionItemLock_);
    extras = extras_;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SetExtras(const AAFwk::WantParams& extras)
{
    {
        std::lock_guard lockGuard(avsessionItemLock_);
        extras_ = extras;
    }

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    if (extras.HasParam("requireAbilityList")) {
        auto value = extras.GetParam("requireAbilityList");
        AAFwk::IArray* list = AAFwk::IArray::Query(value);
        if (list != nullptr && AAFwk::Array::IsStringArray(list)) {
            SetExtrasInner(list);
        }
    }
#endif

    if (extras.HasParam("hw_live_view_hidden_when_keyguard")) {
        auto value = extras.GetParam("hw_live_view_hidden_when_keyguard");
        AAFwk::IArray* list = AAFwk::IArray::Query(value);
        if (list != nullptr && AAFwk::Array::IsBooleanArray(list)) {
            NotificationExtras(list);
        }
    }

    if (extras.HasParam("support-keyevent")) {
        auto value = extras.GetParam("support-keyevent");
        AAFwk::IArray* list = AAFwk::IArray::Query(value);
        if (list != nullptr && AAFwk::Array::IsBooleanArray(list)) {
            KeyEventExtras(list);
        }
    }

    {
        std::lock_guard controllerLockGuard(controllersLock_);
        for (const auto& [pid, controller] : controllers_) {
            if (controller != nullptr) {
                controller->HandleExtrasChange(extras);
            }
        }
    }

    std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
    if (remoteSource_ != nullptr) {
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
    SLOGI("New controller from sessionItem when get controller.");
    controllers_.insert({GetPid(), result});
    return result;
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
void AVSessionItem::InitAVCastControllerProxy()
{
    if (castControllerProxy_ == nullptr) {
        SLOGI("CastControllerProxy is null, start get new proxy");
        {
            std::lock_guard lockGuard(castLock_);
            castControllerProxy_ = AVRouter::GetInstance().GetRemoteController(castHandle_);
        }
    }
}

void AVSessionItem::ReportAVCastControllerInfo()
{
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "getAVCastController", "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_, "SESSION_TYPE", GetSessionType(),
        "ERROR_CODE", AVSESSION_SUCCESS, "ERROR_MSG", "SUCCESS");
}

void AVSessionItem::dealValidCallback(int32_t cmd, std::vector<int32_t>& supportedCastCmds)
{
    {
        std::lock_guard lockGuard(avsessionItemLock_);
        SLOGI("process cast valid cmd: %{public}d", cmd);
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
            SLOGI("sink session should not modify valid cmds");
            supportedCastCmds = {};
            return;
        }
    }
    if (cmd > removeCmdStep_) {
        DeleteSupportCastCommand(cmd - removeCmdStep_);
    } else {
        AddSupportCastCommand(cmd);
    }
    supportedCastCmds = supportedCastCmds_;
    return;
}

sptr<IRemoteObject> AVSessionItem::GetAVCastControllerInner()
{
    InitAVCastControllerProxy();
    CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, nullptr,
        "castControllerProxy_ is null when get avCastController");
    sptr<AVCastControllerItem> castController = new (std::nothrow) AVCastControllerItem();
    CHECK_AND_RETURN_RET_LOG(castController != nullptr, nullptr, "malloc avCastController failed");
    std::shared_ptr<AVCastControllerItem> sharedPtr = std::shared_ptr<AVCastControllerItem>(castController.GetRefPtr(),
        [holder = castController](const auto*) {});
    CHECK_AND_RETURN_RET_LOG(sharedPtr != nullptr, nullptr, "malloc AVCastControllerItem failed");
    ReportAVCastControllerInfo();

    auto validCallback = [this](int32_t cmd, std::vector<int32_t>& supportedCastCmds) {
        dealValidCallback(cmd, supportedCastCmds);
    };

    auto preparecallback = [this]() {
        if (AVRouter::GetInstance().GetMirrorCastHandle() != -1 && isFirstCallback_) {
            isFirstCallback_ = false;
            AVRouter::GetInstance().DisconnectOtherSession(GetSessionId(),
                GetDescriptor().outputDeviceInfo_.deviceInfos_[0]);
        }
    };

    sharedPtr->Init(castControllerProxy_, validCallback, preparecallback);
    {
        std::lock_guard lockGuard(castControllersLock_);
        castControllers_.emplace_back(sharedPtr);
    }
    sptr<IRemoteObject> remoteObject = castController;

    sharedPtr->SetSessionTag(descriptor_.sessionTag_);
    sharedPtr->SetSessionId(descriptor_.sessionId_);
    sharedPtr->SetUserId(userId_);
    if (descriptor_.sessionTag_ != "RemoteCast") {
        std::lock_guard callbackForCastCapLockGuard(callbackForCastCapLock_);
        castControllerProxy_->SetSessionCallbackForCastCap([this](bool isPlaying, bool isMediaChange) {
            std::thread([this, isPlaying, isMediaChange]() {
                CHECK_AND_RETURN_LOG(serviceCallbackForCastNtf_ != nullptr, "serviceCallbackForCastNtf_ is empty");
                SLOGI("MediaCapsule CastCapsule for service isPlaying %{public}d, isMediaChange %{public}d",
                    isPlaying, isMediaChange);
                serviceCallbackForCastNtf_(descriptor_.sessionId_, isPlaying, isMediaChange);
            }).detach();
        });
    }

    InitializeCastCommands();
    return remoteObject;
}

void AVSessionItem::ReleaseAVCastControllerInner()
{
    SLOGI("Release AVCastControllerInner");
    std::lock_guard lockGuard(castControllersLock_);
    for (auto controller : castControllers_) {
        if (controller != nullptr) {
            controller->Destroy();
        }
    }
    castControllerProxy_ = nullptr;
    isFirstCallback_ = true;
}
#endif

void AVSessionItem::RegisterAVSessionCallback(std::shared_ptr<AVSessionCallback> callbackOfMigrate)
{
    std::lock_guard callbackLockGuard(callbackLock_);
    callbackForMigrate_ = callbackOfMigrate;
}

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
        "API_NAME", "Activate", "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_, "SESSION_TYPE", GetSessionType(),
        "ERROR_CODE", AVSESSION_SUCCESS, "ERROR_MSG", "SUCCESS");
    for (const auto& [pid, controller] : controllers_) {
        if (controller != nullptr) {
            controller->HandleActiveStateChange(true);
        }
    }
    if (descriptor_.sessionType_ == AVSession::SESSION_TYPE_VOICE_CALL ||
        descriptor_.sessionType_ == AVSession::SESSION_TYPE_VIDEO_CALL) {
        SLOGI("set audio scene for voip start");
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
    std::lock_guard controllerLockGuard(controllersLock_);
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "Deactivate", "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_, "SESSION_TYPE", GetSessionType(),
        "ERROR_CODE", AVSESSION_SUCCESS, "ERROR_MSG", "SUCCESS");
    for (const auto& [pid, controller] : controllers_) {
        if (controller != nullptr) {
            controller->HandleActiveStateChange(false);
        }
    }
    if (descriptor_.sessionType_ == AVSession::SESSION_TYPE_VOICE_CALL ||
        descriptor_.sessionType_ == AVSession::SESSION_TYPE_VIDEO_CALL) {
        SLOGI("set audio scene for voip end");
        AudioSystemManager *audioManager = AudioSystemManager::GetInstance();
        AudioScene audioScene = AudioScene::AUDIO_SCENE_CALL_END;
        if (audioManager != nullptr) {
            audioManager->SetAudioScene(audioScene);
        }
    }

    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

bool AVSessionItem::IsActive()
{
    return descriptor_.isActive_ || GetSessionId() == "DEFAULT";
}

// LCOV_EXCL_START
int32_t AVSessionItem::AddSupportCommand(int32_t cmd)
{
    CHECK_AND_RETURN_RET_LOG(cmd > AVControlCommand::SESSION_CMD_INVALID, AVSESSION_ERROR, "invalid cmd");
    CHECK_AND_RETURN_RET_LOG(cmd < AVControlCommand::SESSION_CMD_MAX, AVSESSION_ERROR, "invalid cmd");
    SLOGI("AddSupportCommand=%{public}d", cmd);
    if (cmd == AVControlCommand::SESSION_CMD_MEDIA_KEY_SUPPORT) {
        SLOGI("enable media key event listen");
        isMediaKeySupport = true;
        return AVSESSION_SUCCESS;
    }
    auto iter = std::find(supportedCmd_.begin(), supportedCmd_.end(), cmd);
    CHECK_AND_RETURN_RET_LOG(iter == supportedCmd_.end(), AVSESSION_SUCCESS, "cmd already been added");
    {
        std::lock_guard lockGuard(avsessionItemLock_);
        supportedCmd_.push_back(cmd);
    }
    std::string apiParamString = "cmd :" + std::to_string(cmd);
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "OnEvent", "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(), "API_PARAM", apiParamString,
        "ERROR_CODE", AVSESSION_SUCCESS, "ERROR_MSG", "SUCCESS");
    ProcessFrontSession("AddSupportCommand");

    {
        std::lock_guard controllerLockGuard(controllersLock_);
        SLOGI("send add command event to controller, size:%{public}d", static_cast<int>(controllers_.size()));
        for (const auto& [pid, controller] : controllers_) {
            if (controller != nullptr) {
                controller->HandleValidCommandChange(supportedCmd_);
            }
        }
    }

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AddSessionCommandToCast(cmd);
#endif

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
    ReportCommandChange();
#endif
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::DeleteSupportCommand(int32_t cmd)
{
    CHECK_AND_RETURN_RET_LOG(cmd > AVControlCommand::SESSION_CMD_INVALID, AVSESSION_ERROR, "invalid cmd");
    CHECK_AND_RETURN_RET_LOG(cmd < AVControlCommand::SESSION_CMD_MAX, AVSESSION_ERROR, "invalid cmd");
    SLOGI("DeleteSupportCommand=%{public}d", cmd);
    if (cmd == AVControlCommand::SESSION_CMD_MEDIA_KEY_SUPPORT) {
        SLOGI("disable media key event listen");
        isMediaKeySupport = false;
        return AVSESSION_SUCCESS;
    }
    auto iter = std::remove(supportedCmd_.begin(), supportedCmd_.end(), cmd);
    {
        std::lock_guard lockGuard(avsessionItemLock_);
        supportedCmd_.erase(iter, supportedCmd_.end());
    }
    std::string apiParamString = "cmd :" + std::to_string(cmd);
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "OffEvent",
        "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(),
        "API_PARAM", apiParamString,
        "ERROR_CODE", AVSESSION_SUCCESS,
        "ERROR_MSG", "SUCCESS");
    ProcessFrontSession("DeleteSupportCommand");

    {
        SLOGI("send delete command event to controller, size:%{public}d", static_cast<int>(controllers_.size()));
        std::lock_guard controllerLockGuard(controllersLock_);
        for (const auto& [pid, controller] : controllers_) {
            if (controller != nullptr) {
                controller->HandleValidCommandChange(supportedCmd_);
            }
        }
    }

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    RemoveSessionCommandFromCast(cmd);
#endif

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
    ReportCommandChange();
#endif
    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

int32_t AVSessionItem::SetSessionEvent(const std::string& event, const AAFwk::WantParams& args)
{
    {
        std::lock_guard controllerLockGuard(controllersLock_);
        for (const auto& [pid, controller] : controllers_) {
            if (controller != nullptr) {
                controller->HandleSetSessionEvent(event, args);
            }
        }
    }
    std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
    if (remoteSource_ != nullptr) {
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
int32_t AVSessionItem::RegisterListenerStreamToCast(const std::pair<std::string, std::string>& serviceNameStatePair,
    DeviceInfo deviceInfo)
{
    if (castHandle_ > 0) {
        return AVSESSION_ERROR;
    }
    {
        std::lock_guard displayListenerLockGuard(mirrorToStreamLock_);
        mirrorToStreamFlag_ = true;
    }
    std::lock_guard lockGuard(castLock_);
    castServiceNameStatePair_ = serviceNameStatePair;
    OutputDeviceInfo outputDeviceInfo;
    outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
    if (AVRouter::GetInstance().GetMirrorCastHandle() == -1) {
        SetCastHandle(AVRouter::GetInstance().StartCast(outputDeviceInfo, castServiceNameStatePair_, GetSessionId()));
        CHECK_AND_RETURN_RET_LOG(castHandle_ != AVSESSION_ERROR, AVSESSION_ERROR, "StartCast failed");
        AVRouter::GetInstance().RegisterCallback(castHandle_, cssListener_, GetSessionId(), deviceInfo);
        AVRouter::GetInstance().SetServiceAllConnectState(castHandle_, deviceInfo);
        InitAVCastControllerProxy();
    } else {
        SetCastHandle(AVRouter::GetInstance().GetMirrorCastHandle());
        InitAVCastControllerProxy();
        if (castControllerProxy_ !=  nullptr && castControllerProxy_->GetCurrentItem().GetDescription() != nullptr) {
            SetCastHandle(-1);
            castControllerProxy_ = nullptr;
            return AVSESSION_ERROR;
        }
        AVRouter::GetInstance().RegisterCallback(castHandle_, cssListener_, GetSessionId(), deviceInfo);
    }
    castHandleDeviceId_ = deviceInfo.deviceId_;
    SLOGI("RegisterListenerStreamToCast check handle set to %{public}lld", (long long)castHandle_);
    UpdateCastDeviceMap(deviceInfo);
    DoContinuousTaskRegister();
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
    std::lock_guard lockGuard(avsessionItemLock_);
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

int32_t AVSessionItem::SessionCommandToCastCommand(int32_t cmd)
{
    if (cmd == AVControlCommand::SESSION_CMD_SET_LOOP_MODE) {
        return AVCastControlCommand::CAST_CONTROL_CMD_SET_LOOP_MODE;
    }
    return AVCastControlCommand::CAST_CONTROL_CMD_INVALID;
}

void AVSessionItem::AddSessionCommandToCast(int32_t cmd)
{
    if (cmd != AVControlCommand::SESSION_CMD_SET_LOOP_MODE) {
        return;
    }

    if (castControllerProxy_ != nullptr) {
        int32_t castCmd = SessionCommandToCastCommand(cmd);
        std::lock_guard lockGuard(avsessionItemLock_);
        auto iter = std::find(supportedCastCmds_.begin(), supportedCastCmds_.end(), castCmd);
        if (iter != supportedCastCmds_.end()) {
            SLOGI("castCmd have already been added, cmd:%{public}d", castCmd);
            return;
        }
        supportedCastCmds_.push_back(castCmd);
        HandleCastValidCommandChange(supportedCastCmds_);
    }
}

void AVSessionItem::RemoveSessionCommandFromCast(int32_t cmd)
{
    if (cmd != AVControlCommand::SESSION_CMD_SET_LOOP_MODE) {
        return;
    }

    if (castControllerProxy_ != nullptr) {
        int32_t castCmd = SessionCommandToCastCommand(cmd);
        std::lock_guard lockGuard(avsessionItemLock_);
        SLOGI("remove castcmd:%{public}d", castCmd);
        auto iter = std::remove(supportedCastCmds_.begin(), supportedCastCmds_.end(), castCmd);
        supportedCastCmds_.erase(iter, supportedCastCmds_.end());
        HandleCastValidCommandChange(supportedCastCmds_);
    }
}

int32_t AVSessionItem::AddSupportCastCommand(int32_t cmd)
{
    if (cmd <= AVCastControlCommand::CAST_CONTROL_CMD_INVALID ||
        cmd >= AVCastControlCommand::CAST_CONTROL_CMD_MAX) {
        SLOGI("add invalid cmd: %{public}d", cmd);
        return AVSESSION_ERROR;
    }
    {
        std::lock_guard lockGuard(avsessionItemLock_);
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
    }
    ProcessFrontSession("AddSupportCastCommand");
    HandleCastValidCommandChange(supportedCastCmds_);
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::DeleteSupportCastCommand(int32_t cmd)
{
    if (cmd <= AVCastControlCommand::CAST_CONTROL_CMD_INVALID ||
        cmd >= AVCastControlCommand::CAST_CONTROL_CMD_MAX) {
        SLOGI("delete invalid cmd: %{public}d", cmd);
        return AVSESSION_ERROR;
    }
    {
        std::lock_guard lockGuard(avsessionItemLock_);
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

            iter = std::remove(supportedCastCmds_.begin(), supportedCastCmds_.end(),
                AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD);
            supportedCastCmds_.erase(iter, supportedCastCmds_.end());

            iter = std::remove(
                supportedCastCmds_.begin(), supportedCastCmds_.end(), AVCastControlCommand::CAST_CONTROL_CMD_REWIND);
            supportedCastCmds_.erase(iter, supportedCastCmds_.end());
        } else {
            auto iter = std::remove(supportedCastCmds_.begin(), supportedCastCmds_.end(), cmd);
            supportedCastCmds_.erase(iter, supportedCastCmds_.end());
        }
    }
    ProcessFrontSession("DeleteSupportCastCommand");
    HandleCastValidCommandChange(supportedCastCmds_);
    return AVSESSION_SUCCESS;
}

void AVSessionItem::HandleCastValidCommandChange(const std::vector<int32_t> &cmds)
{
    std::lock_guard lockGuard(castControllersLock_);
    SLOGI("send command change event to controller, controller size: %{public}d, cmds size is: %{public}d,",
        static_cast<int>(castControllers_.size()), static_cast<int>(cmds.size()));
    for (auto controller : castControllers_) {
        if (controller != nullptr) {
            controller->HandleCastValidCommandChange(cmds);
        }
    }
}

int32_t AVSessionItem::ReleaseCast(bool continuePlay)
{
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "StopCasting",
        "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(),
        "ERROR_CODE", AVSESSION_SUCCESS,
        "ERROR_MSG", "SUCCESS");
    return StopCast(continuePlay);
}

int32_t AVSessionItem::CastAddToCollaboration(const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("enter CastAddToCollaboration");
    if (castDeviceInfoMap_.count(outputDeviceInfo.deviceInfos_[0].deviceId_) != 1) {
        SLOGE("deviceId map deviceinfo is not exit");
        return AVSESSION_ERROR;
    }
    ListenCollaborationApplyResult();
    DeviceInfo deviceInfo = castDeviceInfoMap_[outputDeviceInfo.deviceInfos_[0].deviceId_];
    CHECK_AND_RETURN_RET_LOG(deviceInfo.deviceId_ != "", AVSESSION_ERROR, "deviceid is empty");
    CollaborationManager::GetInstance().ApplyAdvancedResource(deviceInfo.deviceId_.c_str());
    //wait collaboration callback 10s
    std::unique_lock <std::mutex> applyResultLock(collaborationApplyResultMutex_);
    bool flag = connectWaitCallbackCond_.wait_for(applyResultLock, std::chrono::seconds(collaborationCallbackTimeOut_),
        [this]() {
            return applyResultFlag_;
    });
    //wait user decision collaboration callback 60s
    if (waitUserDecisionFlag_) {
        flag = connectWaitCallbackCond_.wait_for(applyResultLock,
            std::chrono::seconds(collaborationUserCallbackTimeOut_),
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
    std::lock_guard lockGuard(castLock_);

    if (AVRouter::GetInstance().GetMirrorCastHandle() != -1 && castHandle_ <= 0 &&
        descriptor_.sessionType_ == AVSession::SESSION_TYPE_VIDEO) {
        SetCastHandle(AVRouter::GetInstance().GetMirrorCastHandle());
        InitAVCastControllerProxy();
        AVRouter::GetInstance().RegisterCallback(castHandle_, cssListener_,
            GetSessionId(), outputDeviceInfo.deviceInfos_[0]);
        castHandleDeviceId_ = outputDeviceInfo.deviceInfos_[0].deviceId_;
        DoContinuousTaskRegister();
        SLOGI("RegisterListenerStreamToCast check handle set to %{public}lld", (long long)castHandle_);
        return AVSESSION_SUCCESS;
    }

    // unregister pre castSession callback to avoid previous session timeout disconnect influence current session
    if (castHandle_ > 0) {
        if (castHandleDeviceId_ == outputDeviceInfo.deviceInfos_[0].deviceId_) {
            SLOGI("repeat startcast %{public}lld", (long long)castHandle_);
            return AVSESSION_ERROR;
        } else {
            SLOGI("cast check with pre cast alive %{public}lld, unregister callback", (long long)castHandle_);
            isSwitchNewDevice_ = true;
            newOutputDeviceInfo_ = outputDeviceInfo;
            StopCast();
            int32_t flag = CastAddToCollaboration(outputDeviceInfo);
            CHECK_AND_RETURN_RET_LOG(flag == AVSESSION_SUCCESS, AVSESSION_ERROR, "collaboration to start cast fail");
            return AVSESSION_SUCCESS;
        }
    } else {
        int32_t flag = CastAddToCollaboration(outputDeviceInfo);
        CHECK_AND_RETURN_RET_LOG(flag == AVSESSION_SUCCESS, AVSESSION_ERROR, "collaboration to start cast fail");
    }
    return SubStartCast(outputDeviceInfo);
}

int32_t AVSessionItem::SubStartCast(const OutputDeviceInfo& outputDeviceInfo)
{
    int64_t castHandle = AVRouter::GetInstance().StartCast(outputDeviceInfo, castServiceNameStatePair_, GetSessionId());
    CHECK_AND_RETURN_RET_LOG(castHandle != AVSESSION_ERROR, AVSESSION_ERROR, "StartCast failed");

    SetCastHandle(castHandle);
    SLOGI("start cast check handle set to %{public}lld", (long long)castHandle_);
    int32_t ret = AddDevice(static_cast<int32_t>(castHandle), outputDeviceInfo);
    if (ret == AVSESSION_SUCCESS) {
        castHandleDeviceId_ = outputDeviceInfo.deviceInfos_[0].deviceId_;
    }
    DoContinuousTaskRegister();
    return ret;
}

int32_t AVSessionItem::AddDevice(const int64_t castHandle, const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("Add device process");
    std::lock_guard lockGuard(castLock_);
    AVRouter::GetInstance().RegisterCallback(castHandle_, cssListener_,
        GetSessionId(), outputDeviceInfo.deviceInfos_[0]);
    int32_t castId = static_cast<int32_t>(castHandle_);
    int32_t ret = AVRouter::GetInstance().AddDevice(castId, outputDeviceInfo);
    SLOGI("Add device process with ret %{public}d", ret);
    return ret;
}

void AVSessionItem::DealDisconnect(DeviceInfo deviceInfo, bool isNeedRemove)
{
    SLOGI("Is remotecast, received disconnect event for castHandle_: %{public}lld", (long long)castHandle_);
    if (isNeedRemove) {
        AVRouter::GetInstance().UnRegisterCallback(castHandle_, cssListener_, GetSessionId());
        AVRouter::GetInstance().StopCastSession(castHandle_);
        DoContinuousTaskUnregister();
    } else {
        // clear pre session cast info in streamplayer to avoid flash when cast compete
        if (castControllerProxy_ != nullptr) {
            castControllerProxy_->RefreshCurrentAVQueueItem(AVQueueItem {});
        }
    }
    SetCastHandle(-1);
    castHandleDeviceId_ = "-100";
    castControllerProxy_ = nullptr;
    isFirstCallback_ = true;
    if (!isSwitchNewDevice_) {
        {
            std::lock_guard lockGuard(avsessionItemLock_);
            supportedCastCmds_.clear();
        }
        ProcessFrontSession("Disconnect");
    }
    SaveLocalDeviceInfo();
    if (serviceCallbackForCastNtf_) {
        serviceCallbackForCastNtf_(GetSessionId(), false, false);
    }
    ReportStopCastFinish("AVSessionItem::OnCastStateChange", deviceInfo);
}

void AVSessionItem::DealCollaborationPublishState(int32_t castState, DeviceInfo deviceInfo)
{
    SLOGI("enter DealCollaborationPublishState");
    {
        std::lock_guard displayListenerLockGuard(mirrorToStreamLock_);
        if (mirrorToStreamFlag_) {
            mirrorToStreamFlag_ = false;
            SLOGI("cast not add to collaboration when mirror to stream cast");
            return;
        }
    }
    collaborationNeedDeviceId_ = deviceInfo.deviceId_;
    if (castState == authingStateFromCast_) {
        CollaborationManager::GetInstance().PublishServiceState(collaborationNeedDeviceId_.c_str(),
            ServiceCollaborationManagerBussinessStatus::SCM_CONNECTING);
    }
    if (castState == connectStateFromCast_) { // 6 is connected status (stream)
        AVRouter::GetInstance().GetRemoteNetWorkId(
            castHandle_, deviceInfo.deviceId_, collaborationNeedNetworkId_);
        if (collaborationNeedNetworkId_.empty()) {
            SLOGI("networkId is empty, try use deviceId:%{public}s", deviceInfo.deviceId_.c_str());
            collaborationNeedNetworkId_ = deviceInfo.deviceId_;
        }
        CollaborationManager::GetInstance().PublishServiceState(collaborationNeedNetworkId_.c_str(),
            ServiceCollaborationManagerBussinessStatus::SCM_CONNECTED);
    }
    if (castState == disconnectStateFromCast_) { // 5 is disconnected status
        if (collaborationNeedNetworkId_.empty()) {
            SLOGI("networkId is empty, try use deviceId:%{public}s", deviceInfo.deviceId_.c_str());
            collaborationNeedNetworkId_ = deviceInfo.deviceId_;
        }
        CollaborationManager::GetInstance().PublishServiceState(collaborationNeedDeviceId_.c_str(),
            ServiceCollaborationManagerBussinessStatus::SCM_IDLE);
        CollaborationManager::GetInstance().PublishServiceState(collaborationNeedNetworkId_.c_str(),
            ServiceCollaborationManagerBussinessStatus::SCM_IDLE);
    }
}

void AVSessionItem::DealLocalState(int32_t castState)
{
    if (castState == ConnectionState::STATE_DISCONNECTED) {
        if (!isSwitchNewDevice_) {
            OutputDeviceInfo outputDeviceInfo;
            DeviceInfo deviceInfo;
            deviceInfo.castCategory_ = AVCastCategory::CATEGORY_LOCAL;
            deviceInfo.deviceId_ = "0";
            deviceInfo.deviceName_ = "LocalDevice";
            outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
            SetOutputDevice(outputDeviceInfo);
        } else {
            if (newOutputDeviceInfo_.deviceInfos_.size() > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(SWITCH_WAIT_TIME));
                SubStartCast(newOutputDeviceInfo_);
            }
            isSwitchNewDevice_ = false;
        }
    }
}


void AVSessionItem::ListenCollaborationOnStop()
{
    SLOGI("enter ListenCollaborationOnStop");
    CollaborationManager::GetInstance().SendCollaborationOnStop([this](void) {
        if (newCastState == connectStateFromCast_) {
            if (descriptor_.sessionTag_ == "RemoteCast") {
                SLOGI("notify controller avplayer cancle cast when pc recive onstop callback");
                AVRouter::GetInstance().StopCastSession(castHandle_);
            } else {
                StopCast();
            }
        }
    });
}

void AVSessionItem::PublishAVCastHa(int32_t castState, DeviceInfo deviceInfo)
{
    CHECK_AND_RETURN_LOG(descriptor_.sessionTag_ != "RemoteCast", "remote cast session, return");
    if (castState == connectStateFromCast_) {
        AVSessionHiAnalyticsReport::PublishCastEvent(GetBundleName(), connectStateFromCast_,
            castDeviceInfoMap_[deviceInfo.deviceId_]);
    } else if (castState == disconnectStateFromCast_) {
        AVSessionHiAnalyticsReport::PublishCastEvent(GetBundleName(), disconnectStateFromCast_,
            castDeviceInfoMap_[deviceInfo.deviceId_]);
        AVSessionHiAnalyticsReport::PublishCastRecord(GetBundleName(), castDeviceInfoMap_[deviceInfo.deviceId_]);
    }
}

void AVSessionItem::OnCastStateChange(int32_t castState, DeviceInfo deviceInfo, bool isNeedRemove)
{
    SLOGI("OnCastStateChange in with state: %{public}d | id: %{public}s", static_cast<int32_t>(castState),
        deviceInfo.deviceId_.c_str());
    if (deviceInfo.deviceId_ == "-1") { //cast_engine_service abnormal terminated, update deviceId in item
        deviceInfo = GetDescriptor().outputDeviceInfo_.deviceInfos_[0];
    }
    if (isNeedRemove) { //same device cast exchange no publish when hostpot scene
        DealCollaborationPublishState(castState, deviceInfo);
    }
    newCastState = castState;
    ListenCollaborationOnStop();
    OutputDeviceInfo outputDeviceInfo;
    if (castDeviceInfoMap_.count(deviceInfo.deviceId_) > 0) {
        if (static_cast<uint32_t>(castDeviceInfoMap_[deviceInfo.deviceId_].supportedProtocols_) &
            ProtocolType::TYPE_CAST_PLUS_AUDIO) {
            castDeviceInfoMap_[deviceInfo.deviceId_].audioCapabilities_ = deviceInfo.audioCapabilities_;
        }
        outputDeviceInfo.deviceInfos_.emplace_back(castDeviceInfoMap_[deviceInfo.deviceId_]);
    } else {
        outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
    }
    PublishAVCastHa(castState, deviceInfo);
    if (castState == connectStateFromCast_) { // 6 is connected status (stream)
        castState = 1; // 1 is connected status (local)
        descriptor_.outputDeviceInfo_ = outputDeviceInfo;
        ReportConnectFinish("AVSessionItem::OnCastStateChange", deviceInfo);
        if (callStartCallback_ && isNeedRemove && descriptor_.sessionTag_ == "RemoteCast") {
            SLOGI("AVSessionItem send callStart event to service for connected");
            callStartCallback_(*this);
        }
    }
    if (castState == disconnectStateFromCast_) { // 5 is disconnected status
        castState = 6; // 6 is disconnected status of AVSession
        DealDisconnect(deviceInfo, isNeedRemove);
    }
    {
        std::lock_guard aliveLockGuard(isAliveLock_);
        if (isAlivePtr_ != nullptr && *isAlivePtr_) {
            HandleOutputDeviceChange(castState, outputDeviceInfo);
            std::lock_guard controllersLockGuard(controllersLock_);
            for (const auto& controller : controllers_) {
                if (!controllers_.empty() && controller.second != nullptr) {
                    controller.second->HandleOutputDeviceChange(castState, outputDeviceInfo);
                }
            }
        }
    }
    if (castState == ConnectionState::STATE_DISCONNECTED && descriptor_.sessionTag_ == "RemoteCast") {
        SLOGI("Sink cast session is disconnected, avsession item need be destroyed.");
        Destroy();
    } else {
        AVSessionEventHandler::GetInstance().AVSessionPostTask([this, castState]() {
            DealLocalState(castState);
            }, "DealLocalState", 0);
    }
}

void AVSessionItem::OnCastEventRecv(int32_t errorCode, std::string& errorMsg)
{
    SLOGI("OnCastEventRecv in with code and msg %{public}dm %{public}s", errorCode, errorMsg.c_str());
    std::lock_guard lockGuard(castControllersLock_);
    for (auto controller : castControllers_) {
        controller->OnPlayerError(errorCode, errorMsg);
    }
}

void AVSessionItem::ListenCollaborationApplyResult()
{
    SLOGI("enter ListenCollaborationApplyResult");
    CollaborationManager::GetInstance().SendCollaborationApplyResult([this](const int32_t code) {
        std::unique_lock <std::mutex> applyResultLock(collaborationApplyResultMutex_);
        if (code == ServiceCollaborationManagerResultCode::PASS) {
            SLOGI("ApplyResult can cast");
            applyResultFlag_ = true;
            applyUserResultFlag_ = true;
            connectWaitCallbackCond_.notify_one();
        }
        if (code == ServiceCollaborationManagerResultCode::REJECT) {
            SLOGI("ApplyResult can not cast");
            collaborationRejectFlag_ = true;
            applyResultFlag_ = true;
            applyUserResultFlag_ = true;
            connectWaitCallbackCond_.notify_one();
        }
        if (code == ServiceCollaborationManagerResultCode::USERTIP) {
            SLOGI("ApplyResult user tip");
            applyResultFlag_ = true;
            waitUserDecisionFlag_ = true;
            connectWaitCallbackCond_.notify_one();
        }
        if (code == ServiceCollaborationManagerResultCode::USERAGREE) {
            SLOGI("ApplyResult user agree cast");
        }
    });
}

int32_t AVSessionItem::StopCast(bool continuePlay)
{
    std::lock_guard lockGuard(castLock_);
    if (descriptor_.sessionTag_ == "RemoteCast") {
        CollaborationManager::GetInstance().PublishServiceState(collaborationNeedDeviceId_.c_str(),
            ServiceCollaborationManagerBussinessStatus::SCM_IDLE);
        CollaborationManager::GetInstance().PublishServiceState(collaborationNeedNetworkId_.c_str(),
            ServiceCollaborationManagerBussinessStatus::SCM_IDLE);
        AVRouter::GetInstance().UnRegisterCallback(castHandle_, cssListener_, GetSessionId());
        int32_t ret = AVRouter::GetInstance().StopCastSession(castHandle_);
        SetCastHandle(-1);
        castHandleDeviceId_ = "-100";
        SLOGI("Unregister and Stop cast process for sink with ret %{public}d", ret);
        return ret;
    }
    {
        CHECK_AND_RETURN_RET_LOG(castHandle_ != 0 && castHandle_ != -1, AVSESSION_SUCCESS, "Not cast session, return");
        SLOGI("Stop cast process %{public}lld", (long long)castHandle_);
        if (castHandle_ == AVRouter::GetInstance().GetMirrorCastHandle()) {
            if (castControllerProxy_ != nullptr) {
                AVCastControlCommand cmd;
                cmd.SetCommand(AVCastControlCommand::CAST_CONTROL_CMD_STOP);
                castControllerProxy_->SendControlCommand(cmd);
            }
        } else {
            AVSessionRadarInfo info("AVSessionItem::StopCast");
            AVSessionRadar::GetInstance().StopCastBegin(descriptor_.outputDeviceInfo_, info);
            int64_t ret = AVRouter::GetInstance().StopCast(castHandle_, continuePlay);
            AVSessionRadar::GetInstance().StopCastEnd(descriptor_.outputDeviceInfo_, info);
            SLOGI("StopCast with unchange castHandle is %{public}lld", (long long)castHandle_);
            CHECK_AND_RETURN_RET_LOG(ret != AVSESSION_ERROR, AVSESSION_ERROR, "StopCast failed");
        }
    }
    return AVSESSION_SUCCESS;
}

void AVSessionItem::SetCastHandle(const int64_t castHandle)
{
    castHandle_ = castHandle;
    if (serviceCallbackForUpdateSession_) {
        serviceCallbackForUpdateSession_(sessionCastState_, IsCasting());
    }
}

void AVSessionItem::RegisterDeviceStateCallback()
{
    OutputDeviceInfo localDevice;
    DeviceInfo localInfo;
    localInfo.castCategory_ = AVCastCategory::CATEGORY_LOCAL;
    localInfo.deviceId_ = "0";
    localInfo.deviceName_ = "LocalDevice";
    localDevice.deviceInfos_.emplace_back(localInfo);
    descriptor_.outputDeviceInfo_ = localDevice;
    AVRouter::GetInstance().RegisterCallback(castHandle_, cssListener_, GetSessionId(), localInfo);
    SLOGI("register callback for device state change done");
}

void AVSessionItem::UnRegisterDeviceStateCallback()
{
    AVRouter::GetInstance().UnRegisterCallback(castHandle_, cssListener_, GetSessionId());
}

void AVSessionItem::StopCastSession()
{
    SLOGI("Stop cast session process with castHandle: %{public}lld", (long long)castHandle_);
    int64_t ret = AVRouter::GetInstance().StopCastSession(castHandle_);
    DoContinuousTaskUnregister();
    if (ret != AVSESSION_ERROR) {
        SetCastHandle(-1);
        castHandleDeviceId_ = "-100";
    } else {
        SLOGE("Stop cast session process error");
    }
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
    SLOGI("StopCastDisplayListener in");
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "offCastDisplayChange",
        "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(),
        "ERROR_CODE", AVSESSION_SUCCESS,
        "ERROR_MSG", "SUCCESS");
    std::lock_guard displayListenerLockGuard(displayListenerLock_);
    CHECK_AND_RETURN_RET_LOG(displayListener_ != nullptr, AVSESSION_ERROR, "displayListener_ is nullptr");
    Rosen::DMError ret = Rosen::ScreenManagerLite::GetInstance().UnregisterScreenListener(displayListener_);
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
        CHECK_AND_RETURN_LOG(displayListener_ != nullptr, "Create displayListener failed");
        SLOGI("Start to register display listener");
        Rosen::DMError ret = Rosen::ScreenManagerLite::GetInstance().RegisterScreenListener(displayListener_);
        if (ret != Rosen::DMError::DM_OK) {
            SLOGE("UnregisterScreenListener failed, ret: %{public}d.", ret);
        }
    }
    return;
}

int32_t AVSessionItem::GetAllCastDisplays(std::vector<CastDisplayInfo>& castDisplays)
{
    SLOGI("GetAllCastDisplays in");
    std::vector<Rosen::DisplayId> allDisplayIds = Rosen::DisplayManagerLite::GetInstance().GetAllDisplayIds();
    std::vector<CastDisplayInfo> displays;
    for (auto &displayId : allDisplayIds) {
        sptr<Rosen::DisplayLite> display = Rosen::DisplayManagerLite::GetInstance().GetDisplayById(displayId);
        CHECK_AND_RETURN_RET_LOG(display != nullptr, AVSESSION_ERROR, "display is nullptr");
        auto displayInfo = display->GetDisplayInfo();
        SLOGI("GetAllCastDisplays name: %{public}s, id: %{public}llu",
            displayInfo->GetName().c_str(), (unsigned long long)displayInfo->GetDisplayId());
        if (displayInfo->GetName() == "HwCast_AppModeDisplay") {
            displays.clear();
            SLOGI("GetAllCastDisplays AppCast");
            if (displayListener_ != nullptr) {
                displayListener_->SetAppCastDisplayId(displayInfo->GetDisplayId());
            }
            break;
        }
        auto flag = Rosen::DisplayManagerLite::GetInstance().GetVirtualScreenFlag(displayInfo->GetDisplayId());
        if (flag == Rosen::VirtualScreenFlag::CAST) {
            SLOGI("ReportCastDisplay start in");
            CastDisplayInfo castDisplayInfo;
            castDisplayInfo.displayState = CastDisplayState::STATE_ON;
            castDisplayInfo.displayId = displayInfo->GetDisplayId();
            castDisplayInfo.name = displayInfo->GetName();
            castDisplayInfo.width = static_cast<int32_t>(displayInfo->GetWidth());
            castDisplayInfo.height = static_cast<int32_t>(displayInfo->GetHeight());
            displays.push_back(castDisplayInfo);
            std::lock_guard displayListenerLockGuard(displayListenerLock_);
            if (displayListener_ != nullptr) {
                displayListener_->SetDisplayInfo(displayInfo);
            }
        }
    }
    castDisplays = displays;
    SLOGI("GetAllCastDisplays out");
    return AVSESSION_SUCCESS;
}

void AVSessionItem::SetExtrasInner(AAFwk::IArray* list)
{
    auto func = [this](AAFwk::IInterface* object) {
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

void AVSessionItem::SetServiceCallbackForCastNtfCapsule(const std::function<void(std::string, bool, bool)>& callback)
{
    SLOGI("SetServiceCallbackForCastNtfCapsule in");
    serviceCallbackForCastNtf_ = callback;
}
#endif

void AVSessionItem::SetServiceCallbackForUpdateExtras(const std::function<void(std::string)>& callback)
{
    SLOGI("SetServiceCallbackForUpdateExtras in");
    updateExtrasCallback_ = callback;
}

AVSessionDescriptor AVSessionItem::GetDescriptor()
{
    return descriptor_;
}

AVCallState AVSessionItem::GetAVCallState()
{
    std::lock_guard lockGuard(avsessionItemLock_);
    return avCallState_;
}

AVCallMetaData AVSessionItem::GetAVCallMetaData()
{
    std::lock_guard lockGuard(avsessionItemLock_);
    std::string sessionId = GetSessionId();
    std::string fileDir = AVSessionUtils::GetCachePathName(userId_);
    std::string fileName = sessionId + AVSessionUtils::GetFileSuffix();
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = avCallMetaData_.GetMediaImage();
    AVSessionUtils::ReadImageFromFile(innerPixelMap, fileDir, fileName);
    return avCallMetaData_;
}


AVPlaybackState AVSessionItem::GetPlaybackState()
{
    std::lock_guard lockGuard(avsessionItemLock_);
    return playbackState_;
}

AVMetaData AVSessionItem::GetMetaDataWithoutImg()
{
    std::lock_guard lockGuard(avsessionItemLock_);
    return metaData_;
}

AVMetaData AVSessionItem::GetMetaData()
{
    std::lock_guard lockGuard(avsessionItemLock_);
    std::string sessionId = GetSessionId();
    std::string fileDir = AVSessionUtils::GetCachePathName(userId_);
    std::string fileName = sessionId + AVSessionUtils::GetFileSuffix();
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = metaData_.GetMediaImage();
    AVSessionUtils::ReadImageFromFile(innerPixelMap, fileDir, fileName);

    std::string avQueueFileDir = AVSessionUtils::GetFixedPathName(userId_);
    std::string avQueueFileName = GetBundleName() + "_" + metaData_.GetAVQueueId() + AVSessionUtils::GetFileSuffix();
    std::shared_ptr<AVSessionPixelMap> avQueuePixelMap = metaData_.GetAVQueueImage();
    AVSessionUtils::ReadImageFromFile(avQueuePixelMap, avQueueFileDir, avQueueFileName);
    return metaData_;
}

std::vector<AVQueueItem> AVSessionItem::GetQueueItems()
{
    std::lock_guard lock_guard(avsessionItemLock_);
    return queueItems_;
}

std::string AVSessionItem::GetQueueTitle()
{
    std::lock_guard lockGuard(avsessionItemLock_);
    return queueTitle_;
}

std::vector<int32_t> AVSessionItem::GetSupportCommand()
{
    std::lock_guard lockGuard(avsessionItemLock_);
    if (descriptor_.elementName_.GetBundleName() == "castBundleName"
        && descriptor_.elementName_.GetAbilityName() == "castAbilityName") {
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

void AVSessionItem::SetSupportCommand(std::vector<int32_t> cmds)
{
    {
        std::lock_guard lockGuard(avsessionItemLock_);
        supportedCmd_ = cmds;
    }
    std::string apiParamString = "cmd num:" + std::to_string(cmds.size());
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "SetSupportCommand",
        "BUNDLE_NAME", GetBundleName(),
        "SESSION_ID", AVSessionUtils::GetAnonySessionId(GetSessionId()),
        "SESSION_TAG", descriptor_.sessionTag_,
        "SESSION_TYPE", GetSessionType(),
        "API_PARAM", apiParamString,
        "ERROR_CODE", AVSESSION_SUCCESS,
        "ERROR_MSG", "SUCCESS");
    ProcessFrontSession("SetSupportCommand");

    {
        std::lock_guard controllerLockGuard(controllersLock_);
        SLOGI("send add command event to controller, size:%{public}d", static_cast<int>(controllers_.size()));
        for (const auto& [pid, controller] : controllers_) {
            if (controller != nullptr) {
                controller->HandleValidCommandChange(supportedCmd_);
            }
        }
    }
}

AbilityRuntime::WantAgent::WantAgent AVSessionItem::GetLaunchAbility()
{
    return launchAbility_;
}

AAFwk::WantParams AVSessionItem::GetExtras()
{
    std::lock_guard lockGuard(avsessionItemLock_);
    return extras_;
}

void AVSessionItem::NotificationExtras(AAFwk::IArray* list)
{
    auto func = [this](AAFwk::IInterface* object) {
        if (object != nullptr) {
            AAFwk::IBoolean* booleanValue = AAFwk::IBoolean::Query(object);
            if (booleanValue != nullptr && AAFwk::Boolean ::Unbox(booleanValue)) {
                isNotShowNotification_ = true;
            } else {
                isNotShowNotification_ = false;
            }
        }
    };
    AAFwk::Array::ForEach(list, func);
    if (updateExtrasCallback_) {
        updateExtrasCallback_(GetSessionId());
    }
}

void AVSessionItem::KeyEventExtras(AAFwk::IArray* list)
{
    auto func = [this](AAFwk::IInterface* object) {
        if (object != nullptr) {
            AAFwk::IBoolean* booleanValue = AAFwk::IBoolean::Query(object);
            if (booleanValue != nullptr && AAFwk::Boolean::Unbox(booleanValue) &&
                serviceCallbackForKeyEvent_) {
                SLOGI("AVSessionItem send addkeyeventsession event to service");
                serviceCallbackForKeyEvent_(GetSessionId());
            }
        }
    };
    AAFwk::Array::ForEach(list, func);
}

bool AVSessionItem::IsNotShowNotification()
{
    return isNotShowNotification_;
}

void AVSessionItem::HandleMediaKeyEvent(const MMI::KeyEvent& keyEvent)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnMediaKeyEvent");
    CHECK_AND_RETURN_LOG(descriptor_.isActive_, "session is deactive");
    SLOGI("HandleMediaKeyEvent check isMediaKeySupport %{public}d for %{public}d",
        static_cast<int>(isMediaKeySupport), static_cast<int>(keyEvent.GetKeyCode()));
    if (!isMediaKeySupport && keyEventCaller_.count(keyEvent.GetKeyCode()) > 0) {
        AVControlCommand cmd;
        cmd.SetRewindTime(metaData_.GetSkipIntervals());
        cmd.SetForwardTime(metaData_.GetSkipIntervals());
        keyEventCaller_[keyEvent.GetKeyCode()](cmd);
    } else {
        std::lock_guard callbackLockGuard(callbackLock_);
        if (callback_ != nullptr) {
            callback_->OnMediaKeyEvent(keyEvent);
        }
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
    SLOGI("ExecuteControllerCommand code %{public}d from pid %{public}d to pid %{public}d",
        code, static_cast<int>(GetCallingPid()), static_cast<int>(GetPid()));
    {
        std::lock_guard remoteSinkLockGuard(remoteSinkLock_);
        if (remoteSink_ != nullptr) {
            SLOGI("set remote ControlCommand");
            CHECK_AND_RETURN_LOG(remoteSink_->SetControlCommand(cmd) == AVSESSION_SUCCESS, "SetControlCommand failed");
        }
    }
    CHECK_AND_RETURN_LOG(callback_ != nullptr || callbackForMigrate_ != nullptr,
        "callback_ or callbackForMigrate_ is nullptr");
    CHECK_AND_RETURN_LOG(descriptor_.isActive_, "session is deactivate");

    HISYSEVENT_ADD_OPERATION_COUNT(static_cast<Operation>(cmd.GetCommand()));
    HISYSEVENT_ADD_OPERATION_COUNT(Operation::OPT_SUCCESS_CTRL_COMMAND);
    HISYSEVENT_ADD_CONTROLLER_COMMAND_INFO(descriptor_.elementName_.GetBundleName(), GetPid(),
        cmd.GetCommand(), descriptor_.sessionType_);
#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
    ReportSessionControl(descriptor_.elementName_.GetBundleName(), cmd.GetCommand());
#endif
    return cmdHandlers[code](cmd);

    HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "ERROR_TYPE", "INVALID_COMMAND", "CMD", code,
        "ERROR_INFO", "avsessionitem executecontrollercommand, invaild command");
}
// LCOV_EXCL_STOP

void AVSessionItem::ExecueCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::ExecueCommonCommand");
    {
        std::lock_guard callbackLockGuard(callbackLock_);
        if (callbackForMigrate_) {
            callbackForMigrate_->OnCommonCommand(commonCommand, commandArgs);
        }
        CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
        callback_->OnCommonCommand(commonCommand, commandArgs);
    }

    std::lock_guard remoteSinkLockGuard(remoteSinkLock_);
    if (remoteSink_ != nullptr) {
        CHECK_AND_RETURN_LOG(remoteSink_->SetCommonCommand(commonCommand, commandArgs) == AVSESSION_SUCCESS,
            "SetCommonCommand failed");
    }
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
    if (callbackForMigrate_) {
        callbackForMigrate_->OnPlay();
    }
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPlay();
}

void AVSessionItem::HandleOnPause(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnPause");
    std::lock_guard callbackLockGuard(callbackLock_);
    if (callbackForMigrate_) {
        callbackForMigrate_->OnPause();
    }
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPause();
}

void AVSessionItem::HandleOnPlayOrPause(const AVControlCommand& cmd)
{
    std::lock_guard lockGuard(avsessionItemLock_);
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
    if (callbackForMigrate_) {
        callbackForMigrate_->OnPlayNext();
    }
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnPlayNext();
}

void AVSessionItem::HandleOnPlayPrevious(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnPlayPrevious");
    std::lock_guard callbackLockGuard(callbackLock_);
    if (callbackForMigrate_) {
        callbackForMigrate_->OnPlayPrevious();
    }
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

void AVSessionItem::HandleOnSetTargetLoopMode(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnSetTargetLoopMode");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    int32_t targetLoopMode = AVSESSION_ERROR;
    CHECK_AND_RETURN_LOG(cmd.GetTargetLoopMode(targetLoopMode) == AVSESSION_SUCCESS, "GetTargetLoopMode failed");
    callback_->OnSetTargetLoopMode(targetLoopMode);
}

void AVSessionItem::HandleOnToggleFavorite(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnToggleFavorite");
    std::lock_guard callbackLockGuard(callbackLock_);
    std::string assetId;
    CHECK_AND_RETURN_LOG(cmd.GetAssetId(assetId) == AVSESSION_SUCCESS, "GetMediaId failed");
    if (callbackForMigrate_) {
        callbackForMigrate_->OnToggleFavorite(assetId);
    }
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
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

void AVSessionItem::HandleOnPlayWithAssetId(const AVControlCommand& cmd)
{
    AVSESSION_TRACE_SYNC_START("AVSessionItem::OnPlayWithAssetId");
    std::lock_guard callbackLockGuard(callbackLock_);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    std::string assetId;
    CHECK_AND_RETURN_LOG(cmd.GetPlayWithAssetId(assetId) == AVSESSION_SUCCESS, "Get playWithAssetId failed");
    CHECK_AND_RETURN_LOG(!assetId.empty(), "assetId is empty");
    callback_->OnPlayWithAssetId(assetId);
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

void AVSessionItem::SetServiceCallbackForMediaSession(const std::function<void(std::string, bool)>& callback)
{
    SLOGI("SetServiceCallbackForUpdateSession in");
    serviceCallbackForMediaSession_ = callback;
}

void AVSessionItem::SetServiceCallbackForKeyEvent(const std::function<void(std::string)>& callback)
{
    SLOGI("SetServiceCallbackForKeyEvent in");
    serviceCallbackForKeyEvent_ = callback;
}

void AVSessionItem::SetServiceCallbackForNtfCapsule(const std::function<void(std::string, bool)>& callback)
{
    SLOGI("SetServiceCallbackForNtfCapsule in");
    serviceCallbackForNtf_ = callback;
}

void AVSessionItem::HandleOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("output device change, connection state is %{public}d", connectionState);
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
    CHECK_AND_RETURN_LOG(controllers_.size() > 0, "handle with no controller, return");
    for (const auto& controller : controllers_) {
        if (controller.second != nullptr) {
            (controller.second)->HandleOutputDeviceChange(connectionStateConnected, descriptor_.outputDeviceInfo_);
        }
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
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::SourceCancelCastAudio(const std::string& sinkDevice)
{
    SLOGI("start cancel cast audio");
    std::lock_guard remoteSourceLockGuard(remoteSourceLock_);
    CHECK_AND_RETURN_RET_LOG(remoteSource_ != nullptr, AVSESSION_ERROR, "remoteSource_ is nullptr");
    int32_t ret = remoteSource_->CancelCastAudio(sinkDevice);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CastAudioToLocal failed");
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
        ret = AddSupportCommand(cmd);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "AddSupportCommand failed");
    }
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
    SLOGI("UpdateCastDeviceMap with id: %{public}s", deviceInfo.deviceId_.c_str());
    castDeviceInfoMap_[deviceInfo.deviceId_] = deviceInfo;

    if (descriptor_.outputDeviceInfo_.deviceInfos_.size() > 0 &&
        descriptor_.outputDeviceInfo_.deviceInfos_[0].deviceId_ == deviceInfo.deviceId_) {
        OutputDeviceInfo outputDeviceInfo;
        outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
        descriptor_.outputDeviceInfo_ = outputDeviceInfo;
    }
}

std::map<std::string, DeviceInfo> AVSessionItem::GetCastDeviceMap() const
{
    return castDeviceInfoMap_;
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

int32_t AVSessionItem::DoContinuousTaskRegister()
{
#ifdef EFFICIENCY_MANAGER_ENABLE
    if (descriptor_.sessionTag_ == "RemoteCast") {
        SLOGI("sink session no need to register continuousTask");
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
    typedef ErrCode (*handler) (int32_t eventType, int32_t uid, int32_t pid,
        const std::string bundleName, int32_t taskState, int32_t serviceId);
    handler reportContinuousTaskEventEx = reinterpret_cast<handler>(dlsym(handle_, "ReportContinuousTaskEventEx"));
    ErrCode errCode = reportContinuousTaskEventEx(0, uid, pid, bundleName, 1, AVSESSION_SERVICE_ID);
    SLOGI("reportContinuousTaskEventEx done, result: %{public}d", errCode);
#ifndef TEST_COVERAGE
    if (handle_ != nullptr) {
        OPENSSL_thread_stop();
    }
    dlclose(handle_);
#endif
#endif
    return AVSESSION_SUCCESS;
}

int32_t AVSessionItem::DoContinuousTaskUnregister()
{
#ifdef EFFICIENCY_MANAGER_ENABLE
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
    typedef ErrCode (*handler) (int32_t eventType, int32_t uid, int32_t pid,
        const std::string bundleName, int32_t taskState, int32_t serviceId);
    handler reportContinuousTaskEventEx = reinterpret_cast<handler>(dlsym(handle_, "ReportContinuousTaskEventEx"));
    ErrCode errCode = reportContinuousTaskEventEx(0, uid, pid, bundleName, 2, AVSESSION_SERVICE_ID);
    SLOGI("reportContinuousTaskEventEx done when stop cast, result: %{public}d", errCode);
#ifndef TEST_COVERAGE
    if (handle_ != nullptr) {
        OPENSSL_thread_stop();
    }
    dlclose(handle_);
#endif
#endif
    return AVSESSION_SUCCESS;
}

bool AVSessionItem::IsCasting()
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    if (descriptor_.sessionTag_ != "RemoteCast" && castHandle_ > 0) {
        return true;
    }
#endif
    return false;
}

void AVSessionItem::GetCurrentCastItem(AVQueueItem& currentItem)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    CHECK_AND_RETURN_LOG(castControllerProxy_ != nullptr, "cast controller proxy is nullptr");
    currentItem = castControllerProxy_->GetCurrentItem();
#endif
    return;
}

AVPlaybackState AVSessionItem::GetCastAVPlaybackState()
{
    AVPlaybackState playbackState;
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    CHECK_AND_RETURN_RET_LOG(castControllerProxy_ != nullptr, playbackState, "cast controller proxy is nullptr");
    auto ret = castControllerProxy_->GetCastAVPlaybackState(playbackState);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, playbackState, "getstate error");
#endif
    return playbackState;
}

void AVSessionItem::SendControlCommandToCast(AVCastControlCommand cmd)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    CHECK_AND_RETURN_LOG(castControllerProxy_ != nullptr, "cast controller proxy is nullptr");
    castControllerProxy_->SendControlCommand(cmd);
#endif
}

#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
void AVSessionItem::ReportPlaybackState(const AVPlaybackState& state)
{
    if (state.GetState() == AVPlaybackState::PLAYBACK_STATE_PLAY ||
        state.GetState() == AVPlaybackState::PLAYBACK_STATE_PAUSE) {
            AVSessionSysEvent::GetInstance().UpdatePlaybackState(GetBundleName(),
                static_cast<uint8_t>(state.GetState()));
    }
}

void AVSessionItem::ReportMetadataChange(const AVMetaData& metadata)
{
    if ((metadata.GetTitle().compare(lastMetaData_.GetTitle()) != 0) ||
        (metadata.GetMediaImageUri().compare(lastMetaData_.GetMediaImageUri()) != 0)) {
        lastMetaData_ = metadata;
        bool hasTitle = !metadata.GetTitle().empty();
        bool hasImage = metadata.GetMediaImage() != nullptr || !metadata.GetMediaImageUri().empty();
        MetadataQuality metadataQuality;
        if (!hasTitle && !hasImage) {
            metadataQuality = MetadataQuality::METADATA_QUALITY_NONE;
        } else if (hasTitle && hasImage) {
            metadataQuality = MetadataQuality::METADATA_QUALITY_BOTH;
        } else if (hasImage) {
            metadataQuality = MetadataQuality::METADATA_QUALITY_IMG;
        } else {
            metadataQuality = MetadataQuality::METADATA_QUALITY_TITLE;
        }
        AVSessionSysEvent::GetInstance().UpdateMetaQuality(GetBundleName(), metadataQuality);
    }
}

void AVSessionItem::ReportCommandChange()
{
    int32_t commandQuality = 0;
    for (auto cmd : GetSupportCommand()) {
        auto it = g_cmdToOffsetMap.find(cmd);
        if (it != g_cmdToOffsetMap.end()) {
            commandQuality += (1 << it->second);
        }
    }
    AVSessionSysEvent::GetInstance().UpdateCommandQuality(GetBundleName(), commandQuality);
}

void AVSessionItem::ReportSessionControl(const std::string& bundleName, int32_t cmd)
{
    if (cmd == AVControlCommand::SESSION_CMD_PLAY ||
        cmd == AVControlCommand::SESSION_CMD_PAUSE ||
        cmd == CONTROL_COLD_START) {
        AVSessionSysEvent::GetInstance().UpdateControl(bundleName, cmd,
            BundleStatusAdapter::GetInstance().GetBundleNameFromUid(GetCallingUid()));
    }
}
#endif
// LCOV_EXCL_STOP
} // namespace OHOS::AVSession
