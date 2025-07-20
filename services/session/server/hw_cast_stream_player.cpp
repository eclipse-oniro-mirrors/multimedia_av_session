/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "hw_cast_stream_player.h"
#include "int_wrapper.h"
#include "string_wrapper.h"
#include "avsession_log.h"
#include "avcast_player_state.h"
#include "avqueue_item.h"
#include "avmedia_description.h"
#include "avsession_errors.h"
#include "avsession_sysevent.h"
#include "avsession_event_handler.h"
#include "avsession_trace.h"
#include "avsession_radar.h"

using namespace OHOS::CastEngine;

namespace OHOS::AVSession {
HwCastStreamPlayer::~HwCastStreamPlayer()
{
    SLOGI("destruct the HwCastStreamPlayer without release");
}

int32_t HwCastStreamPlayer::Init()
{
    SLOGI("Init the HwCastStreamPlayer");
    std::lock_guard lockGuard(streamPlayerLock_);
    if (streamPlayer_) {
        SLOGI("register self in streamPlayer");
        return streamPlayer_->RegisterListener(shared_from_this());
    }
    return AVSESSION_ERROR;
}

void HwCastStreamPlayer::Release()
{
    SLOGI("Release the HwCastStreamPlayer");

    std::lock_guard lockGuard(streamPlayerLock_);
    if (streamPlayer_) {
        streamPlayer_->UnregisterListener();
        streamPlayer_->Release();
        streamPlayer_ = nullptr;
    }

    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    streamPlayerListenerList_.clear();
    SLOGI("Release the HwCastStreamPlayer done");
}

int32_t HwCastStreamPlayer::CheckCastTime(int32_t castTime)
{
    if (castTime < castMinTime) {
        return castMinTime * castTime;
    } else {
        return castTime;
    }
}

void HwCastStreamPlayer::SendControlCommand(const AVCastControlCommand castControlCommand)
{
    int32_t commandNum = castControlCommand.GetCommand();
    SLOGI("send command to streamPlayer %{public}d", static_cast<int32_t>(commandNum));
    std::lock_guard lockGuard(streamPlayerLock_);
    if (!streamPlayer_) {
        SLOGE("streamPlayer is nullptr");
        HISYSEVENT_FAULT("REMOTE_CONTROL_FAILED",
            "SESSION_TYPE", "cast",
            "ERROR_TYPE", "INNER_ERROR",
            "ERROR_INFO", "streamPlayer is nullptr");
        AVSessionRadarInfo info("HwCastStreamPlayer::SendControlCommand");
        info.errorCode_ = AVSessionRadar::GetRadarErrorCode(ERR_REMOTE_CONNECTION_NOT_EXIST);
        AVSessionRadar::GetInstance().FailToSendControlCommand(info);
        return;
    }
    switch (castControlCommand.GetCommand()) {
        case AVCastControlCommand::CAST_CONTROL_CMD_PLAY:
            streamPlayer_->Play();
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_PAUSE:
            streamPlayer_->Pause();
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_STOP:
            streamPlayer_->Stop();
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT:
            streamPlayer_->Next();
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS:
            streamPlayer_->Previous();
            break;
        default:
            SendControlCommandWithParams(castControlCommand);
            break;
    }
}

void HwCastStreamPlayer::SendCustomData(const std::string& data)
{
    std::lock_guard lockGuard(streamPlayerLock_);
    if (streamPlayer_ == nullptr) {
        SLOGE("streamPlayer is nullptr");
        return;
    }
    streamPlayer_->SendData(DataType::CUSTOM_DATA, data);
}

void HwCastStreamPlayer::SetSpid(const std::string& spid)
{
    SLOGI("SetSpid spid %{public}s", spid.c_str());
    spid_ = spid;
}

void HwCastStreamPlayer::SendControlCommandWithParams(const AVCastControlCommand castControlCommand)
{
    std::lock_guard lockGuard(streamPlayerLock_);
    int32_t param = 0;
    switch (castControlCommand.GetCommand()) {
        case AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD:
            castControlCommand.GetForwardTime(param);
            streamPlayer_->FastForward(CheckCastTime(param));
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_REWIND:
            castControlCommand.GetRewindTime(param);
            streamPlayer_->FastRewind(CheckCastTime(param));
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_SEEK:
            castControlCommand.GetSeekTime(param);
            streamPlayer_->Seek(param);
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME:
            castControlCommand.GetVolume(param);
            streamPlayer_->SetVolume(param);
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_SET_SPEED:
            castControlCommand.GetSpeed(param);
            streamPlayer_->SetSpeed(static_cast<CastEngine::PlaybackSpeed>(param));
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_SET_LOOP_MODE:
            castControlCommand.GetLoopMode(param);
            SLOGD("SetLoopMode int: %{public}d", param);
            CHECK_AND_RETURN_LOG(intLoopModeToCastPlus_.count(param) != 0, "invalid LoopMode");
            streamPlayer_->SetLoopMode(intLoopModeToCastPlus_[param]);
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_TOGGLE_FAVORITE:
            break;
        case AVCastControlCommand::CAST_CONTROL_CMD_TOGGLE_MUTE:
            bool enableMute;
            streamPlayer_->GetMute(enableMute);
            streamPlayer_->SetMute(!enableMute);
            break;
        default:
            SLOGE("invalid command");
            HISYSEVENT_FAULT("REMOTE_CONTROL_FAILED", "ERROR_TYPE", "INNER_ERROR", "ERROR_INFO", "invalid command");
            break;
    }
}

AVQueueItem HwCastStreamPlayer::GetCurrentItem()
{
    SLOGI("Received GetCurrentItem request");
    // do not place streamPlayerLock_ in side of curItemLock_
    std::lock_guard lockGuard(curItemLock_);
    return currentAVQueueItem_;
}

AVQueueItem HwCastStreamPlayer::RefreshCurrentItemDuration()
{
    SLOGD("RefreshCurrentItemDuration in");
    int32_t duration = 0;
    GetDuration(duration);
    // do not place streamPlayerLock_ in side of curItemLock_
    std::lock_guard lockGuard(curItemLock_);
    std::shared_ptr<AVMediaDescription> mediaDes = currentAVQueueItem_.GetDescription();
    CHECK_AND_RETURN_RET_LOG(mediaDes != nullptr, currentAVQueueItem_, "AVMediaDescription get null!");
    mediaDes->SetDuration(duration);
    currentAVQueueItem_.SetDescription(mediaDes);
    SLOGI("refresh duration:%{public}d", duration);
    return currentAVQueueItem_;
}

int32_t HwCastStreamPlayer::RefreshCurrentAVQueueItem(const AVQueueItem& avQueueItem)
{
    std::lock_guard lockGuard(curItemLock_);
    currentAVQueueItem_ = avQueueItem;
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::Start(const AVQueueItem& avQueueItem)
{
    std::shared_ptr<AVMediaDescription> mediaDescription = avQueueItem.GetDescription();
    CastEngine::MediaInfo mediaInfo;
    buildCastInfo(mediaDescription, mediaInfo);

    std::lock_guard lockGuard(streamPlayerLock_);
    if (!streamPlayer_) {
        SLOGE("Set media info and start failed");
        return AVSESSION_ERROR;
    }
    std::shared_ptr<AVMediaDescription> originMediaDescription = nullptr;
    {
        std::lock_guard lockGuard(curItemLock_);
        originMediaDescription = currentAVQueueItem_.GetDescription();
    }
    if (originMediaDescription && originMediaDescription->GetMediaUri() != "http:" &&
        originMediaDescription->GetMediaId() == mediaInfo.mediaId) {
        CHECK_AND_RETURN_RET_LOG(streamPlayer_->Play() == AVSESSION_SUCCESS, AVSESSION_ERROR, "Set play failed");
    } else if (streamPlayer_->Play(mediaInfo) != AVSESSION_SUCCESS) {
        SLOGE("Set media info and start failed");
        return AVSESSION_ERROR;
    }
    RefreshCurrentAVQueueItem(avQueueItem);
    SLOGI("Set media info and start successfully");
    return AVSESSION_SUCCESS;
}

bool HwCastStreamPlayer::RepeatPrepare(std::shared_ptr<AVMediaDescription>& mediaDescription)
{
    bool hasIcon = false;
    {
        std::lock_guard lockGuard(curItemLock_);
        if (mediaDescription != nullptr &&  currentAVQueueItem_.GetDescription() != nullptr &&
            mediaDescription->GetIconUri() == "URI_CACHE" && mediaDescription->GetIcon() != nullptr) {
            currentAVQueueItem_.GetDescription()->SetIcon(mediaDescription->GetIcon());
            SLOGI("Repeat Prepare only setIcon");
            hasIcon = true;
        }
    }
    if (hasIcon && sessionCallbackForCastNtf_ && isPlayingState_) {
        sessionCallbackForCastNtf_(true, true);
    }
    return hasIcon;
}

int32_t HwCastStreamPlayer::Prepare(const AVQueueItem& avQueueItem)
{
    std::shared_ptr<AVMediaDescription> mediaDescription = avQueueItem.GetDescription();
    if (RepeatPrepare(mediaDescription)) {
        return AVSESSION_SUCCESS;
    }
    SLOGI("do Prepare with mediaId %{public}s | title %{public}s",
        mediaDescription->GetMediaId().c_str(), mediaDescription->GetTitle().c_str());

    CastEngine::MediaInfo mediaInfo;
    buildCastInfo(mediaDescription, mediaInfo);

    std::lock_guard lockGuard(streamPlayerLock_);
    SLOGI("pass playerlock, check item lock, mediaInfo mediaUrl and albumCoverUrl");
    if (streamPlayer_ && streamPlayer_->Load(mediaInfo) == AVSESSION_SUCCESS) {
        std::lock_guard lockGuard(curItemLock_);
        SLOGI("Set media info and prepare with curItemLock successed");
        currentAVQueueItem_ = avQueueItem;
        return AVSESSION_SUCCESS;
    }
    SLOGE("Set media info and prepare failed");
    return AVSESSION_ERROR;
}

void HwCastStreamPlayer::buildCastInfo(std::shared_ptr<AVMediaDescription>& mediaDescription,
    CastEngine::MediaInfo& mediaInfo)
{
    mediaInfo.mediaId = mediaDescription->GetMediaId();
    mediaInfo.mediaName = mediaDescription->GetTitle();
    mediaInfo.mediaUrl = mediaDescription->GetMediaUri();
    if (mediaDescription->GetMediaUri() == "") {
        if (mediaDescription->GetFdSrc().fd_ == 0) {
            SLOGW("No media id and fd src");
            mediaInfo.mediaUrl = "http:";
            mediaDescription->SetMediaUri("http:");
        } else {
            mediaInfo.mediaUrl = std::to_string(mediaDescription->GetFdSrc().fd_);
        }
    }
    mediaInfo.mediaType = mediaDescription->GetMediaType();
    mediaInfo.mediaSize = static_cast<uint32_t>(mediaDescription->GetMediaSize());
    mediaInfo.startPosition = static_cast<uint32_t>(mediaDescription->GetStartPosition());
    mediaInfo.duration = static_cast<uint32_t>(mediaDescription->GetDuration());
    SLOGI("mediaDescription duration is %{public}d", mediaDescription->GetDuration());
    mediaInfo.closingCreditsPosition = static_cast<uint32_t>(mediaDescription->GetCreditsPosition());
    mediaInfo.albumCoverUrl = mediaDescription->GetIconUri() == "" ?
        mediaDescription->GetAlbumCoverUri() : mediaDescription->GetIconUri();
    mediaInfo.albumTitle = mediaDescription->GetAlbumTitle();
    mediaInfo.mediaArtist = mediaDescription->GetArtist();
    mediaInfo.lrcUrl = mediaDescription->GetLyricUri();
    mediaInfo.lrcContent = mediaDescription->GetLyricContent();
    mediaInfo.appIconUrl = mediaDescription->GetIconUri();
    mediaInfo.appName = mediaDescription->GetAppName();
    mediaInfo.drmType = mediaDescription->GetDrmScheme();
    if (spid_.length() > 0 && mediaDescription->GetLaunchClientData().length() > 0) {
        mediaInfo.launchClientData = mediaDescription->GetLaunchClientData();
        mediaInfo.spid = spid_;
    }
    AVDataSrcDescriptor dataSrc = mediaDescription->GetDataSrc();
    SLOGI("has dataSrc hasCallback %{public}d", dataSrc.hasCallback);
    if (dataSrc.hasCallback) {
        if (castDataSrc_ == nullptr) {
            castDataSrc_ = std::make_shared<AVSession::HwCastDataSourceDescriptor>();
        }
        castDataSrc_->SetCallback(dataSrc.callback_);
        castDataSrc_->SetSize(dataSrc.fileSize);
        mediaInfo.mediaUrl = "/file";
        mediaInfo.dataSrc = castDataSrc_;
    }
    if (mediaDescription->GetPcmSrc() && mediaDescription->GetCastInfo() != nullptr) {
        uid_t appUid = mediaDescription->GetCastInfo()->GetAppUid();
        SLOGI("buildCastInfo AUDIO_PCM uid %{public}d", appUid);
        mediaInfo.appUid = appUid;
        mediaInfo.mediaType = "AUDIO_PCM";
    }
}

int32_t HwCastStreamPlayer::GetDuration(int32_t& duration)
{
    SLOGI("GetDuration begin");
    std::lock_guard lockGuard(streamPlayerLock_);
    if (!streamPlayer_) {
        SLOGE("streamPlayer is nullptr");
        return AVSESSION_ERROR;
    }
    streamPlayer_->GetDuration(duration);
    SLOGI("GetDuration successed");
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::GetCastAVPlaybackState(AVPlaybackState& avPlaybackState)
{
    SLOGI("GetCastAVPlaybackState begin");
    std::lock_guard lockGuard(streamPlayerLock_);
    if (!streamPlayer_) {
        SLOGE("streamPlayer is nullptr");
        return AVSESSION_ERROR;
    }
    CastEngine::PlayerStates castPlayerStates;
    streamPlayer_->GetPlayerStatus(castPlayerStates);
    if (castPlusStateToString_.count(castPlayerStates) != 0) {
        avPlaybackState.SetState(castPlusStateToString_[castPlayerStates]);
    }
    CastEngine::PlaybackSpeed castPlaybackSpeed;
    streamPlayer_->GetPlaySpeed(castPlaybackSpeed);
    if (castPlusSpeedToDouble_.count(castPlaybackSpeed) != 0) {
        avPlaybackState.SetSpeed(castPlusSpeedToDouble_[castPlaybackSpeed]);
    }
    int castPosition = 0;
    streamPlayer_->GetPosition(castPosition);
    AVPlaybackState::Position position;
    position.elapsedTime_ = static_cast<int64_t>(castPosition);
    avPlaybackState.SetPosition(position);
    CastEngine::LoopMode castLoopMode;
    streamPlayer_->GetLoopMode(castLoopMode);
    if (castPlusLoopModeToInt_.count(castLoopMode) != 0) {
        avPlaybackState.SetLoopMode(castPlusLoopModeToInt_[castLoopMode]);
    }
    int32_t castVolume = 0;
    int32_t maxCastVolume = 0;
    streamPlayer_->GetVolume(castVolume, maxCastVolume);
    avPlaybackState.SetVolume(castVolume);

    std::shared_ptr<AAFwk::WantParams> wantParams = std::make_shared<AAFwk::WantParams>();
    sptr<AAFwk::IInterface> intIt = AAFwk::Integer::Box(maxCastVolume);
    if (wantParams == nullptr || intIt == nullptr) {
        return AVSESSION_ERROR;
    }
    wantParams->SetParam("maxCastVolume", intIt);
    avPlaybackState.SetExtras(wantParams);

    SLOGI("GetCastAVPlaybackState successed with state: %{public}d", avPlaybackState.GetState());
    return AVSESSION_SUCCESS;
}

void HwCastStreamPlayer::GetMediaDecodeOfVideoFromCJSON(cJSON* videoValue)
{
    CHECK_AND_RETURN_LOG(videoValue != nullptr && !cJSON_IsInvalid(videoValue), "videoValue get invalid");
    if (cJSON_HasObjectItem(videoValue, decodeSupportResolutionStr_.c_str())) {
        cJSON* resolutionItem = cJSON_GetObjectItem(videoValue, decodeSupportResolutionStr_.c_str());
        CHECK_AND_RETURN_LOG(resolutionItem != nullptr && !cJSON_IsInvalid(resolutionItem), "resolution get invalid");
        std::vector<ResolutionLevel> resolutionLevels;
        std::map<std::string, std::vector<ResolutionLevel>> decodeToResolution;
        int num;
        if (cJSON_HasObjectItem(resolutionItem, decodeOfVideoHevcStr_.c_str())) {
            cJSON* decodeOfVideoHevcArray = cJSON_GetObjectItem(resolutionItem, decodeOfVideoHevcStr_.c_str());
            CHECK_AND_RETURN_LOG(decodeOfVideoHevcArray != nullptr && !cJSON_IsInvalid(decodeOfVideoHevcArray) &&
                cJSON_IsArray(decodeOfVideoHevcArray), "decodeOfVideoHevc get invalid");
            cJSON* valueItem = nullptr;
            cJSON_ArrayForEach(valueItem, decodeOfVideoHevcArray) {
                CHECK_AND_CONTINUE(valueItem != nullptr && !cJSON_IsInvalid(valueItem) && cJSON_IsNumber(valueItem));
                num = valueItem->valueint;
                SLOGI("decodeSupportResolution's video/hevc is %{public}d", num);
                resolutionLevels.emplace_back(static_cast<ResolutionLevel>(num));
            }
            decodeToResolution[decodeOfVideoHevcStr_] = resolutionLevels;
        }
        resolutionLevels.clear();
        if (cJSON_HasObjectItem(resolutionItem, decodeOfVideoAvcStr_.c_str())) {
            cJSON* decodeOfVideoAvcArray = cJSON_GetObjectItem(resolutionItem, decodeOfVideoAvcStr_.c_str());
            CHECK_AND_RETURN_LOG(decodeOfVideoAvcArray != nullptr && !cJSON_IsInvalid(decodeOfVideoAvcArray) &&
                cJSON_IsArray(decodeOfVideoAvcArray), "decodeOfVideoAvc get invalid");
            cJSON* valueItem = nullptr;
            cJSON_ArrayForEach(valueItem, decodeOfVideoAvcArray) {
                CHECK_AND_CONTINUE(valueItem != nullptr && !cJSON_IsInvalid(valueItem) && cJSON_IsNumber(valueItem));
                num = valueItem->valueint;
                SLOGI("decodeSupportResolution's video/avc is %{public}d", num);
                resolutionLevels.emplace_back(static_cast<ResolutionLevel>(num));
            }
            jsonCapabilitiesSptr_->decoderSupportResolutions_ = decodeToResolution;
        }
    } else {
        SLOGI("%{public}s of %{public}s no contains", videoStr_.c_str(), decodeSupportResolutionStr_.c_str());
    }
}

void HwCastStreamPlayer::GetMediaCapabilitiesOfVideo(cJSON* videoValue)
{
    CHECK_AND_RETURN_LOG(videoValue != nullptr && !cJSON_IsInvalid(videoValue), "videoValue get invalid");
    if (cJSON_HasObjectItem(videoValue, decodeTypeStr_.c_str())) {
        cJSON* decodeTypeArray = cJSON_GetObjectItem(videoValue, decodeTypeStr_.c_str());
        CHECK_AND_RETURN_LOG(decodeTypeArray != nullptr && !cJSON_IsInvalid(decodeTypeArray) &&
            cJSON_IsArray(decodeTypeArray), "decodeType get invalid");
        cJSON* decodeTypeItem = nullptr;
        cJSON_ArrayForEach(decodeTypeItem, decodeTypeArray) {
            CHECK_AND_CONTINUE(decodeTypeItem != nullptr && !cJSON_IsInvalid(decodeTypeItem) &&
                cJSON_IsString(decodeTypeItem));
            std::string str(decodeTypeItem->valuestring);
            SLOGI("get %{public}s is %{public}s", decodeTypeStr_.c_str(), str.c_str());
            jsonCapabilitiesSptr_->decoderTypes_.emplace_back(str);
        }
    }

    GetMediaDecodeOfVideoFromCJSON(videoValue);

    if (cJSON_HasObjectItem(videoValue, hdrFormatStr_.c_str())) {
        cJSON* hdrFormatArray = cJSON_GetObjectItem(videoValue, hdrFormatStr_.c_str());
        CHECK_AND_RETURN_LOG(hdrFormatArray != nullptr && !cJSON_IsInvalid(hdrFormatArray) &&
            cJSON_IsArray(hdrFormatArray), "hdrFormat get invalid");
        cJSON* hdrFormatItem = nullptr;
        cJSON_ArrayForEach(hdrFormatItem, hdrFormatArray) {
            CHECK_AND_CONTINUE(hdrFormatItem != nullptr && !cJSON_IsInvalid(hdrFormatItem) &&
                cJSON_IsNumber(hdrFormatItem));
            int num = hdrFormatItem->valueint;
            SLOGI("get %{public}s is %{public}d", hdrFormatStr_.c_str(), num);
            jsonCapabilitiesSptr_->hdrFormats_.emplace_back(static_cast<HDRFormat>(num));
        }
    } else {
        SLOGI("%{public}s of %{public}s no contains", videoStr_.c_str(), hdrFormatStr_.c_str());
    }
}

void HwCastStreamPlayer::GetMediaCapabilitiesOfAudio(cJSON* audioValue)
{
    CHECK_AND_RETURN_LOG(audioValue != nullptr && !cJSON_IsInvalid(audioValue), "audioValue get invalid");
    if (cJSON_HasObjectItem(audioValue, decodeTypeStr_.c_str())) {
        cJSON* decodeTypeItem = cJSON_GetObjectItem(audioValue, decodeTypeStr_.c_str());
        CHECK_AND_RETURN_LOG(decodeTypeItem != nullptr && !cJSON_IsInvalid(decodeTypeItem) &&
            cJSON_IsString(decodeTypeItem), "decodeType str get invalid");
        std::string str(decodeTypeItem->valuestring);
        SLOGI("%{public}s of %{public}s", decodeTypeStr_.c_str(), str.c_str());
        jsonCapabilitiesSptr_->decoderTypes_.emplace_back(str);
    }
}

void HwCastStreamPlayer::ClearJsonCapabilities()
{
    SLOGI("enter ClearJsonCapabilities");
    jsonCapabilitiesSptr_->decoderTypes_.clear();
    jsonCapabilitiesSptr_->hdrFormats_.clear();
    jsonCapabilitiesSptr_->playSpeeds_.clear();
    jsonCapabilitiesSptr_->decoderSupportResolutions_.clear();
}

int32_t HwCastStreamPlayer::GetMediaCapabilities()
{
    SLOGI("GetMediaCapabilities begin");
    std::lock_guard lockGuard(streamPlayerLock_);
    CHECK_AND_RETURN_RET_LOG(streamPlayer_, AVSESSION_ERROR, "streamPlayer_ is nullptr");
    CHECK_AND_RETURN_RET_LOG(jsonCapabilitiesSptr_, AVSESSION_ERROR, "jsonCapabilitiesSptr_ is nullptr");
    std::string supportCapabilities;
    ClearJsonCapabilities();
    streamPlayer_->GetMediaCapabilities(supportCapabilities);

    cJSON* valueItem = cJSON_Parse(supportCapabilities.c_str());
    CHECK_AND_RETURN_RET_LOG(valueItem != nullptr, AVSESSION_ERROR, "supportCapabilities is nullptr");
    if (cJSON_IsInvalid(valueItem)) {
        SLOGE("supportCapabilities is invalid");
        cJSON_Delete(valueItem);
        return AVSESSION_ERROR;
    }
    if (cJSON_HasObjectItem(valueItem, videoStr_.c_str())) {
        cJSON* videoItem = cJSON_GetObjectItem(valueItem, videoStr_.c_str());
        GetMediaCapabilitiesOfVideo(videoItem);
    } else if (cJSON_HasObjectItem(valueItem, audioStr_.c_str())) {
        cJSON* audioItem = cJSON_GetObjectItem(valueItem, audioStr_.c_str());
        GetMediaCapabilitiesOfAudio(audioItem);
    }

    if (cJSON_HasObjectItem(valueItem, speedStr_.c_str())) {
        cJSON* speedArray = cJSON_GetObjectItem(valueItem, speedStr_.c_str());
        CHECK_AND_RETURN_RET_LOG(speedArray != nullptr && !cJSON_IsInvalid(speedArray) &&
            cJSON_IsArray(speedArray), AVSESSION_ERROR, "speed get invalid");
        cJSON* speedItem = nullptr;
        cJSON_ArrayForEach(speedItem, speedArray) {
            CHECK_AND_CONTINUE(speedItem != nullptr && !cJSON_IsInvalid(speedItem) &&
                cJSON_IsNumber(speedItem));
            CastEngine::PlaybackSpeed num = static_cast<CastEngine::PlaybackSpeed>(speedItem->valueint);
            SLOGI("support play speed is %{public}f", castPlusSpeedToDouble_[num]);
            jsonCapabilitiesSptr_->playSpeeds_.emplace_back(castPlusSpeedToDouble_[num]);
        }
    }
    cJSON_Delete(valueItem);
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::GetSupportedDecoders(std::vector<std::string>& decoderTypes)
{
    SLOGI("enter GetSupportedDecoders");
    std::lock_guard lockGuard(streamPlayerLock_);
    CHECK_AND_RETURN_RET_LOG(jsonCapabilitiesSptr_, AVSESSION_ERROR, "jsonCapabilitiesSptr_ is nullptr");
    if (jsonCapabilitiesSptr_->decoderTypes_.empty()) {
        GetMediaCapabilities();
    }
    decoderTypes = jsonCapabilitiesSptr_->decoderTypes_;
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::GetRecommendedResolutionLevel(std::string& decoderType, ResolutionLevel& resolutionLevel)
{
    SLOGI("enter GetRecommendedResolutionLevel");
    std::lock_guard lockGuard(streamPlayerLock_);
    CHECK_AND_RETURN_RET_LOG(jsonCapabilitiesSptr_, AVSESSION_ERROR, "jsonCapabilitiesSptr_ is nullptr");
    if (jsonCapabilitiesSptr_->decoderSupportResolutions_.empty()) {
        GetMediaCapabilities();
    }
    auto it = jsonCapabilitiesSptr_->decoderSupportResolutions_.find(decoderType);
    if (it != jsonCapabilitiesSptr_->decoderSupportResolutions_.end()) {
        std::vector<ResolutionLevel> resolutionLevels = jsonCapabilitiesSptr_->decoderSupportResolutions_[decoderType];
        auto maxResolutionLevel = *std::max_element(resolutionLevels.begin(), resolutionLevels.end());
        SLOGI("find %{public}s map to %{public}d", decoderType.c_str(), maxResolutionLevel);
        resolutionLevel = static_cast<ResolutionLevel>(maxResolutionLevel);
    } else {
        SLOGI("no find %{public}s map to resolutionLevel", decoderType.c_str());
        return  AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::GetSupportedHdrCapabilities(std::vector<HDRFormat>& hdrFormats)
{
    SLOGI("enter GetSupportedHdrCapabilities");
    std::lock_guard lockGuard(streamPlayerLock_);
    CHECK_AND_RETURN_RET_LOG(jsonCapabilitiesSptr_, AVSESSION_ERROR, "jsonCapabilitiesSptr_ is nullptr");
    if (jsonCapabilitiesSptr_->hdrFormats_.empty()) {
        GetMediaCapabilities();
    }
    hdrFormats = jsonCapabilitiesSptr_->hdrFormats_;
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::GetSupportedPlaySpeeds(std::vector<float>& playSpeeds)
{
    SLOGI("enter GetSupportedPlaySpeeds");
    std::lock_guard lockGuard(streamPlayerLock_);
    CHECK_AND_RETURN_RET_LOG(jsonCapabilitiesSptr_, AVSESSION_ERROR, "jsonCapabilitiesSptr_ is nullptr");
    if (jsonCapabilitiesSptr_->playSpeeds_.empty()) {
        GetMediaCapabilities();
    }
    playSpeeds = jsonCapabilitiesSptr_->playSpeeds_;
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::SetDisplaySurface(std::string &surfaceId)
{
    SLOGI("SetDisplaySurface begin");
    std::lock_guard lockGuard(streamPlayerLock_);
    if (!streamPlayer_) {
        SLOGE("streamPlayer is nullptr");
        return AVSESSION_ERROR;
    }
    streamPlayer_->SetSurface(surfaceId);
    SLOGI("SetDisplaySurface successed");
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::ProcessMediaKeyResponse(const std::string& assetId, const std::vector<uint8_t>& response)
{
    SLOGI("ProcessMediaKeyResponse begin");
    std::lock_guard lockGuard(streamPlayerLock_);
    if (!streamPlayer_) {
        SLOGE("streamPlayer is nullptr");
        return AVSESSION_ERROR;
    }
    streamPlayer_->ProvideKeyResponse(assetId, response);
    SLOGI("ProcessMediaKeyResponse successed");
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::RegisterControllerListener(std::shared_ptr<IAVCastControllerProxyListener> listener)
{
    SLOGI("RegisterControllerListener begin");
    if (listener == nullptr) {
        SLOGE("RegisterControllerListener failed for the listener is nullptr");
        return AVSESSION_ERROR;
    }

    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    if (find(streamPlayerListenerList_.begin(), streamPlayerListenerList_.end(), listener)
        != streamPlayerListenerList_.end()) {
        SLOGE("listener is already in streamPlayerListenerList_");
        return AVSESSION_ERROR;
    }
    SLOGI("RegisterControllerListener successed, and add it to streamPlayerListenerList_");
    streamPlayerListenerList_.emplace_back(listener);
    SLOGI("RegisterControllerListener done with size %{public}d", static_cast<int>(streamPlayerListenerList_.size()));
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::UnRegisterControllerListener(std::shared_ptr<IAVCastControllerProxyListener> listener)
{
    if (listener == nullptr) {
        SLOGE("UnRegisterCastSessionStateListener failed for the listener is nullptr");
        return AVSESSION_ERROR;
    }

    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto iter = streamPlayerListenerList_.begin(); iter != streamPlayerListenerList_.end();) {
        if (*iter == listener) {
            streamPlayerListenerList_.erase(iter);
            SLOGI("UnRegisterControllerListener successed, and erase it from streamPlayerListenerList_");
            return AVSESSION_SUCCESS;
        } else {
            ++iter;
        }
    }
    SLOGE("listener is not found in streamPlayerListenerList_, so UnRegisterControllerListener failed");

    return AVSESSION_ERROR;
}

int32_t HwCastStreamPlayer::GetValidAbility(std::vector<int32_t>& validCmdList)
{
    SLOGI("GetValidAbility in");
    if (streamPlayer_ == nullptr) {
        SLOGE("streamPlayer is nullptr");
        return AVSESSION_ERROR;
    }
    CastEngine::StreamCapability streamCapability;
    streamPlayer_->GetAvailableCapability(streamCapability);
    checkCmdsFromAbility(streamCapability, validCmdList);
    return AVSESSION_SUCCESS;
}

int32_t HwCastStreamPlayer::SetValidAbility(const std::vector<int32_t>& validCmdList)
{
    SLOGI("SetValidAbility begin");
    if (streamPlayer_ == nullptr) {
        SLOGE("streamPlayer is nullptr");
        return AVSESSION_ERROR;
    }
    CastEngine::StreamCapability streamCapability;
    checkAbilityFromCmds(validCmdList, streamCapability);
    streamPlayer_->SetAvailableCapability(streamCapability);
    return AVSESSION_SUCCESS;
}

void HwCastStreamPlayer::SetSessionCallbackForCastCap(const std::function<void(bool, bool)>& callback)
{
    sessionCallbackForCastNtf_ = callback;
}

void HwCastStreamPlayer::CheckIfCancelCastCapsule()
{
    isPlayingState_ = false;
    AVSessionEventHandler::GetInstance().AVSessionRemoveTask("CancelCastCapsule");
    AVSessionEventHandler::GetInstance().AVSessionPostTask(
        [this]() {
            if (sessionCallbackForCastNtf_ && !isPlayingState_) {
                SLOGI("MediaCapsule delCastCapsule isPlayingState_ %{public}d", isPlayingState_);
                sessionCallbackForCastNtf_(false, false);
            }
        }, "CancelCastCapsule", cancelTimeout);
}

void HwCastStreamPlayer::OnStateChanged(const CastEngine::PlayerStates playbackState, bool isPlayWhenReady)
{
    AVPlaybackState avCastPlaybackState;
    if (castPlusStateToString_.count(playbackState) == 0) {
        SLOGE("current playbackState status is not exist in castPlusStateToString_");
        avCastPlaybackState.SetState(AVPlaybackState::PLAYBACK_STATE_ERROR);
    } else {
        SLOGD("On state changed, get state %{public}d", castPlusStateToString_[playbackState]);
        avCastPlaybackState.SetState(castPlusStateToString_[playbackState]);
    }
    if (avCastPlaybackState.GetState() == AVPlaybackState::PLAYBACK_STATE_PLAY) {
        // play state try notify cast notification
        isPlayingState_ = true;
        if (sessionCallbackForCastNtf_) {
            SLOGI("MediaCapsule addCastCapsule");
            sessionCallbackForCastNtf_(true, false);
        }
    } else {
        CheckIfCancelCastCapsule();
    }
    RefreshCurrentItemDuration();
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnCastPlaybackStateChange for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
    SLOGI("onCastStateChange with duration");
}

void HwCastStreamPlayer::OnPositionChanged(int position, int bufferPosition, int duration)
{
    if (position == -1 && bufferPosition == -1 && duration == -1) { // -1 is invalid(default) value
        SLOGW("Invalid position change callback");
        return;
    }
    AVPlaybackState avCastPlaybackState;
    if (position != -1) { // -1 is invalid position
        AVPlaybackState::Position castPosition;
        castPosition.elapsedTime_ = position;
        avCastPlaybackState.SetPosition(castPosition);
        SLOGD("Received elapsedTime: %{public}d", position);
    }
    if (bufferPosition != -1) { // -1 is invalid buffer position
        avCastPlaybackState.SetBufferedTime(bufferPosition);
        SLOGD("Received bufferPosition: %{public}d", bufferPosition);
    }
    if (duration != -1) {
        std::shared_ptr<AAFwk::WantParams> wantParams = std::make_shared<AAFwk::WantParams>();
        sptr<AAFwk::IInterface> intIt = AAFwk::Integer::Box(duration);
        wantParams->SetParam("duration", intIt);
        avCastPlaybackState.SetExtras(wantParams);
        SLOGD("Received duration: %{public}d", duration);
    }
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGD("trigger the OnPositionChange");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
    SLOGI("on cast position change done");
}

void HwCastStreamPlayer::OnMediaItemChanged(const CastEngine::MediaInfo& mediaInfo)
{
    SLOGD("Stream player received mediaItemChanged event");
    std::shared_ptr<AVMediaDescription> mediaDescription = std::make_shared<AVMediaDescription>();
    mediaDescription->SetMediaId(mediaInfo.mediaId);
    mediaDescription->SetTitle(mediaInfo.mediaName);
    mediaDescription->SetMediaUri(mediaInfo.mediaUrl);
    mediaDescription->SetMediaType(mediaInfo.mediaType);
    mediaDescription->SetMediaSize(mediaInfo.mediaSize);
    mediaDescription->SetStartPosition(static_cast<uint32_t>(mediaInfo.startPosition));
    mediaDescription->SetDuration(static_cast<uint32_t>(mediaInfo.duration));
    mediaDescription->SetCreditsPosition(static_cast<int32_t>(mediaInfo.closingCreditsPosition));
    mediaDescription->SetAlbumCoverUri(mediaInfo.albumCoverUrl);
    mediaDescription->SetAlbumTitle(mediaInfo.albumTitle);
    mediaDescription->SetArtist(mediaInfo.mediaArtist);
    mediaDescription->SetLyricUri(mediaInfo.lrcUrl);
    mediaDescription->SetLyricContent(mediaInfo.lrcContent);
    mediaDescription->SetIconUri(mediaInfo.appIconUrl);
    mediaDescription->SetAppName(mediaInfo.appName);
    mediaDescription->SetDrmScheme(mediaInfo.drmType);
    std::shared_ptr<AVMediaDescription> originMediaDescription = nullptr;
    {
        std::lock_guard lockGuard(curItemLock_);
        originMediaDescription = currentAVQueueItem_.GetDescription();
    }
    if (originMediaDescription != nullptr && originMediaDescription->GetIcon() != nullptr
        && mediaInfo.mediaId == originMediaDescription->GetMediaId()) {
        SLOGI("cacheMedia:%{public}s", originMediaDescription->GetMediaId().c_str());
        mediaDescription->SetIcon(originMediaDescription->GetIcon());
    }
    AVQueueItem queueItem;
    queueItem.SetDescription(mediaDescription);
    {
        std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
        for (auto listener : streamPlayerListenerList_) {
            if (listener != nullptr) {
                SLOGI("trigger the OnMediaItemChange for registered listeners");
                listener->OnMediaItemChange(queueItem);
            }
        }
    }
    {
        std::lock_guard lockGuard(curItemLock_);
        currentAVQueueItem_ = queueItem;
    }

    SLOGI("StreamPlayer received mediaItemChanged event done");
}

void HwCastStreamPlayer::OnNextRequest()
{
    SLOGD("StreamPlayer received next request");
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPlayNext for registered listeners");
            listener->OnPlayNext();
        }
    }
    SLOGI("StreamPlayer received next request done");
}

void HwCastStreamPlayer::OnPreviousRequest()
{
    SLOGD("StreamPlayer received previous request");
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPlayPrevious for registered listeners");
            listener->OnPlayPrevious();
        }
    }
    SLOGI("StreamPlayer received previous request done");
}

void HwCastStreamPlayer::OnVolumeChanged(int volume, int maxVolume)
{
    SLOGD("StreamPlayer received volume changed event: %{public}d", volume);
    AVPlaybackState avCastPlaybackState;
    avCastPlaybackState.SetVolume(volume);

    std::shared_ptr<AAFwk::WantParams> wantParams = std::make_shared<AAFwk::WantParams>();
    sptr<AAFwk::IInterface> intIt = AAFwk::Integer::Box(maxVolume);
    if (wantParams == nullptr || intIt == nullptr) {
        return;
    }
    wantParams->SetParam("maxCastVolume", intIt);
    avCastPlaybackState.SetExtras(wantParams);

    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnVolumeChanged for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
    SLOGI("StreamPlayer received volume changed event done: %{public}d", volume);
}

void HwCastStreamPlayer::OnLoopModeChanged(const CastEngine::LoopMode loopMode)
{
    AVPlaybackState avCastPlaybackState;
    if (castPlusLoopModeToInt_.count(loopMode) == 0) {
        SLOGE("current playbackState status is not exist in castPlusStateToString_");
    } else {
        SLOGD("StreamPlayer received loop mode changed event: %{public}d", castPlusLoopModeToInt_[loopMode]);
        avCastPlaybackState.SetLoopMode(castPlusLoopModeToInt_[loopMode]);
    }
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnLoopModeChanged for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
    SLOGI("loop mode changed event done: %{public}d", castPlusLoopModeToInt_[loopMode]);
}

void HwCastStreamPlayer::OnPlaySpeedChanged(const CastEngine::PlaybackSpeed speed)
{
    AVPlaybackState avCastPlaybackState;
    if (castPlusSpeedToDouble_.count(speed) == 0) {
        SLOGE("current speed is not exist in castPlusSpeedToDouble_");
        return;
    }
    SLOGD("StreamPlayer received play speed changed event: %{public}f", castPlusSpeedToDouble_[speed]);
    avCastPlaybackState.SetSpeed(castPlusSpeedToDouble_[speed]);
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPlaySpeedChanged for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
    SLOGI("play speed changed event done: %{public}f", castPlusSpeedToDouble_[speed]);
}

void HwCastStreamPlayer::OnPlayerError(int errorCode, const std::string &errorMsg)
{
    SLOGD("StreamPlayer received error event, code: %{public}d, message: %{public}s", errorCode, errorMsg.c_str());
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPlayerError for registered listeners");
            listener->OnPlayerError(errorCode, errorMsg);
        }
    }
    SLOGI("error event done, code: %{public}d, message: %{public}s", errorCode, errorMsg.c_str());
}

void HwCastStreamPlayer::OnSeekDone(int32_t seekNumber)
{
    SLOGD("StreamPlayer received seek done event: %{public}d", seekNumber);
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnSeekDone for registered listeners");
            listener->OnSeekDone(seekNumber);
        }
    }
    SLOGI("StreamPlayer received seek done event done with: %{public}d", seekNumber);
}

void HwCastStreamPlayer::OnVideoSizeChanged(int width, int height)
{
    SLOGD("StreamPlayer received video size change event, width: %{public}d, height: %{public}d", width, height);
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnVideoSizeChange for registered listeners");
            listener->OnVideoSizeChange(width, height);
        }
    }
    SLOGI("video size change event done, width: %{public}d, height: %{public}d", width, height);
}

void HwCastStreamPlayer::OnEndOfStream(int isLooping)
{
    SLOGD("Received EndOfStream callback, value is %{public}d", isLooping);
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnEndOfStream for registered listeners");
            listener->OnEndOfStream(isLooping);
        }
    }

    AVPlaybackState avCastPlaybackState;
    std::shared_ptr<AAFwk::WantParams> wantParams = std::make_shared<AAFwk::WantParams>();
    sptr<AAFwk::IInterface> intIt = AAFwk::Integer::Box(isLooping);
    if (wantParams == nullptr || intIt == nullptr) {
        return;
    }
    wantParams->SetParam("endofstream", intIt);
    avCastPlaybackState.SetExtras(wantParams);
    SLOGD("Received end of stream event: %{public}d", isLooping);

    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnEndOfStream for registered listeners");
            listener->OnCastPlaybackStateChange(avCastPlaybackState);
        }
    }
    SLOGI("Received EndOfStream callback done, value is %{public}d", isLooping);
}

void HwCastStreamPlayer::OnPlayRequest(const CastEngine::MediaInfo& mediaInfo)
{
    SLOGI("Stream player received PlayRequest event");
    std::shared_ptr<AVMediaDescription> mediaDescription = std::make_shared<AVMediaDescription>();
    mediaDescription->SetMediaId(mediaInfo.mediaId);
    mediaDescription->SetTitle(mediaInfo.mediaName);
    mediaDescription->SetMediaUri(mediaInfo.mediaUrl);
    mediaDescription->SetMediaType(mediaInfo.mediaType);
    mediaDescription->SetMediaSize(mediaInfo.mediaSize);
    mediaDescription->SetStartPosition(static_cast<uint32_t>(mediaInfo.startPosition));
    mediaDescription->SetDuration(static_cast<uint32_t>(mediaInfo.duration));
    mediaDescription->SetCreditsPosition(static_cast<int32_t>(mediaInfo.closingCreditsPosition));
    mediaDescription->SetAlbumCoverUri(mediaInfo.albumCoverUrl);
    mediaDescription->SetAlbumTitle(mediaInfo.albumTitle);
    mediaDescription->SetArtist(mediaInfo.mediaArtist);
    mediaDescription->SetLyricUri(mediaInfo.lrcUrl);
    mediaDescription->SetLyricContent(mediaInfo.lrcContent);
    mediaDescription->SetIconUri(mediaInfo.appIconUrl);
    mediaDescription->SetAppName(mediaInfo.appName);
    mediaDescription->SetDrmScheme(mediaInfo.drmType);
    AVQueueItem queueItem;
    queueItem.SetDescription(mediaDescription);
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnPlayRequest for registered listeners");
            listener->OnPlayRequest(queueItem);
        }
    }
    SLOGI("Stream player received PlayRequest event done");
}

void HwCastStreamPlayer::OnImageChanged(std::shared_ptr<Media::PixelMap> pixelMap)
{
    SLOGD("Stream player received ImageChanged event");
}

void HwCastStreamPlayer::OnData(const CastEngine::DataType dataType, const std::string& dataStr)
{
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            AAFwk::WantParams data;
            data.SetParam("customData", AAFwk::String::Box(dataStr));
            listener->OnCustomData(data);
        }
    }
}

void HwCastStreamPlayer::OnAlbumCoverChanged(std::shared_ptr<Media::PixelMap> pixelMap)
{
    SLOGI("Received AlbumCoverChanged callback");
    if (pixelMap == nullptr) {
        SLOGE("Invalid pixelMap null");
        return;
    }
    std::shared_ptr<AVSessionPixelMap> innerPixelMap =
        AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap);
    if (innerPixelMap == nullptr) {
        SLOGE("Invalid innerPixelMap null");
        return;
    }

    std::shared_ptr<AVMediaDescription> mediaDescription = nullptr;
    {
        std::lock_guard lockGuard(curItemLock_);
        mediaDescription = currentAVQueueItem_.GetDescription();
    }
    if (mediaDescription == nullptr) {
        SLOGE("OnAlbumCoverChanged with nullptr mediaDescription, return with default");
        return;
    }
    mediaDescription->SetIcon(innerPixelMap);
    AVQueueItem queueItem;
    queueItem.SetDescription(mediaDescription);
    {
        std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
        for (auto listener : streamPlayerListenerList_) {
            if (listener != nullptr) {
                SLOGI("trigger the OnMediaItemChange for registered listeners on Album change");
                listener->OnMediaItemChange(queueItem);
            }
        }
    }
    {
        std::lock_guard lockGuard(curItemLock_);
        currentAVQueueItem_ = queueItem;
    }
    SLOGI("Received AlbumCoverChanged callback done");
}

void HwCastStreamPlayer::OnAvailableCapabilityChanged(const CastEngine::StreamCapability &streamCapability)
{
    SLOGE("Received OnAvailableCapabilityChanged callback");
    std::vector<int32_t> supportedCastCmds;
    checkCmdsFromAbility(streamCapability, supportedCastCmds);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnValidCommandChange for registered listeners");
            listener->OnValidCommandChange(supportedCastCmds);
        }
    }
}

void HwCastStreamPlayer::OnKeyRequest(const std::string& assetId, const std::vector<uint8_t>& keyRequestData)
{
    SLOGD("Stream player received keyRequest event");
    std::lock_guard playerListLockGuard(streamPlayerListenerListLock_);
    for (auto listener : streamPlayerListenerList_) {
        if (listener != nullptr) {
            SLOGI("trigger the OnKeyRequest for registered listeners");
            listener->OnKeyRequest(assetId, keyRequestData);
        }
    }
    SLOGI("Stream player received keyRequest event done");
}

void HwCastStreamPlayer::checkCmdsFromAbility(
    const CastEngine::StreamCapability& streamCapability, std::vector<int32_t>& supportedCastCmds)
{
    if (streamCapability.isPlaySupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PLAY);
    }
    if (streamCapability.isPauseSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PAUSE);
    }
    if (streamCapability.isStopSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_STOP);
    }
    if (streamCapability.isNextSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT);
    }
    if (streamCapability.isPreviousSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS);
    }
    if (streamCapability.isSeekSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_SEEK);
    }
    if (streamCapability.isFastForwardSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD);
    }
    if (streamCapability.isFastRewindSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_REWIND);
    }
    if (streamCapability.isLoopModeSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_SET_LOOP_MODE);
    }
    if (streamCapability.isSetVolumeSupported) {
        supportedCastCmds.push_back(AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME);
    }
}

void HwCastStreamPlayer::checkAbilityFromCmds(
    const std::vector<int32_t>& supportedCastCmds, CastEngine::StreamCapability& streamCapability)
{
    for (const int32_t cmd : supportedCastCmds) {
        switch (cmd) {
            case AVCastControlCommand::CAST_CONTROL_CMD_PLAY:
                streamCapability.isPlaySupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_PAUSE:
                streamCapability.isPauseSupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_STOP:
                streamCapability.isStopSupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT:
                streamCapability.isNextSupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS:
                streamCapability.isPreviousSupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_SEEK:
                streamCapability.isSeekSupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_FAST_FORWARD:
                streamCapability.isFastForwardSupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_REWIND:
                streamCapability.isFastRewindSupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_SET_LOOP_MODE:
                streamCapability.isLoopModeSupported = true;
                break;
            case AVCastControlCommand::CAST_CONTROL_CMD_SET_VOLUME:
                streamCapability.isSetVolumeSupported = true;
                break;
            default:
                break;
        }
    }
    streamCapability.isToggleFavoriteSupported = false;
}
} // namespace OHOS::AVSession
