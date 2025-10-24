/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef LOG_TAG
#define LOG_TAG "AVCastControllerImpl"
#endif

#include "taihe_avcast_controller.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_radar.h"
#include "avsession_trace.h"
#include "pixel_map.h"
#include "avsession_pixel_map_adapter.h"
#include "avsession_event_handler.h"
#include "taihe_avsession_manager.h"
#include "taihe_cast_control_command.h"
#include "taihe_queue_item.h"
#include "taihe_utils.h"
#include "taihe_playback_state.h"

namespace ANI::AVSession {
std::set<std::string> AVCastControllerImpl::eventHandlers_ = {
    "playbackStateChange",
    "mediaItemChange",
    "playNext",
    "playPrevious",
    "requestPlay",
    "seekDone",
    "validCommandChange",
    "videoSizeChange",
    "error",
    "castControlGenericError",
    "castControlIoError",
    "castControlParsingError",
    "castControlDecodingError",
    "castControlAudioRendererError",
    "castControlDrmError",
    "endOfStream",
    "requestPlay",
    "keyRequest",
    "customDataChange",
};

static const int32_t ERROR = -1;

AVCastControllerImpl::AVCastControllerImpl()
{
    SLOGI("AVCastControllerImpl construct");
}

AVCastControllerImpl::AVCastControllerImpl(std::shared_ptr<OHOS::AVSession::AVCastController> &nativeController)
{
    if (nativeController != nullptr) {
        castController_ = std::move(nativeController);
    }
}

AVCastControllerImpl::~AVCastControllerImpl()
{
    SLOGI("AVCastControllerImpl destroy");
}

int32_t AVCastControllerImpl::NewInstance(std::shared_ptr<OHOS::AVSession::AVCastController> &nativeController,
    AVCastController &out)
{
    CHECK_RETURN(nativeController != nullptr, "get native cast controller failed", OHOS::AVSession::AVSESSION_ERROR);
    out = make_holder<AVCastControllerImpl, AVCastController>(nativeController);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

void AVCastControllerImpl::ReportStartFailInfo(int32_t error)
{
    OHOS::AVSession::AVSessionRadarInfo info("AVCastControllerImpl::Start");
    info.errorCode_ = OHOS::AVSession::AVSessionRadar::GetRadarErrorCode(error);
    OHOS::AVSession::AVSessionRadar::GetInstance().StartPlayFailed(info);
}

void AVCastControllerImpl::ReportSendControlCommandFailInfo(int32_t error)
{
    OHOS::AVSession::AVSessionRadarInfo info("AVCastControllerImpl::SendControlCommand");
    info.errorCode_ = OHOS::AVSession::AVSessionRadar::GetRadarErrorCode(error);
    OHOS::AVSession::AVSessionRadar::GetInstance().FailToSendControlCommand(info);
}

std::string AVCastControllerImpl::GetSendControlCommandErrMsg(int32_t error)
{
    std::string msg;
    switch (error) {
        case OHOS::AVSession::ERR_SESSION_NOT_EXIST:
            msg = "SendControlCommand failed : native session not exist";
            break;
        case OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST:
            msg = "SendControlCommand failed : native controller not exist";
            break;
        case OHOS::AVSession::ERR_SESSION_DEACTIVE:
            msg = "SendControlCommand failed : native session is not active";
            break;
        case OHOS::AVSession::ERR_NO_PERMISSION:
            msg = "SendControlCommand failed : native no permission";
            break;
        case OHOS::AVSession::ERR_COMMAND_NOT_SUPPORT:
            msg = "SendControlCommand failed : native command not support";
            break;
        case OHOS::AVSession::ERR_COMMAND_SEND_EXCEED_MAX:
            msg = "SendControlCommand failed : native command send nums overload";
            break;
        default:
            msg = "SendControlCommand failed : native server exception";
            break;
    }
    return msg;
}

void AVCastControllerImpl::SetDisplaySurfaceSync(string_view surfaceId)
{
    if (castController_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "SetDisplaySurfaceSync failed : cast controller is nullptr");
        return;
    }
    std::string surfaceId_;
    if (TaiheUtils::GetString(surfaceId, surfaceId_) != OHOS::AVSession::AVSESSION_SUCCESS || surfaceId_.empty()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SetDisplaySurfaceSync failed : invalid surfaceId");
        return;
    }
    int32_t ret = castController_->SetDisplaySurface(surfaceId_);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "SetDisplaySurfaceSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "SetDisplaySurfaceSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "SetDisplaySurfaceSync failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "SetDisplaySurfaceSync failed : native no permission";
        } else if (ret == OHOS::AVSession::ERR_SESSION_DEACTIVE) {
            errMessage = "SetDisplaySurfaceSync failed : native session is not active";
        } else if (ret == OHOS::AVSession::ERR_COMMAND_NOT_SUPPORT) {
            errMessage = "SetDisplaySurfaceSync failed : native command not support";
        } else if (ret == OHOS::AVSession::ERR_COMMAND_SEND_EXCEED_MAX) {
            errMessage = "SetDisplaySurfaceSync failed : native command send nums overload";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

array<DecoderType> AVCastControllerImpl::GetSupportedDecodersSync()
{
    array<DecoderType> undefinedArray{};
    if (castController_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetSupportedDecodersSync failed : cast controller is nullptr");
        return undefinedArray;
    }
    std::vector<std::string> decoderTypes;
    int32_t ret = castController_->GetSupportedDecoders(decoderTypes);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetSupportedDecodersSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetSupportedDecodersSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetSupportedDecodersSync failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetSupportedDecodersSync failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return undefinedArray;
    }
    array<DecoderType> output = TaiheUtils::ToTaiheDecoderTypeArray(decoderTypes);
    return output;
}

ResolutionLevel AVCastControllerImpl::GetRecommendedResolutionLevelSync(DecoderType decoderType)
{
    ResolutionLevel undefinedLevel = ResolutionLevel::from_value(static_cast<int32_t>(ERROR));
    if (castController_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetRecommendedResolutionLevelSync failed : cast controller is nullptr");
        return undefinedLevel;
    }
    std::string decoderTypeStr = decoderType.get_value();
    OHOS::AVSession::ResolutionLevel resolutionLevel;
    int32_t ret = castController_->GetRecommendedResolutionLevel(decoderTypeStr, resolutionLevel);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetRecommendedResolutionLevelSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetRecommendedResolutionLevelSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetRecommendedResolutionLevelSync failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetRecommendedResolutionLevelSync failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return undefinedLevel;
    }
    return ResolutionLevel::from_value(static_cast<int32_t>(resolutionLevel));
}

array<uintptr_t> AVCastControllerImpl::GetSupportedHdrCapabilitiesSync()
{
    array<uintptr_t> undefinedArray {};
    if (castController_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetSupportedHdrCapabilitiesSync failed : cast controller is nullptr");
        return undefinedArray;
    }
    std::vector<OHOS::AVSession::HDRFormat> hdrFormats;
    int32_t ret = castController_->GetSupportedHdrCapabilities(hdrFormats);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetSupportedHdrCapabilitiesSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetSupportedHdrCapabilitiesSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetSupportedHdrCapabilitiesSync failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetSupportedHdrCapabilitiesSync failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return undefinedArray;
    }

    std::vector<uintptr_t> outHdrFormats;
    for (const auto &format : hdrFormats) {
        ani_enum_item aniEnumItem {};
        if (!TaiheAVSessionEnum::ToAniEnumHDRFormat(format, aniEnumItem)) {
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
                "GetSupportedHdrCapabilitiesSync failed : cast controller is nullptr");
            return undefinedArray;
        }
        outHdrFormats.emplace_back(reinterpret_cast<uintptr_t>(aniEnumItem));
    }
    return array<uintptr_t>(outHdrFormats);
}

array<double> AVCastControllerImpl::GetSupportedPlaySpeedsSync()
{
    array<double> undefinedArray{};
    if (castController_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetSupportedPlaySpeedsSync failed : cast controller is nullptr");
        return undefinedArray;
    }
    std::vector<float> playSpeeds;
    int32_t ret = castController_->GetSupportedPlaySpeeds(playSpeeds);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetSupportedPlaySpeedsSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetSupportedPlaySpeedsSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetSupportedPlaySpeedsSync failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetSupportedPlaySpeedsSync failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return undefinedArray;
    }
    std::vector<double> result(playSpeeds.size());
    for (float speed : playSpeeds) {
        result.emplace_back(static_cast<double>(speed));
    }
    return array<double>(result);
}

void AVCastControllerImpl::SendControlCommandSync(AVCastControlCommand const &command)
{
    OHOS::AVSession::AVSessionTrace trace("AVCastControllerImpl::SendControlCommandSync");
    OHOS::AVSession::AVCastControlCommand castCommand;
    if (TaiheCastControlCommand::GetValue(command, castCommand) != OHOS::AVSession::AVSESSION_SUCCESS) {
        ReportSendControlCommandFailInfo(OHOS::AVSession::ERR_INVALID_PARAM);
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SendControlCommandSync get cast command failed");
        return;
    }

    if (castController_ == nullptr) {
        ReportSendControlCommandFailInfo(OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST);
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "SendControlCommandSync failed : cast controller is nullptr");
        return;
    }

    int32_t ret = castController_->SendControlCommand(castCommand);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        ReportSendControlCommandFailInfo(ret);
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], GetSendControlCommandErrMsg(ret));
        return;
    }
}

void AVCastControllerImpl::SendCustomDataSync(uintptr_t data)
{
    OHOS::AVSession::AVSessionTrace trace("AVCastControllerImpl::SendCustomData");
    if (castController_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "SendCustomDataSync failed : controller is nullptr");
        return;
    }
    OHOS::AAFwk::WantParams dataArgs;
    if (TaiheUtils::GetWantParams(data, dataArgs) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SendCustomDataSync failed : invalid command args");
        return;
    }
    int32_t ret = castController_->SendCustomData(dataArgs);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "SendCustomData error";
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

static void ErrCodeToMessage(int32_t errCode, std::string& message)
{
    switch (errCode) {
        case OHOS::AVSession::ERR_SESSION_NOT_EXIST:
            message = "SetSessionEvent failed : native session not exist";
            break;
        case OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST:
            message = "SendCommonCommand failed : native controller not exist";
            break;
        case OHOS::AVSession::ERR_SESSION_DEACTIVE:
            message = "SendCommonCommand failed : native session is not active";
            break;
        case OHOS::AVSession::ERR_NO_PERMISSION:
            message = "SetSessionEvent failed : native no permission";
            break;
        default:
            message = "SetSessionEvent failed : native server exception";
            break;
    }
}

void AVCastControllerImpl::StartSync(AVQueueItem const& item)
{
    if (castController_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "StartSync failed : cast controller is nullptr");
        ReportStartFailInfo(OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST);
        return;
    }
    OHOS::AVSession::AVQueueItem avQueueItem;
    if (TaiheUtils::GetAVQueueItem(item, avQueueItem) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "StartSync failed : get AVQueueItem failed");
        return;
    }
    int32_t ret = castController_->Start(avQueueItem);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage;
        ErrCodeToMessage(ret, errMessage);
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        ReportStartFailInfo(ret);
        return;
    }
}

static int32_t DownloadCastImg(std::shared_ptr<OHOS::AVSession::AVMediaDescription> description,
    const std::string& uri)
{
    CHECK_AND_RETURN_RET_LOG(description != nullptr, OHOS::AVSession::AVSESSION_ERROR,
        "DownloadCastImg description is null");
    SLOGI("DownloadCastImg with title %{public}s", description->GetTitle().c_str());

    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = nullptr;
    bool ret = TaiheUtils::DoDownloadInCommon(pixelMap, uri);
    SLOGI("DownloadCastImg with ret %{public}d, %{public}d",
        static_cast<int>(ret), static_cast<int>(pixelMap == nullptr));
    if (ret && pixelMap != nullptr) {
        SLOGI("DownloadCastImg success");
        description->SetIcon(OHOS::AVSession::AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap));
        return OHOS::AVSession::AVSESSION_SUCCESS;
    }
    return OHOS::AVSession::AVSESSION_ERROR;
}

static std::function<void()> PrepareAsyncExecutor(OHOS::AVSession::AVCastController* castController,
    OHOS::AVSession::AVQueueItem& data)
{
    return [castController, data]() {
        if (castController == nullptr) {
            return;
        }
        SLOGI("do prepare set with online download prepare with uri alive");
        std::shared_ptr<OHOS::AVSession::AVMediaDescription> description = data.GetDescription();
        if (description == nullptr) {
            SLOGE("do prepare download image description is null");
            return;
        }
        auto uri = description->GetIconUri() == "" ?
            description->GetAlbumCoverUri() : description->GetIconUri();
        OHOS::AVSession::AVQueueItem item;
        if (description->GetIcon() == nullptr && !uri.empty()) {
            auto ret = DownloadCastImg(description, uri);
            SLOGI("DownloadCastImg complete with ret %{public}d", ret);
            if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
                SLOGE("DownloadCastImg failed but not repeat setmetadata again");
            } else {
                description->SetIconUri("URI_CACHE");
                item.SetDescription(description);
                auto ret = castController->Prepare(item);
                SLOGI("do prepare set second with ret %{public}d", ret);
            }
        }
    };
}

void AVCastControllerImpl::PrepareSync(AVQueueItem const& item)
{
    if (castController_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "PrepareSync failed : cast controller is nullptr");
        return;
    }
    OHOS::AVSession::AVQueueItem avQueueItem;
    int32_t ret = TaiheQueueItem::GetAVQueueItem(item, avQueueItem);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage;
        ErrCodeToMessage(ret, errMessage);
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
    auto asyncExecutor = PrepareAsyncExecutor(castController_.get(), avQueueItem);
    CHECK_AND_PRINT_LOG(OHOS::AVSession::AVSessionEventHandler::GetInstance()
        .AVSessionPostTask(asyncExecutor, "PrepareAsync"),
        "AVCastControllerImpl PrepareAsync handler postTask failed");
}

AVQueueItem AVCastControllerImpl::GetCurrentItemSync()
{
    AVQueueItem undefinedItem = TaiheQueueItem::CreateUndefinedAVQueueItem();
    if (castController_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetCurrentItemSync failed : cast controller is nullptr");
        return undefinedItem;
    }

    OHOS::AVSession::AVQueueItem currentItem;
    int32_t ret = castController_->GetCurrentItem(currentItem);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetCurrentItem failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetCurrentItem failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetCurrentItem failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetCurrentItem failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return undefinedItem;
    }

    AVQueueItem output = TaiheQueueItem::CreateUndefinedAVQueueItem();
    ret = TaiheQueueItem::SetAVQueueItem(currentItem, output);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "convert native object to ets object failed");
        return undefinedItem;
    }
    return output;
}

void AVCastControllerImpl::ProcessMediaKeyResponseSync(string_view assetId, array_view<uint8_t> response)
{
    if (castController_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "ProcessMediaKeyResponseSync failed : cast controller is nullptr");
        return;
    }
    std::string assetId_;
    if (TaiheUtils::GetString(assetId, assetId_) != OHOS::AVSession::AVSESSION_SUCCESS || assetId_.empty()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "ProcessMediaKeyResponseSync failed : invalid assetId");
        return;
    }
    std::vector<uint8_t> response_(response.begin(), response.end());
    int32_t ret = castController_->ProcessMediaKeyResponse(assetId_, response_);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "ProcessMediaKeyResponseSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "ProcessMediaKeyResponseSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "ProcessMediaKeyResponseSync failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "ProcessMediaKeyResponseSync failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

void AVCastControllerImpl::ReleaseSync()
{
    if (castController_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "ReleaseSync failed : cast controller is nullptr");
        return;
    }
    int32_t ret = castController_->Destroy();
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "ReleaseSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "ReleaseSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "ReleaseSync failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_SESSION_DEACTIVE) {
            errMessage = "ReleaseSync failed : native session is not active";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "ReleaseSync failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

void AVCastControllerImpl::OnPlaybackStateChange(array_view<string> filter,
    callback_view<void(AVPlaybackState const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("playbackStateChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVCastControllerCallback object is nullptr");
        int32_t status = SetCastPlaybackStateFilter(this, filter);
        if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("SetCastPlaybackStateFilter failed");
            return;
        }
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_PLAYBACK_STATE_CHANGE,
            cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS,
            "OnPlaybackStateChange AddCallback failed");

        CHECK_RETURN_VOID_THROW_ON_ERR(castController_ != nullptr, "castController_ is nullptr");
        ret = castController_->AddAvailableCommand(
            OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_PLAY_STATE_CHANGE);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS,
            "OnPlaybackStateChange add cmd failed");
    }
}

AVPlaybackState AVCastControllerImpl::GetAVPlaybackStateSync()
{
    AVPlaybackState undefinedState = TaihePlaybackState::CreateUndefinedAVPlaybackState();
    if (castController_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetCastAVPlaybackState failed : controller is nullptr");
        return undefinedState;
    }

    OHOS::AVSession::AVPlaybackState state;
    int32_t ret = castController_->GetCastAVPlaybackState(state);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetCastAVPlaybackState failed : native server exception, \
            you are advised to : 1.scheduled retry.\
            2.destroy the current session or session controller and re-create it.";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetCastAVPlaybackState failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetCastAVPlaybackState failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetCastAVPlaybackState failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return undefinedState;
    }

    AVPlaybackState output = TaihePlaybackState::CreateUndefinedAVPlaybackState();
    ret = TaihePlaybackState::SetAVPlaybackState(state, output);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "convert native object to ets object failed");
        return undefinedState;
    }
    return output;
}

array<string> AVCastControllerImpl::GetValidCommandsSync()
{
    std::vector<string> emptyCmds;
    if (castController_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetValidCommandsSync failed : controller is nullptr");
        return array<string>(emptyCmds);
    }

    std::vector<int32_t> cmds;
    int32_t ret = castController_->GetValidCommands(cmds);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetValidCommands failed : native server exception, \
            you are advised to : 1.scheduled retry.\
            2.destroy the current session or session controller and re-create it.";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetValidCommands failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetValidCommands failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetValidCommands failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return array<string>(emptyCmds);
    }

    std::vector<std::string> stringCmds = TaiheCastControlCommand::ConvertCommands(cmds);
    return array<string>(TaiheUtils::ToTaiheStringArray(stringCmds));
}

void AVCastControllerImpl::OnPlaybackStateChangeAll(callback_view<void(AVPlaybackState const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("playbackStateChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVCastControllerCallback object is nullptr");
        string filter("all");
        string_view filterView = filter;
        int32_t status = SetCastPlaybackStateFilter(this, filterView);
        if (status != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("SetCastPlaybackStateFilter failed");
            return;
        }
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_PLAYBACK_STATE_CHANGE,
            cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS,
            "OnPlaybackStateChange AddCallback failed");
        CHECK_RETURN_VOID_THROW_ON_ERR(castController_ != nullptr, "castController_ is nullptr");
        ret = castController_->AddAvailableCommand(
            OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_PLAY_STATE_CHANGE);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS,
            "OnPlaybackStateChange add cmd failed");
    }
}

void AVCastControllerImpl::OnMediaItemChange(callback_view<void(AVQueueItem const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("mediaItemChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVCastControllerCallback object is nullptr");
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_MEDIA_ITEM_CHANGE, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "AddCallback failed");
    }
}

void AVCastControllerImpl::OnPlayNext(callback_view<void()> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("playNext", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVCastControllerCallback object is nullptr");
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_PLAY_NEXT, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "AddCallback failed");

        CHECK_RETURN_VOID_THROW_ON_ERR(castController_ != nullptr, "castController_ is nullptr");
        ret = castController_->AddAvailableCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "add cmd failed");
    }
}

void AVCastControllerImpl::OnPlayPrevious(callback_view<void()> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("playPrevious", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVCastControllerCallback object is nullptr");
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_PLAY_PREVIOUS, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "AddCallback failed");

        CHECK_RETURN_VOID_THROW_ON_ERR(castController_ != nullptr, "castController_ is nullptr");
        ret = castController_
            ->AddAvailableCommand(OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "add cmd failed");
    }
}

void AVCastControllerImpl::OnRequestPlay(callback_view<void(AVQueueItem const&)> callback)
{
    SLOGI("AVCastControllerImpl::OnRequestPlay");
    return;
}

void AVCastControllerImpl::OnEndOfStream(callback_view<void()> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("endOfStream", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVCastControllerCallback object is nullptr");
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_END_OF_STREAM, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "AddCallback failed");
    }
}

void AVCastControllerImpl::OnSeekDone(callback_view<void(int32_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("seekDone", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVCastControllerCallback object is nullptr");
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_SEEK_DONE, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "AddCallback failed");
    }
}

void AVCastControllerImpl::OnValidCommandChange(callback_view<void(array_view<string>)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("validCommandChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGI("OnValidCommandChange");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVCastControllerCallback object is nullptr");
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_VALID_COMMAND_CHANGED,
            cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "AddCallback failed");
    }
}

void AVCastControllerImpl::OnVideoSizeChange(callback_view<void(int32_t, int32_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("videoSizeChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVCastControllerCallback object is nullptr");
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_VIDEO_SIZE_CHANGE, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "AddCallback failed");
    }
}

void AVCastControllerImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("error", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "TaiheAVCastControllerCallback object is nullptr");
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_ERROR, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "AddCallback failed");
    }
}

void AVCastControllerImpl::OnCastControlGenericError(callback_view<void(uintptr_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("castControlGenericError", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(cacheCallback != nullptr, "callback is nullptr");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback_ is nullptr");
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_GENERIC_ERR, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "AddCallback failed");
    }
}

void AVCastControllerImpl::OnCastControlIoError(callback_view<void(uintptr_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("castControlIoError", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(cacheCallback != nullptr, "callback is nullptr");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback_ is nullptr");
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_IO_ERR, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "AddCallback failed");
    }
}

void AVCastControllerImpl::OnCastControlParsingError(callback_view<void(uintptr_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("castControlParsingError", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(cacheCallback != nullptr, "callback is nullptr");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback_ is nullptr");
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_PARSING_ERR, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "AddCallback failed");
    }
}

void AVCastControllerImpl::OnCastControlDecodingError(callback_view<void(uintptr_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("castControlDecodingError", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(cacheCallback != nullptr, "callback is nullptr");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback_ is nullptr");
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_DECOD_EERR, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "AddCallback failed");
    }
}

void AVCastControllerImpl::OnCastControlAudioRendererError(callback_view<void(uintptr_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("castControlAudioRendererError", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(cacheCallback != nullptr, "callback is nullptr");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback_ is nullptr");
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_RENDER_ERR, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "AddCallback failed");
    }
}

void AVCastControllerImpl::OnCastControlDrmError(callback_view<void(uintptr_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("castControlDrmError", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(cacheCallback != nullptr, "callback is nullptr");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback_ is nullptr");
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_DRM_ERR, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "AddCallback failed");
    }
}

void AVCastControllerImpl::OnKeyRequest(callback_view<void(string_view,
    array_view<uint8_t>)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("keyRequest", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(cacheCallback != nullptr, "callback is nullptr");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback_ is nullptr");
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_KEY_REQUEST, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "AddCallback failed");
    }
}

void AVCastControllerImpl::OnCustomDataChange(callback_view<void(uintptr_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("customDataChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        auto ret = callback_->AddCallback(TaiheAVCastControllerCallback::EVENT_CAST_CUSTOM_DATA_CHANGE, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "AddCallback failed");
    }
}

void AVCastControllerImpl::OffPlaybackStateChange(optional_view<callback<void(AVPlaybackState const&)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("playbackStateChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        auto status = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_PLAYBACK_STATE_CHANGE,
            cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");

        if (callback_->IsCallbacksEmpty(TaiheAVCastControllerCallback::EVENT_CAST_PLAYBACK_STATE_CHANGE)) {
            CHECK_RETURN_VOID_THROW_ON_ERR(castController_ != nullptr, "castController_ is nullptr");
            int32_t ret = castController_->RemoveAvailableCommand(
                OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_PLAY_STATE_CHANGE);
            CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "remove stateChange cmd failed");
        }
    }
}

void AVCastControllerImpl::OffMediaItemChange(optional_view<callback<void(AVQueueItem const&)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("mediaItemChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        int32_t ret = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_MEDIA_ITEM_CHANGE,
            cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
    }
}

void AVCastControllerImpl::OffPlayNext(optional_view<callback<void()>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("playNext", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        auto status = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_PLAY_NEXT, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");

        if (callback_->IsCallbacksEmpty(TaiheAVCastControllerCallback::EVENT_CAST_PLAY_NEXT)) {
            CHECK_RETURN_VOID_THROW_ON_ERR(castController_ != nullptr, "castController_ is nullptr");
            int32_t ret = castController_->RemoveAvailableCommand(
                OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT);
            CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "add cmd failed");
        }
    }
}

void AVCastControllerImpl::OffPlayPrevious(optional_view<callback<void()>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("playPrevious", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        auto status = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_PLAY_PREVIOUS, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");

        if (callback_->IsCallbacksEmpty(TaiheAVCastControllerCallback::EVENT_CAST_PLAY_PREVIOUS)) {
            CHECK_RETURN_VOID_THROW_ON_ERR(castController_ != nullptr, "castController_ is nullptr");
            int32_t ret = castController_->RemoveAvailableCommand(
                OHOS::AVSession::AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS);
            CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "remove cmd failed");
        }
    }
}

void AVCastControllerImpl::OffRequestPlay(optional_view<callback<void(AVQueueItem const&)>> callback)
{
    SLOGI("AVCastControllerImpl::OffRequestPlay");
    return;
}

void AVCastControllerImpl::OffEndOfStream(optional_view<callback<void()>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("endOfStream", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        int32_t ret = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_END_OF_STREAM, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
    }
}

void AVCastControllerImpl::OffSeekDone(optional_view<callback<void(int32_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("seekDone", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        auto status = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_SEEK_DONE, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(status == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
    }
}

void AVCastControllerImpl::OffValidCommandChange(optional_view<callback<void(array_view<string>)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("validCommandChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        int32_t ret = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_VALID_COMMAND_CHANGED,
            cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
    }
}

void AVCastControllerImpl::OffVideoSizeChange(optional_view<callback<void(int32_t, int32_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("videoSizeChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        int32_t ret = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_VIDEO_SIZE_CHANGE,
            cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
    }
}

void AVCastControllerImpl::OffError(optional_view<callback<void(uintptr_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("error", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        int32_t ret = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_ERROR, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
    }
}

void AVCastControllerImpl::OffCastControlGenericError(optional_view<callback<void(uintptr_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("castControlGenericError", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        int32_t ret = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_GENERIC_ERR, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
    }
}

void AVCastControllerImpl::OffCastControlIoError(optional_view<callback<void(uintptr_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("castControlIoError", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        int32_t ret = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_IO_ERR, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
    }
}

void AVCastControllerImpl::OffCastControlParsingError(optional_view<callback<void(uintptr_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("castControlParsingError", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        int32_t ret = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_PARSING_ERR, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
    }
}

void AVCastControllerImpl::OffCastControlDecodingError(optional_view<callback<void(uintptr_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("castControlDecodingError", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        int32_t ret = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_DECOD_EERR, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
    }
}

void AVCastControllerImpl::OffCastControlAudioRendererError(optional_view<callback<void(uintptr_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("castControlAudioRendererError", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        int32_t ret = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_RENDER_ERR, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
    }
}

void AVCastControllerImpl::OffCastControlDrmError(optional_view<callback<void(uintptr_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("castControlDrmError", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        int32_t ret = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_DRM_ERR, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
    }
}

void AVCastControllerImpl::OffKeyRequest(optional_view<callback<void(string_view,
    array_view<uint8_t>)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("keyRequest", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(cacheCallback != nullptr, "callback is nullptr");
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback_ is nullptr");
        int32_t ret = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_KEY_REQUEST, cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
    }
}

void AVCastControllerImpl::OffCustomDataChange(optional_view<callback<void(uintptr_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("customDataChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID_THROW_ON_ERR(callback_ != nullptr, "callback has not been registered");
        auto ret = callback_->RemoveCallback(TaiheAVCastControllerCallback::EVENT_CAST_CUSTOM_DATA_CHANGE,
            cacheCallback);
        CHECK_RETURN_VOID_THROW_ON_ERR(ret == OHOS::AVSession::AVSESSION_SUCCESS, "RemoveCallback failed");
    }
}

int32_t AVCastControllerImpl::OnEvent(const std::string& event, AVCastControllerImpl *taiheCastController)
{
    std::string eventName = event;
    return RegisterCallback(eventName, taiheCastController);
}

int32_t AVCastControllerImpl::OffEvent(const std::string& event, AVCastControllerImpl *taiheCastController)
{
    CHECK_AND_RETURN_RET_LOG(taiheCastController != nullptr, OHOS::AVSession::ERR_INVALID_PARAM,
        "taiheCastController is nullptr");

    std::string eventName = event;
    auto it = eventHandlers_.find(eventName);
    if (it == eventHandlers_.end()) {
        SLOGE("event name invalid:%{public}s", eventName.c_str());
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "event name invalid");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }

    if (taiheCastController->callback_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "callback not register yet");
        return OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST;
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t AVCastControllerImpl::RegisterCallback(const std::string& event, AVCastControllerImpl *taiheCastController)
{
    CHECK_AND_RETURN_RET_LOG(taiheCastController != nullptr, OHOS::AVSession::ERR_INVALID_PARAM,
        "taiheCastController is nullptr");
    auto it = eventHandlers_.find(event);
    if (it == eventHandlers_.end()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "event name invalid");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    if (taiheCastController->castController_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "OnEvent failed : controller is nullptr");
        return OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST;
    }
    if (taiheCastController->callback_ == nullptr) {
        taiheCastController->callback_ = std::make_shared<TaiheAVCastControllerCallback>();
        if (taiheCastController->callback_ == nullptr) {
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_NO_MEMORY],
                "OnEvent failed : no memory");
            return OHOS::AVSession::ERR_NO_MEMORY;
        }
        auto ret = taiheCastController->castController_->RegisterCallback(taiheCastController->callback_);
        if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("controller RegisterCallback failed:%{public}d", ret);
            std::string errMessage = "OnEvent failed : native server exception";
            if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
                errMessage = "OnEvent failed : native controller not exist";
            } else if (ret == OHOS::AVSession::ERR_NO_MEMORY) {
                errMessage = "OnEvent failed : no memory";
            } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
                errMessage = "OnEvent failed : native no permission";
            }
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
            taiheCastController->callback_ = nullptr;
            return OHOS::AVSession::AVSESSION_ERROR;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

template<typename T>
int32_t AVCastControllerImpl::SetCastPlaybackStateFilter(AVCastControllerImpl *taiheCastController, T filter)
{
    CHECK_AND_RETURN_RET_LOG(taiheCastController != nullptr, OHOS::AVSession::ERR_INVALID_PARAM,
        "taiheCastController is nullptr");
    CHECK_AND_RETURN_RET_LOG(taiheCastController->castController_ != nullptr, OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST,
        "castController_ is nullptr");
    OHOS::AVSession::AVPlaybackState::PlaybackStateMaskType playbackMask;
    auto status = TaihePlaybackState::ConvertFilter(filter, playbackMask);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "convert filter failed", status);
    auto ret = taiheCastController->castController_->SetCastPlaybackFilter(playbackMask);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("CastController SetCastPlaybackFilter failed:%{public}d", ret);
        return ret;
    }
    return ret;
}
} // namespace ANI::AVSession