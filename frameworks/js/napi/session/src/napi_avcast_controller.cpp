/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "key_event.h"
#include "napi_async_work.h"
#include "napi_avcast_controller_callback.h"
#include "napi_cast_control_command.h"
#include "napi_meta_data.h"
#include "napi_playback_state.h"
#include "napi_utils.h"
#include "napi_media_description.h"
#include "napi_queue_item.h"
#include "want_agent.h"
#include "avsession_errors.h"
#include "avsession_trace.h"
#include "napi_avsession_manager.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "napi_avcast_controller.h"
#include "avsession_radar.h"
#include "curl/curl.h"
#include "image_source.h"
#include "pixel_map.h"
#include "avsession_pixel_map_adapter.h"
#include "avsession_event_handler.h"

namespace OHOS::AVSession {

static __thread napi_ref AVCastControllerConstructorRef = nullptr;
std::map<std::string, std::pair<NapiAVCastController::OnEventHandlerType,
    NapiAVCastController::OffEventHandlerType>> NapiAVCastController::EventHandlers_ = {
    { "playbackStateChange", { OnPlaybackStateChange, OffPlaybackStateChange } },
    { "mediaItemChange", { OnMediaItemChange, OffMediaItemChange } },
    { "playNext", { OnPlayNext, OffPlayNext } },
    { "playPrevious", { OnPlayPrevious, OffPlayPrevious } },
    { "requestPlay", { OnRequestPlay, OffRequestPlay } },
    { "seekDone", { OnSeekDone, OffSeekDone } },
    { "validCommandChange", { OnValidCommandChange, OffValidCommandChange } },
    { "videoSizeChange", { OnVideoSizeChange, OffVideoSizeChange } }, // timeUpdate -> videoSizeChange
    { "error", { OnPlayerError, OffPlayerError } },
    { "castControlGenericError", { OnCastControlGenericError, OffCastControlGenericError } },
    { "castControlIoError", { OnCastControlIoError, OffCastControlIoError } },
    { "castControlParsingError", { OnCastControlParsingError, OffCastControlParsingError } },
    { "castControlDecodingError", { OnCastControlDecodingError, OffCastControlDecodingError } },
    { "castControlAudioRendererError", { OnCastControlAudioRendererError, OffCastControlAudioRendererError } },
    { "castControlDrmError", { OnCastControlDrmError, OffCastControlDrmError } },
    { "endOfStream", { OnEndOfStream, OffEndOfStream } },
    { "requestPlay", { OnPlayRequest, OffPlayRequest } },
    { "keyRequest", { OnKeyRequest, OffKeyRequest } },
};

NapiAVCastController::NapiAVCastController()
{
    SLOGI("NapiAVCastController construct");
}

NapiAVCastController::~NapiAVCastController()
{
    SLOGI("NapiAVCastController destroy");
}

napi_value NapiAVCastController::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("on", OnEvent),
        DECLARE_NAPI_FUNCTION("off", OffEvent),
        DECLARE_NAPI_FUNCTION("start", Start),
        DECLARE_NAPI_FUNCTION("prepare", Prepare),
        DECLARE_NAPI_FUNCTION("sendControlCommand", SendControlCommand),
        DECLARE_NAPI_FUNCTION("getDuration", GetDuration),
        DECLARE_NAPI_FUNCTION("getAVPlaybackState", GetCastAVPlaybackState),
        DECLARE_NAPI_FUNCTION("getSupportedDecoders", GetSupportedDecoders),
        DECLARE_NAPI_FUNCTION("getRecommendedResolutionLevel", GetRecommendedResolutionLevel),
        DECLARE_NAPI_FUNCTION("getSupportedHdrCapabilities", GetSupportedHdrCapabilities),
        DECLARE_NAPI_FUNCTION("getSupportedPlaySpeeds", GetSupportedPlaySpeeds),
        DECLARE_NAPI_FUNCTION("getCurrentItem", GetCurrentItem),
        DECLARE_NAPI_FUNCTION("getValidCommands", GetValidCommands),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_FUNCTION("setDisplaySurface", SetDisplaySurface),
        DECLARE_NAPI_FUNCTION("processMediaKeyResponse", ProcessMediaKeyResponse),
    };

    auto property_count = sizeof(descriptors) / sizeof(napi_property_descriptor);
    napi_value constructor {};
    auto status = napi_define_class(env, "AVCastController", NAPI_AUTO_LENGTH, ConstructorCallback, nullptr,
        property_count, descriptors, &constructor);
    if (status != napi_ok) {
        SLOGE("define class failed");
        return NapiUtils::GetUndefinedValue(env);
    }
    napi_create_reference(env, constructor, 1, &AVCastControllerConstructorRef);
    return exports;
}

napi_value NapiAVCastController::ConstructorCallback(napi_env env, napi_callback_info info)
{
    napi_value self;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr), nullptr);

    auto finalize = [](napi_env env, void* data, void* hint) {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(data);
        napi_delete_reference(env, napiCastController->wrapperRef_);
        delete napiCastController;
        napiCastController = nullptr;
    };

    auto* napiCastController = new(std::nothrow) NapiAVCastController();
    if (napiCastController == nullptr) {
        SLOGE("no memory");
        return nullptr;
    }
    //The last parameter of napi_wrap must be null
    if (napi_wrap(env, self, static_cast<void*>(napiCastController), finalize,
        &(napiCastController->wrapperRef_),  nullptr) != napi_ok) {
        SLOGE("wrap failed");
        return nullptr;
    }
    return self;
}

napi_status NapiAVCastController::NewInstance(napi_env env, std::shared_ptr<AVCastController>& nativeController,
    napi_value& out)
{
    napi_value constructor {};
    NAPI_CALL_BASE(env, napi_get_reference_value(env, AVCastControllerConstructorRef, &constructor),
        napi_generic_failure);
    napi_value instance {};
    NAPI_CALL_BASE(env, napi_new_instance(env, constructor, 0, nullptr, &instance), napi_generic_failure);
    NapiAVCastController* napiCastController {};
    NAPI_CALL_BASE(env, napi_unwrap(env, instance, reinterpret_cast<void**>(&napiCastController)),
        napi_generic_failure);
    napiCastController->castController_ = std::move(nativeController);

    out = instance;
    return napi_ok;
}

napi_value NapiAVCastController::SendControlCommand(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastController::SendControlCommand");
    struct ConcrentContext : public ContextBase {
        AVCastControlCommand castCommand_;
    };
    auto context = std::make_shared<ConcrentContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CheckSendCtrlCmdReportRadar((argc == ARGC_ONE), ERR_INVALID_PARAM);
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);

        context->status = NapiCastControlCommand::GetValue(env, argv[ARGV_FIRST], context->castCommand_);
        CheckSendCtrlCmdReportRadar((context->status == napi_ok), ERR_INVALID_PARAM);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok), "invalid command",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_CAST_CONTROLLER_SEND_CONTROL_COMMAND_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("SendControlCommand failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "SendControlCommand failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            ReportSendControlCommandFailInfo(ERR_CONTROLLER_NOT_EXIST);
            return;
        }

        int32_t ret = napiCastController->castController_->SendControlCommand(context->castCommand_);
        if (ret != AVSESSION_SUCCESS) {
            context->errMessage = GetSendControlCommandErrMsg(ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
            ReportSendControlCommandFailInfo(ret);
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "SendControlCommand", executor);
}

napi_value NapiAVCastController::Start(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastController::Start");
    struct ConcreteContext : public ContextBase {
        AVQueueItem avQueueItem_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("Start failed : no memory");
        ReportStartFailInfo(ERR_NO_MEMORY);
        NapiUtils::ThrowError(env, "Start failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        int napiErr = NapiAVSessionManager::errcode_[ERR_INVALID_PARAM];
        CheckStartReportRadar((argc == ARGC_ONE), ERR_INVALID_PARAM);
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "Invalid arguments", napiErr);
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->callback_ != nullptr) {
            napiCastController->callback_->saveDataSrc(env, argv[ARGV_FIRST]);
        }

        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->avQueueItem_);
        CheckStartReportRadar((context->status == napi_ok), ERR_INVALID_PARAM);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "Get play queue item failed", napiErr);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_CAST_CONTROLLER_START_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("Start failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "Start failed : castController_ is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            ReportStartFailInfo(ERR_CONTROLLER_NOT_EXIST);
            return;
        }
        int32_t ret = napiCastController->castController_->Start(context->avQueueItem_);
        if (ret != AVSESSION_SUCCESS) {
            ErrCodeToMessage(ret, context->errMessage);
            SLOGE("CastController Start failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
            ReportStartFailInfo(ret);
        }
    };

    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "Start", executor, complete);
}

int32_t NapiAVCastController::DownloadCastImg(std::shared_ptr<AVMediaDescription> description, const std::string& uri)
{
    SLOGI("DownloadCastImg with title %{public}s", description->GetTitle().c_str());

    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    bool ret = NapiUtils::DoDownloadInCommon(pixelMap, uri);
    SLOGI("DownloadCastImg with ret %{public}d, %{public}d",
        static_cast<int>(ret), static_cast<int>(pixelMap == nullptr));
    if (ret && pixelMap != nullptr) {
        SLOGI("DownloadCastImg success");
        description->SetIcon(AVSessionPixelMapAdapter::ConvertToInnerWithLimitedSize(pixelMap));
        return AVSESSION_SUCCESS;
    }
    return AVSESSION_ERROR;
}

std::function<void()> NapiAVCastController::PrepareAsyncExecutor(std::shared_ptr<AVCastController> castController_,
    AVQueueItem& data)
{
    return [castController_, data]() {
        if (castController_>castController_ == nullptr) {
            return;
        }
        SLOGI("do prepare set with online download prepare with uri alive");
        std::shared_ptr<AVMediaDescription> description = data.GetDescription();
        if (description == nullptr) {
            SLOGE("do prepare download image description is null");
            return;
        }
        auto uri = description->GetIconUri() == "" ?
            description->GetAlbumCoverUri() : description->GetIconUri();
        AVQueueItem item;
        if (description->GetIcon() == nullptr && !uri.empty()) {
            auto ret = DownloadCastImg(description, uri);
            SLOGI("DownloadCastImg complete with ret %{public}d", ret);
            if (ret != AVSESSION_SUCCESS) {
                SLOGE("DownloadCastImg failed but not repeat setmetadata again");
            } else {
                description->SetIconUri("URI_CACHE");
                item.SetDescription(description);
                if (castController_ == nullptr) {
                    return;
                }
                auto ret = castController_->Prepare(item);
                SLOGI("do prepare set second with ret %{public}d", ret);
            }
        }
    };
}

napi_value NapiAVCastController::Prepare(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastController::Prepare");
    struct ConcreteContext : public ContextBase {
        AVQueueItem avQueueItem_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("Prepare failed : no memory");
        NapiUtils::ThrowError(env, "Prepare failed : no memory",
            NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "Invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->callback_ != nullptr) {
            napiCastController->callback_->saveDataSrc(env, argv[ARGV_FIRST]);
        }
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->avQueueItem_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "Get play queue item failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_CAST_CONTROLLER_PREPARE_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("Prepare failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "Prepare failed : castController_ is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->Prepare(context->avQueueItem_);
        if (ret != AVSESSION_SUCCESS) {
            ErrCodeToMessage(ret, context->errMessage);
            SLOGE("CastController UpdateMediaInfo failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        auto asyncExecutor = PrepareAsyncExecutor(napiCastController->castController_, context->avQueueItem_);
        CHECK_AND_PRINT_LOG(AVSessionEventHandler::GetInstance()
            .AVSessionPostTask(asyncExecutor, "PrepareAsync"),
            "NapiAVCastController PrepareAsync handler postTask failed");
    };
    return NapiAsyncWork::Enqueue(env, context, "Prepare", executor, complete);
}

napi_value NapiAVCastController::GetDuration(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        int32_t duration;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_CAST_CONTROLLER_GET_DURATION_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("GetDuration failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetDuration failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->GetDuration(context->duration);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetDuration failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetDuration failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetDuration failed : native no permission";
            } else {
                context->errMessage = "GetDuration failed : native server exception";
            }
            SLOGE("controller GetDuration failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->duration = NapiUtils::SetValue(env, context->duration, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetDuration", executor, complete);
}

napi_value NapiAVCastController::GetCastAVPlaybackState(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        AVPlaybackState castAVPlaybackState_;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_CAST_CONTROLLER_GET_PLAY_STATE_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("GetCastAVPlaybackState failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetCastAVPlaybackState failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->GetCastAVPlaybackState(context->castAVPlaybackState_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetCastAVPlaybackState failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetCastAVPlaybackState failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetCastAVPlaybackState failed : native no permission";
            } else {
                context->errMessage = "GetCastAVPlaybackState failed : native server exception";
            }
            SLOGE("controller GetCastAVPlaybackState failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->castAVPlaybackState_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetCastAVPlaybackState", executor, complete);
}

napi_value NapiAVCastController::GetSupportedDecoders(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        std::vector<std::string> decoderTypes;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_CAST_CONTROL_GET_SUPPORT_DECODER_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("GetSupportedDecoders failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetSupportedDecoders failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->GetSupportedDecoders(context->decoderTypes);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetSupportedDecoders failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetSupportedDecoders failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetSupportedDecoders failed : native no permission";
            } else {
                context->errMessage = "GetSupportedDecoders failed : native server exception";
            }
            SLOGE("controller GetSupportedDecoders failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->decoderTypes, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetSupportedDecoders", executor, complete);
}

napi_value NapiAVCastController::GetRecommendedResolutionLevel(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        std::string decoderType;
        ResolutionLevel resolutionLevel;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);

        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->decoderType);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok), "invalid command",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_CAST_CONTROL_GET_RECOMMEND_RESOLUTION_LEVEL_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("GetRecommendedResolutionLevel failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetRecommendedResolutionLevel failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->GetRecommendedResolutionLevel(
            context->decoderType, context->resolutionLevel);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetRecommendedResolutionLevel failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetRecommendedResolutionLevel failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetRecommendedResolutionLevel failed : native no permission";
            } else {
                context->errMessage = "GetRecommendedResolutionLevel failed : native server exception";
            }
            SLOGE("controller GetRecommendedResolutionLevel failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->resolutionLevel, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetRecommendedResolutionLevel", executor, complete);
}

napi_value NapiAVCastController::GetSupportedHdrCapabilities(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        std::vector<HDRFormat> hdrFormats;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_CAST_CONTROL_GET_SUPPORT_HDR_CAPABILITIES_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("GetSupportedHdrCapabilities failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetSupportedHdrCapabilities failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->GetSupportedHdrCapabilities(context->hdrFormats);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetSupportedHdrCapabilities failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetSupportedHdrCapabilities failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetSupportedHdrCapabilities failed : native no permission";
            } else {
                context->errMessage = "GetSupportedHdrCapabilities failed : native server exception";
            }
            SLOGE("controller GetSupportedHdrCapabilities failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->hdrFormats, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetSupportedHdrCapabilities", executor, complete);
}

napi_value NapiAVCastController::GetSupportedPlaySpeeds(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        std::vector<float> playSpeeds;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_CAST_CONTROL_GET_SUPPORT_PLAY_SPEED_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("GetSupportedPlaySpeeds failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetSupportedPlaySpeeds failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->GetSupportedPlaySpeeds(context->playSpeeds);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetSupportedPlaySpeeds failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetSupportedPlaySpeeds failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetSupportedPlaySpeeds failed : native no permission";
            } else {
                context->errMessage = "GetSupportedPlaySpeeds failed : native server exception";
            }
            SLOGE("controller GetSupportedPlaySpeeds failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->playSpeeds, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetSupportedPlaySpeeds", executor, complete);
}

napi_value NapiAVCastController::GetCurrentItem(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        AVQueueItem currentItem_;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_CAST_CONTROLLER_GET_CURRENT_ITEM_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("GetCurrentItem failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetCurrentItem failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->GetCurrentItem(context->currentItem_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetCurrentItem failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetCurrentItem failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetCurrentItem failed : native no permission";
            } else {
                context->errMessage = "GetCurrentItem failed : native server exception";
            }
            SLOGE("controller GetCurrentItem failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->currentItem_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetCurrentItem", executor, complete);
}

napi_value NapiAVCastController::GetValidCommands(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        std::vector<std::string> stringCmds;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_CAST_CONTROLLER_GET_CURRENT_ITEM_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("GetValidCommands failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetValidCommands failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        std::vector<int32_t> cmds;
        int32_t ret = napiCastController->castController_->GetValidCommands(cmds);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetValidCommands failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetValidCommands failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetValidCommands failed : native no permission";
            } else {
                context->errMessage = "GetValidCommands failed : native server exception";
            }
            SLOGE("controller GetValidCommands failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
        context->stringCmds = NapiCastControlCommand::ConvertCommands(cmds);
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->stringCmds, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetValidCommands", executor, complete);
}

napi_value NapiAVCastController::Release(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("Release failed : no memory");
        NapiUtils::ThrowError(env, "Release failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }
    context->GetCbInfo(env, info);
    context->taskId = NAPI_CAST_CONTROLLER_GET_CURRENT_ITEM_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("release failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "release failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        std::vector<int32_t> cmds;
        int32_t ret = napiCastController->castController_->Destroy();
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "release failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "release failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "release failed : native no permission";
            } else {
                context->errMessage = "release failed : native server exception";
            }
            SLOGE("controller release failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "release", executor);
}

napi_value NapiAVCastController::SetDisplaySurface(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastController::SetDisplaySurface");
    struct ConcrentContext : public ContextBase {
        std::string surfaceId;
    };
    auto context = std::make_shared<ConcrentContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->surfaceId);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok), "invalid command",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_CAST_CONTROLLER_SET_DISPLAY_SURFACE_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("SetDisplaySurface failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "SetDisplaySurface failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->SetDisplaySurface(context->surfaceId);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SetDisplaySurface failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "SetDisplaySurface failed : native controller not exist";
            } else if (ret == ERR_SESSION_DEACTIVE) {
                context->errMessage = "SetDisplaySurface failed : native session is not active";
            } else if (ret == ERR_COMMAND_NOT_SUPPORT) {
                context->errMessage = "SetDisplaySurface failed : native command not support";
            } else if (ret == ERR_COMMAND_SEND_EXCEED_MAX) {
                context->errMessage = "SetDisplaySurface failed : native command send nums overload";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SetDisplaySurface failed : native no permission";
            } else {
                context->errMessage = "SetDisplaySurface failed : native server exception";
            }
            SLOGE("controller SetDisplaySurface failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "SetDisplaySurface", executor);
}

napi_value NapiAVCastController::ProcessMediaKeyResponse(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastController::ProcessMediaKeyResponse");
    struct ConcrentContext : public ContextBase {
        std::string assetId;
        std::vector<uint8_t> response;
    };
    auto context = std::make_shared<ConcrentContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_TWO, "invalid arguments",
                               NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->assetId);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok), "invalid command",
                               NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_SECOND], context->response);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok), "invalid command",
                               NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_PROVIDE_KEY_RESPONSE_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("ProcessMediaKeyResponse failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "ProcessMediaKeyResponse failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->ProcessMediaKeyResponse(context->assetId, context->response);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "ProcessMediaKeyResponse failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "ProcessMediaKeyResponse failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "ProcessMediaKeyResponse failed : native no permission";
            } else {
                context->errMessage = "ProcessMediaKeyResponse failed : native server exception";
            }
            SLOGE("controller ProcessMediaKeyResponse failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "ProcessMediaKeyResponse", executor);
}

napi_status NapiAVCastController::RegisterCallback(napi_env env, const std::shared_ptr<ContextBase>& context,
    const std::string& event, napi_value filter, napi_value callback)
{
    auto it = EventHandlers_.find(event);
    if (it == EventHandlers_.end()) {
        SLOGE("event name invalid");
        NapiUtils::ThrowError(env, "event name invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return napi_generic_failure;
    }
    auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
    if (napiCastController->castController_ == nullptr) {
        SLOGE("OnEvent failed : controller is nullptr");
        NapiUtils::ThrowError(env, "OnEvent failed : controller is nullptr",
            NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST]);
        return napi_generic_failure;
    }
    if (napiCastController->callback_ == nullptr) {
        napiCastController->callback_ = std::make_shared<NapiAVCastControllerCallback>();
        if (napiCastController->callback_ == nullptr) {
            SLOGE("OnEvent failed : no memory");
            NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
            return napi_generic_failure;
        }
        auto ret = napiCastController->castController_->RegisterCallback(napiCastController->callback_);
        if (ret != AVSESSION_SUCCESS) {
            SLOGE("controller RegisterCallback failed:%{public}d", ret);
            if (ret == ERR_CONTROLLER_NOT_EXIST) {
                NapiUtils::ThrowError(env, "OnEvent failed : native controller not exist",
                    NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST]);
            } else if (ret == ERR_NO_MEMORY) {
                NapiUtils::ThrowError(env, "OnEvent failed : native no memory",
                    NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
            } else if (ret == ERR_NO_PERMISSION) {
                NapiUtils::ThrowError(env, "OnEvent failed : native no permission",
                    NapiAVSessionManager::errcode_[ERR_NO_PERMISSION]);
            } else {
                NapiUtils::ThrowError(env, "OnEvent failed : native server exception",
                    NapiAVSessionManager::errcode_[ret]);
            }
            napiCastController->callback_ = nullptr;
            return napi_generic_failure;
        }
    }
    if (it->second.first(env, napiCastController, filter, callback) != napi_ok) {
        SLOGE("add event callback failed");
        NapiUtils::ThrowError(env, "add event callback failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        return napi_generic_failure;
    }
    return napi_ok;
}

static bool IsThreeParamForOnEvent(const std::string& event)
{
    return event == "metadataChange" || event == "playbackStateChange";
}

napi_value NapiAVCastController::OnEvent(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    std::string eventName;
    napi_value filter {};
    napi_value callback {};
    auto input = [&eventName, &callback, &filter, env, &context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc >= ARGC_ONE, "invalid argument number",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], eventName);
        CHECK_STATUS_RETURN_VOID(context, "get event name failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        napi_valuetype type = napi_undefined;
        if (!IsThreeParamForOnEvent(eventName)) {
            CHECK_ARGS_RETURN_VOID(context, argc == ARGC_TWO, "invalid argument number",
                NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            context->status = napi_typeof(env, argv[ARGV_SECOND], &type);
            CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_function),
                                   "callback type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            callback = argv[ARGV_SECOND];
        } else {
            CHECK_ARGS_RETURN_VOID(context, argc == ARGC_THREE, "invalid argument number",
                NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            context->status = napi_typeof(env, argv[ARGV_SECOND], &type);
            CHECK_ARGS_RETURN_VOID(
                context, (context->status == napi_ok) && (type == napi_object || type == napi_string),
                "Second param type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            filter = argv[ARGV_SECOND];
            context->status = napi_typeof(env, argv[ARGV_THIRD], &type);
            CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_function),
                                   "callback type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            callback = argv[ARGV_THIRD];
        }
    };
    context->GetCbInfo(env, info, input, true);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }
    RegisterCallback(env, context, eventName, filter, callback);

    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVCastController::OffEvent(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    std::string eventName;
    napi_value callback = nullptr;
    auto input = [&eventName, env, &context, &callback](size_t argc, napi_value* argv) {
        uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
        bool isSystemApp = Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
        if (!isSystemApp) {
            SLOGI("check is not system app but do nothing");
        }

        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE || argc == ARGC_TWO, "invalid argument number",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], eventName);
        CHECK_STATUS_RETURN_VOID(context, "get event name failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        if (argc == ARGC_TWO) {
            callback = argv[ARGV_SECOND];
        }
    };

    context->GetCbInfo(env, info, input, true);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto it = EventHandlers_.find(eventName);
    if (it == EventHandlers_.end()) {
        SLOGE("event name invalid:%{public}s", eventName.c_str());
        NapiUtils::ThrowError(env, "event name invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
    if (napiCastController->callback_ == nullptr) {
        SLOGI("function %{public}s not register yet", eventName.c_str());
        return NapiUtils::GetUndefinedValue(env);
    }

    if (it->second.second(env, napiCastController, callback) != napi_ok) {
        NapiUtils::ThrowError(env, "remove event callback failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    }
    return NapiUtils::GetUndefinedValue(env);
}

napi_status NapiAVCastController::SetCastPlaybackStateFilter(napi_env env, NapiAVCastController *napiCastController,
    napi_value filter)
{
    AVPlaybackState::PlaybackStateMaskType playbackMask;
    auto status = NapiPlaybackState::ConvertFilter(env, filter, playbackMask);
    CHECK_RETURN(status == napi_ok, "convert filter failed", status);
    auto ret = napiCastController->castController_->SetCastPlaybackFilter(playbackMask);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("CastController SetCastPlaybackFilter failed:%{public}d", ret);
        status = napi_generic_failure;
    }
    return status;
}

napi_status NapiAVCastController::OnPlaybackStateChange(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    SLOGI("OnPlaybackStateChange");
    if (SetCastPlaybackStateFilter(env, napiCastController, param) != napi_ok) {
        return napi_generic_failure;
    }
    auto status = napiCastController->callback_->AddCallback(
        env, NapiAVCastControllerCallback::EVENT_CAST_PLAYBACK_STATE_CHANGE, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "OnPlaybackStateChange AddCallback failed");

    int32_t ret = napiCastController->castController_->AddAvailableCommand(
        AVCastControlCommand::CAST_CONTROL_CMD_PLAY_STATE_CHANGE);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "OnPlaybackStateChange add cmd failed");
    return napi_ok;
}

napi_status NapiAVCastController::OnMediaItemChange(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_MEDIA_ITEM_CHANGE, callback);
}

napi_status NapiAVCastController::OnPlayNext(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "NapiAVCastControllerCallback object is nullptr");
    auto status = napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_PLAY_NEXT, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "AddCallback failed");

    int32_t ret = napiCastController->castController_
        ->AddAvailableCommand(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add cmd failed");
    return napi_ok;
}

napi_status NapiAVCastController::OnPlayPrevious(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "NapiAVCastControllerCallback object is nullptr");
    auto status = napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_PLAY_PREVIOUS, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "AddCallback failed");

    int32_t ret = napiCastController->castController_
        ->AddAvailableCommand(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add cmd failed");
    return napi_ok;
}

napi_status NapiAVCastController::OnRequestPlay(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napi_ok;
}

napi_status NapiAVCastController::OnSeekDone(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "NapiAVCastControllerCallback object is nullptr");
    auto status = napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_SEEK_DONE, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "AddCallback failed");
    return napi_ok;
}

napi_status NapiAVCastController::OnValidCommandChange(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    SLOGI("OnValidCommandChange");
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "NapiAVCastControllerCallback object is nullptr");
    return napiCastController->callback_->AddCallback(
        env, NapiAVCastControllerCallback::EVENT_CAST_VALID_COMMAND_CHANGED, callback);
}

napi_status NapiAVCastController::OnVideoSizeChange(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_VIDEO_SIZE_CHANGE, callback);
}

napi_status NapiAVCastController::OnPlayerError(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_ERROR, callback);
}

napi_status NapiAVCastController::OnCastControlGenericError(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController != nullptr, napi_generic_failure, "napiCastController is nullptr");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, napi_generic_failure, "callback is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "napiCastController->callback_ is nullptr");
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_GENERIC_ERR, callback);
}

napi_status NapiAVCastController::OnCastControlIoError(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController != nullptr, napi_generic_failure, "napiCastController is nullptr");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, napi_generic_failure, "callback is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "napiCastController->callback_ is nullptr");
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_IO_ERR, callback);
}

napi_status NapiAVCastController::OnCastControlParsingError(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController != nullptr, napi_generic_failure, "napiCastController is nullptr");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, napi_generic_failure, "callback is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "napiCastController->callback_ is nullptr");
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_PARSING_ERR, callback);
}

napi_status NapiAVCastController::OnCastControlDecodingError(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController != nullptr, napi_generic_failure, "napiCastController is nullptr");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, napi_generic_failure, "callback is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "napiCastController->callback_ is nullptr");
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_DECOD_EERR, callback);
}

napi_status NapiAVCastController::OnCastControlAudioRendererError(napi_env env,
    NapiAVCastController* napiCastController, napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController != nullptr, napi_generic_failure, "napiCastController is nullptr");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, napi_generic_failure, "callback is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "napiCastController->callback_ is nullptr");
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_RENDER_ERR, callback);
}

napi_status NapiAVCastController::OnCastControlDrmError(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController != nullptr, napi_generic_failure, "napiCastController is nullptr");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, napi_generic_failure, "callback is nullptr");
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "napiCastController->callback_ is nullptr");
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_DRM_ERR, callback);
}

napi_status NapiAVCastController::OnEndOfStream(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_END_OF_STREAM, callback);
}

napi_status NapiAVCastController::OnPlayRequest(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_PLAY_REQUEST, callback);
}

napi_status NapiAVCastController::OnKeyRequest(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_KEY_REQUEST, callback);
}

napi_status NapiAVCastController::OffPlaybackStateChange(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    auto status = napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_PLAYBACK_STATE_CHANGE, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");

    if (napiCastController->callback_
            ->IsCallbacksEmpty(NapiAVCastControllerCallback::EVENT_CAST_PLAYBACK_STATE_CHANGE)) {
        int32_t ret = napiCastController->castController_
            ->RemoveAvailableCommand(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_STATE_CHANGE);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure,
            "remove stateChange cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVCastController::OffMediaItemChange(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_MEDIA_ITEM_CHANGE, callback);
}

napi_status NapiAVCastController::OffPlayNext(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    auto status = napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_PLAY_NEXT, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");

    if (napiCastController->callback_->IsCallbacksEmpty(NapiAVCastControllerCallback::EVENT_CAST_PLAY_NEXT)) {
        int32_t ret = napiCastController->castController_
            ->RemoveAvailableCommand(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_NEXT);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "add cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVCastController::OffPlayPrevious(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    auto status = napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_PLAY_PREVIOUS, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");

    if (napiCastController->callback_->IsCallbacksEmpty(NapiAVCastControllerCallback::EVENT_CAST_PLAY_PREVIOUS)) {
        int32_t ret = napiCastController->castController_
            ->RemoveAvailableCommand(AVCastControlCommand::CAST_CONTROL_CMD_PLAY_PREVIOUS);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, napi_generic_failure, "remove cmd failed");
    }
    return napi_ok;
}

napi_status NapiAVCastController::OffRequestPlay(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    return napi_ok;
}

napi_status NapiAVCastController::OffSeekDone(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    auto status = napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_SEEK_DONE, callback);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, status, "RemoveCallback failed");
    return napi_ok;
}

napi_status NapiAVCastController::OffValidCommandChange(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(
        napiCastController->callback_ != nullptr, napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(
        env, NapiAVCastControllerCallback::EVENT_CAST_VALID_COMMAND_CHANGED, callback);
}

napi_status NapiAVCastController::OffVideoSizeChange(napi_env env,
    NapiAVCastController* napiCastController, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_VIDEO_SIZE_CHANGE, callback);
}

napi_status NapiAVCastController::OffPlayerError(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_ERROR, callback);
}

napi_status NapiAVCastController::OffCastControlGenericError(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_GENERIC_ERR, callback);
}

napi_status NapiAVCastController::OffCastControlIoError(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_IO_ERR, callback);
}

napi_status NapiAVCastController::OffCastControlParsingError(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_PARSING_ERR, callback);
}

napi_status NapiAVCastController::OffCastControlDecodingError(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_DECOD_EERR, callback);
}

napi_status NapiAVCastController::OffCastControlAudioRendererError(napi_env env,
    NapiAVCastController* napiCastController, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_RENDER_ERR, callback);
}

napi_status NapiAVCastController::OffCastControlDrmError(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_DRM_ERR, callback);
}

napi_status NapiAVCastController::OffEndOfStream(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_END_OF_STREAM, callback);
}

napi_status NapiAVCastController::OffPlayRequest(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_PLAY_REQUEST, callback);
}

napi_status NapiAVCastController::OffKeyRequest(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_KEY_REQUEST, callback);
}

void NapiAVCastController::ErrCodeToMessage(int32_t errCode, std::string& message)
{
    switch (errCode) {
        case ERR_SESSION_NOT_EXIST:
            message = "SetSessionEvent failed : native session not exist";
            break;
        case ERR_CONTROLLER_NOT_EXIST:
            message = "SendCommonCommand failed : native controller not exist";
            break;
        case ERR_SESSION_DEACTIVE:
            message = "SendCommonCommand failed : native session is not active";
            break;
        case ERR_NO_PERMISSION:
            message = "SetSessionEvent failed : native no permission";
            break;
        default:
            message = "SetSessionEvent failed : native server exception";
            break;
    }
}

void NapiAVCastController::ReportStartFailInfo(int error)
{
    AVSessionRadarInfo info("NapiAVCastController::Start");
    info.errorCode_ = AVSessionRadar::GetRadarErrorCode(error);
    AVSessionRadar::GetInstance().StartPlayFailed(info);
}

void NapiAVCastController::ReportSendControlCommandFailInfo(int error)
{
    AVSessionRadarInfo info("NapiAVCastController::SendControlCommand");
    info.errorCode_ = AVSessionRadar::GetRadarErrorCode(error);
    AVSessionRadar::GetInstance().FailToSendControlCommand(info);
}

void NapiAVCastController::CheckSendCtrlCmdReportRadar(bool condition, int32_t error)
{
    if (!condition) {
        ReportSendControlCommandFailInfo(error);
    }
}

void NapiAVCastController::CheckStartReportRadar(bool condition, int32_t error)
{
    if (!condition) {
        ReportStartFailInfo(error);
    }
}

std::string NapiAVCastController::GetSendControlCommandErrMsg(int32_t error)
{
    std::string msg;
    switch (error) {
        case ERR_SESSION_NOT_EXIST:
            msg = "SendControlCommand failed : native session not exist";
            break;
        case ERR_CONTROLLER_NOT_EXIST:
            msg = "SendControlCommand failed : native controller not exist";
            break;
        case ERR_SESSION_DEACTIVE:
            msg = "SendControlCommand failed : native session is not active";
            break;
        case ERR_NO_PERMISSION:
            msg = "SendControlCommand failed : native no permission";
            break;
        case ERR_COMMAND_NOT_SUPPORT:
            msg = "SendControlCommand failed : native command not support";
            break;
        case ERR_COMMAND_SEND_EXCEED_MAX:
            msg = "SendControlCommand failed : native command send nums overload";
            break;
        default:
            msg = "SendControlCommand failed : native server exception";
            break;
    }
    return msg;
}
} // namespace OHOS::AVSession
