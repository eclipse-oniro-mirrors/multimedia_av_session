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

namespace OHOS::AVSession {
static __thread napi_ref AVCastControllerConstructorRef = nullptr;
std::map<std::string, std::pair<NapiAVCastController::OnEventHandlerType,
    NapiAVCastController::OffEventHandlerType>> NapiAVCastController::EventHandlers_ = {
    { "stateChange", { OnStateChanged, OffStateChange } },
    { "mediaItemChange", { OnMediaItemChanged, OffMediaItemChange } },
    { "volumeChange", { OnVolumeChanged, OffVolumeChange } },
    { "loopModeChange", { OnLoopModeChanged, OffLoopModeChange } },
    { "playSpeedChange", { OnPlaySpeedChanged, OffPlaySpeedChange } },
    { "positionChange", { OnPositionChanged, OffPositionChange } }, // seek done -> positionChange
    { "videoSizeChange", { OnVideoSizeChanged, OffVideoSizeChange } }, // timeUpdate -> videoSizeChange
    { "error", { OnPlayerError, OffError } },
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
        DECLARE_NAPI_FUNCTION("setMediaList", SetMediaList),
        DECLARE_NAPI_FUNCTION("updateMediaInfo", UpdateMediaInfo),
        DECLARE_NAPI_FUNCTION("sendControlCommand", SendControlCommand),
        DECLARE_NAPI_FUNCTION("getDuration", GetDuration),
        DECLARE_NAPI_FUNCTION("getPosition", GetPosition),
        DECLARE_NAPI_FUNCTION("getVolume", GetVolume),
        DECLARE_NAPI_FUNCTION("getLoopMode", GetLoopMode),
        DECLARE_NAPI_FUNCTION("getPlaySpeed", GetPlaySpeed),
        DECLARE_NAPI_FUNCTION("getPlayState", GetPlayState),
        DECLARE_NAPI_FUNCTION("setDisplaySurface", SetDisplaySurface),
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
    };

    auto* napiCastController = new(std::nothrow) NapiAVCastController();
    if (napiCastController == nullptr) {
        SLOGE("no memory");
        return nullptr;
    }
    if (napi_wrap(env, self, static_cast<void*>(napiCastController), finalize, nullptr,
        &(napiCastController->wrapperRef_)) != napi_ok) {
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

napi_value NapiAVCastController::SetMediaList(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastController::Start");
    struct ConcreteContext : public ContextBase {
        MediaInfoHolder mediaInfoHolder_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("Start failed : no memory");
        NapiUtils::ThrowError(env, "Start failed : no memory",
            NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "Invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->mediaInfoHolder_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "Get play info holder failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
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
            return;
        }
        int32_t ret = napiCastController->castController_->SetMediaList(context->mediaInfoHolder_);
        if (ret != AVSESSION_SUCCESS) {
            ErrCodeToMessage(ret, context->errMessage);
            SLOGE("CastController Start failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "Start", executor, complete);
}

napi_value NapiAVCastController::UpdateMediaInfo(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastController::UpdateMediaInfo");
    struct ConcreteContext : public ContextBase {
        MediaInfo mediaInfo_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("UpdateMediaInfo failed : no memory");
        NapiUtils::ThrowError(env, "UpdateMediaInfo failed : no memory",
            NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "Invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->mediaInfo_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "Get play info holder failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, inputParser);
    context->taskId = NAPI_CAST_CONTROLLER_UPDATE_MEDIA_INFO_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("Start failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "Start failed : castController_ is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->UpdateMediaInfo(context->mediaInfo_);
        if (ret != AVSESSION_SUCCESS) {
            ErrCodeToMessage(ret, context->errMessage);
            SLOGE("CastController UpdateMediaInfo failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "UpdateMediaInfo", executor, complete);
}


napi_value NapiAVCastController::SendControlCommand(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVCastController::SendControlCommand");
    struct ConcrentContext : public ContextBase {
        AVCastControlCommand castCommand_;
    };
    auto context = std::make_shared<ConcrentContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiCastControlCommand::GetValue(env, argv[ARGV_FIRST], context->castCommand_);
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
            return;
        }
        int32_t ret = napiCastController->castController_->SendControlCommand(context->castCommand_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SendControlCommand failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "SendControlCommand failed : native controller not exist";
            } else if (ret == ERR_SESSION_DEACTIVE) {
                context->errMessage = "SendControlCommand failed : native session is not active";
            } else if (ret == ERR_COMMAND_NOT_SUPPORT) {
                context->errMessage = "SendControlCommand failed : native command not support";
            } else if (ret == ERR_COMMAND_SEND_EXCEED_MAX) {
                context->errMessage = "SendControlCommand failed : native command send nums overload";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SendControlCommand failed : native no permission";
            } else {
                context->errMessage = "SendControlCommand failed : native server exception";
            }
            SLOGE("controller SendControlCommand failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "SendControlCommand", executor);
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

napi_value NapiAVCastController::GetPosition(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        int32_t position;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_CAST_CONTROLLER_GET_POSITION_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("GetPosition failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetPosition failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->GetPosition(context->position);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetPosition failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetPosition failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetPosition failed : native no permission";
            } else {
                context->errMessage = "GetPosition failed : native server exception";
            }
            SLOGE("controller GetPosition failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->position, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetPosition", executor, complete);
}

napi_value NapiAVCastController::GetVolume(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        int32_t volume;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_CAST_CONTROLLER_GET_VOLUME_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("GetVolume failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetVolume failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->GetVolume(context->volume);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetVolume failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetVolume failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetVolume failed : native no permission";
            } else {
                context->errMessage = "GetVolume failed : native server exception";
            }
            SLOGE("controller GetVolume failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->volume, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetVolume", executor, complete);
}

napi_value NapiAVCastController::GetLoopMode(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        int32_t loopMode;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_CAST_CONTROLLER_GET_LOOPMODE_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("GetLoopMode failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetLoopMode failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->GetLoopMode(context->loopMode);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetLoopMode failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetLoopMode failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetLoopMode failed : native no permission";
            } else {
                context->errMessage = "GetLoopMode failed : native server exception";
            }
            SLOGE("controller GetLoopMode failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->loopMode, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetLoopMode", executor, complete);
}

napi_value NapiAVCastController::GetPlaySpeed(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        int32_t playSpeed;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_CAST_CONTROLLER_GET_PLAY_SPEED_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("GetPlaySpeed failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetPlaySpeed failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->GetPlaySpeed(context->playSpeed);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetPlaySpeed failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetPlaySpeed failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetPlaySpeed failed : native no permission";
            } else {
                context->errMessage = "GetPlaySpeed failed : native server exception";
            }
            SLOGE("controller GetPlaySpeed failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->playSpeed, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetPlaySpeed", executor, complete);
}

napi_value NapiAVCastController::GetPlayState(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        AVCastPlayerState playerState;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);
    context->taskId = NAPI_CAST_CONTROLLER_GET_PLAY_STATE_TASK_ID;

    auto executor = [context]() {
        auto* napiCastController = reinterpret_cast<NapiAVCastController*>(context->native);
        if (napiCastController->castController_ == nullptr) {
            SLOGE("GetPlayState failed : controller is nullptr");
            context->status = napi_generic_failure;
            context->errMessage = "GetPlayState failed : controller is nullptr";
            context->errCode = NapiAVSessionManager::errcode_[ERR_CONTROLLER_NOT_EXIST];
            return;
        }
        int32_t ret = napiCastController->castController_->GetPlayState(context->playerState);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetPlayState failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_NOT_EXIST) {
                context->errMessage = "GetPlayState failed : native controller not exist";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetPlayState failed : native no permission";
            } else {
                context->errMessage = "GetPlayState failed : native server exception";
            }
            SLOGE("controller GetPlayState failed:%{public}d", ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->playerState, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetPlayState", executor, complete);
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
        napiCastController->callback_= std::make_shared<NapiAVCastControllerCallback>();
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
            CHECK_ARGS_RETURN_VOID(context, argc == ARGC_THERE, "invalid argument number",
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
        CHECK_ARGS_RETURN_VOID(context, isSystemApp, "Check system permission error",
            NapiAVSessionManager::errcode_[ERR_NO_PERMISSION]);

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

napi_status NapiAVCastController::OnStateChanged(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_STATE_CHANGE, callback);
}

napi_status NapiAVCastController::OnMediaItemChanged(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_STATE_CHANGE, callback);
}

napi_status NapiAVCastController::OnVolumeChanged(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_VOLUME_CHANGE, callback);
}

napi_status NapiAVCastController::OnLoopModeChanged(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_LOOP_MODE_CHANGE, callback);
}

napi_status NapiAVCastController::OnPlaySpeedChanged(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_PLAY_SPEED_CHANGE, callback);
}

napi_status NapiAVCastController::OnPositionChanged(napi_env env, NapiAVCastController* napiCastController,
    napi_value param, napi_value callback)
{
    return napiCastController->callback_->AddCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_POSITON_CHANGE, callback);
}

napi_status NapiAVCastController::OnVideoSizeChanged(napi_env env, NapiAVCastController* napiCastController,
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

napi_status NapiAVCastController::OffStateChange(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env, NapiAVCastControllerCallback::EVENT_CAST_STATE_CHANGE,
        callback);
}

napi_status NapiAVCastController::OffMediaItemChange(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_MEDIA_ITEM_CHANGE, callback);
}

napi_status NapiAVCastController::OffVolumeChange(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_VOLUME_CHANGE, callback);
}

napi_status NapiAVCastController::OffLoopModeChange(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_LOOP_MODE_CHANGE, callback);
}

napi_status NapiAVCastController::OffPlaySpeedChange(napi_env env,
    NapiAVCastController* napiCastController, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr, napi_generic_failure,
        "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_PLAY_SPEED_CHANGE, callback);
}

napi_status NapiAVCastController::OffPositionChange(napi_env env, NapiAVCastController* napiCastController,
    napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_POSITON_CHANGE, callback);
}

napi_status NapiAVCastController::OffVideoSizeChange(napi_env env,
    NapiAVCastController* napiCastController, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_VIDEO_SIZE_CHANGE, callback);
}

napi_status NapiAVCastController::OffError(napi_env env, NapiAVCastController* napiCastController, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(napiCastController->callback_ != nullptr,
        napi_generic_failure, "callback has not been registered");
    return napiCastController->callback_->RemoveCallback(env,
        NapiAVCastControllerCallback::EVENT_CAST_ERROR, callback);
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
} // namespace OHOS::AVSession
