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

#include "napi_avsession_manager.h"
#include "avcontrol_command.h"
#include "avplayback_state.h"
#include "avsession_errors.h"
#include "key_event.h"
#include "ability.h"
#include "napi_base_context.h"
#include "napi_utils.h"
#include "napi_async_work.h"
#include "napi_avsession.h"
#include "napi_avsession_controller.h"
#include "napi_control_command.h"
#include "avsession_trace.h"
#include "avsession_sysevent.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "avsession_radar.h"
#include "permission_checker.h"

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include "napi_avcast_controller.h"
#endif

namespace OHOS::AVSession {
using namespace Security::AccessToken;
std::map<std::string, std::pair<NapiAVSessionManager::OnEventHandlerType, NapiAVSessionManager::OffEventHandlerType>>
    NapiAVSessionManager::eventHandlers_ = {
    { "sessionCreate", { OnSessionCreate, OffSessionCreate } },
    { "sessionDestroy", { OnSessionDestroy, OffSessionDestroy } },
    { "topSessionChange", { OnTopSessionChange, OffTopSessionChange } },
    { "sessionServiceDie", { OnServiceDie, OffServiceDie } },
    { "deviceAvailable", { OnDeviceAvailable, OffDeviceAvailable } },
    { "deviceLogEvent", { OnDeviceLogEvent, OffDeviceLogEvent } },
    { "deviceOffline", { OnDeviceOffline, OffDeviceOffline } },
};

std::map<DistributedSessionType, std::pair<NapiAVSessionManager::OnEventHandlerType,
    NapiAVSessionManager::OffEventHandlerType>> NapiAVSessionManager::distributedControllerEventHandlers_ = {
    { DistributedSessionType::TYPE_SESSION_REMOTE, {
        OnRemoteDistributedSessionChange, OffRemoteDistributedSessionChange } },
};

const std::string NapiAVSessionManager::DISTRIBUTED_SESSION_CHANGE_EVENT = "distributedSessionChange";

std::shared_ptr<NapiSessionListener> NapiAVSessionManager::listener_;
std::shared_ptr<NapiAsyncCallback> NapiAVSessionManager::asyncCallback_;
std::list<napi_ref> NapiAVSessionManager::serviceDiedCallbacks_;
std::mutex createControllerMutex_;
std::mutex listenerMutex_;

std::map<int32_t, int32_t> NapiAVSessionManager::errcode_ = {
    {AVSESSION_ERROR, 6600101},
    {ERR_NO_MEMORY, 6600101},
    {ERR_SERVICE_NOT_EXIST, 6600101},
    {ERR_SESSION_LISTENER_EXIST, 6600101},
    {ERR_MARSHALLING, 6600101},
    {ERR_UNMARSHALLING, 6600101},
    {ERR_IPC_SEND_REQUEST, 6600101},
    {ERR_CONTROLLER_IS_EXIST, 6600101},
    {ERR_START_ABILITY_IS_RUNNING, 6600101},
    {ERR_ABILITY_NOT_AVAILABLE, 6600101},
    {ERR_START_ABILITY_TIMEOUT, 6600101},
    {ERR_SESSION_NOT_EXIST, 6600102},
    {ERR_CONTROLLER_NOT_EXIST, 6600103},
    {ERR_RPC_SEND_REQUEST, 6600104},
    {ERR_COMMAND_NOT_SUPPORT, 6600105},
    {ERR_SESSION_DEACTIVE, 6600106},
    {ERR_COMMAND_SEND_EXCEED_MAX, 6600107},
    {ERR_DEVICE_CONNECTION_FAILED, 6600108},
    {ERR_REMOTE_CONNECTION_NOT_EXIST, 6600109},
    {ERR_SESSION_IS_EXIST, 6600101},
    {ERR_PERMISSION_DENIED, 201},
    {ERR_NO_PERMISSION, 202},
    {ERR_INVALID_PARAM, 401},
};
napi_value NapiAVSessionManager::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createAVSession", CreateAVSession),
        DECLARE_NAPI_STATIC_FUNCTION("getAllSessionDescriptors", GetAllSessionDescriptors),
        DECLARE_NAPI_STATIC_FUNCTION("getHistoricalSessionDescriptors", GetHistoricalSessionDescriptors),
        DECLARE_NAPI_STATIC_FUNCTION("getHistoricalAVQueueInfos", GetHistoricalAVQueueInfos),
        DECLARE_NAPI_STATIC_FUNCTION("startAVPlayback", StartAVPlayback),
        DECLARE_NAPI_STATIC_FUNCTION("createController", CreateController),
        DECLARE_NAPI_STATIC_FUNCTION("getAVCastController", GetAVCastController),
        DECLARE_NAPI_STATIC_FUNCTION("castAudio", CastAudio),
        DECLARE_NAPI_STATIC_FUNCTION("on", OnEvent),
        DECLARE_NAPI_STATIC_FUNCTION("off", OffEvent),
        DECLARE_NAPI_STATIC_FUNCTION("sendSystemAVKeyEvent", SendSystemAVKeyEvent),
        DECLARE_NAPI_STATIC_FUNCTION("sendSystemControlCommand", SendSystemControlCommand),
        DECLARE_NAPI_STATIC_FUNCTION("startCastDeviceDiscovery", StartCastDiscovery),
        DECLARE_NAPI_STATIC_FUNCTION("stopCastDeviceDiscovery", StopCastDiscovery),
        DECLARE_NAPI_STATIC_FUNCTION("startDeviceLogging", StartDeviceLogging),
        DECLARE_NAPI_STATIC_FUNCTION("stopDeviceLogging", StopDeviceLogging),
        DECLARE_NAPI_STATIC_FUNCTION("setDiscoverable", SetDiscoverable),
        DECLARE_NAPI_STATIC_FUNCTION("startCasting", StartCast),
        DECLARE_NAPI_STATIC_FUNCTION("stopCasting", StopCast),
        DECLARE_NAPI_STATIC_FUNCTION("getDistributedSessionController", GetDistributedSessionControllers),
    };

    napi_status status = napi_define_properties(env, exports, sizeof(descriptors) / sizeof(napi_property_descriptor),
                                                descriptors);
    if (status != napi_ok) {
        SLOGE("define manager properties failed");
        return NapiUtils::GetUndefinedValue(env);
    }
    return exports;
}

napi_value NapiAVSessionManager::CreateAVSession(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::CreateAVSession");
    struct ConcreteContext : public ContextBase {
        std::string tag_;
        int32_t type_{};
        AppExecFwk::ElementName elementName_;
        std::shared_ptr<AVSession> session_;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->taskId = NAPI_CREATE_AVSESSION_TASK_ID;

    auto inputParser = [env, context](size_t argc, napi_value* argv) {
        // require 3 arguments <context> <tag> <type>
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_THREE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->elementName_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "invalid context",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_SECOND], context->tag_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok && !context->tag_.empty(), "invalid tag",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        std::string typeString;
        context->status = NapiUtils::GetValue(env, argv[ARGV_THIRD], typeString);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok && !typeString.empty(), "invalid type",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->type_ = NapiUtils::ConvertSessionType(typeString);
        CHECK_ARGS_RETURN_VOID(context, context->type_ >= 0, "wrong session type",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = napi_ok;
    };
    context->GetCbInfo(env, info, inputParser);

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().CreateSession(context->tag_, context->type_,
                                                                    context->elementName_, context->session_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_SESSION_IS_EXIST) {
                context->errMessage = "CreateAVSession failed : session is existed";
            } else {
                context->errMessage = "CreateAVSession failed : native create session failed";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [context](napi_value& output) {
        context->status = NapiAVSession::NewInstance(context->env, context->session_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };

    return NapiAsyncWork::Enqueue(env, context, "CreateAVSession", executor, complete);
}

napi_value NapiAVSessionManager::GetAllSessionDescriptors(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        std::vector<AVSessionDescriptor> descriptors_;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().GetAllSessionDescriptors(context->descriptors_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetAllSessionDescriptors failed : native no permission";
            } else if (ret == ERR_PERMISSION_DENIED) {
                context->errMessage = "GetAllSessionDescriptors failed : native permission denied";
            } else {
                context->errMessage = "GetAllSessionDescriptors failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->descriptors_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetAllSessionDescriptors", executor, complete);
}

napi_value NapiAVSessionManager::GetHistoricalSessionDescriptors(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        int32_t maxSize_ {};
        std::vector<AVSessionDescriptor> descriptors_;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto input = [env, context](size_t argc, napi_value* argv) {
        if (argc == ARGC_ONE && !NapiUtils::TypeCheck(env, argv[ARGV_FIRST], napi_undefined)
            && !NapiUtils::TypeCheck(env, argv[ARGV_FIRST], napi_null)) {
            context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->maxSize_);
            CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "invalid arguments",
                NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            CHECK_ARGS_RETURN_VOID(context,
                (context->maxSize_ >= static_cast<int32_t>(HISTORICAL_MIN_NUM)
                && context->maxSize_ <= static_cast<int32_t>(HISTORICAL_MAX_NUM)),
                "invalid arguments", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        } else {
            context->maxSize_ = HISTORICAL_UNSET_NUM;
        }
    };

    context->GetCbInfo(env, info, input);

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().GetHistoricalSessionDescriptors(context->maxSize_,
            context->descriptors_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetHistoricalSessionDescriptors failed : native no permission";
            } else if (ret == ERR_PERMISSION_DENIED) {
                context->errMessage = "GetHistoricalSessionDescriptors failed : native permission denied";
            } else {
                context->errMessage = "GetHistoricalSessionDescriptors failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->descriptors_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetHistoricalSessionDescriptors", executor, complete);
}

napi_value NapiAVSessionManager::GetHistoricalAVQueueInfos(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        int32_t maxSize_ {};
        int32_t maxAppSize_ {};
        std::vector<AVQueueInfo> avQueueInfos_;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto input = [env, context](size_t argc, napi_value* argv) {
        if (argc == ARGC_TWO && (!NapiUtils::TypeCheck(env, argv[ARGV_FIRST], napi_undefined)
            && !NapiUtils::TypeCheck(env, argv[ARGV_FIRST], napi_null)
            && !NapiUtils::TypeCheck(env, argv[ARGV_SECOND], napi_undefined)
            && !NapiUtils::TypeCheck(env, argv[ARGV_SECOND], napi_null))) {
            context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->maxSize_);
            CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, " get avqueueinfo invalid maxSize",
                NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);

            context->status = NapiUtils::GetValue(env, argv[ARGV_SECOND], context->maxAppSize_);
            CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, " get avqueueinfo invalid maxAppSize",
                NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        }
    };

    context->GetCbInfo(env, info, input);

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().GetHistoricalAVQueueInfos(context->maxSize_,
            context->maxAppSize_, context->avQueueInfos_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetHistoricalAVQueueInfos failed : native no permission";
            } else if (ret == ERR_PERMISSION_DENIED) {
                context->errMessage = "GetHistoricalAVQueueInfos failed : native permission denied";
            } else {
                context->errMessage = "GetHistoricalAVQueueInfos failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->avQueueInfos_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetHistoricalAVQueueInfos", executor, complete);
}

napi_value NapiAVSessionManager::StartAVPlayback(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        std::string bundleName_ {};
        std::string assetId_ {};
    };
    auto context = std::make_shared<ConcreteContext>();

    auto input = [env, context](size_t argc, napi_value* argv) {
        if (argc == ARGC_TWO && (!NapiUtils::TypeCheck(env, argv[ARGV_FIRST], napi_undefined)
            && !NapiUtils::TypeCheck(env, argv[ARGV_FIRST], napi_null)
            && !NapiUtils::TypeCheck(env, argv[ARGV_SECOND], napi_undefined)
            && !NapiUtils::TypeCheck(env, argv[ARGV_SECOND], napi_null))) {
            context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->bundleName_);
            CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok && !context->bundleName_.empty(),
              " StartAVPlayback invalid bundlename", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            
            context->status = NapiUtils::GetValue(env, argv[ARGV_SECOND], context->assetId_);
            CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, " StartAVPlayback invalid assetId",
                NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        }
    };

    context->GetCbInfo(env, info, input);

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().StartAVPlayback(context->bundleName_, context->assetId_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "StartAVPlayback failed : native no permission";
            } else if (ret == ERR_PERMISSION_DENIED) {
                context->errMessage = "StartAVPlayback failed : native permission denied";
            } else {
                context->errMessage = "StartAVPlayback failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "StartAVPlayback", executor);
}

napi_value NapiAVSessionManager::GetDistributedSessionControllers(napi_env env, napi_callback_info info)
{
    SLOGI("GetDistributedSessionControllers");
    struct ConcreteContext : public ContextBase {
        DistributedSessionType sessionType_ {};
        std::vector<std::shared_ptr<AVSessionController>> controllers_;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto input = [env, context](size_t argc, napi_value* argv) {
        int32_t err = PermissionChecker::GetInstance().CheckPermission(
            PermissionChecker::CHECK_SYSTEM_PERMISSION);
        CHECK_ARGS_RETURN_VOID(context, err == ERR_NONE, "Check system permission error",
            NapiAVSessionManager::errcode_[ERR_NO_PERMISSION]);
        if (argc == ARGC_ONE && (!NapiUtils::TypeCheck(env, argv[ARGV_FIRST], napi_undefined)
            && !NapiUtils::TypeCheck(env, argv[ARGV_FIRST], napi_null))) {
            int32_t sessionTypeValue;
            context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], sessionTypeValue);
            context->sessionType_ = DistributedSessionType(sessionTypeValue);
            CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok &&
                context->sessionType_ >= DistributedSessionType::TYPE_SESSION_REMOTE &&
                context->sessionType_ < DistributedSessionType::TYPE_SESSION_MAX,
                "GetDistributedSessionControllers invalid sessionType",
                NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        }
    };

    context->GetCbInfo(env, info, input);

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().GetDistributedSessionControllers(
            context->sessionType_, context->controllers_);
        SLOGI("GetDistributedSessionControllers executor ret: %{public}d, controller size: %{public}d", ret,
            (int) context->controllers_.size());
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetDistributedSessionControllers failed : native no permission";
            } else if (ret == ERR_PERMISSION_DENIED) {
                context->errMessage = "GetDistributedSessionControllers failed : native permission denied";
            } else {
                context->errMessage = "GetDistributedSessionControllers failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiUtils::SetValue(env, context->controllers_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
                                 NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "GetDistributedSessionControllers", executor, complete);
}

napi_value NapiAVSessionManager::CreateController(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::CreateController");
    struct ConcreteContext : public ContextBase {
        std::string sessionId_ {};
        std::shared_ptr<AVSessionController> controller_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->sessionId_);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (!context->sessionId_.empty()),
                               "invalid sessionId", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_CREATE_CONTROLLER_TASK_ID;
    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().CreateController(context->sessionId_, context->controller_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "CreateController failed : native no permission";
            } else if (ret == ERR_PERMISSION_DENIED) {
                context->errMessage = "CreateController failed : native permission denied";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "CreateController failed : native invalid parameters";
            } else if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "CreateController failed : native session not exist";
            } else if (ret == ERR_CONTROLLER_IS_EXIST) {
                SLOGE("create controlller with already has one");
                context->errCode = ERR_CONTROLLER_IS_EXIST;
                return;
            } else {
                context->errMessage = "CreateController failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env, context](napi_value& output) {
        SLOGE("check create controller with errCode %{public}d", static_cast<int>(context->errCode));
        std::lock_guard lockGuard(createControllerMutex_);
        if (context->errCode == ERR_CONTROLLER_IS_EXIST) {
            SLOGE("check create controller meet repeat for sessionId: %{public}s", context->sessionId_.c_str());
            context->status = NapiAVSessionController::RepeatedInstance(env, context->sessionId_, output);
        } else {
            context->status = NapiAVSessionController::NewInstance(env, context->controller_, output);
        }
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };
    return NapiAsyncWork::Enqueue(env, context, "CreateController", executor, complete);
}

napi_value NapiAVSessionManager::GetAVCastController(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::GetAVCastController");
    struct ConcreteContext : public ContextBase {
        std::string sessionId_ {};
        std::shared_ptr<AVCastController> castController_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->sessionId_);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (!context->sessionId_.empty()),
            "invalid sessionId", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_CREATE_CAST_CONTROLLER_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().GetAVCastController(context->sessionId_,
            context->castController_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "GetAVCastController failed : native no permission";
            } else if (ret == ERR_PERMISSION_DENIED) {
                context->errMessage = "GetAVCastController failed : native permission denied";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "GetAVCastController failed : native invalid parameters";
            } else if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "GetAVCastController failed : native session not exist";
            } else {
                context->errMessage = "GetAVCastController failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    auto complete = [env, context](napi_value& output) {
        context->status = NapiAVCastController::NewInstance(env, context->castController_, output);
        CHECK_STATUS_RETURN_VOID(context, "convert native object to javascript object failed",
            NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetAVCastController", executor, complete);
#else
    return nullptr;
#endif
}

napi_value NapiAVSessionManager::CastAudio(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::CastAudio");
    struct ConcreteContext : public ContextBase {
        SessionToken sessionToken_ {};
        bool isAll_ = false;
        std::vector<AudioStandard::AudioDeviceDescriptor> audioDeviceDescriptors_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_TWO, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        napi_valuetype type = napi_undefined;
        context->status = napi_typeof(env, argv[ARGV_FIRST], &type);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_string || type == napi_object),
                               "invalid type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        if (type == napi_string) {
            std::string flag;
            context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], flag);
            CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (flag == "all"),
                                   "invalid argument", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            context->isAll_ = true;
        }
        if (type == napi_object) {
            context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->sessionToken_);
            CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (!context->sessionToken_.sessionId.empty()),
                                   "invalid session token", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        }
        context->status = NapiUtils::GetValue(env, argv[ARGV_SECOND], context->audioDeviceDescriptors_);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (context->audioDeviceDescriptors_.size() > 0),
                               "invalid AudioDeviceDescriptor", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_CAST_AUDIO_TASK_ID;
    auto executor = [context]() {
        int32_t ret = AVSESSION_ERROR;
        if (context->isAll_) {
            ret = AVSessionManager::GetInstance().CastAudioForAll(context->audioDeviceDescriptors_);
        } else {
            ret = AVSessionManager::GetInstance().CastAudio(context->sessionToken_, context->audioDeviceDescriptors_);
        }
        if (ret != AVSESSION_SUCCESS) {
            ErrCodeToMessage(ret, "CastAudio", context->errMessage);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    auto complete = [env](napi_value& output) { output = NapiUtils::GetUndefinedValue(env); };
    return NapiAsyncWork::Enqueue(env, context, "CastAudio", executor, complete);
}

void NapiAVSessionManager::ErrCodeToMessage(int32_t errCode, const std::string& tag, std::string& message)
{
    message = tag;
    SLOGE("check error code for message:%{public}d", errCode);
    switch (errCode) {
        case ERR_SESSION_NOT_EXIST:
            message.append(" failed : native session not exist");
            break;
        case ERR_INVALID_PARAM:
            message.append(" failed : native invalid parameters");
            break;
        case ERR_NO_PERMISSION:
            message.append(" failed : native no permission");
            break;
        case ERR_PERMISSION_DENIED:
            message.append(" failed : native permission denied");
            break;
        default:
            message.append(" failed : native server exception");
            break;
    }
}

napi_status NapiAVSessionManager::RegisterNativeSessionListener(napi_env env)
{
    std::lock_guard lockGuard(listenerMutex_);
    if (listener_ != nullptr) {
        return napi_ok;
    }

    listener_ = std::make_shared<NapiSessionListener>();
    if (AVSessionManager::GetInstance().RegisterServiceDeathCallback(HandleServiceDied) != AVSESSION_SUCCESS) {
        SLOGE("register service death callback fail!");
        return napi_generic_failure;
    }
    if (listener_ == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return napi_generic_failure;
    }
    int32_t ret = AVSessionManager::GetInstance().RegisterSessionListener(listener_);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("native register session listener failed");
        if (ret == ERR_INVALID_PARAM) {
            NapiUtils::ThrowError(env, "OnEvent failed : native invalid parameters",
                NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        } else if (ret == ERR_NO_PERMISSION) {
            NapiUtils::ThrowError(env, "OnEvent failed : native no permission",
                NapiAVSessionManager::errcode_[ERR_NO_PERMISSION]);
        } else {
            NapiUtils::ThrowError(env, "OnEvent failed : native server exception",
                NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
        }
        return napi_generic_failure;
    }

    return napi_ok;
}

napi_value NapiAVSessionManager::OnEvent(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OnEvent failed : no memory");
        NapiUtils::ThrowError(env, "OnEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    std::string eventName;
    napi_value callback = nullptr;
    auto input = [&eventName, &callback, env, &context](size_t argc, napi_value* argv) {
        int32_t err = PermissionChecker::GetInstance().CheckPermission(
            PermissionChecker::CHECK_SYSTEM_PERMISSION);
        CHECK_ARGS_RETURN_VOID(context, err == ERR_NONE, "Check system permission error",
            NapiAVSessionManager::errcode_[ERR_NO_PERMISSION]);
        /* require 2 arguments <event, callback> */
        CHECK_ARGS_RETURN_VOID(context, argc >= ARGC_TWO, "invalid argument number",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], eventName);
        CHECK_STATUS_RETURN_VOID(context, "get event name failed", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        CHECK_RETURN_VOID(eventName != DISTRIBUTED_SESSION_CHANGE_EVENT,
                          "no need process the distributed session changed event");
        napi_valuetype type = napi_undefined;
        context->status = napi_typeof(env, argv[ARGV_SECOND], &type);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_function),
                               "callback type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        callback = argv[ARGV_SECOND];
    };

    context->GetCbInfo(env, info, input, true);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    if (eventName == DISTRIBUTED_SESSION_CHANGE_EVENT) {
        return OnDistributedSessionChangeEvent(env, info);
    }

    auto it = eventHandlers_.find(eventName);
    if (it == eventHandlers_.end()) {
        SLOGE("event name invalid");
        NapiUtils::ThrowError(env, "event name invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return NapiUtils::GetUndefinedValue(env);
    }

    if (RegisterNativeSessionListener(env) == napi_generic_failure) {
        return NapiUtils::GetUndefinedValue(env);
    }

    if (it->second.first(env, callback) != napi_ok) {
        NapiUtils::ThrowError(env, "add event callback failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    }

    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSessionManager::OffEvent(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("OffEvent failed : no memory");
        NapiUtils::ThrowError(env, "OffEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    std::string eventName;
    napi_value callback = nullptr;
    auto input = [&eventName, env, &context, &callback](size_t argc, napi_value* argv) {
        int32_t err = PermissionChecker::GetInstance().CheckPermission(
            PermissionChecker::CHECK_SYSTEM_PERMISSION);
        CHECK_ARGS_RETURN_VOID(context, err == ERR_NONE, "Check system permission error",
            NapiAVSessionManager::errcode_[ERR_NO_PERMISSION]);
        CHECK_ARGS_RETURN_VOID(context, argc >= ARGC_ONE || argc <= ARGC_THREE, "invalid argument number",
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

    if (eventName == DISTRIBUTED_SESSION_CHANGE_EVENT) {
        return OffDistributedSessionChangeEvent(env, info);
    }

    auto it = eventHandlers_.find(eventName);
    if (it == eventHandlers_.end()) {
        SLOGE("event name invalid");
        NapiUtils::ThrowError(env, "event name invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return NapiUtils::GetUndefinedValue(env);
    }

    if (it->second.second(env, callback) != napi_ok) {
        NapiUtils::ThrowError(env, "remove event callback failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    }

    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSessionManager::OnDistributedSessionChangeEvent(napi_env env, napi_callback_info info)
{
    SLOGI("OnDistributedSessionChangeEvent");
    struct ConcreteContext : public ContextBase {
        DistributedSessionType sessionType_ {};
        napi_value callback_ = nullptr;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        NapiUtils::ThrowError(env, "OnSessionEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto input = [env, &context](size_t argc, napi_value* argv) {
        int32_t err = PermissionChecker::GetInstance().CheckPermission(
            PermissionChecker::CHECK_SYSTEM_PERMISSION);
        CHECK_ARGS_RETURN_VOID(context, err == ERR_NONE, "Check system permission error",
            NapiAVSessionManager::errcode_[ERR_NO_PERMISSION]);
        /* require 3 arguments <event, callback> */
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_THREE, "invalid argument number",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        int32_t sessionTypeValue;
        context->status = NapiUtils::GetValue(env, argv[ARGV_SECOND], sessionTypeValue);
        CHECK_STATUS_RETURN_VOID(context, "get session type failed", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->sessionType_ = DistributedSessionType(sessionTypeValue);
        CHECK_ARGS_RETURN_VOID(context, context->sessionType_ >= DistributedSessionType::TYPE_SESSION_REMOTE &&
            context->sessionType_ < DistributedSessionType::TYPE_SESSION_MAX,
            "GetDistributedSessionControllers invalid sessionType",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        napi_valuetype type = napi_undefined;
        context->status = napi_typeof(env, argv[ARGV_THIRD], &type);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_function),
                               "callback type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->callback_ = argv[ARGV_THIRD];
    };

    context->GetCbInfo(env, info, input, true);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto it = distributedControllerEventHandlers_.find(context->sessionType_);
    if (it == distributedControllerEventHandlers_.end()) {
        NapiUtils::ThrowError(env, "session type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return NapiUtils::GetUndefinedValue(env);
    }

    if (RegisterNativeSessionListener(env) == napi_generic_failure) {
        return NapiUtils::GetUndefinedValue(env);
    }

    if (it->second.first(env, context->callback_) != napi_ok) {
        NapiUtils::ThrowError(env, "add event callback failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    }

    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSessionManager::OffDistributedSessionChangeEvent(napi_env env, napi_callback_info info)
{
    SLOGI("OffDistributedSessionChangeEvent");
    struct ConcreteContext : public ContextBase {
        DistributedSessionType sessionType_ {};
        napi_value callback_ = nullptr;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        NapiUtils::ThrowError(env, "OffSessionEvent failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto input = [env, &context](size_t argc, napi_value* argv) {
        int32_t err = PermissionChecker::GetInstance().CheckPermission(
            PermissionChecker::CHECK_SYSTEM_PERMISSION);
        CHECK_ARGS_RETURN_VOID(context, err == ERR_NONE, "Check system permission error",
            NapiAVSessionManager::errcode_[ERR_NO_PERMISSION]);
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_TWO || argc == ARGC_THREE, "invalid argument number",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        int32_t sessionTypeValue;
        context->status = NapiUtils::GetValue(env, argv[ARGV_SECOND], sessionTypeValue);
        CHECK_STATUS_RETURN_VOID(context, "get session type failed", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->sessionType_ = DistributedSessionType(sessionTypeValue);
        CHECK_ARGS_RETURN_VOID(context, context->sessionType_ >= DistributedSessionType::TYPE_SESSION_REMOTE &&
            context->sessionType_ < DistributedSessionType::TYPE_SESSION_MAX,
            "GetDistributedSessionControllers invalid sessionType",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        if (argc == ARGC_THREE) {
            napi_valuetype type = napi_undefined;
            context->status = napi_typeof(env, argv[ARGV_THIRD], &type);
            CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (type == napi_function),
                "callback type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
            context->callback_ = argv[ARGV_THIRD];
        }
    };

    context->GetCbInfo(env, info, input, true);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto it = distributedControllerEventHandlers_.find(context->sessionType_);
    if (it == distributedControllerEventHandlers_.end()) {
        NapiUtils::ThrowError(env, "session type invalid", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        return NapiUtils::GetUndefinedValue(env);
    }

    if (it->second.second(env, context->callback_) != napi_ok) {
        NapiUtils::ThrowError(env, "add event callback failed", NapiAVSessionManager::errcode_[AVSESSION_ERROR]);
    }

    return NapiUtils::GetUndefinedValue(env);
}

napi_value NapiAVSessionManager::SendSystemAVKeyEvent(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::SendSystemAVKeyEvent");
    struct ConcreteContext : public ContextBase {
        std::shared_ptr<MMI::KeyEvent> keyEvent_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->keyEvent_);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok) && (context->keyEvent_ != nullptr),
                               "invalid keyEvent", NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_SEND_SYSTEM_AV_KEY_EVENT_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().SendSystemAVKeyEvent(*context->keyEvent_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_COMMAND_NOT_SUPPORT) {
                context->errMessage = "SendSystemAVKeyEvent failed : native invalid keyEvent";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SendSystemAVKeyEvent failed : native no permission";
            } else if (ret == ERR_PERMISSION_DENIED) {
                context->errMessage = "SendSystemAVKeyEvent failed : native permission denied";
            } else {
                context->errMessage = "SendSystemAVKeyEvent failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "SendSystemAVKeyEvent", executor);
}

napi_value NapiAVSessionManager::SendSystemControlCommand(napi_env env, napi_callback_info info)
{
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::SendSystemControlCommand");
    struct ConcrentContext : public ContextBase {
        AVControlCommand command;
    };
    auto context = std::make_shared<ConcrentContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiControlCommand::GetValue(env, argv[ARGV_FIRST], context->command);
        CHECK_ARGS_RETURN_VOID(context, (context->status == napi_ok), "invalid command",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_SEND_SYSTEM_CONTROL_COMMAND_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().SendSystemControlCommand(context->command);
#ifdef ENABLE_AVSESSION_SYSEVENT_CONTROL
            double speed;
            int64_t time;
            int32_t mode;
            std::string assetId;
            context->command.GetSpeed(speed);
            context->command.GetSeekTime(time);
            context->command.GetLoopMode(mode);
            context->command.GetAssetId(assetId);
            HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "ERROR_TYPE", "SEND_CMD_FAILED",
                "CMD", context->command.GetCommand(), "TIME", time, "SPEED", speed, "MODE", mode, "ASSETID", assetId,
                "ERROR_CODE", ret, "ERROR_INFO", "native send control command failed");
#endif
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_COMMAND_NOT_SUPPORT) {
                context->errMessage = "SendSystemControlCommand failed : native invalid command";
            } else if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SendSystemControlCommand failed : native send control command no permission";
                HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "ERROR_CODE", ret,
                                    "ERROR_INFO", "SendSystemControlCommand failed : native no permission");
            } else if (ret == ERR_PERMISSION_DENIED) {
                context->errMessage = "SendSystemControlCommand failed : native send control command permission denied";
            } else if (ret == ERR_COMMAND_SEND_EXCEED_MAX) {
                context->errMessage = "SendSystemControlCommand failed : native send command overload";
            } else {
                context->errMessage = "SendSystemControlCommand failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };

    return NapiAsyncWork::Enqueue(env, context, "SendSystemControlCommand", executor);
}

napi_value NapiAVSessionManager::StartCastDiscovery(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::StartCastDiscovery");
    struct ConcreteContext : public ContextBase {
        int32_t castDeviceCapability_;
        std::vector<std::string> drmSchemes_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        context->status = ProcessCastDiscoveryParams(env, argc, argv,
            context->castDeviceCapability_, context->drmSchemes_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "invalid params",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_START_CAST_DISCOVERY_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().StartCastDiscovery(context->castDeviceCapability_,
            context->drmSchemes_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "StartCastDiscovery failed : native no permission";
            } else if (ret == ERR_PERMISSION_DENIED) {
                context->errMessage = "StartCastDiscovery failed : native permission denied";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "StartCastDiscovery failed : native invalid parameters";
            } else if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "StartCastDiscovery failed : native session not exist";
            } else {
                context->errMessage = "StartCastDiscovery failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
            ReportStartCastDiscoveryFailInfo("NapiAVSessionManager::StartCastDiscovery", ret);
        }
    };
    return NapiAsyncWork::Enqueue(env, context, "StartCastDiscovery", executor);
#else
    return nullptr;
#endif
}

napi_status NapiAVSessionManager::ProcessCastDiscoveryParams(
    napi_env env, size_t argc, napi_value* argv, int32_t& castDeviceCapability, std::vector<std::string>& drmSchemes)
{
    napi_status status = napi_ok;
    if (argc == ARGC_ONE && !NapiUtils::TypeCheck(env, argv[ARGV_FIRST], napi_undefined)
        && !NapiUtils::TypeCheck(env, argv[ARGV_FIRST], napi_null)) {
        status = NapiUtils::GetValue(env, argv[ARGV_FIRST], castDeviceCapability);
    } else if (argc == ARGC_TWO) {
        SLOGD("get in argc two process");
        if (!NapiUtils::TypeCheck(env, argv[ARGV_FIRST], napi_undefined) &&
            !NapiUtils::TypeCheck(env, argv[ARGV_FIRST], napi_null)) {
            status = NapiUtils::GetValue(env, argv[ARGV_FIRST], castDeviceCapability);
            if (status != napi_ok) {
                ReportStartCastDiscoveryFailInfo("NapiAVSessionManager::StartCastDiscovery", ERR_INVALID_PARAM);
            }
        } else {
            castDeviceCapability = ProtocolType::TYPE_CAST_PLUS_STREAM;
        }
        if (!NapiUtils::TypeCheck(env, argv[ARGV_SECOND], napi_undefined) &&
            !NapiUtils::TypeCheck(env, argv[ARGV_SECOND], napi_null)) {
            status = NapiUtils::GetValue(env, argv[ARGV_SECOND], drmSchemes);
            if (status != napi_ok) {
                ReportStartCastDiscoveryFailInfo("NapiAVSessionManager::StartCastDiscovery", ERR_INVALID_PARAM);
            }
        }
    } else {
        castDeviceCapability = ProtocolType::TYPE_CAST_PLUS_STREAM;
    }
    return status;
}

napi_value NapiAVSessionManager::StopCastDiscovery(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::StopCastDiscovery");
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("Activate failed : no memory");
        ReportStopCastDiscoveryFailInfo("NapiAVSessionManager::StopCastDiscovery", ERR_NO_MEMORY);
        NapiUtils::ThrowError(env, "Activate failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }

    context->GetCbInfo(env, info);
    context->taskId = NAPI_STOP_CAST_DISCOVERY_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSESSION_ERROR;
        ret = AVSessionManager::GetInstance().StopCastDiscovery();
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "StopCastDiscovery failed : native no permission";
            } else if (ret == ERR_PERMISSION_DENIED) {
                context->errMessage = "StopCastDiscovery failed : native permission denied";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "StopCastDiscovery failed : native invalid parameters";
            } else if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "StopCastDiscovery failed : native session not exist";
            } else {
                context->errMessage = "StopCastDiscovery failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
            ReportStopCastDiscoveryFailInfo("NapiAVSessionManager::StopCastDiscovery", ret);
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "StopCastDiscovery", executor, complete);
#else
    return nullptr;
#endif
}

napi_value NapiAVSessionManager::SetDiscoverable(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::SetDiscoverable");
    struct ConcreteContext : public ContextBase {
        bool enable_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->enable_);
        CHECK_ARGS_RETURN_VOID(context, context->status == napi_ok, "get streamIds_ failed",
            NapiAVSessionManager::errcode_[ERR_INVALID_PARAM]);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_SET_DISCOVERABLE_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().SetDiscoverable(context->enable_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "SetDiscoverable failed : native no permission";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "SetDiscoverable failed : native invalid parameters";
            } else if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "SetDiscoverable failed : native session not exist";
            } else {
                context->errMessage = "SetDiscoverable failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
        }
    };
    return NapiAsyncWork::Enqueue(env, context, "SetDiscoverable", executor);
#else
    return nullptr;
#endif
}

std::string NapiAVSessionManager::GetStartCastErrMsg(int32_t error)
{
    std::string err;
    if (error == ERR_NO_PERMISSION) {
        err = "StartCast failed : native no permission";
    } else if (error == ERR_PERMISSION_DENIED) {
        err = "StartCast failed : native permission denied";
    } else if (error == ERR_INVALID_PARAM) {
        err = "StartCast failed : native invalid parameters";
    } else if (error == ERR_SESSION_NOT_EXIST) {
        err = "StartCast failed : native session not exist";
    } else {
        err = "StartCast failed : native server exception";
    }
    return err;
}

bool NapiAVSessionManager::JudgeNumString(std::string str)
{
    SLOGI("enter JudgeNumString");
    if (str.empty()) {
        return false;
    }
    
    int minNumChar = 48;
    int maxNumChar = 57;
    for (int i = 0; i < static_cast<int>(str.size()); i++) {
        if (str[i] < minNumChar || str[i] > maxNumChar) {
            return false;
        }
    }
    return true;
}

napi_value NapiAVSessionManager::StartDeviceLogging(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::StartDeviceLogging");
    struct ConcreteContext : public ContextBase {
        std::string fd_;
        uint32_t maxSize_;
    };
    auto context = std::make_shared<ConcreteContext>();
    if (context == nullptr) {
        SLOGE("Activate failed : no memory");
        NapiUtils::ThrowError(env, "Activate failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }
    auto input = [env, context](size_t argc, napi_value* argv) {
        int32_t napiInvalidParamErr = NapiAVSessionManager::errcode_[ERR_INVALID_PARAM];
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_TWO, "invalid arguments", napiInvalidParamErr);

        napi_valuetype type = napi_undefined;
        context->status = napi_typeof(env, argv[ARGV_FIRST], &type);
        bool condition = (context->status == napi_ok) && (type == napi_string);
        CHECK_ARGS_RETURN_VOID(context, condition, "invalid type invalid", napiInvalidParamErr);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->fd_);
        condition = (context->status == napi_ok);
        CHECK_ARGS_RETURN_VOID(context, condition, "fd getvalue fail", napiInvalidParamErr);
        CHECK_ARGS_RETURN_VOID(context, JudgeNumString(context->fd_),
            "fd is not a num string", napiInvalidParamErr);

        context->status = napi_typeof(env, argv[ARGV_SECOND], &type);
        condition = (context->status == napi_ok) && (type == napi_number);
        CHECK_ARGS_RETURN_VOID(context, condition, "invalid type invalid", napiInvalidParamErr);
        context->status = NapiUtils::GetValue(env, argv[ARGV_SECOND], context->maxSize_);
        condition = (context->status == napi_ok);
        CHECK_ARGS_RETURN_VOID(context, condition, "maxSize getvalue fail", napiInvalidParamErr);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_START_DEVICE_LOGGING_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSessionManager::GetInstance().StartDeviceLogging(
            std::stoi(context->fd_), context->maxSize_);
        if (ret != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
            SLOGE("StartDeviceLogging return error code = %{public}d", ret);
        }
    };
    return NapiAsyncWork::Enqueue(env, context, "StartDeviceLogging", executor);
#else
    return nullptr;
#endif
}

napi_value NapiAVSessionManager::StopDeviceLogging(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::StopCast");
    auto context = std::make_shared<ContextBase>();
    if (context == nullptr) {
        SLOGE("Activate failed : no memory");
        NapiUtils::ThrowError(env, "Activate failed : no memory", NapiAVSessionManager::errcode_[ERR_NO_MEMORY]);
        return NapiUtils::GetUndefinedValue(env);
    }
    context->GetCbInfo(env, info);
    context->taskId = NAPI_STOP_DEVICE_LOGGING_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSESSION_ERROR;
        ret = AVSessionManager::GetInstance().StopDeviceLogging();
        if (ret != AVSESSION_SUCCESS) {
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
            SLOGE("StopDeviceLogging return error code = %{public}d", ret);
        }
    };
    auto complete = [env](napi_value& output) {
        output = NapiUtils::GetUndefinedValue(env);
    };
    return NapiAsyncWork::Enqueue(env, context, "StopDeviceLogging", executor, complete);
#else
    return nullptr;
#endif
}

napi_value NapiAVSessionManager::StartCast(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::StartCast");
    struct ConcreteContext : public ContextBase {
        SessionToken sessionToken_ {};
        OutputDeviceInfo outputdeviceInfo_;
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        int32_t napiInvalidParamErr = NapiAVSessionManager::errcode_[ERR_INVALID_PARAM];
        CheckStartCastReportRadar(argc == ARGC_TWO, ERR_INVALID_PARAM);
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_TWO, "invalid arguments", napiInvalidParamErr);

        napi_valuetype type = napi_undefined;
        context->status = napi_typeof(env, argv[ARGV_FIRST], &type);
        bool condition = (context->status == napi_ok) && (type == napi_object);
        CheckStartCastReportRadar(condition, ERR_INVALID_PARAM);
        CHECK_ARGS_RETURN_VOID(context, condition, "invalid type invalid", napiInvalidParamErr);

        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->sessionToken_);
        condition = (context->status == napi_ok) && (!context->sessionToken_.sessionId.empty());
        CheckStartCastReportRadar(condition, ERR_INVALID_PARAM);
        CHECK_ARGS_RETURN_VOID(context, condition, "invalid session token", napiInvalidParamErr);

        context->status = NapiUtils::GetValue(env, argv[ARGV_SECOND], context->outputdeviceInfo_);
        condition = (context->status == napi_ok) && (context->outputdeviceInfo_.deviceInfos_.size() > 0);
        CheckStartCastReportRadar(condition, ERR_INVALID_PARAM);
        CHECK_ARGS_RETURN_VOID(context, condition, "invalid outputdeviceInfo", napiInvalidParamErr);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_START_CAST_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSESSION_ERROR;
        ret = AVSessionManager::GetInstance().StartCast(context->sessionToken_, context->outputdeviceInfo_);
        if (ret != AVSESSION_SUCCESS) {
            context->errMessage = GetStartCastErrMsg(ret);
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
            ReportStartCastFailInfo(ret, context->outputdeviceInfo_);
        }
    };

    auto complete = [env](napi_value& output) { output = NapiUtils::GetUndefinedValue(env); };

    return NapiAsyncWork::Enqueue(env, context, "StartCast", executor, complete);
#else
    return nullptr;
#endif
}

napi_value NapiAVSessionManager::StopCast(napi_env env, napi_callback_info info)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    AVSESSION_TRACE_SYNC_START("NapiAVSessionManager::StopCast");
    struct ConcreteContext : public ContextBase {
        SessionToken sessionToken_ {};
    };
    auto context = std::make_shared<ConcreteContext>();
    auto input = [env, context](size_t argc, napi_value* argv) {
        int32_t napiInvalidParamErr = NapiAVSessionManager::errcode_[ERR_INVALID_PARAM];
        CheckStopCastReportRadar(argc == ARGC_ONE, ERR_INVALID_PARAM);
        CHECK_ARGS_RETURN_VOID(context, argc == ARGC_ONE, "invalid arguments", napiInvalidParamErr);

        napi_valuetype type = napi_undefined;
        context->status = napi_typeof(env, argv[ARGV_FIRST], &type);
        bool condition = (context->status == napi_ok) && (type == napi_object);
        CheckStopCastReportRadar(condition, ERR_INVALID_PARAM);
        CHECK_ARGS_RETURN_VOID(context, condition, "invalid type invalid", napiInvalidParamErr);

        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->sessionToken_);
        condition = (context->status == napi_ok) && (!context->sessionToken_.sessionId.empty());
        CheckStopCastReportRadar(condition, ERR_INVALID_PARAM);
        CHECK_ARGS_RETURN_VOID(context, condition, "invalid session token", napiInvalidParamErr);
    };
    context->GetCbInfo(env, info, input);
    context->taskId = NAPI_STOP_CAST_TASK_ID;

    auto executor = [context]() {
        int32_t ret = AVSESSION_ERROR;
        ret = AVSessionManager::GetInstance().StopCast(context->sessionToken_);
        if (ret != AVSESSION_SUCCESS) {
            if (ret == ERR_NO_PERMISSION) {
                context->errMessage = "StopCast failed : native no permission";
            } else if (ret == ERR_INVALID_PARAM) {
                context->errMessage = "StopCast failed : native invalid parameters";
            } else if (ret == ERR_SESSION_NOT_EXIST) {
                context->errMessage = "StopCast failed : native session not exist";
            } else {
                context->errMessage = "StopCast failed : native server exception";
            }
            context->status = napi_generic_failure;
            context->errCode = NapiAVSessionManager::errcode_[ret];
            ReportStopCastFailInfo(ret);
        }
    };

    auto complete = [env](napi_value& output) { output = NapiUtils::GetUndefinedValue(env); };

    return NapiAsyncWork::Enqueue(env, context, "StopCast", executor, complete);
#else
    return nullptr;
#endif
}

napi_status NapiAVSessionManager::OnSessionCreate(napi_env env, napi_value callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->AddCallback(env, NapiSessionListener::EVENT_SESSION_CREATED, callback);
}

napi_status NapiAVSessionManager::OnSessionDestroy(napi_env env, napi_value callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->AddCallback(env, NapiSessionListener::EVENT_SESSION_DESTROYED, callback);
}

napi_status NapiAVSessionManager::OnTopSessionChange(napi_env env, napi_value callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->AddCallback(env, NapiSessionListener::EVENT_TOP_SESSION_CHANGED, callback);
}

napi_status NapiAVSessionManager::OnAudioSessionChecked(napi_env env, napi_value callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->AddCallback(env, NapiSessionListener::EVENT_AUDIO_SESSION_CHECKED, callback);
}

napi_status NapiAVSessionManager::OnDeviceAvailable(napi_env env, napi_value callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->AddCallback(env, NapiSessionListener::EVENT_DEVICE_AVAILABLE, callback);
}

napi_status NapiAVSessionManager::OnDeviceLogEvent(napi_env env, napi_value callback)
{
    return listener_->AddCallback(env, NapiSessionListener::EVENT_DEVICE_LOG_EVENT, callback);
}

napi_status NapiAVSessionManager::OnDeviceOffline(napi_env env, napi_value callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->AddCallback(env, NapiSessionListener::EVENT_DEVICE_OFFLINE, callback);
}

napi_status NapiAVSessionManager::OnServiceDie(napi_env env, napi_value callback)
{
    napi_ref ref = nullptr;
    CHECK_AND_RETURN_RET_LOG(napi_ok == NapiUtils::GetRefByCallback(env, serviceDiedCallbacks_, callback, ref),
                             napi_generic_failure, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(ref == nullptr, napi_ok, "callback has been registered");
    napi_status status = napi_create_reference(env, callback, ARGC_ONE, &ref);
    if (status != napi_ok) {
        SLOGE("napi_create_reference failed");
        return status;
    }
    if (asyncCallback_ == nullptr) {
        asyncCallback_ = std::make_shared<NapiAsyncCallback>(env);
        if (asyncCallback_ == nullptr) {
            SLOGE("no memory");
            return napi_generic_failure;
        }
    }
    serviceDiedCallbacks_.push_back(ref);
    SLOGI("do service die register when listener setup");
    return napi_ok;
}

napi_status NapiAVSessionManager::OnRemoteDistributedSessionChange(napi_env env, napi_value callback)
{
    SLOGI("OnRemoteDistributedSessionChange AddCallback");
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->AddCallback(env, NapiSessionListener::EVENT_REMOTE_DISTRIBUTED_SESSION_CHANGED, callback);
}

void NapiAVSessionManager::HandleServiceDied()
{
    if (!serviceDiedCallbacks_.empty() && asyncCallback_ != nullptr) {
        for (auto callbackRef = serviceDiedCallbacks_.begin(); callbackRef != serviceDiedCallbacks_.end();
             ++callbackRef) {
            asyncCallback_->Call(*callbackRef);
        }
    }
    std::lock_guard lockGuard(listenerMutex_);
    if (listener_ != nullptr) {
        SLOGI("clear listener for service die");
        listener_ = nullptr;
    }
}

napi_status NapiAVSessionManager::OffSessionCreate(napi_env env, napi_value callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->RemoveCallback(env, NapiSessionListener::EVENT_SESSION_CREATED, callback);
}

napi_status NapiAVSessionManager::OffSessionDestroy(napi_env env, napi_value callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->RemoveCallback(env, NapiSessionListener::EVENT_SESSION_DESTROYED, callback);
}

napi_status NapiAVSessionManager::OffTopSessionChange(napi_env env, napi_value callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->RemoveCallback(env, NapiSessionListener::EVENT_TOP_SESSION_CHANGED, callback);
}

napi_status NapiAVSessionManager::OffAudioSessionChecked(napi_env env, napi_value callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->RemoveCallback(env, NapiSessionListener::EVENT_AUDIO_SESSION_CHECKED, callback);
}

napi_status NapiAVSessionManager::OffDeviceAvailable(napi_env env, napi_value callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->RemoveCallback(env, NapiSessionListener::EVENT_DEVICE_AVAILABLE, callback);
}

napi_status NapiAVSessionManager::OffDeviceLogEvent(napi_env env, napi_value callback)
{
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->RemoveCallback(env, NapiSessionListener::EVENT_DEVICE_LOG_EVENT, callback);
}

napi_status NapiAVSessionManager::OffDeviceOffline(napi_env env, napi_value callback)
{
    std::lock_guard lockGuard(listenerMutex_);
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->RemoveCallback(env, NapiSessionListener::EVENT_DEVICE_OFFLINE, callback);
}

napi_status NapiAVSessionManager::OffRemoteDistributedSessionChange(napi_env env, napi_value callback)
{
    SLOGI("OffRemoteDistributedSessionChange RemoveCallback");
    CHECK_AND_RETURN_RET_LOG(listener_ != nullptr, napi_generic_failure, "callback has not been registered");
    return listener_->RemoveCallback(env, NapiSessionListener::EVENT_REMOTE_DISTRIBUTED_SESSION_CHANGED, callback);
}

napi_status NapiAVSessionManager::OffServiceDie(napi_env env, napi_value callback)
{
    AVSessionManager::GetInstance().UnregisterServiceDeathCallback();
    if (callback == nullptr) {
        for (auto callbackRef = serviceDiedCallbacks_.begin(); callbackRef != serviceDiedCallbacks_.end();
             ++callbackRef) {
            napi_status ret = napi_delete_reference(env, *callbackRef);
            CHECK_AND_RETURN_RET_LOG(napi_ok == ret, ret, "delete callback reference failed");
            *callbackRef = nullptr;
        }
        serviceDiedCallbacks_.clear();
        return napi_ok;
    }
    napi_ref ref = nullptr;
    CHECK_AND_RETURN_RET_LOG(napi_ok == NapiUtils::GetRefByCallback(env, serviceDiedCallbacks_, callback, ref),
                             napi_generic_failure, "get callback reference failed");
    CHECK_AND_RETURN_RET_LOG(ref != nullptr, napi_ok, "callback has been remove");
    serviceDiedCallbacks_.remove(ref);
    return napi_delete_reference(env, ref);
}

void NapiAVSessionManager::ReportStartCastDiscoveryFailInfo(std::string func, int32_t error)
{
    AVSessionRadarInfo info(func);
    info.errorCode_ = AVSessionRadar::GetRadarErrorCode(error);
    AVSessionRadar::GetInstance().FailToStartCastDiscovery(info);
}

void NapiAVSessionManager::ReportStopCastDiscoveryFailInfo(std::string func, int32_t error)
{
    AVSessionRadarInfo info(func);
    info.errorCode_ = AVSessionRadar::GetRadarErrorCode(error);
    AVSessionRadar::GetInstance().FailToStopCastDiscovery(info);
}

void NapiAVSessionManager::ReportStartCastFailInfo(int32_t error)
{
    AVSessionRadarInfo info("NapiAVSessionManager::StartCast");
    info.errorCode_ = AVSessionRadar::GetRadarErrorCode(error);
    AVSessionRadar::GetInstance().FailToStartCast(info);
}

void NapiAVSessionManager::ReportStartCastFailInfo(int32_t error, const OutputDeviceInfo &outputDeviceInfo)
{
    AVSessionRadarInfo info("NapiAVSessionManager::StartCast");
    info.errorCode_ = AVSessionRadar::GetRadarErrorCode(error);
    AVSessionRadar::GetInstance().FailToStartCast(outputDeviceInfo, info);
}

void NapiAVSessionManager::ReportStopCastFailInfo(int32_t error)
{
    AVSessionRadarInfo info("NapiAVSessionManager::StopCast");
    info.errorCode_ = AVSessionRadar::GetRadarErrorCode(error);
    AVSessionRadar::GetInstance().FailToStopCast(info);
}

void NapiAVSessionManager::CheckStartCastReportRadar(bool condition, int32_t error)
{
    if (!condition) {
        ReportStartCastFailInfo(error);
    }
}

void NapiAVSessionManager::CheckStopCastReportRadar(bool condition, int32_t error)
{
    if (!condition) {
        ReportStopCastFailInfo(error);
    }
}
} // namespace OHOS::AVSession
