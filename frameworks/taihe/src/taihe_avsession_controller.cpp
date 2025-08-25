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
#define LOG_TAG "AVSessionControllerImpl"
#endif

#include "taihe_avsession_controller.h"

#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "taihe_avcall_meta_data.h"
#include "taihe_avcall_state.h"
#include "taihe_avsession_manager.h"
#include "taihe_control_command.h"
#include "taihe_meta_data.h"
#include "taihe_playback_state.h"
#include "taihe_utils.h"

namespace ANI::AVSession {
std::set<std::string> AVSessionControllerImpl::eventHandlers_ = {
    "callMetadataChange",
    "callStateChange",
    "sessionDestroy",
    "metadataChange",
    "playbackStateChange",
    "activeStateChange",
    "validCommandChange",
    "outputDeviceChange",
    "sessionEvent",
    "queueItemsChange",
    "queueTitleChange",
    "extrasChange",
};
std::map<std::string, std::shared_ptr<AVSessionControllerImpl>> AVSessionControllerImpl::controllerList_ = {};
std::mutex AVSessionControllerImpl::uvMutex_;
std::mutex AVSessionControllerImpl::controllerListMutex_;

int32_t AVSessionControllerImpl::NewInstance(
    const std::shared_ptr<OHOS::AVSession::AVSessionController> &nativeController, AVSessionController &out)
{
    CHECK_RETURN(nativeController != nullptr, "get native controller failed", OHOS::AVSession::AVSESSION_ERROR);
    std::shared_ptr<AVSessionControllerImpl> taiheController = std::make_shared<AVSessionControllerImpl>();
    CHECK_RETURN(taiheController != nullptr, "make shared pointer failed", OHOS::AVSession::ERR_NO_MEMORY);
    taiheController->sessionId_ = nativeController->GetSessionId();
    taiheController->controller_ = std::move(nativeController);

    CHECK_RETURN(DoRegisterCallback(taiheController) == OHOS::AVSession::AVSESSION_SUCCESS,
        "add callback failed", OHOS::AVSession::AVSESSION_ERROR);

    SLOGD("add taiheController instance prelock for sessionId: %{public}s", taiheController->sessionId_.c_str());
    std::lock_guard<std::mutex> lock(controllerListMutex_);
    SLOGD("add taiheController instance aftlock for sessionId: %{public}s", taiheController->sessionId_.c_str());
    controllerList_[taiheController->sessionId_] = taiheController;

    out = make_holder<AVSessionControllerImpl, AVSessionController>(taiheController);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t AVSessionControllerImpl::RepeatedInstance(const std::string &controllerId, AVSessionController &out)
{
    SLOGD("check repeat controller prelock with sessionId %{public}s", controllerId.c_str());
    std::lock_guard<std::mutex> lock(controllerListMutex_);
    SLOGI("check repeat controller aftlock with sessionId %{public}s", controllerId.c_str());
    if (controllerList_.count(controllerId) <= 0) {
        SLOGE("check repeat without cur session");
        return OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST;
    }

    out = make_holder<AVSessionControllerImpl, AVSessionController>(controllerList_[controllerId]);
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t AVSessionControllerImpl::DoRegisterCallback(std::shared_ptr<AVSessionControllerImpl> &taiheController)
{
    return DoRegisterCallback(taiheController.get());
}

int32_t AVSessionControllerImpl::DoRegisterCallback(AVSessionControllerImpl *taiheController)
{
    CHECK_RETURN(taiheController != nullptr, "taiheController is nullptr", OHOS::AVSession::AVSESSION_ERROR);
    std::string registerControllerId = taiheController->sessionId_;
    SLOGI("do register callback with for sessionId: %{public}s", registerControllerId.c_str());
    if (taiheController->callback_ == nullptr) {
        taiheController->callback_ = std::make_shared<TaiheAVControllerCallback>(get_env());
        if (taiheController->callback_ == nullptr) {
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_NO_MEMORY],
                "OnEvent failed : no memory");
            return OHOS::AVSession::ERR_NO_MEMORY;
        }
        taiheController->callback_->AddCallbackForSessionDestroy([registerControllerId]() {
            SLOGI("repeat list check for session destroy: %{public}s", registerControllerId.c_str());
            std::lock_guard<std::mutex> lock(controllerListMutex_);
            if (!controllerList_.empty() && controllerList_.find(registerControllerId) != controllerList_.end()) {
                SLOGI("repeat list erase controller for session destroy: %{public}s", registerControllerId.c_str());
                controllerList_.erase(registerControllerId);
            } else {
                SLOGI("repeat list erase fail for session not in list: %{public}s", registerControllerId.c_str());
            }
        });
        CHECK_RETURN(taiheController->controller_ != nullptr,
            "OnEvent failed : controller is nullptr", OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST);
        int32_t ret = taiheController->controller_->RegisterCallback(taiheController->callback_);
        if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
            SLOGE("controller RegisterCallback failed:%{public}d", ret);
            std::string errorMessage = "OnEvent failed : native server exception";
            if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
                errorMessage = "OnEvent failed : native controller not exist";
            } else if (ret == OHOS::AVSession::ERR_NO_MEMORY) {
                errorMessage = "OnEvent failed : native no memory";
            } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
                errorMessage = "OnEvent failed : native no permission";
            }
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errorMessage);
            taiheController->callback_ = nullptr;
            return ret;
        }
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

AVSessionControllerImpl::AVSessionControllerImpl()
{
    SLOGI("construct");
}

AVSessionControllerImpl::AVSessionControllerImpl(std::shared_ptr<AVSessionControllerImpl> &taiheController)
{
    CHECK_RETURN_VOID(taiheController != nullptr, "taiheController is nullptr");
    sessionId_ = taiheController->sessionId_;
    controller_ = taiheController->controller_;
    callback_ = taiheController->callback_;
    SLOGI("check repeat controller for copy res %{public}d", (controller_ == nullptr));
}

AVSessionControllerImpl::~AVSessionControllerImpl()
{
    SLOGI("destroy");
}

string AVSessionControllerImpl::GetSessionId()
{
    return taihe::string(sessionId_);
}

AVPlaybackState AVSessionControllerImpl::GetAVPlaybackStateSync()
{
    AVPlaybackState undefinedState = TaihePlaybackState::CreateUndefinedAVPlaybackState();
    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetAVPlaybackStateSync failed : controller is nullptr");
        return undefinedState;
    }

    OHOS::AVSession::AVPlaybackState state;
    int32_t ret = controller_->GetAVPlaybackState(state);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetAVPlaybackState failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetAVPlaybackState failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetAVPlaybackState failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetAVPlaybackState failed : native no permission";
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

AVMetadata AVSessionControllerImpl::GetAVMetadataSync()
{
    AVMetadata undefinedMeta = TaiheMetaData::CreateUndefinedAVMetaData();
    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetAVMetadataSync failed : controller is nullptr");
        return undefinedMeta;
    }

    OHOS::AVSession::AVMetaData metaData;
    int32_t ret = controller_->GetAVMetaData(metaData);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetAVMetaData failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetAVMetaData failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetAVMetaData failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetAVMetaData failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return undefinedMeta;
    }

    AVMetadata output = TaiheMetaData::CreateUndefinedAVMetaData();
    ret = TaiheMetaData::SetAVMetaData(metaData, output);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "convert native object to ets object failed");
        return undefinedMeta;
    }
    return output;
}

AVCallState AVSessionControllerImpl::GetAVCallStateSync()
{
    AVCallState undefinedAVCallState = TaiheAVCallState::CreateUndefinedAVCallState();
    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetAVCallStateSync failed : controller is nullptr");
        return undefinedAVCallState;
    }

    OHOS::AVSession::AVCallState avCallState;
    int32_t ret = controller_->GetAVCallState(avCallState);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetAVCallState failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetAVCallState failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetAVCallState failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetAVCallState failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return undefinedAVCallState;
    }

    AVCallState output = TaiheAVCallState::CreateUndefinedAVCallState();
    ret = TaiheAVCallState::SetAVCallState(avCallState, output);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "convert native object to ets object failed");
        return undefinedAVCallState;
    }
    return output;
}

CallMetadata AVSessionControllerImpl::GetCallMetadataSync()
{
    CallMetadata undefinedCallMeta = TaiheAVCallMetaData::CreateUndefinedCallMetadata();
    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetCallMetadataSync failed : controller is nullptr");
        return undefinedCallMeta;
    }

    OHOS::AVSession::AVCallMetaData avCallMetaData;
    int32_t ret = controller_->GetAVCallMetaData(avCallMetaData);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetAVCallMetaData failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetAVCallMetaData failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetAVCallMetaData failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetAVCallMetaData failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return undefinedCallMeta;
    }

    CallMetadata output = TaiheAVCallMetaData::CreateUndefinedCallMetadata();
    ret = TaiheAVCallMetaData::SetCallMetadata(avCallMetaData, output);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "convert native object to ets object failed");
        return undefinedCallMeta;
    }
    return output;
}

string AVSessionControllerImpl::GetAVQueueTitleSync()
{
    SLOGD("Start GetAVQueueTitleSync");
    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetAVQueueTitleSync failed : controller is nullptr");
        return taihe::string("");
    }
    std::string title;
    int32_t ret = controller_->GetAVQueueTitle(title);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetAVQueueTitleSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetAVQueueTitleSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetAVQueueTitleSync failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetAVQueueTitleSync failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return taihe::string("");
    }
    return taihe::string(title);
}

array<AVQueueItem> AVSessionControllerImpl::GetAVQueueItemsSync()
{
    SLOGD("Start GetAVQueueItemsSync");
    std::vector<AVQueueItem> emptyItems;
    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetAVQueueItemsSync failed : controller is nullptr");
        return array<AVQueueItem>(emptyItems);
    }
    std::vector<OHOS::AVSession::AVQueueItem> items;
    int32_t ret = controller_->GetAVQueueItems(items);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetAVQueueItemsSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetAVQueueItemsSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetAVQueueItemsSync failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetAVQueueItemsSync failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return array<AVQueueItem>(emptyItems);
    }
    return TaiheUtils::ToTaiheAVQueueItemArray(items);
}

void AVSessionControllerImpl::SkipToQueueItemSync(int32_t itemId)
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionControllerImpl::SkipToQueueItemSync");
    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "SkipToQueueItemSync failed : controller is nullptr");
        return;
    }
    int32_t ret = controller_->SkipToQueueItem(itemId);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "SkipToQueueItemSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "SkipToQueueItemSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "SkipToQueueItemSync failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_SESSION_DEACTIVE) {
            errMessage = "SkipToQueueItemSync failed : native session is not active";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "SkipToQueueItemSync failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

OutputDeviceInfo AVSessionControllerImpl::GetOutputDeviceSync()
{
    OutputDeviceInfo undefinedOutput = TaiheUtils::CreateUndefinedOutputDeviceInfo();
    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetOutputDeviceSync failed : controller is nullptr");
        return undefinedOutput;
    }

    OHOS::AVSession::AVSessionDescriptor descriptor;
    int32_t ret = OHOS::AVSession::AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId(
        controller_->GetSessionId(), descriptor);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "GetSessionDescriptorsBySessionId failed : native server exception");
        return undefinedOutput;
    }

    return TaiheUtils::ToTaiheOutputDeviceInfo(descriptor.outputDeviceInfo_);
}

void AVSessionControllerImpl::SendAVKeyEventSync(keyEvent::KeyEvent const &event)
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionControllerImpl::SendAVKeyEventSync");
    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "SendAVKeyEventSync failed : controller is nullptr");
        return;
    }
    auto keyEventPtr = OHOS::MMI::KeyEvent::Create();
    CHECK_RETURN_VOID(keyEventPtr != nullptr, "SendAVKeyEventSync failed : create key event failed");
    OHOS::MMI::KeyEvent keyEvent = *keyEventPtr;
    if (TaiheUtils::GetKeyEvent(event, keyEvent) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SendAVKeyEventSync failed : invalid key event");
        return;
    }
    int32_t ret = controller_->SendAVKeyEvent(keyEvent);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "SendAVKeyEventSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "SendAVKeyEventSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "SendAVKeyEventSync failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_SESSION_DEACTIVE) {
            errMessage = "SendAVKeyEventSync failed : native session is not active";
        } else if (ret == OHOS::AVSession::ERR_COMMAND_NOT_SUPPORT) {
            errMessage = "SendAVKeyEventSync failed : native invalid KeyEvent";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "SendAVKeyEventSync failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

uintptr_t AVSessionControllerImpl::GetLaunchAbilitySync()
{
    uintptr_t undefinedAbility = reinterpret_cast<uintptr_t>(nullptr);
    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetLaunchAbilitySync failed : controller is nullptr");
        return undefinedAbility;
    }

    OHOS::AbilityRuntime::WantAgent::WantAgent* ability;
    int32_t ret = controller_->GetLaunchAbilityInner(ability);
    SLOGE("GetLaunchAbilityInner check:%{public}d", ability != nullptr);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetLaunchAbilityInner failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetLaunchAbilityInner failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetLaunchAbilityInner failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetLaunchAbilityInner failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return undefinedAbility;
    }

    auto result = TaiheUtils::ToAniWantAgent(ability);
    return reinterpret_cast<uintptr_t>(result);
}

int64_t AVSessionControllerImpl::GetRealPlaybackPositionSync()
{
    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetRealPlaybackPositionSync failed : controller is nullptr");
        return 0;
    }

    return controller_->GetRealPlaybackPosition();
}

bool AVSessionControllerImpl::IsActiveSync()
{
    SLOGD("Start IsSessionActiveSync");
    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "IsActiveSync failed : controller is nullptr");
        return false;
    }
    bool isActive = false;
    int32_t ret = controller_->IsSessionActive(isActive);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage;
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "IsActiveSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "IsActiveSync failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "IsActiveSync failed : native no permission";
        } else {
            ret = OHOS::AVSession::AVSESSION_ERROR;
            errMessage = "IsActiveSync failed : native server exception";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return false;
    }
    return isActive;
}

void AVSessionControllerImpl::DestroySync()
{
    {
        SLOGD("Start Taihe AVSessionControllerImpl destroy process check lock");
        std::lock_guard<std::mutex> lock(uvMutex_);
        SLOGI("Start Taihe AVSessionControllerImpl destroy process");
        if (controller_ == nullptr) {
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
                "DestroySync failed : controller is nullptr");
            return;
        }

        int32_t ret = controller_->Destroy();
        if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
            std::string errMessage = "Destroy failed : native server exception";
            if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
                errMessage = "Destroy failed : native controller not exist";
            } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
                errMessage = "Destroy failed : native no permission";
            }
            TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
            return;
        }
    }

    {
        callback_ = nullptr;
        controller_ = nullptr;
        std::lock_guard<std::mutex> lock(controllerListMutex_);
        SLOGI("repeat list check for controller destroy: %{public}s", sessionId_.c_str());
        if (!controllerList_.empty() && controllerList_.find(sessionId_) != controllerList_.end()) {
            SLOGI("repeat list erase for controller destroy: %{public}s", sessionId_.c_str());
            controllerList_.erase(sessionId_);
        }
    }
}

array<string> AVSessionControllerImpl::GetValidCommandsSync()
{
    std::vector<string> emptyCmds;
    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetValidCommandsSync failed : controller is nullptr");
        return array<string>(emptyCmds);
    }

    std::vector<int32_t> cmds;
    int32_t ret = controller_->GetValidCommands(cmds);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetValidCommands failed : native server exception";
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

    std::vector<std::string> stringCmds = TaiheControlCommand::ConvertCommands(cmds);
    return array<string>(TaiheUtils::ToTaiheStringArray(stringCmds));
}

void AVSessionControllerImpl::SendControlCommandSync(AVControlCommand const &command)
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionControllerImpl::SendControlCommandSync");
    OHOS::AVSession::AVControlCommand commandInner;
    if (TaiheControlCommand::GetValue(command, commandInner) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SendControlCommandSync get command failed");
        return;
    }

    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "SendControlCommandSync failed : controller is nullptr");
        return;
    }

    int32_t ret = controller_->SendControlCommand(commandInner);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "SendControlCommand failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "SendControlCommand failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "SendControlCommand failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_SESSION_DEACTIVE) {
            errMessage = "SendControlCommand failed : native session is not active";
        } else if (ret == OHOS::AVSession::ERR_COMMAND_NOT_SUPPORT) {
            errMessage = "SendControlCommand failed : native command not support";
        } else if (ret == OHOS::AVSession::ERR_COMMAND_SEND_EXCEED_MAX) {
            errMessage = "SendControlCommand failed : native command send nums overload";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "SendControlCommand failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

void AVSessionControllerImpl::SendCommonCommandSync(string_view command, uintptr_t args)
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionControllerImpl::SendCommonCommandSync");
    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "SendCommonCommandSync failed : controller is nullptr");
        return;
    }
    std::string commonCommand;
    if (TaiheUtils::GetString(command, commonCommand) != OHOS::AVSession::AVSESSION_SUCCESS || commonCommand.empty()) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SendCommonCommandSync failed : invalid command");
        return;
    }
    OHOS::AAFwk::WantParams commandArgs;
    if (TaiheUtils::GetWantParams(args, commandArgs) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "SendCommonCommandSync failed : invalid command args");
        return;
    }
    int32_t ret = controller_->SendCommonCommand(commonCommand, commandArgs);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "SendCommonCommandSync failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "SendCommonCommandSync failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "SendCommonCommandSync failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_SESSION_DEACTIVE) {
            errMessage = "SendCommonCommandSync failed : native session is not active";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "SendCommonCommandSync failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return;
    }
}

uintptr_t AVSessionControllerImpl::GetExtrasSync()
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionControllerImpl::GetExtrasSync");
    std::lock_guard<std::mutex> lock(uvMutex_);
    ani_object undefinedAniExtras = TaiheUtils::CreateAniEmptyRecord();
    uintptr_t undefinedExtras = reinterpret_cast<uintptr_t>(undefinedAniExtras);
    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetExtrasSync failed : controller is nullptr");
        return undefinedExtras;
    }

    OHOS::AAFwk::WantParams extras;
    int32_t ret = controller_->GetExtras(extras);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetExtras failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetExtras failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetExtras failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_NO_PERMISSION) {
            errMessage = "GetExtras failed : native no permission";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return undefinedExtras;
    }

    auto result = TaiheUtils::ToAniWantParams(extras);
    if (result == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "GetExtrasSync failed : native server exception");
        return undefinedExtras;
    }
    return reinterpret_cast<uintptr_t>(result);
}

uintptr_t AVSessionControllerImpl::GetExtrasWithEventSync(string_view extraEvent)
{
    OHOS::AVSession::AVSessionTrace trace("AVSessionControllerImpl::GetExtrasWithEventSync");
    SLOGI("Start AVSessionControllerImpl GetExtrasWithEventSync process");
    ani_object undefinedAniExtras = TaiheUtils::CreateAniEmptyRecord();
    uintptr_t undefinedExtras = reinterpret_cast<uintptr_t>(undefinedAniExtras);
    if (controller_ == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "GetExtrasWithEventSync failed : controller is nullptr");
        return undefinedExtras;
    }
    OHOS::AAFwk::WantParams extras;
    std::string extraEventStr;
    if (TaiheUtils::GetString(extraEvent, extraEventStr) != OHOS::AVSession::AVSESSION_SUCCESS) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "GetExtrasWithEventSync failed : invalid extra event");
        return undefinedExtras;
    }
    int32_t ret = controller_->GetExtrasWithEvent(extraEventStr, extras);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        std::string errMessage = "GetExtrasWithEvent failed : native server exception";
        if (ret == OHOS::AVSession::ERR_SESSION_NOT_EXIST) {
            errMessage = "GetExtrasWithEvent failed : native session not exist";
        } else if (ret == OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST) {
            errMessage = "GetExtrasWithEvent failed : native controller not exist";
        } else if (ret == OHOS::AVSession::ERR_COMMAND_NOT_SUPPORT) {
            errMessage = "GetExtrasWithEvent failed : native invalid key event";
        }
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[ret], errMessage);
        return undefinedExtras;
    }

    auto result = TaiheUtils::ToAniWantParams(extras);
    if (result == nullptr) {
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::AVSESSION_ERROR],
            "GetExtrasWithEventSync failed : native server exception");
        return undefinedExtras;
    }
    return reinterpret_cast<uintptr_t>(result);
}

void AVSessionControllerImpl::OnMetadataChangeFilter(array_view<string> filter,
    callback_view<void(AVMetadata const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("metadataChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        int32_t status = SetMetaFilter(this, filter);
        CHECK_RETURN_VOID(status == OHOS::AVSession::AVSESSION_SUCCESS, "SetMetaFilter failed");
        callback_->AddCallback(TaiheAVControllerCallback::EVENT_META_DATA_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OnMetadataChangeAll(string_view filter, callback_view<void(AVMetadata const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("metadataChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        int32_t status = SetMetaFilter(this, filter);
        CHECK_RETURN_VOID(status == OHOS::AVSession::AVSESSION_SUCCESS, "SetMetaFilter failed");
        callback_->AddCallback(TaiheAVControllerCallback::EVENT_META_DATA_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OnPlaybackStateChangeFilter(array_view<string> filter,
    callback_view<void(AVPlaybackState const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("playbackStateChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        int32_t status = SetPlaybackStateFilter(this, filter);
        CHECK_RETURN_VOID(status == OHOS::AVSession::AVSESSION_SUCCESS, "SetPlaybackStateFilter failed");
        callback_->AddCallback(TaiheAVControllerCallback::EVENT_PLAYBACK_STATE_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OnPlaybackStateChangeAll(string_view filter,
    callback_view<void(AVPlaybackState const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("playbackStateChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        int32_t status = SetPlaybackStateFilter(this, filter);
        CHECK_RETURN_VOID(status == OHOS::AVSession::AVSESSION_SUCCESS, "SetPlaybackStateFilter failed");
        callback_->AddCallback(TaiheAVControllerCallback::EVENT_PLAYBACK_STATE_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OnCallMetadataChangeFilter(array_view<string> filter,
    callback_view<void(CallMetadata const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("callMetadataChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        int32_t status = SetAVCallMetaFilter(this, filter);
        CHECK_RETURN_VOID(status == OHOS::AVSession::AVSESSION_SUCCESS, "SetAVCallMetaFilter failed");
        callback_->AddCallback(TaiheAVControllerCallback::EVENT_AVCALL_META_DATA_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OnCallMetadataChangeAll(string_view filter,
    callback_view<void(CallMetadata const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("callMetadataChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        int32_t status = SetAVCallMetaFilter(this, filter);
        CHECK_RETURN_VOID(status == OHOS::AVSession::AVSESSION_SUCCESS, "SetAVCallMetaFilter failed");
        callback_->AddCallback(TaiheAVControllerCallback::EVENT_AVCALL_META_DATA_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OnCallStateChangeFilter(array_view<string> filter,
    callback_view<void(AVCallState const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("callStateChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        int32_t status = SetAVCallStateFilter(this, filter);
        CHECK_RETURN_VOID(status == OHOS::AVSession::AVSESSION_SUCCESS, "SetAVCallStateFilter failed");
        callback_->AddCallback(TaiheAVControllerCallback::EVENT_AVCALL_STATE_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OnCallStateChangeAll(string_view filter,
    callback_view<void(AVCallState const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("callStateChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        int32_t status = SetAVCallStateFilter(this, filter);
        CHECK_RETURN_VOID(status == OHOS::AVSession::AVSESSION_SUCCESS, "SetAVCallStateFilter failed");
        callback_->AddCallback(TaiheAVControllerCallback::EVENT_AVCALL_STATE_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OnSessionDestroy(callback_view<void()> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("sessionDestroy", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->AddCallback(TaiheAVControllerCallback::EVENT_SESSION_DESTROY, cacheCallback);
    }
}

void AVSessionControllerImpl::OnActiveStateChange(callback_view<void(bool)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("activeStateChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->AddCallback(TaiheAVControllerCallback::EVENT_ACTIVE_STATE_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OnValidCommandChange(callback_view<void(array_view<string>)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("validCommandChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->AddCallback(TaiheAVControllerCallback::EVENT_VALID_COMMAND_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OnOutputDeviceChange(
    callback_view<void(ConnectionState, OutputDeviceInfo const&)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("outputDeviceChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->AddCallback(TaiheAVControllerCallback::EVENT_OUTPUT_DEVICE_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OnSessionEvent(callback_view<void(string_view, uintptr_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("sessionEvent", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->AddCallback(TaiheAVControllerCallback::EVENT_SESSION_EVENT_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OnQueueItemsChange(callback_view<void(array_view<AVQueueItem>)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("queueItemsChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->AddCallback(TaiheAVControllerCallback::EVENT_QUEUE_ITEMS_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OnQueueTitleChange(callback_view<void(string_view)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("queueTitleChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->AddCallback(TaiheAVControllerCallback::EVENT_QUEUE_TITLE_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OnExtrasChange(callback_view<void(uintptr_t)> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback = TaiheUtils::TypeCallback(callback);
    if (OnEvent("extrasChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->AddCallback(TaiheAVControllerCallback::EVENT_EXTRAS_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OffMetadataChange(optional_view<callback<void(AVMetadata const&)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("metadataChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->RemoveCallback(TaiheAVControllerCallback::EVENT_META_DATA_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OffPlaybackStateChange(optional_view<callback<void(AVPlaybackState const&)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("playbackStateChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->RemoveCallback(TaiheAVControllerCallback::EVENT_PLAYBACK_STATE_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OffCallMetadataChange(optional_view<callback<void(CallMetadata const&)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("callMetadataChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->RemoveCallback(TaiheAVControllerCallback::EVENT_AVCALL_META_DATA_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OffCallStateChange(optional_view<callback<void(AVCallState const&)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("callStateChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->RemoveCallback(TaiheAVControllerCallback::EVENT_AVCALL_STATE_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OffSessionDestroy(optional_view<callback<void()>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("sessionDestroy", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->RemoveCallback(TaiheAVControllerCallback::EVENT_SESSION_DESTROY, cacheCallback);
    }
}

void AVSessionControllerImpl::OffActiveStateChange(optional_view<callback<void(bool)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("activeStateChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->RemoveCallback(TaiheAVControllerCallback::EVENT_ACTIVE_STATE_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OffValidCommandChange(optional_view<callback<void(array_view<string>)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("validCommandChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->RemoveCallback(TaiheAVControllerCallback::EVENT_VALID_COMMAND_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OffOutputDeviceChange(
    optional_view<callback<void(ConnectionState, OutputDeviceInfo const&)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("outputDeviceChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->RemoveCallback(TaiheAVControllerCallback::EVENT_OUTPUT_DEVICE_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OffSessionEvent(optional_view<callback<void(string_view, uintptr_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("sessionEvent", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->RemoveCallback(TaiheAVControllerCallback::EVENT_SESSION_EVENT_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OffQueueItemsChange(optional_view<callback<void(array_view<AVQueueItem>)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("queueItemsChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->RemoveCallback(TaiheAVControllerCallback::EVENT_QUEUE_ITEMS_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OffQueueTitleChange(optional_view<callback<void(string_view)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("queueTitleChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->RemoveCallback(TaiheAVControllerCallback::EVENT_QUEUE_TITLE_CHANGE, cacheCallback);
    }
}

void AVSessionControllerImpl::OffExtrasChange(optional_view<callback<void(uintptr_t)>> callback)
{
    std::shared_ptr<uintptr_t> cacheCallback;
    if (callback.has_value()) {
        cacheCallback = TaiheUtils::TypeCallback(callback.value());
    }
    if (OffEvent("extrasChange", this) == OHOS::AVSession::AVSESSION_SUCCESS) {
        CHECK_RETURN_VOID(callback_ != nullptr, "callback has not been registered");
        callback_->RemoveCallback(TaiheAVControllerCallback::EVENT_EXTRAS_CHANGE, cacheCallback);
    }
}

int32_t AVSessionControllerImpl::OnEvent(const std::string& event, AVSessionControllerImpl *taiheController)
{
    std::string eventName = event;
    return RegisterCallback(eventName, taiheController);
}

int32_t AVSessionControllerImpl::OffEvent(const std::string& event, AVSessionControllerImpl *taiheController)
{
    CHECK_AND_RETURN_RET_LOG(taiheController != nullptr, OHOS::AVSession::ERR_INVALID_PARAM,
        "taiheController is nullptr");
    std::string eventName = event;
    auto it = eventHandlers_.find(eventName);
    if (it == eventHandlers_.end()) {
        SLOGE("event name invalid:%{public}s", eventName.c_str());
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "event name invalid");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }

    if (taiheController->callback_ == nullptr) {
        SLOGI("function %{public}s not register yet", eventName.c_str());
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "callback not register yet");
        return OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST;
    }

    SLOGD("check offEvent done");
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

int32_t AVSessionControllerImpl::RegisterCallback(const std::string& event, AVSessionControllerImpl *taiheController)
{
    CHECK_AND_RETURN_RET_LOG(taiheController != nullptr, OHOS::AVSession::ERR_INVALID_PARAM,
        "taiheController is nullptr");
    auto it = eventHandlers_.find(event);
    if (it == eventHandlers_.end()) {
        SLOGE("event name invalid");
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_INVALID_PARAM],
            "event name invalid");
        return OHOS::AVSession::ERR_INVALID_PARAM;
    }
    SLOGD("taiheController RegisterCallback process check lock");
    std::lock_guard<std::mutex> lock(uvMutex_);
    SLOGD("taiheController RegisterCallback process");
    if (taiheController->controller_ == nullptr) {
        SLOGE("OnEvent failed : controller is nullptr");
        TaiheUtils::ThrowError(TaiheAVSessionManager::errcode_[OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST],
            "OnEvent CTL null");
        return OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST;
    }
    int32_t ret = DoRegisterCallback(taiheController);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("do register callback fail!");
        return ret;
    }
    return OHOS::AVSession::AVSESSION_SUCCESS;
}

template<typename T>
int32_t AVSessionControllerImpl::SetAVCallMetaFilter(AVSessionControllerImpl *taiheController, T filter)
{
    CHECK_AND_RETURN_RET_LOG(taiheController != nullptr, OHOS::AVSession::ERR_INVALID_PARAM,
        "taiheController is nullptr");
    CHECK_AND_RETURN_RET_LOG(taiheController->controller_ != nullptr, OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST,
        "controller is nullptr");
    OHOS::AVSession::AVCallMetaData::AVCallMetaMaskType avCallMetaMask;
    auto status = TaiheAVCallMetaData::ConvertFilter(filter, avCallMetaMask);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "convert filter failed", status);
    auto ret = taiheController->controller_->SetAVCallMetaFilter(avCallMetaMask);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("controller SetAVCallMetaFilter failed:%{public}d", ret);
        return ret;
    }
    return ret;
}

template<typename T>
int32_t AVSessionControllerImpl::SetAVCallStateFilter(AVSessionControllerImpl *taiheController, T filter)
{
    CHECK_AND_RETURN_RET_LOG(taiheController != nullptr, OHOS::AVSession::ERR_INVALID_PARAM,
        "taiheController is nullptr");
    CHECK_AND_RETURN_RET_LOG(taiheController->controller_ != nullptr, OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST,
        "controller is nullptr");
    OHOS::AVSession::AVCallState::AVCallStateMaskType avCallStateMask;
    auto status = TaiheAVCallState::ConvertFilter(filter, avCallStateMask);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "convert filter failed", status);
    auto ret = taiheController->controller_->SetAVCallStateFilter(avCallStateMask);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("controller SetAVCallStateFilter failed:%{public}d", ret);
        return ret;
    }
    return ret;
}

template<typename T>
int32_t AVSessionControllerImpl::SetPlaybackStateFilter(AVSessionControllerImpl *taiheController, T filter)
{
    CHECK_AND_RETURN_RET_LOG(taiheController != nullptr, OHOS::AVSession::ERR_INVALID_PARAM,
        "taiheController is nullptr");
    CHECK_AND_RETURN_RET_LOG(taiheController->controller_ != nullptr, OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST,
        "controller is nullptr");
    OHOS::AVSession::AVPlaybackState::PlaybackStateMaskType playbackMask;
    auto status = TaihePlaybackState::ConvertFilter(filter, playbackMask);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "convert filter failed", status);
    auto ret = taiheController->controller_->SetPlaybackFilter(playbackMask);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("controller SetPlaybackFilter failed:%{public}d", ret);
        return ret;
    }
    return ret;
}

template<typename T>
int32_t AVSessionControllerImpl::SetMetaFilter(AVSessionControllerImpl *taiheController, T filter)
{
    CHECK_AND_RETURN_RET_LOG(taiheController != nullptr, OHOS::AVSession::ERR_INVALID_PARAM,
        "taiheController is nullptr");
    CHECK_AND_RETURN_RET_LOG(taiheController->controller_ != nullptr, OHOS::AVSession::ERR_CONTROLLER_NOT_EXIST,
        "controller is nullptr");
    OHOS::AVSession::AVMetaData::MetaMaskType metaMask;
    auto status = TaiheMetaData::ConvertFilter(filter, metaMask);
    CHECK_RETURN(status == OHOS::AVSession::AVSESSION_SUCCESS, "convert filter failed", status);
    auto ret = taiheController->controller_->SetMetaFilter(metaMask);
    if (ret != OHOS::AVSession::AVSESSION_SUCCESS) {
        SLOGE("controller SetMetaFilter failed:%{public}d", ret);
        return ret;
    }
    return ret;
}
} // namespace ANI::AVSession