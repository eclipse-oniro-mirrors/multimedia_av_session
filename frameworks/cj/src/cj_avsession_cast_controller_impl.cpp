/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cj_avsession_cast_controller_impl.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>
#include <string>

#include "want.h"
#include "avqueue_item.h"
#include "avsession_log.h"
#include "avsession_manager.h"
#include "avcast_controller.h"
#include "cj_avsession_utils.h"
#include "cj_avsession_prototypes.h"

namespace OHOS::AVSession {

constexpr int32_t CJ_CAST_CONTROLLER_PLAYBACK_STATE_CHANGE = 0;
constexpr int32_t CJ_CAST_CONTROLLER_MEDIAI_ITEM_CHANGE = 1;
constexpr int32_t CJ_CAST_CONTROLLER_PLAY_NEXT = 2;
constexpr int32_t CJ_CAST_CONTROLLER_PLAY_PREVIOUS = 3;
constexpr int32_t CJ_CAST_CONTROLLER_REQUEST_PLAY = 4;
constexpr int32_t CJ_CAST_CONTROLLER_END_OF_STREAM = 5;
constexpr int32_t CJ_CAST_CONTROLLER_SEEK_DONE = 6;
constexpr int32_t CJ_CAST_CONTROLLER_VALID_COMMAND_CHANGE = 7;
constexpr int32_t CJ_CAST_CONTROLLER_VALID_ERROR = 8;
constexpr int32_t CJ_CAST_CONTROLLER_VALID_REQUEST = 9;

std::map<std::string, std::shared_ptr<CJAVCastControllerImpl>> CJAVCastControllerImpl::ControllerList_ = {};
std::mutex CJAVCastControllerImpl::controllerListMutex_;
std::mutex CJAVCastControllerImpl::callbackMutex_;

CJAVCastControllerImpl::CJAVCastControllerImpl(
    std::shared_ptr<AVCastController>& nativeController, const std::string& sessionId)
{
    sessionId_ = sessionId;
    controller_ = nativeController;
}

CJAVCastControllerImpl::~CJAVCastControllerImpl() {}

CJAVCastControllerInvalidImpl::CJAVCastControllerInvalidImpl() {}
CJAVCastControllerInvalidImpl::~CJAVCastControllerInvalidImpl() {}

std::shared_ptr<CJAVCastControllerBase> CJAVCastControllerImpl::GetInstance(const std::string &sessionId)
{
    std::lock_guard<std::mutex> lock(controllerListMutex_);
    if (ControllerList_.count(sessionId) == 1) {
        return std::static_pointer_cast<CJAVCastControllerBase>(ControllerList_[sessionId]);
    }
    return std::static_pointer_cast<CJAVCastControllerBase>(CJ_CAST_CONTROLLER_INVALID_IMPL);
}

std::shared_ptr<CJAVCastControllerImpl> CJAVCastControllerImpl::NewInstance(
    std::shared_ptr<AVCastController> &nativeController, const std::string& sessionId)
{
    struct CJAVCastControllerImplInner: public CJAVCastControllerImpl {
        CJAVCastControllerImplInner(std::shared_ptr<AVCastController>& nativeController, const std::string& sessionId)
            : CJAVCastControllerImpl(nativeController, sessionId) {}
    };
    auto controller = std::make_shared<CJAVCastControllerImplInner>(nativeController, sessionId);
    std::lock_guard<std::mutex> lock(controllerListMutex_);
    ControllerList_[sessionId] = controller;
    return controller;
}

int32_t CJAVCastControllerImpl::SetCastPlaybackStateFilter(CParameters* extras)
{
    AVPlaybackState::PlaybackStateMaskType mask;
    if (extras == nullptr) {
        SLOGE("filter provided is nullptr!");
        return AVSESSION_ERROR;
    } else {
        if (extras->valueType != I32_PTR_TYPE) {
            SLOGE("Expect CastPlaybackStateFilter Kind is 'int32_t array', but actual is %{public}d",
                extras->valueType);
            return AVSESSION_ERROR;
        }
        if (extras->value == nullptr || extras->size == 0) {
            SLOGE("No filter is provided to set!");
            return AVSESSION_ERROR;
        }
        auto head = static_cast<int32_t *>(extras->value);
        for (int i = 0; i < extras->size; i++) {
            if (head[i] == AVPlaybackState::PLAYBACK_KEY_MAX) {
                mask.set();
                break;
            } else {
                mask.set(head[i]);
            }
        }
    }
    return controller_->SetCastPlaybackFilter(mask);
}

int32_t CJAVCastControllerImpl::SubscribeCallback(int32_t type, CParameters* extras, DoCallFunc doCall)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (!callback_) {
        callback_ = std::make_shared<CJAVCastControllerCallback>();
        callback_->AddCallback(doCall);
        controller_->RegisterCallback(callback_);
    }
    switch (type) {
        case CJ_CAST_CONTROLLER_PLAYBACK_STATE_CHANGE:
            SetCastPlaybackStateFilter(extras);
            break;

        case CJ_CAST_CONTROLLER_MEDIAI_ITEM_CHANGE:
        case CJ_CAST_CONTROLLER_PLAY_NEXT:
        case CJ_CAST_CONTROLLER_PLAY_PREVIOUS:
        case CJ_CAST_CONTROLLER_REQUEST_PLAY:
        case CJ_CAST_CONTROLLER_END_OF_STREAM:
        case CJ_CAST_CONTROLLER_SEEK_DONE:
        case CJ_CAST_CONTROLLER_VALID_COMMAND_CHANGE:
        case CJ_CAST_CONTROLLER_VALID_ERROR:
        case CJ_CAST_CONTROLLER_VALID_REQUEST:
            break;
        
        default:
            SLOGE("INVALID CALLBACK TYPE:No callback is subscribed!");
            return AVSESSION_ERROR;
    }
    return CJNO_ERROR;
}

int32_t CJAVCastControllerImpl::Start(CAVQueueItem& item)
{
    auto call = [&](AVQueueItem& native) {
        return controller_->Start(native);
    };
    return CJAVSessionSetterCStruct<AVQueueItem, CAVQueueItem>(call, item, "Start");
}
int32_t CJAVCastControllerImpl::Prepare(CAVQueueItem& item)
{
    auto call = [&](AVQueueItem& native) {
        return controller_->Prepare(native);
    };
    return CJAVSessionSetterCStruct<AVQueueItem, CAVQueueItem>(call, item, "Prepare");
}

int32_t CJAVCastControllerImpl::SendControlCommand(CAVSessionCommand& command)
{
    auto call = [&](AVCastControlCommand& native) {
        return controller_->SendControlCommand(native);
    };
    return CJAVSessionSetterCStruct<AVCastControlCommand, CAVSessionCommand>(call, command, "SendControlCommand");
}

int32_t CJAVCastControllerImpl::GetAVPlaybackState(CAVPlaybackState& avPlaybackState)
{
    auto call = [&](AVPlaybackState& native) {
        return controller_->GetCastAVPlaybackState(native);
    };
    return CJControllerGetterCStruct<AVPlaybackState, CAVPlaybackState>(call, avPlaybackState, "GetAVPlaybackState");
}

int32_t CJAVCastControllerImpl::GetCurrentItem(CAVQueueItem& item)
{
    auto call =  [&](AVQueueItem& native) {
        return controller_->GetCurrentItem(native);
    };
    return CJControllerGetterCStruct<AVQueueItem, CAVQueueItem>(call, item, "GetCurrentItem");
}

int32_t CJAVCastControllerImpl::GetValidCommands(CArray& commands)
{
    auto call =  [&](std::vector<int32_t>& native) {
        return controller_->GetValidCommands(native);
    };
    return CJControllerGetterCStruct<std::vector<int32_t>, CArray>(call, commands, "GetValidCommands");
}

int32_t CJAVCastControllerImpl::Release()
{
    auto call = [&]() {
        return controller_->Destroy();
    };
    return CJExecMethod(call, "Release");
}

int32_t CJAVCastControllerImpl::ProcessMediaKeyResponse(char*& assetId, CArray& response)
{
    std::string native(assetId);
    std::vector<uint8_t> native2;
    int ret = convertCJStructToNative(response, native2);
    if (ret != CJNO_ERROR) {
        SLOGE("ProcessMediaKeyResponse failed:%{public}d", ret);
        return ret;
    }
    ret = controller_->ProcessMediaKeyResponse(native, native2);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("ProcessMediaKeyResponse failed:%{public}d", ret);
    }
    return ret;
}
} // namespace OHOS::AVSession