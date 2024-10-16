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

#include "cj_avsession_controller_impl.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>
#include <string>

#include "want.h"
#include "avqueue_item.h"
#include "avsession_log.h"
#include "avsession_manager.h"
#include "cj_avsession_utils.h"

namespace OHOS::AVSession {

template<class NT, class CJT>
int32_t CJControllerGetterCStruct(
    std::function<int32_t(NT&)> method, CJT& cj, std::string method_name)
{
    NT native;
    int32_t ret = method(native);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("controller %{public}s failed:%{public}d", method_name.c_str(), ret);
    } else {
        ret = convertNativeToCJStruct(native, cj);
        if (ret != CJNO_ERROR) {
            SLOGE("controller %{public}s failed:%{public}d", method_name.c_str(), ret);
        }
    }
    return ret;
}

std::map<std::string, std::shared_ptr<CJAVSessionControllerImpl>> CJAVSessionControllerImpl::ControllerList_ = {};
std::mutex CJAVSessionControllerImpl::controllerListMutex_;

CJAVSessionControllerImpl::CJAVSessionControllerImpl(std::shared_ptr<AVSessionController>& nativeController)
{
    if (nativeController) {
        sessionId_ = nativeController->GetSessionId();
    }
    controller_ = nativeController;
}

CJAVSessionControllerImpl::~CJAVSessionControllerImpl() {}


CJAVSessionControllerInvalidImpl::CJAVSessionControllerInvalidImpl() {}
CJAVSessionControllerInvalidImpl::~CJAVSessionControllerInvalidImpl() {}

std::shared_ptr<CJAVSessionControllerBase> CJAVSessionControllerImpl::GetInstance(const std::string &sessionId)
{
    std::lock_guard<std::mutex> lock(controllerListMutex_);
    if (ControllerList_.count(sessionId) == 1) {
        return std::static_pointer_cast<CJAVSessionControllerBase>(ControllerList_[sessionId]);
    }
    return std::static_pointer_cast<CJAVSessionControllerBase>(CJ_AVSESSION_CONTROLLER_INVALID_IMPL);
}

std::shared_ptr<CJAVSessionControllerImpl> CJAVSessionControllerImpl::NewInstance(
    std::shared_ptr<AVSessionController> &nativeController)
{
    struct CJAVSessionControllerImplInner: public CJAVSessionControllerImpl {
        CJAVSessionControllerImplInner(std::shared_ptr<AVSessionController>& nativeController)
            : CJAVSessionControllerImpl(nativeController) {}
    };
    auto controller = std::make_shared<CJAVSessionControllerImplInner>(nativeController);
    std::lock_guard<std::mutex> lock(controllerListMutex_);
    ControllerList_[nativeController->GetSessionId()] = controller;
    return controller;
}

int32_t CJAVSessionControllerImpl::Destroy()
{
    {
        std::lock_guard<std::mutex> lock(controllerListMutex_);
        ControllerList_.erase(sessionId_);
    }
    return controller_->Destroy();
}

int32_t CJAVSessionControllerImpl::GetAVCallState(CAVCallState& avCallState)
{
    auto call =  [&](AVCallState& native) {
        return controller_->GetAVCallState(native);
    };
    return CJControllerGetterCStruct<AVCallState, CAVCallState>(call, avCallState, "GetAVCallState");
}

int32_t CJAVSessionControllerImpl::GetAVCallMetaData(CAVCallMetaData& avCallMetadata)
{
    auto call =  [&](AVCallMetaData& native) {
        return controller_->GetAVCallMetaData(native);
    };
    return CJControllerGetterCStruct<AVCallMetaData, CAVCallMetaData>(call, avCallMetadata, "GetAVCallMetaData");
}

int32_t CJAVSessionControllerImpl::GetAVPlaybackState(CAVPlaybackState& avPlaybackState)
{
    auto call =  [&](AVPlaybackState& native) {
        return controller_->GetAVPlaybackState(native);
    };
    return CJControllerGetterCStruct<AVPlaybackState, CAVPlaybackState>(call, avPlaybackState, "GetAVPlaybackState");
}

int32_t CJAVSessionControllerImpl::GetAVMetaData(CAVMetaData& avMetadata)
{
    auto call =  [&](AVMetaData& native) {
        return controller_->GetAVMetaData(native);
    };
    return CJControllerGetterCStruct<AVMetaData, CAVMetaData>(call, avMetadata, "GetAVMetaData");
}

int32_t CJAVSessionControllerImpl::GetOutputDevice(COutputDeviceInfo& outputDeviceInfo)
{
    auto call =  [&](OutputDeviceInfo& native) {
        AVSessionDescriptor descriptor;
        AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId(controller_->GetSessionId(), descriptor);
        native = descriptor.outputDeviceInfo_;
        return CJNO_ERROR;
    };
    return CJControllerGetterCStruct<OutputDeviceInfo, COutputDeviceInfo>(call, outputDeviceInfo, "GetOutputDevice");
}

int32_t CJAVSessionControllerImpl::GetRealPlaybackPosition(int64_t& position)
{
    position = controller_->GetRealPlaybackPosition();
    return AVSESSION_SUCCESS;
}

int32_t CJAVSessionControllerImpl::IsActive(bool& isActive)
{
    auto call =  [&](bool& native) {
        return controller_->IsSessionActive(native);
    };
    return CJControllerGetterCStruct<bool, bool>(call, isActive, "IsActive");
}

int32_t CJAVSessionControllerImpl::GetValidCommands(CArray& commands)
{
    auto call =  [&](std::vector<int32_t>& native) {
        return controller_->GetValidCommands(native);
    };
    return CJControllerGetterCStruct<std::vector<int32_t>, CArray>(call, commands, "GetValidCommands");
}

int32_t CJAVSessionControllerImpl::GetAVQueueItems(CArray& items)
{
    auto call =  [&](std::vector<AVQueueItem>& native) {
        return controller_->GetAVQueueItems(native);
    };
    return CJControllerGetterCStruct<std::vector<AVQueueItem>, CArray>(call, items, "GetAVQueueItems");
}

int32_t CJAVSessionControllerImpl::GetAVQueueTitle(char*& title)
{
    auto call =  [&](std::string& native) {
        return controller_->GetAVQueueTitle(native);
    };
    return CJControllerGetterCStruct<std::string, char*>(call, title, "GetAVQueueTitle");
}

int32_t CJAVSessionControllerImpl::GetExtras(CArray& extras)
{
    auto call =  [&](AAFwk::WantParams& native) {
        return controller_->GetExtras(native);
    };
    return CJControllerGetterCStruct<AAFwk::WantParams, CArray>(call, extras, "GetExtras");
}

int32_t CJAVSessionControllerImpl::SendCommonCommand(char*& command, CArray& args)
{
    if (args.size != 1) {
        return ERR_INVALID_PARAM;
    }
    AAFwk::WantParams commandArgs;
    convertCJStructToNative(args, commandArgs);
    int32_t ret = controller_->SendCommonCommand(std::string(command), commandArgs);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("controller SendCommonCommand failed:%{public}d", ret);
    }
    return ret;
}

int32_t CJAVSessionControllerImpl::SkipToQueueItem(int32_t& itemId)
{
    int32_t ret = controller_->SkipToQueueItem(itemId);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("controller SkipToQueueItem failed:%{public}d", ret);
    }
    return ret;
}

} // namespace OHOS::AVSession