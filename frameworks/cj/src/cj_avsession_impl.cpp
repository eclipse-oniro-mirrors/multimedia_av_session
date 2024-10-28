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

#include "cj_avsession_impl.h"

#include "avsession_log.h"
#include "avsession_manager.h"
#include "cj_avsession_utils.h"
#include "cj_avsession_manager_impl.h"
#include "cj_avsession_controller_impl.h"

namespace OHOS::AVSession {

template<class NT, class CJT>
int32_t CJAVSessionSetterCStruct(
    std::function<int32_t(NT&)> method, CJT& cj, std::string method_name)
{
    NT native;
    int32_t ret = convertCJStructToNative(cj, native);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("controller %{public}s failed:%{public}d", method_name.c_str(), ret);
    } else {
        ret = method(native);
        if (ret != CJNO_ERROR) {
            SLOGE("controller %{public}s failed:%{public}d", method_name.c_str(), ret);
        }
    }
    return ret;
}

int32_t CJExecMethod(std::function<int32_t()> method, std::string method_name)
{
    int32_t ret = method();
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("controller %{public}s failed:%{public}d", method_name.c_str(), ret);
    }
    return ret;
}

CJAVSessionImpl::CJAVSessionImpl(std::shared_ptr<AVSession> session)
{
    session_ = session;
    sessionId_ = session_->GetSessionId();
    sessionType_ = session_->GetSessionType();
}

int32_t CJAVSessionImpl::SetAVMetaData(CAVMetaData& data)
{
    auto call = [&](AVMetaData& native) {
        return session_->SetAVMetaData(native);
    };
    return CJAVSessionSetterCStruct<AVMetaData, CAVMetaData>(call, data, "SetAVMetaData");
}

int32_t CJAVSessionImpl::SetAVCallMetaData(CAVCallMetaData& data)
{
    auto call = [&](AVCallMetaData& native) {
        return session_->SetAVCallMetaData(native);
    };
    return CJAVSessionSetterCStruct<AVCallMetaData, CAVCallMetaData>(call, data, "SetAVCallMetaData");
}

int32_t CJAVSessionImpl::SetAVCallState(CAVCallState& state)
{
    auto call = [&](AVCallState& native) {
        return session_->SetAVCallState(native);
    };
    return CJAVSessionSetterCStruct<AVCallState, CAVCallState>(call, state, "SetAVCallState");
}

int32_t CJAVSessionImpl::SetAVPlaybackState(CAVPlaybackState& state)
{
    auto call = [&](AVPlaybackState& native) {
        return session_->SetAVPlaybackState(native);
    };
    return CJAVSessionSetterCStruct<AVPlaybackState, CAVPlaybackState>(call, state, "SetAVPlaybackState");
}

int32_t CJAVSessionImpl::SetAVQueueItems(CArray& items)
{
    auto call = [&](std::vector<AVQueueItem>& native) {
        return session_->SetAVQueueItems(native);
    };
    return CJAVSessionSetterCStruct<std::vector<AVQueueItem>, CArray>(call, items, "SetAVQueueItems");
}

int32_t CJAVSessionImpl::SetAVQueueTitle(char*& title)
{
    int32_t ret = session_->SetAVQueueTitle(std::string(title));
    if (ret != CJNO_ERROR) {
        SLOGE("controller SetAVQueueTitle failed:%{public}d", ret);
    }
    return ret;
}

int32_t CJAVSessionImpl::SetExtras(CArray& extras)
{
    auto call = [&](AAFwk::WantParams& native) {
        return session_->SetExtras(native);
    };
    return CJAVSessionSetterCStruct<AAFwk::WantParams, CArray>(call, extras, "SetExtras");
}

int32_t CJAVSessionImpl::GetController()
{
    auto controller = CJAVSessionControllerImpl::GetInstance(sessionId_);
    if (controller) {
        return CJNO_ERROR;
    } else {
        return CJ_AVSESSION_MANAGER_IMPL->CreateController(sessionId_);
    }
}

int32_t CJAVSessionImpl::GetOutputDevice(COutputDeviceInfo& outputDeviceInfo)
{
    AVSessionDescriptor descriptor;
    AVSessionManager::GetInstance().GetSessionDescriptorsBySessionId(sessionId_, descriptor);
    int32_t ret = convertNativeToCJStruct(descriptor.outputDeviceInfo_, outputDeviceInfo);
    if (ret != CJNO_ERROR) {
        SLOGE("controller GetOutputDevice failed:%{public}d", ret);
    }
    return ret;
}

int32_t CJAVSessionImpl::Activate()
{
    auto call = [&]() {
        return session_->Activate();
    };
    return CJExecMethod(call, "Activate");
}

int32_t CJAVSessionImpl::Deactivate()
{
    auto call = [&]() {
        return session_->Deactivate();
    };
    return CJExecMethod(call, "Deactivate");
}

int32_t CJAVSessionImpl::Destroy()
{
    auto call = [&]() {
        return session_->Destroy();
    };
    return CJExecMethod(call, "Destroy");
}

int32_t CJAVSessionImpl::StopCasting()
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    auto call = [&]() {
        return session_->ReleaseCast();
    };
    return CJExecMethod(call, "StopCasting");
#else
    return CJNO_ERROR;
#endif
}
    
}  // namespace AVSession::OHOS