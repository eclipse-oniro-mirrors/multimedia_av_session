/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <dlfcn.h>
#include "remote_session_source_impl.h"
#include "avsession_trace.h"
#include "remote_session_source_proxy.h"

namespace OHOS::AVSession {
RemoteSessionSourceProxy::RemoteSessionSourceProxy()
{
    LoadSourceImplement();
}
RemoteSessionSourceProxy::~RemoteSessionSourceProxy()
{
    UnLoadSourceImplement();
}

int32_t RemoteSessionSourceProxy::LoadSourceImplement() __attribute__((no_sanitize("cfi")))
{
    handle_ = dlopen("libremote_session_source.z.so", RTLD_NOW);
    if (handle_ == nullptr) {
        SLOGE("Failed to open library %{public}s, reason: %{public}sn",
            "libremote_session_source.z.so", dlerror());
        return AVSESSION_ERROR;
    }
    using SourceImpl = RemoteSessionSourceImpl* (*)();

    auto createRemoteSessionSourceImpl = (SourceImpl)(dlsym(handle_, "CreateRemoteSessionSourceImpl"));
    if (createRemoteSessionSourceImpl == nullptr) {
        if (handle_ != nullptr) {
#ifndef TEST_COVERAGE
            dlclose(handle_);
#endif
        }
        SLOGE("Failed to get extension symbol %{public}s in %{public}s",
            "RemoteSessionSourceImpl", "libremote_session_source.z.so");
        return AVSESSION_ERROR;
    }

    sourceImpl_ = createRemoteSessionSourceImpl();
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSourceProxy::UnLoadSourceImplement() __attribute__((no_sanitize("cfi")))
{
    using SourceImpl = void(*)(RemoteSessionSourceImpl*);
    auto destroyRemoteSessionSourceImpl = (SourceImpl)(dlsym(handle_, "DestroyRemoteSessionSourceImpl"));
    if (destroyRemoteSessionSourceImpl == nullptr) {
        if (handle_ != nullptr) {
#ifndef TEST_COVERAGE
            dlclose(handle_);
#endif
        }
        SLOGE("Failed to get extension symbol %{public}s in %{public}s",
            "DestroyRemoteSessionSourceImpl", "libremote_session_source.z.so");
        return AVSESSION_ERROR;
    }
    destroyRemoteSessionSourceImpl(sourceImpl_);
    if (handle_ != nullptr) {
#ifndef TEST_COVERAGE
        dlclose(handle_);
#endif
    }
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSourceProxy::CastSessionToRemote(const sptr <AVSessionItem>& session,
                                                      const std::string& sourceDevice,
                                                      const std::string& sinkDevice,
                                                      const std::string& sinkCapability)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSourceProxy::CastSessionToRemote");
    CHECK_AND_RETURN_RET_LOG(sourceImpl_ != nullptr, AVSESSION_ERROR, "sourceImpl_ is nullptr");
    int32_t ret = sourceImpl_->CastSessionToRemote(session, sourceDevice, sinkDevice, sinkCapability);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "source CastSessionToRemote error");
    return AVSESSION_SUCCESS;
}

int32_t  RemoteSessionSourceProxy::CancelCastAudio(const std::string& sinkDevice)
{
    CHECK_AND_RETURN_RET_LOG(sourceImpl_ != nullptr, AVSESSION_ERROR, "sourceImpl_ is nullptr");
    int32_t ret = sourceImpl_->CancelCastAudio(sinkDevice);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "source CastSessionToLocal error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSourceProxy::SetAVMetaData(const AVMetaData& metaData)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSourceProxy::SetAVMetaData");
    CHECK_AND_RETURN_RET_LOG(sourceImpl_ != nullptr, AVSESSION_ERROR, "sourceImpl_ is nullptr");
    int32_t ret = sourceImpl_->SetAVMetaData(metaData);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "source SetAVMetaData error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSourceProxy::SetAVPlaybackState(const AVPlaybackState& state)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSourceProxy::SetAVPlaybackState");
    CHECK_AND_RETURN_RET_LOG(sourceImpl_ != nullptr, AVSESSION_ERROR, "sourceImpl_ is nullptr");
    int32_t ret = sourceImpl_->SetAVPlaybackState(state);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "source SetAVPlaybackState error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSourceProxy::SetSessionEventRemote(const std::string& event, const AAFwk::WantParams& args)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSourceProxy::SetSessionEventRemote");
    CHECK_AND_RETURN_RET_LOG(sourceImpl_ != nullptr, AVSESSION_ERROR, "sourceImpl_ is nullptr");
    int32_t ret = sourceImpl_->SetSessionEventRemote(event, args);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "source SetSessionEventRemote error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSourceProxy::SetAVQueueItems(const std::vector<AVQueueItem>& items)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSourceProxy::SetAVQueueItems");
    CHECK_AND_RETURN_RET_LOG(sourceImpl_ != nullptr, AVSESSION_ERROR, "sourceImpl_ is nullptr");
    int32_t ret = sourceImpl_->SetAVQueueItems(items);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "source SetAVQueueItems error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSourceProxy::SetAVQueueTitle(const std::string& title)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSourceProxy::SetAVQueueTitle");
    CHECK_AND_RETURN_RET_LOG(sourceImpl_ != nullptr, AVSESSION_ERROR, "sourceImpl_ is nullptr");
    int32_t ret = sourceImpl_->SetAVQueueTitle(title);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "source SetAVQueueTitle error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSourceProxy::SetExtrasRemote(const AAFwk::WantParams& extras)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSourceProxy::SetExtrasRemote");
    CHECK_AND_RETURN_RET_LOG(sourceImpl_ != nullptr, AVSESSION_ERROR, "sourceImpl_ is nullptr");
    int32_t ret = sourceImpl_->SetExtrasRemote(extras);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "source SetExtrasRemote error");
    return AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession
