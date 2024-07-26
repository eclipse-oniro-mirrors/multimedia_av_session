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
#include "avsession_trace.h"
#include "remote_session_sink_proxy.h"

namespace OHOS::AVSession {
RemoteSessionSinkProxy::RemoteSessionSinkProxy()
{
    LoadSinkImplement();
}

RemoteSessionSinkProxy::~RemoteSessionSinkProxy()
{
    UnLoadSinkImplement();
}

int32_t RemoteSessionSinkProxy::LoadSinkImplement() __attribute__((no_sanitize("cfi")))
{
    handle_ = dlopen("libremote_session_sink.z.so", RTLD_NOW);
    if (handle_ == nullptr) {
        SLOGE("Failed to open extension library, reason: %{public}sn", dlerror());
        return AVSESSION_ERROR;
    }
    using SinkImpl = RemoteSessionSinkImpl* (*)();

    auto createRemoteSessionSinkImpl = (SinkImpl)(dlsym(handle_, "CreateRemoteSessionSinkImpl"));
    if (createRemoteSessionSinkImpl == nullptr) {
        if (handle_ != nullptr) {
            dlclose(handle_);
        }
        SLOGE("Failed to get extension symbol %{public}s", "RemoteSessionSinkImpl");
        return AVSESSION_ERROR;
    }

    sinkImpl_ = createRemoteSessionSinkImpl();
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSinkProxy::UnLoadSinkImplement() __attribute__((no_sanitize("cfi")))
{
    using SinkImpl = void(*)(RemoteSessionSinkImpl*);
    auto destroyRemoteSessionSinkImpl = (SinkImpl)(dlsym(handle_, "DestroyRemoteSessionSinkImpl"));
    if (destroyRemoteSessionSinkImpl == nullptr) {
        if (handle_ != nullptr) {
            dlclose(handle_);
        }
        SLOGE("Failed to get extension symbol %{public}s in %{public}s", "DestroyRemoteSessionSinkImpl",
              g_sinkLibraryPath.c_str());
        return AVSESSION_ERROR;
    }
    destroyRemoteSessionSinkImpl(sinkImpl_);

    if (handle_ != nullptr) {
        dlclose(handle_);
    }
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSinkProxy::CastSessionFromRemote(const sptr <AVSessionItem>& session,
                                                      const std::string& sourceSessionId,
                                                      const std::string& sourceDevice,
                                                      const std::string& sinkDevice,
                                                      const std::string& sourceCap)
{
    CHECK_AND_RETURN_RET_LOG(sinkImpl_ != nullptr, AVSESSION_ERROR, "sinkImpl_ is nullptr");
    int32_t ret = sinkImpl_->CastSessionFromRemote(session, sourceSessionId, sourceDevice, sinkDevice, sourceCap);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "source CastSessionFromRemote error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSinkProxy::CancelCastSession()
{
    CHECK_AND_RETURN_RET_LOG(sinkImpl_ != nullptr, AVSESSION_ERROR, "sinkImpl_ is nullptr");
    int32_t ret = sinkImpl_->CancelCastSession();
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "source CancelCastSession error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSinkProxy::SetControlCommand(const AVControlCommand& command)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSinkProxy::SetControlCommand");
    CHECK_AND_RETURN_RET_LOG(sinkImpl_ != nullptr, AVSESSION_ERROR, "sinkImpl_ is nullptr");
    int32_t ret = sinkImpl_->SetControlCommand(command);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "source SetControlCommand error");
    return AVSESSION_SUCCESS;
}

int32_t RemoteSessionSinkProxy::SetCommonCommand(const std::string& commonCommand,
    const AAFwk::WantParams& commandArgs)
{
    AVSESSION_TRACE_SYNC_START("RemoteSessionSinkProxy::SetCommonCommand");
    CHECK_AND_RETURN_RET_LOG(sinkImpl_ != nullptr, AVSESSION_ERROR, "sinkImpl_ is nullptr");
    int32_t ret = sinkImpl_->SetCommonCommand(commonCommand, commandArgs);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "Source SetCommonCommand error");
    return AVSESSION_SUCCESS;
}
} // namespace OHOS::AVSession
