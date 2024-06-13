/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVSESSION_STUB_H
#define OHOS_AVSESSION_STUB_H

#include "iav_session.h"
#include "iremote_stub.h"
#include "want_agent.h"
#include "want_params.h"
#include "avsession_log.h"
#include "avsession_errors.h"

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include "avcast_controller.h"
#endif

namespace OHOS::AVSession {
class AVSessionStub : public IRemoteStub<IAVSession> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

    int32_t RegisterCallback(const std::shared_ptr<AVSessionCallback>& callback) override
    {
        return ERR_NONE;
    }

    std::shared_ptr<AVSessionController> GetController() override
    {
        return nullptr;
    }
    
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    std::shared_ptr<AVCastController> GetAVCastController() override
    {
        return nullptr;
    }
#endif

private:
    int32_t HandleGetSessionId(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetSessionType(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetAVCallMetaData(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetAVCallState(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVMetaData(MessageParcel& data, MessageParcel& reply);

    int32_t SetImageData(AVMetaData& meta, const char *buffer, int twoImageLength);

    int32_t HandleSetAVMetaData(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVPlaybackState(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetAVPlaybackState(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetLaunchAbility(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetExtras(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetExtras(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetController(MessageParcel& data, MessageParcel& reply);

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    int32_t HandleGetAVCastController(MessageParcel& data, MessageParcel& reply);

    int32_t HandleReleaseCast(MessageParcel& data, MessageParcel& reply);

    int32_t HandleStartCastDisplayListener(MessageParcel& data, MessageParcel& reply);

    int32_t HandleStopCastDisplayListener(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAllCastDisplays(MessageParcel& data, MessageParcel& reply);
#endif

    int32_t HandleRegisterCallbackInner(MessageParcel& data, MessageParcel& reply);

    int32_t HandleActivate(MessageParcel& data, MessageParcel& reply);

    int32_t HandleDeactivate(MessageParcel& data, MessageParcel& reply);

    int32_t HandleIsActive(MessageParcel& data, MessageParcel& reply);

    int32_t HandleDestroy(MessageParcel& data, MessageParcel& reply);

    int32_t HandleAddSupportCommand(MessageParcel& data, MessageParcel& reply);

    int32_t HandleDeleteSupportCommand(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetSessionEvent(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVQueueItems(MessageParcel& data, MessageParcel& reply);
    
    int32_t HandleSetAVQueueItems(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVQueueTitle(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetAVQueueTitle(MessageParcel& data, MessageParcel& reply);

    static bool CheckInterfaceToken(MessageParcel& data);

    using HandlerFunc = int32_t(AVSessionStub::*)(MessageParcel&, MessageParcel&);
    static inline HandlerFunc handlers[] = {
        &AVSessionStub::HandleGetSessionId,
        &AVSessionStub::HandleGetSessionType,
        &AVSessionStub::HandleGetAVMetaData,
        &AVSessionStub::HandleSetAVMetaData,
        &AVSessionStub::HandleGetAVPlaybackState,
        &AVSessionStub::HandleSetAVPlaybackState,
        &AVSessionStub::HandleGetAVQueueItems,
        &AVSessionStub::HandleSetAVQueueItems,
        &AVSessionStub::HandleGetAVQueueTitle,
        &AVSessionStub::HandleSetAVQueueTitle,
        &AVSessionStub::HandleGetExtras,
        &AVSessionStub::HandleSetExtras,
        &AVSessionStub::HandleSetLaunchAbility,
        &AVSessionStub::HandleGetController,
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
        &AVSessionStub::HandleGetAVCastController,
        &AVSessionStub::HandleStartCastDisplayListener,
        &AVSessionStub::HandleStopCastDisplayListener,
        &AVSessionStub::HandleGetAllCastDisplays,
#endif
        &AVSessionStub::HandleRegisterCallbackInner,
        &AVSessionStub::HandleActivate,
        &AVSessionStub::HandleDeactivate,
        &AVSessionStub::HandleIsActive,
        &AVSessionStub::HandleDestroy,
        &AVSessionStub::HandleAddSupportCommand,
        &AVSessionStub::HandleDeleteSupportCommand,
        &AVSessionStub::HandleSetSessionEvent,
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
        &AVSessionStub::HandleReleaseCast,
#endif
        &AVSessionStub::HandleSetAVCallMetaData,
        &AVSessionStub::HandleSetAVCallState,
    };

    int32_t MAX_IMAGE_SIZE = 10 * 1024 * 1024;
};
}
#endif // OHOS_AVSESSION_STUB_H
