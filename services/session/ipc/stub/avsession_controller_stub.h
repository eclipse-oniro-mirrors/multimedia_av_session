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

#ifndef OHOS_AVSESSION_CONTROLLER_STUB_H
#define OHOS_AVSESSION_CONTROLLER_STUB_H

#include "iavsession_controller.h"
#include "iremote_stub.h"

namespace OHOS::AVSession {
class AVSessionControllerStub : public IRemoteStub<IAVSessionController> {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

    int32_t RegisterCallback(const std::shared_ptr<AVControllerCallback>& callback) override
    {
        return 0;
    }

    int64_t GetRealPlaybackPosition() override
    {
        return 0;
    }

    bool IsDestroy() override
    {
        return true;
    }

private:
    int32_t HandleRegisterCallbackInner(MessageParcel& data, MessageParcel& reply);

    int32_t HandleDestroy(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVPlaybackState(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSendControlCommand(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSendCommonCommand(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVMetaData(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVQueueItems(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetAVQueueTitle(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSkipToQueueItem(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetExtras(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSendAVKeyEvent(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetLaunchAbility(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetValidCommands(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetMetaFilter(MessageParcel& data, MessageParcel& reply);

    int32_t HandleSetPlaybackFilter(MessageParcel& data, MessageParcel& reply);

    int32_t HandleIsSessionActive(MessageParcel& data, MessageParcel& reply);

    int32_t HandleGetSessionId(MessageParcel& data, MessageParcel& reply);

    static bool CheckInterfaceToken(MessageParcel& data);

    using HandlerFunc = int32_t (AVSessionControllerStub::*)(MessageParcel& data, MessageParcel& reply);
    static inline HandlerFunc handlers[] = {
        &AVSessionControllerStub::HandleRegisterCallbackInner,
        &AVSessionControllerStub::HandleDestroy,
        &AVSessionControllerStub::HandleGetAVPlaybackState,
        &AVSessionControllerStub::HandleGetAVMetaData,
        &AVSessionControllerStub::HandleSendAVKeyEvent,
        &AVSessionControllerStub::HandleGetLaunchAbility,
        &AVSessionControllerStub::HandleGetValidCommands,
        &AVSessionControllerStub::HandleSendControlCommand,
        &AVSessionControllerStub::HandleSendCommonCommand,
        &AVSessionControllerStub::HandleSetMetaFilter,
        &AVSessionControllerStub::HandleSetPlaybackFilter,
        &AVSessionControllerStub::HandleIsSessionActive,
        &AVSessionControllerStub::HandleGetSessionId,
        &AVSessionControllerStub::HandleGetAVQueueItems,
        &AVSessionControllerStub::HandleGetAVQueueTitle,
        &AVSessionControllerStub::HandleSkipToQueueItem,
        &AVSessionControllerStub::HandleGetExtras,
    };
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_CONTROLLER_STUB_H