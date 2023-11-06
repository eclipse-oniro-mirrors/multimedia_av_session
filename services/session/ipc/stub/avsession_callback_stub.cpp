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

#include "avsession_callback_stub.h"
#include "avsession_errors.h"
#include "iavsession_callback.h"
#include "key_event.h"
#include "avsession_log.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
int32_t AVSessionCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
    MessageOption& option)
{
    if (!CheckInterfaceToken(data)) {
        return AVSESSION_ERROR;
    }
    if (code < SESSION_CALLBACK_MAX) {
        return (this->*handlers[code])(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool AVSessionCallbackStub::CheckInterfaceToken(MessageParcel& data)
{
    auto localDescriptor = IAVSessionCallback::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        SLOGI("interface token is not equal");
        return false;
    }
    return true;
}

int32_t AVSessionCallbackStub::HandleOnPlay(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionCallbackStub::OnPlay");
    OnPlay();
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnPause(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionCallbackStub::OnPause");
    OnPause();
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnStop(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionCallbackStub::OnStop");
    OnStop();
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnPlayNext(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionCallbackStub::OnPlayNext");
    OnPlayNext();
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnPlayPrevious(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionCallbackStub::OnPlayPrevious");
    OnPlayPrevious();
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnFastForward(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionCallbackStub::OnFastForward");
    int32_t time = -1;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(time), ERR_NONE, "read time failed");
    OnFastForward(time);
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnRewind(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionCallbackStub::OnRewind");
    int32_t time = -1;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(time), ERR_NONE, "read time failed");
    OnRewind(time);
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnSeek(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionCallbackStub::OnSeek");
    int32_t time = -1;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(time), ERR_NONE, "read time failed");
    OnSeek(time);
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnSetSpeed(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionCallbackStub::OnSetSpeed");
    double speed = 0.0;
    CHECK_AND_RETURN_RET_LOG(data.ReadDouble(speed), ERR_NONE, "read speed failed");
    OnSetSpeed(speed);
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnSetLoopMode(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionCallbackStub::OnSetLoopMode");
    int32_t loopMode = -1;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(loopMode), ERR_NONE, "read loopMode failed");
    OnSetLoopMode(loopMode);
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnToggleFavorite(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionCallbackStub::OnToggleFavorite");
    std::string mediaId;
    CHECK_AND_RETURN_RET_LOG(data.ReadString(mediaId), ERR_NONE, "read mediaId failed");
    OnToggleFavorite(mediaId);
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnMediaKeyEvent(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionCallbackStub::OnMediaKeyEvent");
    auto keyEvent = MMI::KeyEvent::Create();
    CHECK_AND_RETURN_RET_LOG((*keyEvent).ReadFromParcel(data), ERR_NONE, "read keyEvent failed");
    OnMediaKeyEvent(*keyEvent);
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnOutputDeviceChange(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionCallbackStub::OnOutputDeviceChange");
    int32_t connectionState;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(connectionState), false, "write deviceInfoSize failed");
    OutputDeviceInfo outputDeviceInfo;
    int32_t deviceInfoSize;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(deviceInfoSize), false, "write deviceInfoSize failed");
    int32_t maxDeviceInfoSize = 1000; // A maximum of 1000 device change events can be processed at a time
    CHECK_AND_RETURN_RET_LOG((deviceInfoSize >= 0) && (deviceInfoSize < maxDeviceInfoSize),
        false, "deviceInfoSize is illegal");
    for (int i = 0; i < deviceInfoSize; i++) {
        DeviceInfo deviceInfo;
        CHECK_AND_RETURN_RET_LOG(data.ReadInt32(deviceInfo.castCategory_), false, "Read castCategory failed");
        CHECK_AND_RETURN_RET_LOG(data.ReadString(deviceInfo.deviceId_), false, "Read deviceId failed");
        CHECK_AND_RETURN_RET_LOG(data.ReadString(deviceInfo.deviceName_), false, "Read deviceName failed");
        CHECK_AND_RETURN_RET_LOG(data.ReadInt32(deviceInfo.deviceType_), false, "Read deviceType failed");
        CHECK_AND_RETURN_RET_LOG(data.ReadString(deviceInfo.ipAddress_), false, "Read ipAddress failed");
        CHECK_AND_RETURN_RET_LOG(data.ReadInt32(deviceInfo.providerId_), false, "Read providerId failed");
        CHECK_AND_RETURN_RET_LOG(data.ReadInt32(deviceInfo.supportedProtocols_), false,
            "Read supportedProtocols failed");
        CHECK_AND_RETURN_RET_LOG(data.ReadInt32(deviceInfo.authenticationStatus_), false,
            "Read authenticationStatus failed");
        outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
    }
    
    OnOutputDeviceChange(connectionState, outputDeviceInfo);
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnCommonCommand(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionCallbackStub::OnCommonCommand");
    auto commonCommand = data.ReadString();
    sptr commonArgs = data.ReadParcelable<AAFwk::WantParams>();
    CHECK_AND_RETURN_RET_LOG(commonArgs != nullptr, ERR_NONE, "Read common args failed");
    OnCommonCommand(commonCommand, *commonArgs);
    return ERR_NONE;
}

int32_t AVSessionCallbackStub::HandleOnSkipToQueueItem(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionCallbackStub::OnSkipToQueueItem");
    int32_t itemId = -1;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(itemId), ERR_NONE, "read itemId failed");
    OnSkipToQueueItem(itemId);
    return ERR_NONE;
}
} // namespace OHOS::AVSession
