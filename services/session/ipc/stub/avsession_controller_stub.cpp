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

#include "avsession_controller_stub.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "session_xcollie.h"

namespace OHOS::AVSession {
bool AVSessionControllerStub::CheckInterfaceToken(MessageParcel& data)
{
    auto localDescriptor = IAVSessionController::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        SLOGI("interface token is not equal");
        return false;
    }
    return true;
}

int32_t AVSessionControllerStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
    MessageOption &option)
{
    SessionXCollie sessionXCollie(mapCodeToFuncNameXCollie[code]);
    if (!CheckInterfaceToken(data)) {
        return AVSESSION_ERROR;
    }
    if (code < CONTROLLER_CMD_MAX) {
        return handlers[code](data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AVSessionControllerStub::HandleRegisterCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write RegisterCallback ret failed");
    } else {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(RegisterCallbackInner(remoteObject)),
            "write RegisterCallback ret failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleDestroy(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteInt32(Destroy()), "write release() ret failed");
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetAVCallState(MessageParcel& data, MessageParcel& reply)
{
    AVCallState state;
    int32_t ret = GetAVCallState(state);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteParcelable(&state), "write AVCallState failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetAVCallMetaData(MessageParcel& data, MessageParcel& reply)
{
    AVCallMetaData metaData;
    int32_t ret = GetAVCallMetaData(metaData);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteParcelable(&metaData), "write AVCallMetaData failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetAVPlaybackState(MessageParcel& data, MessageParcel& reply)
{
    AVPlaybackState state;
    int32_t ret = GetAVPlaybackState(state);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteParcelable(&state), "write AVPlaybackState failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleSendControlCommand(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionControllerStub::SendControlCommand");
    sptr<AVControlCommand> cmd = data.ReadParcelable<AVControlCommand>();
    if (cmd == nullptr) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write SendCommand ret failed");
    } else {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(SendControlCommand(*cmd)), "write SendCommand ret failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleSendCommonCommand(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionControllerStub::SendCommonCommand");
    auto commonCommand = data.ReadString();
    sptr commandArgs = data.ReadParcelable<AAFwk::WantParams>();
    if (commandArgs == nullptr) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "WriteInt32 result failed");
        return ERR_NONE;
    }
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(SendCommonCommand(commonCommand, *commandArgs)),
        ERR_NONE, "WriteInt32 result failed");
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetAVMetaData(MessageParcel& data, MessageParcel& reply)
{
    AVMetaData metaData;
    int32_t ret = GetAVMetaData(metaData);
    std::string uri = metaData.GetMediaImageUri();
    if (ret != ERR_INVALID_PARAM) {
        SLOGI("ImgSetLoop get controller isFromSession true");
    } else {
        ret = AVSESSION_SUCCESS;
        SLOGI("ImgSetLoop get controller isFromSession false, set empty");
        metaData.SetMediaImageUri("");
    }
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ERR_NONE, "GetAVMetaData failed");

    int res = DoMetadataGetReplyInStub(metaData, reply);
    SLOGI("ImgSetLoop DoMetadataGetReplyInStub with res %{public}d", res);
    metaData.SetMediaImageUri(uri);
    DoMetadataImgCleanInStub(metaData);
    return ERR_NONE;
}

int32_t AVSessionControllerStub::DoMetadataGetReplyInStub(AVMetaData& metaData, MessageParcel& reply)
{
    int mediaImageLength = 0;
    std::vector<uint8_t> mediaImageBuffer;
    std::shared_ptr<AVSessionPixelMap> mediaPixelMap = metaData.GetMediaImage();
    if (mediaPixelMap != nullptr) {
        mediaImageBuffer = mediaPixelMap->GetInnerImgBuffer();
        mediaImageLength = static_cast<int>(mediaImageBuffer.size());
        metaData.SetMediaLength(mediaImageLength);
    }

    int avQueueImageLength = 0;
    std::vector<uint8_t> avQueueImageBuffer;
    std::shared_ptr<AVSessionPixelMap> avQueuePixelMap = metaData.GetAVQueueImage();
    if (avQueuePixelMap != nullptr) {
        avQueueImageBuffer = avQueuePixelMap->GetInnerImgBuffer();
        avQueueImageLength = static_cast<int>(avQueueImageBuffer.size());
        metaData.SetAVQueueLength(avQueueImageLength);
    }

    int twoImageLength = mediaImageLength + avQueueImageLength;
    if (twoImageLength == 0) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(twoImageLength), "write twoImageLength failed");
        CHECK_AND_PRINT_LOG(reply.WriteParcelable(&metaData), "write AVMetaData failed");
        return ERR_NONE;
    }

    unsigned char *buffer = new (std::nothrow) unsigned char[twoImageLength];
    if (buffer == nullptr) {
        SLOGE("new buffer failed of length = %{public}d", twoImageLength);
        return AVSESSION_ERROR;
    }

    for (int i = 0; i < mediaImageLength; i++) {
        buffer[i] = mediaImageBuffer[i];
    }

    for (int j = mediaImageLength, k = 0; j < twoImageLength && k < avQueueImageLength; j++, k++) {
        buffer[j] = avQueueImageBuffer[k];
    }

    if (!reply.WriteInt32(twoImageLength) || !AVMetaData::MarshallingExceptImg(reply, metaData)) {
        SLOGE("fail to write image length & metadata except img with clean");
        delete[] buffer;
        return AVSESSION_ERROR;
    }
    int32_t retForWriteRawData = reply.WriteRawData(buffer, twoImageLength);
    SLOGI("write img raw data ret with clean %{public}d", retForWriteRawData);
    delete[] buffer;
    return retForWriteRawData;
}

void AVSessionControllerStub::DoMetadataImgCleanInStub(AVMetaData& data)
{
    SLOGI("still clear media img in DoMetadataImgCleanInStub");
    std::shared_ptr<AVSessionPixelMap> innerQueuePixelMap = data.GetAVQueueImage();
    if (innerQueuePixelMap != nullptr) {
        innerQueuePixelMap->Clear();
    }
    std::shared_ptr<AVSessionPixelMap> innerMediaPixelMap = data.GetMediaImage();
    if (innerMediaPixelMap != nullptr) {
        innerMediaPixelMap->Clear();
    }
}

int32_t AVSessionControllerStub::HandleGetAVQueueItems(MessageParcel& data, MessageParcel& reply)
{
    std::vector<AVQueueItem> items;
    int32_t ret = GetAVQueueItems(items);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(items.size()), ERR_NONE, "write items num int32 failed");
        for (auto &parcelable : items) {
            CHECK_AND_RETURN_RET_LOG(reply.WriteParcelable(&parcelable), ERR_NONE, "Write items failed");
        }
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetAVQueueTitle(MessageParcel& data, MessageParcel& reply)
{
    std::string title;
    int32_t ret = GetAVQueueTitle(title);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteString(title), "write title failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleSkipToQueueItem(MessageParcel& data, MessageParcel& reply)
{
    int32_t itemId;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(itemId), ERR_NONE, "read itemId int32 failed");
    int32_t ret = SkipToQueueItem(itemId);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetExtras(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionControllerStub::HandleGetExtras");
    AAFwk::WantParams extras;
    int32_t ret = GetExtras(extras);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteParcelable(&extras), "write title failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleSendAVKeyEvent(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionControllerStub::SendAVKeyEvent");
    std::shared_ptr<MMI::KeyEvent> event = MMI::KeyEvent::Create();
    if (event == nullptr) {
        SLOGI("malloc keyEvent failed");
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_NO_MEMORY), "write SendAVKeyEvent ret failed");
        return ERR_NONE;
    }

    event->ReadFromParcel(data);
    if (!event->IsValid()) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write SendAVKeyEvent ret failed");
    } else {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(SendAVKeyEvent(*(event.get()))),
            "write SendAVKeyEvent ret failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetLaunchAbility(MessageParcel& data, MessageParcel& reply)
{
    AbilityRuntime::WantAgent::WantAgent ability;
    int32_t ret = GetLaunchAbility(ability);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteParcelable(&ability), "write LaunchAbility failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetValidCommands(MessageParcel& data, MessageParcel& reply)
{
    std::vector<int32_t> cmds;
    int32_t ret = GetValidCommands(cmds);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32Vector(cmds), "write int32 vector failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleSetAVCallMetaFilter(MessageParcel& data, MessageParcel& reply)
{
    std::string str = data.ReadString();
    if (str.length() != AVCallMetaData::AVCALL_META_KEY_MAX) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write SetAVCallMetaFilter ret failed");
        return ERR_NONE;
    }
    if (str.find_first_not_of("01") != std::string::npos) {
        SLOGI("mask string not 0 or 1");
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write int32 failed");
        return ERR_NONE;
    }
    AVCallMetaData::AVCallMetaMaskType filter(str);
    CHECK_AND_PRINT_LOG(reply.WriteInt32(SetAVCallMetaFilter(filter)), "write int32 failed");
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleSetAVCallStateFilter(MessageParcel& data, MessageParcel& reply)
{
    std::string str = data.ReadString();
    if (str.length() != AVCallState::AVCALL_STATE_KEY_MAX) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write SetAVCallStateFilter ret failed");
        return ERR_NONE;
    }
    if (str.find_first_not_of("01") != std::string::npos) {
        SLOGI("mask string not all 0 or 1");
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write int32 failed");
        return ERR_NONE;
    }
    AVCallState::AVCallStateMaskType filter(str);
    CHECK_AND_PRINT_LOG(reply.WriteInt32(SetAVCallStateFilter(filter)), "write int32 failed");
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleSetMetaFilter(MessageParcel& data, MessageParcel& reply)
{
    std::string str = data.ReadString();
    if (str.length() != AVMetaData::META_KEY_MAX) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write SetMetaFilter ret failed");
        return ERR_NONE;
    }
    if (str.find_first_not_of("01") != std::string::npos) {
        SLOGI("mask string not 0 or 1");
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write int32 failed");
        return ERR_NONE;
    }
    AVMetaData::MetaMaskType filter(str);
    CHECK_AND_PRINT_LOG(reply.WriteInt32(SetMetaFilter(filter)), "write int32 failed");
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleSetPlaybackFilter(MessageParcel& data, MessageParcel& reply)
{
    std::string str = data.ReadString();
    if (str.length() != AVPlaybackState::PLAYBACK_KEY_MAX) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write SetPlaybackFilter ret failed");
        return ERR_NONE;
    }
    if (str.find_first_not_of("01") != std::string::npos) {
        SLOGI("mask string not all 0 or 1");
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write int32 failed");
        return ERR_NONE;
    }
    AVPlaybackState::PlaybackStateMaskType filter(str);
    CHECK_AND_PRINT_LOG(reply.WriteInt32(SetPlaybackFilter(filter)), "write int32 failed");
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleIsSessionActive(MessageParcel& data, MessageParcel& reply)
{
    bool isActive = false;
    int32_t ret = IsSessionActive(isActive);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteBool(isActive), "write bool failed");
    }
    return ERR_NONE;
}

int32_t AVSessionControllerStub::HandleGetSessionId(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteString(GetSessionId()), "write int32_t failed");
    return ERR_NONE;
}
} // namespace OHOS::AVSession