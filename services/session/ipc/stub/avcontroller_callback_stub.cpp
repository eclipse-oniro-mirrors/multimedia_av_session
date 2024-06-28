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
#include "avcontroller_callback_stub.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
bool AVControllerCallbackStub::CheckInterfaceToken(MessageParcel& data)
{
    auto localDescriptor = IAVControllerCallback::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        SLOGI("interface token is not equal");
        return false;
    }
    return true;
}

int32_t AVControllerCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
    MessageOption &option)
{
    if (!CheckInterfaceToken(data)) {
        return AVSESSION_ERROR;
    }
    if (code < CONTROLLER_CMD_MAX) {
        return handlers[code](data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AVControllerCallbackStub::HandleOnSessionDestroy(MessageParcel& data, MessageParcel& reply)
{
    OnSessionDestroy();
    return ERR_NONE;
}

int32_t AVControllerCallbackStub::HandleOnAVCallMetadataChange(MessageParcel& data, MessageParcel& reply)
{
    sptr<AVCallMetaData> metaData = data.ReadParcelable<AVCallMetaData>();

    CHECK_AND_RETURN_RET_LOG(metaData != nullptr, ERR_NONE, "read AVCall MetaData failed");
    AVSESSION_TRACE_SYNC_START("AVControllerCallbackStub::OnAVCallMetaDataChange");
    OnAVCallMetaDataChange(*metaData);
    return ERR_NONE;
}

int32_t AVControllerCallbackStub::HandleOnAVCallStateChange(MessageParcel& data, MessageParcel& reply)
{
    sptr<AVCallState> state = data.ReadParcelable<AVCallState>();

    CHECK_AND_RETURN_RET_LOG(state != nullptr, ERR_NONE, "read AVCallState failed");
    AVSESSION_TRACE_SYNC_START("AVControllerCallbackStub::OnAVCallStateChange");
    OnAVCallStateChange(*state);
    return ERR_NONE;
}

int32_t AVControllerCallbackStub::HandleOnPlaybackStateChange(MessageParcel& data, MessageParcel& reply)
{
    sptr<AVPlaybackState> state = data.ReadParcelable<AVPlaybackState>();
    if (state == nullptr) {
        SLOGE("HandleOnPlaybackStateChange meet state nullptr, return");
        return ERR_NONE;
    }

    std::lock_guard lockGuard(onPlaybackChangeLock_);
    SLOGI("do HandleOnPlaybackStateChange");

    CHECK_AND_RETURN_RET_LOG(state != nullptr, ERR_NONE, "read PlaybackState failed");
    AVSESSION_TRACE_SYNC_START("AVControllerCallbackStub::OnPlaybackStateChange");
    OnPlaybackStateChange(*state);
    reply.WriteInt32(AVSESSION_SUCCESS);
    return ERR_NONE;
}

int32_t AVControllerCallbackStub::HandleOnMetadataChange(MessageParcel& data, MessageParcel& reply)
{
    std::lock_guard lockGuard(onMetadataChangeLock_);
    SLOGI("do HandleOnMetadataChange");

    AVSESSION_TRACE_SYNC_START("AVControllerCallbackStub::OnMetaDataChange");
    int twoImageLength = data.ReadInt32();
    SLOGI("read length from twoImage %{public}d", twoImageLength);
    if (twoImageLength <= 0 || twoImageLength > MAX_IMAGE_SIZE) {
        sptr avMetaData = data.ReadParcelable<AVMetaData>();
        CHECK_AND_RETURN_RET_LOG(avMetaData != nullptr, ERR_NONE, "read MetaData failed");
        OnMetaDataChange(*avMetaData);
        reply.WriteInt32(AVSESSION_SUCCESS);
        return ERR_NONE;
    }

    AVMetaData meta;
    AVMetaData::UnmarshallingExceptImg(data, meta);
    const char *buffer = nullptr;
    buffer = reinterpret_cast<const char *>(data.ReadRawData(twoImageLength));
    int mediaImageLength = meta.GetMediaLength();
    if (buffer == nullptr || mediaImageLength <= 0) {
        SLOGE("read raw data with null %{public}d, or err media img length:%{public}d",
            static_cast<int>(buffer == nullptr), mediaImageLength);
        OnMetaDataChange(meta);
        reply.WriteInt32(AVSESSION_SUCCESS);
        return ERR_NONE;
    }

    auto mediaPixelMap = new (std::nothrow) AVSessionPixelMap();
    std::vector<uint8_t> mediaImageBuffer;
    for (int i = 0; i < mediaImageLength; i++) {
        mediaImageBuffer.push_back((uint8_t)buffer[i]);
    }
    mediaPixelMap->SetInnerImgBuffer(mediaImageBuffer);
    meta.SetMediaImage(std::shared_ptr<AVSessionPixelMap>(mediaPixelMap));

    if (twoImageLength > mediaImageLength) {
        auto avQueuePixelMap = new (std::nothrow) AVSessionPixelMap();
        std::vector<uint8_t> avQueueImageBuffer;
        for (int j = mediaImageLength; j < twoImageLength; j++) {
            avQueueImageBuffer.push_back((uint8_t)buffer[j]);
        }
        avQueuePixelMap->SetInnerImgBuffer(avQueueImageBuffer);
        meta.SetAVQueueImage(std::shared_ptr<AVSessionPixelMap>(avQueuePixelMap));
    }
    OnMetaDataChange(meta);
    reply.WriteInt32(AVSESSION_SUCCESS);
    return ERR_NONE;
}

int32_t AVControllerCallbackStub::HandleOnActiveStateChange(MessageParcel& data, MessageParcel& reply)
{
    bool isActive = false;
    CHECK_AND_RETURN_RET_LOG(data.ReadBool(isActive), ERR_NONE, "read isActive failed");
    OnActiveStateChange(isActive);
    return ERR_NONE;
}

int32_t AVControllerCallbackStub::HandleOnValidCommandChange(MessageParcel& data, MessageParcel& reply)
{
    std::vector<int32_t> cmds;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32Vector(&cmds), ERR_NONE, "read int32 vector failed");
    std::lock_guard lockGuard(onCommandChangeLock_);
    SLOGI("do HandleOnValidCommandChange with cmd list size %{public}d", static_cast<int>(cmds.size()));

    OnValidCommandChange(cmds);
    reply.WriteInt32(AVSESSION_SUCCESS);
    return ERR_NONE;
}

int32_t AVControllerCallbackStub::HandleOnOutputDeviceChange(MessageParcel& data, MessageParcel& reply)
{
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
        int32_t supportedDrmCapabilityLen = 0;
        CHECK_AND_RETURN_RET_LOG(data.ReadInt32(supportedDrmCapabilityLen), false,
            "read supportedDrmCapabilityLen failed");
        std::vector<std::string> supportedDrmCapabilities;
        int32_t maxSupportedDrmCapabilityLen = 10;
        CHECK_AND_RETURN_RET_LOG((supportedDrmCapabilityLen >= 0) &&
            (supportedDrmCapabilityLen <= maxSupportedDrmCapabilityLen), false, "supportedDrmCapabilityLen is illegal");
        for (int j = 0; j < supportedDrmCapabilityLen; j++) {
            std::string supportedDrmCapability;
            CHECK_AND_RETURN_RET_LOG(data.ReadString(supportedDrmCapability), false,
                "read supportedDrmCapability failed");
            supportedDrmCapabilities.emplace_back(supportedDrmCapability);
        }
        deviceInfo.supportedDrmCapabilities_ = supportedDrmCapabilities;
        outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
    }

    OnOutputDeviceChange(connectionState, outputDeviceInfo);
    return ERR_NONE;
}

int32_t AVControllerCallbackStub::HandleOnSessionEventChange(MessageParcel& data, MessageParcel& reply)
{
    auto event = data.ReadString();
    sptr want = data.ReadParcelable<AAFwk::WantParams>();

    CHECK_AND_RETURN_RET_LOG(want != nullptr, ERR_NONE, "read want args failed");
    AVSESSION_TRACE_SYNC_START("AVControllerCallbackStub::OnSessionEventChange");
    OnSessionEventChange(event, *want);
    return ERR_NONE;
}

int32_t AVControllerCallbackStub::HandleOnQueueItemsChange(MessageParcel& data, MessageParcel& reply)
{
    std::vector<AVQueueItem> items_;
    int32_t maxItemNumber = 1000; // A maximum of 1000 queue items can be processed at a time
    int32_t itemNum = data.ReadInt32();
    CHECK_AND_RETURN_RET_LOG((itemNum >= 0) && (itemNum < maxItemNumber), ERR_NONE, "read int32 itemNum failed");
    for (int32_t i = 0; i < itemNum; i++) {
        AVQueueItem *item = data.ReadParcelable<AVQueueItem>();
        if (item == nullptr) {
            SLOGE("GetAVQueueItems: read parcelable AVQueueItem failed");
            delete item;
            return ERR_UNMARSHALLING;
        }
        items_.emplace_back(*item);
        delete item;
    }
    AVSESSION_TRACE_SYNC_START("AVControllerCallbackStub::OnQueueItemsChange");
    OnQueueItemsChange(items_);
    return ERR_NONE;
}

int32_t AVControllerCallbackStub::HandleOnQueueTitleChange(MessageParcel& data, MessageParcel& reply)
{
    auto title = data.ReadString();
    AVSESSION_TRACE_SYNC_START("AVControllerCallbackStub::OnQueueTitleChange");
    OnQueueTitleChange(title);
    return ERR_NONE;
}

int32_t AVControllerCallbackStub::HandleOnExtrasChange(MessageParcel& data, MessageParcel& reply)
{
    sptr extras = data.ReadParcelable<AAFwk::WantParams>();
    CHECK_AND_RETURN_RET_LOG(extras != nullptr, ERR_NONE, "read extras failed");
    AVSESSION_TRACE_SYNC_START("AVControllerCallbackStub::OnExtrasChange");
    OnExtrasChange(*extras);
    return ERR_NONE;
}
} // namespace OHOS::AVSession
