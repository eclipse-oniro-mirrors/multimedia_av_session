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

#include "avcontroller_callback_proxy.h"
#include "avsession_log.h"

namespace OHOS::AVSession {
AVControllerCallbackProxy::AVControllerCallbackProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IAVControllerCallback>(impl)
{
    SLOGD("construct");
}

void AVControllerCallbackProxy::OnSessionDestroy()
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CONTROLLER_CMD_ON_SESSION_DESTROY, parcel, reply, option) == 0,
        "send request failed");
}

void AVControllerCallbackProxy::OnAVCallMetaDataChange(const AVCallMetaData& data)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteParcelable(&data), "write AVCallMetaData failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CONTROLLER_CMD_ON_AVCALL_METADATA_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}


void AVControllerCallbackProxy::OnAVCallStateChange(const AVCallState& state)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteParcelable(&state), "write AVCallState failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CONTROLLER_CMD_ON_AVCALL_STATE_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}


void AVControllerCallbackProxy::OnPlaybackStateChange(const AVPlaybackState& state)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteParcelable(&state), "write PlaybackState failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CONTROLLER_CMD_ON_PLAYBACK_STATE_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

int32_t AVControllerCallbackProxy::GetPixelMapBuffer(AVMetaData& metaData, MessageParcel& parcel)
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
        return 0;
    }

    unsigned char *buffer = new (std::nothrow) unsigned char[twoImageLength];
    if (buffer == nullptr) {
        SLOGE("new buffer failed of length = %{public}d", twoImageLength);
        return -1;
    }

    for (int i = 0; i < mediaImageLength; i++) {
        buffer[i] = mediaImageBuffer[i];
    }

    for (int j = mediaImageLength, k = 0; j < twoImageLength && k < avQueueImageLength; j++, k++) {
        buffer[j] = avQueueImageBuffer[k];
    }

    if (!parcel.WriteInt32(twoImageLength) || !AVMetaData::MarshallingExceptImg(parcel, metaData)) {
        SLOGE("fail to write image length & metadata except img");
        delete[] buffer;
        return -1;
    }
    int32_t retForWriteRawData = parcel.WriteRawData(buffer, twoImageLength);
    SLOGI("write img raw data ret %{public}d", retForWriteRawData);

    delete[] buffer;
    return twoImageLength;
}

void AVControllerCallbackProxy::OnMetaDataChange(const AVMetaData& data)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");

    AVMetaData metaData;
    CHECK_AND_RETURN_LOG(metaData.CopyFrom(data), "avmetadata CopyFrom error");

    int twoImageLength = GetPixelMapBuffer(metaData, parcel);
    if (twoImageLength == 0) {
        CHECK_AND_RETURN_LOG(parcel.WriteInt32(twoImageLength), "write twoImageLength failed");
        CHECK_AND_RETURN_LOG(parcel.WriteParcelable(&data), "write AVMetaData failed");
        CHECK_AND_RETURN_LOG(remote->SendRequest(CONTROLLER_CMD_ON_METADATA_CHANGE, parcel, reply, option) == 0,
            "send request failed");
        return;
    }
    if (twoImageLength == -1) {
        SLOGE("fail to write parcel");
        return;
    }

    CHECK_AND_RETURN_LOG(remote->SendRequest(CONTROLLER_CMD_ON_METADATA_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVControllerCallbackProxy::OnActiveStateChange(bool isActive)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteBool(isActive), "write bool failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CONTROLLER_CMD_ON_ACTIVE_STATE_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVControllerCallbackProxy::OnValidCommandChange(const std::vector<int32_t>& cmds)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteInt32Vector(cmds), "write int32 vector failed");

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CONTROLLER_CMD_ON_VALID_COMMAND_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVControllerCallbackProxy::OnOutputDeviceChange(const int32_t connectionState,
    const OutputDeviceInfo& outputDeviceInfo)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteInt32(connectionState), "write connectionState failed");

    int32_t deviceInfoSize = static_cast<int32_t>(outputDeviceInfo.deviceInfos_.size());
    CHECK_AND_RETURN_LOG(parcel.WriteInt32(deviceInfoSize), "write deviceInfoSize failed");
    for (DeviceInfo deviceInfo : outputDeviceInfo.deviceInfos_) {
        CHECK_AND_RETURN_LOG(parcel.WriteInt32(deviceInfo.castCategory_), "write castCategory failed");
        CHECK_AND_RETURN_LOG(parcel.WriteString(deviceInfo.deviceId_), "write deviceId failed");
        CHECK_AND_RETURN_LOG(parcel.WriteString(deviceInfo.deviceName_), "write deviceName failed");
        CHECK_AND_RETURN_LOG(parcel.WriteInt32(deviceInfo.deviceType_), "write deviceType failed");
        CHECK_AND_RETURN_LOG(parcel.WriteString(deviceInfo.ipAddress_), "write ipAddress failed");
        CHECK_AND_RETURN_LOG(parcel.WriteInt32(deviceInfo.providerId_), "write providerId failed");
        CHECK_AND_RETURN_LOG(parcel.WriteInt32(deviceInfo.supportedProtocols_),
            "write supportedProtocols failed");
        CHECK_AND_RETURN_LOG(parcel.WriteInt32(deviceInfo.authenticationStatus_),
            "write authenticationStatus failed");
        CHECK_AND_RETURN_LOG(parcel.WriteInt32(deviceInfo.supportedDrmCapabilities_.size()),
            "write supportedDrmCapabilities size failed");
        for (auto supportedDrmCapability : deviceInfo.supportedDrmCapabilities_) {
            CHECK_AND_RETURN_LOG(parcel.WriteString(supportedDrmCapability),
                "write supportedDrmCapability failed");
        }
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CONTROLLER_CMD_ON_OUTPUT_DEVICE_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVControllerCallbackProxy::OnSessionEventChange(const std::string& event, const AAFwk::WantParams& args)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteString(event), "write event string failed");
    CHECK_AND_RETURN_LOG(parcel.WriteParcelable(&args), "Write Want failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CONTROLLER_CMD_ON_SET_SESSION_EVENT, parcel, reply, option) == 0,
        "send request failed");
}

void AVControllerCallbackProxy::OnQueueItemsChange(const std::vector<AVQueueItem>& items)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");

    CHECK_AND_RETURN_LOG(parcel.WriteInt32(items.size()), "write items num int32 failed");
    for (auto &parcelable : items) {
        CHECK_AND_RETURN_LOG(parcel.WriteParcelable(&parcelable), "Write items failed");
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CONTROLLER_CMD_ON_QUEUE_ITEMS_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVControllerCallbackProxy::OnQueueTitleChange(const std::string& title)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteString(title), "write string failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CONTROLLER_CMD_ON_QUEUE_TITLE_CHANGE, parcel, reply, option) == 0,
        "send request failed");
}

void AVControllerCallbackProxy::OnExtrasChange(const AAFwk::WantParams& extras)
{
    MessageParcel parcel;
    CHECK_AND_RETURN_LOG(parcel.WriteInterfaceToken(GetDescriptor()), "write interface token failed");
    CHECK_AND_RETURN_LOG(parcel.WriteParcelable(&extras), "Write extras failed");
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    auto remote = Remote();
    CHECK_AND_RETURN_LOG(remote != nullptr, "get remote service failed");
    CHECK_AND_RETURN_LOG(remote->SendRequest(CONTROLLER_CMD_ON_SET_EXTRAS_EVENT, parcel, reply, option) == 0,
        "send request failed");
}
} // namespace OHOS::AVSession
