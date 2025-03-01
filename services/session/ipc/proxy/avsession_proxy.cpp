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

#include "avsession_proxy.h"
#include "avsession_callback_client.h"
#include "avsession_controller_proxy.h"
#include "iavsession_callback.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_trace.h"

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include "avcast_controller_proxy.h"
#endif

namespace OHOS::AVSession {
AVSessionProxy::AVSessionProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IAVSession>(impl)
{
    SLOGD("construct");
}

AVSessionProxy::~AVSessionProxy()
{
    SLOGI("destroy");
    Destroy();
}

std::string AVSessionProxy::GetSessionId()
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, "", "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), "", "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, "", "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_GET_SESSION_ID, data, reply, option) == 0,
        "", "send request failed");

    std::string sessionId;
    CHECK_AND_RETURN_RET_LOG(reply.ReadString(sessionId), "", "read sessionId failed");
    return sessionId;
}

std::string AVSessionProxy::GetSessionType()
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, "", "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), "", "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, "", "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_GET_SESSION_TYPE, data, reply, option) == 0,
        "", "send request failed");

    std::string sessionType;
    CHECK_AND_RETURN_RET_LOG(reply.ReadString(sessionType), "", "read sessionType failed");
    return sessionType;
}

int32_t AVSessionProxy::RegisterCallback(const std::shared_ptr<AVSessionCallback>& callback)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, ERR_INVALID_PARAM, "callback is nullptr");
    callback_ = new(std::nothrow) AVSessionCallbackClient(callback);
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, ERR_NO_MEMORY, "new AVSessionCallbackClient failed");
    if (RegisterCallbackInner(callback_) != AVSESSION_SUCCESS) {
        callback_.clear();
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionProxy::RegisterCallbackInner(const sptr<IAVSessionCallback>& callback)
{
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()), ERR_MARSHALLING,
                             "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteRemoteObject(callback->AsObject()), ERR_MARSHALLING,
                             "write remote object failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_REGISTER_CALLBACK, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::Destroy()
{
    std::lock_guard isDestroyedLockGuard(isDestroyedLock_);
    SLOGI("enter");
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_DESTROY, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    if (!reply.ReadInt32(ret)) {
        return AVSESSION_ERROR;
    }
    if (ret == AVSESSION_SUCCESS) {
        isDestroyed_ = true;
        controller_ = nullptr;
    }
    return ret;
}

int32_t AVSessionProxy::SetAVCallMetaData(const AVCallMetaData& avCallMetaData)
{
    AVSESSION_TRACE_SYNC_START("AVSessionProxy::SetAVCallMetaData");
    CHECK_AND_RETURN_RET_LOG(avCallMetaData.IsValid(), ERR_INVALID_PARAM, "invalid call meta data");
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&avCallMetaData),
        ERR_MARSHALLING, "WriteParcelable failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_SET_AVCALL_META_DATA, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::SetAVCallState(const AVCallState& avCallState)
{
    AVSESSION_TRACE_SYNC_START("AVSessionProxy::SetAVCallState");
    CHECK_AND_RETURN_RET_LOG(avCallState.IsValid(), ERR_INVALID_PARAM, "av call state not valid");
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&avCallState),
        ERR_MARSHALLING, "Write state failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_SET_AVCALL_STATE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}


int32_t AVSessionProxy::GetPixelMapBuffer(AVMetaData& metaData, MessageParcel& data)
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

    if (!data.WriteInt32(twoImageLength) || !AVMetaData::MarshallingExceptImg(data, metaData)) {
        SLOGE("fail to write image length & metadata except img");
        delete[] buffer;
        return -1;
    }
    int32_t retForWriteRawData = data.WriteRawData(buffer, twoImageLength);
    SLOGI("write img raw data ret %{public}d", retForWriteRawData);

    delete[] buffer;
    return twoImageLength;
}

int32_t AVSessionProxy::SetAVMetaData(const AVMetaData& meta)
{
    AVSESSION_TRACE_SYNC_START("AVSessionProxy::SetAVMetaData");
    CHECK_AND_RETURN_RET_LOG(meta.IsValid(), ERR_INVALID_PARAM, "invalid meta data");

    std::lock_guard lockGuard(setMetadataLock_);
    SLOGI("SetAVMetaData in proxy");

    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    data.SetMaxCapacity(defaultIpcCapacity);
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");

    AVMetaData metaData;
    CHECK_AND_RETURN_RET_LOG(metaData.CopyFrom(meta), AVSESSION_ERROR, "avmetadata CopyFrom error");
    int twoImageLength = GetPixelMapBuffer(metaData, data);
    if (twoImageLength == 0) {
        CHECK_AND_RETURN_RET_LOG(data.WriteInt32(twoImageLength), ERR_MARSHALLING, "write twoImageLength failed");
        CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&meta), ERR_MARSHALLING, "write AVMetaData failed");
        CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_SET_META_DATA, data, reply, option) == 0,
            ERR_IPC_SEND_REQUEST, "send request failed");

        int32_t ret = AVSESSION_ERROR;
        return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
    }
    
    if (twoImageLength == -1) {
        SLOGE("fail to write parcel");
        return AVSESSION_ERROR;
    }

    if (remote->SendRequest(SESSION_CMD_SET_META_DATA, data, reply, option) != 0) {
        SLOGE("send request fail with raw img");
        return ERR_IPC_SEND_REQUEST;
    }
    SLOGI("set avmetadata done");
    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::GetAVMetaData(AVMetaData& meta)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
                             ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    reply.SetMaxCapacity(defaultIpcCapacity);
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_GET_META_DATA, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        std::shared_ptr<AVMetaData> metaData(reply.ReadParcelable<AVMetaData>());
        CHECK_AND_RETURN_RET_LOG(metaData != nullptr, ERR_UNMARSHALLING, "read metaData failed");
        meta = *metaData;
    }
    return ret;
}

int32_t AVSessionProxy::SetAVQueueItems(const std::vector<AVQueueItem>& items)
{
    AVSESSION_TRACE_SYNC_START("AVSessionProxy::SetAVQueueItems");
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    data.SetMaxCapacity(defaultIpcCapacity);
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(items.size()), ERR_MARSHALLING, "write items num int32 failed");
    for (auto &parcelable : items) {
        CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&parcelable), ERR_MARSHALLING, "Write items failed");
    }
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_SET_QUEUE_ITEMS, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::GetAVQueueItems(std::vector<AVQueueItem>& items)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
                             ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_GET_QUEUE_ITEMS, data, reply, option) == 0,
                             ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        std::vector<AVQueueItem> items_;
        int32_t maxItemNumber = 1000; // A maximum of 1000 queue items can be processed at a time
        int32_t itemNum = reply.ReadInt32();
        CHECK_AND_RETURN_RET_LOG((itemNum >= 0) && (itemNum < maxItemNumber),
            ERR_UNMARSHALLING, "read int32 itemNum failed");
        for (int32_t i = 0; i < itemNum; i++) {
            AVQueueItem *item = reply.ReadParcelable<AVQueueItem>();
            if (item == nullptr) {
                SLOGE("GetAVQueueItems: read parcelable AVQueueItem failed");
                delete item;
                item = nullptr;
                return ERR_UNMARSHALLING;
            }
            items_.emplace_back(*item);
            delete item;
            item = nullptr;
        }
        items = items_;
    }
    return ret;
}

int32_t AVSessionProxy::GetAVQueueTitle(std::string& title)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_GET_QUEUE_TITLE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        std::string title_;
        CHECK_AND_RETURN_RET_LOG(reply.ReadString(title), ERR_UNMARSHALLING, "read title string failed");
        title = title_;
    }
    return ret;
}

int32_t AVSessionProxy::SetAVQueueTitle(const std::string& title)
{
    AVSESSION_TRACE_SYNC_START("AVSessionProxy::SetAVQueueTitle");
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(title),
        ERR_MARSHALLING, "Write state failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_SET_QUEUE_TITLE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::GetAVPlaybackState(AVPlaybackState& state)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_GET_PLAYBACK_STATE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        std::shared_ptr<AVPlaybackState> playbackState(reply.ReadParcelable<AVPlaybackState>());
        CHECK_AND_RETURN_RET_LOG(playbackState != nullptr, ERR_UNMARSHALLING, "read playbackState failed");
        state = *playbackState;
    }
    return ret;
}

int32_t AVSessionProxy::SetAVPlaybackState(const AVPlaybackState& state)
{
    AVSESSION_TRACE_SYNC_START("AVSessionProxy::SetAVPlaybackState");
    CHECK_AND_RETURN_RET_LOG(state.IsValid(), ERR_INVALID_PARAM, "state not valid");
    std::lock_guard lockGuard(setPlaybackLock_);
    SLOGI("SetAVPlaybackState:%{public}d", state.GetState());

    std::lock_guard isDestroyedLockGuard(isDestroyedLock_);
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&state),
        ERR_MARSHALLING, "Write state failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_SET_PLAYBACK_STATE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::SetLaunchAbility(const AbilityRuntime::WantAgent::WantAgent& ability)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&ability),
        ERR_MARSHALLING, "Write WantAgent failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_SET_LAUNCH_ABILITY, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::GetExtras(AAFwk::WantParams& extras)
{
    AVSESSION_TRACE_SYNC_START("AVSessionProxy::GetExtras");
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_GET_EXTRAS, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_UNMARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        std::shared_ptr<AAFwk::WantParams> extrasData(reply.ReadParcelable<AAFwk::WantParams>());
        CHECK_AND_RETURN_RET_LOG(extrasData != nullptr, ERR_UNMARSHALLING, "read metaData failed");
        extras = *extrasData;
    }
    return ret;
}

int32_t AVSessionProxy::SetExtras(const AAFwk::WantParams& extras)
{
    AVSESSION_TRACE_SYNC_START("AVSessionProxy::SetExtras");
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&extras),
        ERR_MARSHALLING, "Write extras failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_SET_EXTRAS, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

sptr<IRemoteObject> AVSessionProxy::GetControllerInner()
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, nullptr, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
                             nullptr, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, nullptr, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_GET_CONTROLLER, data, reply, option) == 0,
                             nullptr, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), nullptr, "read int32 failed");
    sptr <IRemoteObject> controller = nullptr;
    if (ret == AVSESSION_SUCCESS) {
        controller = reply.ReadRemoteObject();
        CHECK_AND_RETURN_RET_LOG(controller != nullptr, nullptr, "read IRemoteObject failed");
    }
    return controller;
}

std::shared_ptr<AVSessionController> AVSessionProxy::GetController()
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, nullptr, "session is destroyed");
    CHECK_AND_RETURN_RET_LOG(controller_ == nullptr || controller_->IsDestroy(), controller_,
        "controller already exist");
    sptr <IRemoteObject> object = GetControllerInner();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "get object failed");
    auto controller = iface_cast<AVSessionControllerProxy>(object);
    controller_ = std::shared_ptr<AVSessionController>(controller.GetRefPtr(), [holder = controller](const auto*) {});
    return controller_;
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
sptr<IRemoteObject> AVSessionProxy::GetAVCastControllerInner()
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, nullptr, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
                             nullptr, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, nullptr, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_GET_AVCAST_CONTROLLER, data, reply, option) == 0,
        nullptr, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), nullptr, "read int32 failed");
    sptr <IRemoteObject> castController = nullptr;
    if (ret == AVSESSION_SUCCESS) {
        castController = reply.ReadRemoteObject();
        CHECK_AND_RETURN_RET_LOG(castController != nullptr, nullptr, "read IRemoteObject failed");
    }
    return castController;
}

std::shared_ptr<AVCastController> AVSessionProxy::GetAVCastController()
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, nullptr, "session is destroyed");
    sptr <IRemoteObject> object = GetAVCastControllerInner();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "get object failed");
    auto castController = iface_cast<AVCastControllerProxy>(object);
    castController_ = std::shared_ptr<AVCastController>(castController.GetRefPtr(),
        [holder = castController](const auto*) {});
    return castController_;
}

int32_t AVSessionProxy::StartCastDisplayListener()
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
                             ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_START_CAST_DISPLAY_LISTENER, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::StopCastDisplayListener()
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
                             ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_STOP_CAST_DISPLAY_LISTENER, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::GetAllCastDisplays(std::vector<CastDisplayInfo>& castDisplays)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
                             ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_GET_ALL_CAST_DISPLAYS, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(ret), ERR_MARSHALLING, "read int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        int32_t castDisplayNum = 0;
        CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(castDisplayNum), ERR_MARSHALLING, "read castDisplayNum failed");
        CHECK_AND_RETURN_RET_LOG(castDisplayNum > 0, ERR_MARSHALLING, "castDisplayNum is illegal");
        std::vector<CastDisplayInfo> displays;
        for (int32_t i = 0; i < castDisplayNum; i++) {
            CastDisplayInfo castDisplayInfo;
            int32_t displayState = -1;
            CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(displayState), ERR_MARSHALLING, "read displayState failed");
            castDisplayInfo.displayState = static_cast<CastDisplayState>(displayState);
            uint64_t displayId = 0;
            CHECK_AND_RETURN_RET_LOG(reply.ReadUint64(displayId), ERR_MARSHALLING, "read displayId failed");
            castDisplayInfo.displayId = displayId;
            std::string name = "";
            CHECK_AND_RETURN_RET_LOG(reply.ReadString(name), ERR_MARSHALLING, "read name failed");
            castDisplayInfo.name = name;
            int32_t width = -1;
            CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(width), ERR_MARSHALLING, "read width failed");
            castDisplayInfo.width = width;
            int32_t height = -1;
            CHECK_AND_RETURN_RET_LOG(reply.ReadInt32(height), ERR_MARSHALLING, "read height failed");
            castDisplayInfo.height = height;
            displays.push_back(castDisplayInfo);
        }
        castDisplays = displays;
    }
    return ret;
}
#endif

int32_t AVSessionProxy::Activate()
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_ACTIVATE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::Deactivate()
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_DEACTIVATE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

bool AVSessionProxy::IsActive()
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_ISACTIVE, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    bool ret = false;
    return reply.ReadBool(ret) ? ret : false;
}

int32_t AVSessionProxy::AddSupportCommand(const int32_t cmd)
{
    std::lock_guard lockGuard(setCommandLock_);
    SLOGI("add support command for %{public}d", cmd);

    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    CHECK_AND_RETURN_RET_LOG(cmd > AVControlCommand::SESSION_CMD_INVALID, AVSESSION_ERROR, "invalid cmd");
    CHECK_AND_RETURN_RET_LOG(cmd < AVControlCommand::SESSION_CMD_MAX, AVSESSION_ERROR, "invalid cmd");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(cmd),
        ERR_MARSHALLING, "Write cmd failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_ADD_SUPPORT_COMMAND, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::DeleteSupportCommand(const int32_t cmd)
{
    std::lock_guard lockGuard(setCommandLock_);
    SLOGI("del support command for %{public}d", cmd);

    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    CHECK_AND_RETURN_RET_LOG(cmd > AVControlCommand::SESSION_CMD_INVALID, AVSESSION_ERROR, "invalid cmd");
    CHECK_AND_RETURN_RET_LOG(cmd < AVControlCommand::SESSION_CMD_MAX, AVSESSION_ERROR, "invalid cmd");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
                             ERR_MARSHALLING, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteInt32(cmd),
                             ERR_MARSHALLING, "Write cmd failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_DELETE_SUPPORT_COMMAND, data, reply, option) == 0,\
                             ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

int32_t AVSessionProxy::SetSessionEvent(const std::string& event, const AAFwk::WantParams& args)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteString(event), ERR_MARSHALLING, "write event string failed");
    CHECK_AND_RETURN_RET_LOG(data.WriteParcelable(&args),
        ERR_MARSHALLING, "Write Want failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_SET_SESSION_EVENT, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
int32_t AVSessionProxy::ReleaseCast(bool continuePlay)
{
    CHECK_AND_RETURN_RET_LOG(!isDestroyed_, ERR_SESSION_NOT_EXIST, "session is destroyed");
    MessageParcel data;
    CHECK_AND_RETURN_RET_LOG(data.WriteInterfaceToken(GetDescriptor()),
        ERR_MARSHALLING, "write interface token failed");
    MessageParcel reply;
    MessageOption option;
    auto remote = Remote();
    CHECK_AND_RETURN_RET_LOG(remote != nullptr, ERR_SERVICE_NOT_EXIST, "get remote service failed");
    CHECK_AND_RETURN_RET_LOG(remote->SendRequest(SESSION_CMD_RELEASE_CAST, data, reply, option) == 0,
        ERR_IPC_SEND_REQUEST, "send request failed");

    int32_t ret = AVSESSION_ERROR;
    return reply.ReadInt32(ret) ? ret : AVSESSION_ERROR;
}
#endif
} // namespace OHOS::AVSession
