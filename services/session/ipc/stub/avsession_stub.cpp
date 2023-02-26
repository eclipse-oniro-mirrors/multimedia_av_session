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

#include "avsession_stub.h"
#include "avsession_callback_proxy.h"
#include "avsession_trace.h"

namespace OHOS::AVSession {
bool AVSessionStub::CheckInterfaceToken(MessageParcel& data)
{
    auto localDescriptor = IAVSession::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        SLOGI("interface token is not equal");
        return false;
    }
    return true;
}

int32_t AVSessionStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    if (!CheckInterfaceToken(data)) {
        return AVSESSION_ERROR;
    }
    SLOGI("cmd code is %{public}d", code);
    if (code < SESSION_CMD_MAX) {
        return (this->*handlers[code])(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AVSessionStub::HandleGetSessionId(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteString(GetSessionId()), "write int32_t failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleRegisterCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "write int32_t failed");
        return ERR_NONE;
    }
    auto callback = iface_cast<AVSessionCallbackProxy>(remoteObject);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, ERR_NONE, "callback is nullptr");
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(RegisterCallbackInner(callback)),
                             ERR_NONE, "write int32_t failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleDestroy(MessageParcel& data, MessageParcel& reply)
{
    int32_t ret = Destroy();
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(AVSESSION_SUCCESS), ERR_NONE, "write int32_t failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "Destroy failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleGetAVPlaybackState(MessageParcel& data, MessageParcel& reply)
{
    AVPlaybackState avPlaybackState;
    int32_t ret = GetAVPlaybackState(avPlaybackState);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "GetAVPlaybackState failed");
    CHECK_AND_RETURN_RET_LOG(reply.WriteParcelable(&avPlaybackState), ERR_NONE, "write avPlaybackState failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleSetAVPlaybackState(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionStub::SetAVPlaybackState");
    sptr avPlaybackState = data.ReadParcelable<AVPlaybackState>();
    if (avPlaybackState == nullptr) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "WriteInt32 result failed");
        return ERR_NONE;
    }
    int32_t ret = SetAVPlaybackState(*avPlaybackState);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "WriteInt32 result failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "GetAVPlaybackState failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleSetAVMetaData(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionStub::SetAVMetaData");
    sptr avMetaData = data.ReadParcelable<AVMetaData>();
    if (avMetaData == nullptr) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "WriteInt32 result failed");
        return ERR_NONE;
    }
    int32_t ret = SetAVMetaData(*avMetaData);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "WriteInt32 result failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "GetAVPlaybackState failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleSetLaunchAbility(MessageParcel& data, MessageParcel& reply)
{
    sptr want = data.ReadParcelable<AbilityRuntime::WantAgent::WantAgent>();
    if (want == nullptr) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "WriteInt32 result failed");
        return ERR_NONE;
    }
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(SetLaunchAbility(*want)), ERR_NONE, "WriteInt32 result failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleGetAVMetaData(MessageParcel& data, MessageParcel& reply)
{
    AVMetaData avMetaData;
    int32_t ret = GetAVMetaData(avMetaData);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ERR_NONE, "GetAVMetaData failed");
    CHECK_AND_RETURN_RET_LOG(reply.WriteParcelable(&avMetaData), ERR_NONE, "write avMetaData failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleGetAVQueueItems(MessageParcel& data, MessageParcel& reply)
{
    std::vector<AVQueueItem> avQueueItems;
    int32_t ret = GetAVQueueItems(avQueueItems);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ERR_NONE, "GetAVQueueItems failed");
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(avQueueItems.size()), ERR_NONE, "write items num int32 failed");
    for (auto &parcelable : avQueueItems) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteParcelable(&parcelable), ERR_NONE, "Write items failed");
    }
    return ERR_NONE;
}

int32_t AVSessionStub::HandleSetAVQueueItems(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionStub::SetAVQueueItems");
    std::vector<AVQueueItem> items_;
    int32_t itemNum = data.ReadInt32();
    CHECK_AND_RETURN_RET_LOG(itemNum >= 0, ERR_UNMARSHALLING, "read int32 itemNum failed");
    for (int32_t i = 0; i < itemNum; i++) {
        AVQueueItem *item = data.ReadParcelable<AVQueueItem>();
        CHECK_AND_RETURN_RET_LOG(item != nullptr, ERR_UNMARSHALLING, "read parcelable AVQueueItem failed");
        items_.emplace_back(*item);
        delete item;
    }
    int32_t ret = SetAVQueueItems(items_);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "WriteInt32 result failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetAVQueueItems failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleGetAVQueueTitle(MessageParcel& data, MessageParcel& reply)
{
    std::string title;
    int32_t ret = GetAVQueueTitle(title);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ERR_NONE, "GetAVQueueTitle failed");
    CHECK_AND_RETURN_RET_LOG(reply.WriteString(title), ERR_NONE, "write title string failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleSetAVQueueTitle(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionStub::SetAVQueueTitle");
    std::string title;
    CHECK_AND_RETURN_RET_LOG(data.ReadString(title), ERR_NONE, "read title string failed");
    int32_t ret = SetAVQueueTitle(title);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "WriteInt32 result failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetAVQueueTitle failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleGetController(MessageParcel& data, MessageParcel& reply)
{
    sptr<IRemoteObject> controller = GetControllerInner();
    if (controller == nullptr) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(AVSESSION_ERROR), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(AVSESSION_SUCCESS), ERR_NONE, "write int32 failed");
    CHECK_AND_RETURN_RET_LOG(reply.WriteRemoteObject(controller), ERR_NONE, "write object failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleActivate(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(Activate()), ERR_NONE, "WriteInt32 failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleDeactivate(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(Deactivate()), ERR_NONE, "WriteInt32 failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleIsActive(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_RETURN_RET_LOG(reply.WriteBool(IsActive()), ERR_NONE, "WriteBool failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleAddSupportCommand(MessageParcel& data, MessageParcel& reply)
{
    int32_t ret = AddSupportCommand(data.ReadInt32());
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "WriteInt32 failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ERR_NONE, "AddSupportCommand failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleDeleteSupportCommand(MessageParcel& data, MessageParcel& reply)
{
    int32_t ret = DeleteSupportCommand(data.ReadInt32());
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "WriteInt32 failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ERR_NONE, "DeleteSupportCommand failed");
    return ERR_NONE;
}

int32_t AVSessionStub::HandleSetSessionEvent(MessageParcel& data, MessageParcel& reply)
{
    auto event = data.ReadString();
    sptr want = data.ReadParcelable<AAFwk::WantParams>();
    if (want == nullptr) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING), ERR_NONE, "WriteInt32 result failed");
        return ERR_NONE;
    }
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(SetSessionEvent(event, *want)), ERR_NONE, "WriteInt32 result failed");
    return ERR_NONE;
}
}