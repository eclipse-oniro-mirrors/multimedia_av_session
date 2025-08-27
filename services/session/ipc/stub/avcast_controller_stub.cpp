/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "avcast_controller_stub.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "ipc_skeleton.h"
#include "media_info_holder.h"
#include "surface_utils.h"
#include "session_xcollie.h"
#include "permission_checker.h"

namespace OHOS::AVSession {
bool AVCastControllerStub::CheckInterfaceToken(MessageParcel& data)
{
    auto localDescriptor = IAVCastController::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        SLOGI("interface token is not equal");
        return false;
    }
    return true;
}

int32_t AVCastControllerStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
    MessageOption &option)
{
    CHECK_AND_RETURN_RET_LOG(IPCSkeleton::IsLocalCalling(), AVSESSION_ERROR, "forbid rpc remote request");
    if (code >= static_cast<uint32_t>(IAVCastController::CAST_CONTROLLER_CMD_SEND_CONTROL_COMMAND)
        && code < static_cast<uint32_t>(IAVCastController::CAST_CONTROLLER_CMD_MAX)) {
        SessionXCollie sessionXCollie(mapCodeToFuncNameXCollie[code]);
    }
    if (!CheckInterfaceToken(data)) {
        return AVSESSION_ERROR;
    }
    if (code >= static_cast<uint32_t>(IAVCastController::CAST_CONTROLLER_CMD_SEND_CONTROL_COMMAND)
        && code < static_cast<uint32_t>(IAVCastController::CAST_CONTROLLER_CMD_MAX)) {
        return handlers[code](data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AVCastControllerStub::HandleRegisterCallbackInner(MessageParcel& data, MessageParcel& reply)
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

int32_t AVCastControllerStub::HandleSendControlCommand(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVCastControllerStub::SendControlCommand");
    sptr<AVCastControlCommand> cmd = data.ReadParcelable<AVCastControlCommand>();
    if (cmd == nullptr) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING),
            ERR_UNMARSHALLING, "write SendCommand ret failed");
    } else {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(SendControlCommand(*cmd)),
            ERR_UNMARSHALLING, "write SendCommand ret failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleSendCustomData(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVCastControllerStub::SendCustomData");
    sptr customData = data.ReadParcelable<AAFwk::WantParams>();
    if (customData == nullptr) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ERR_UNMARSHALLING),
            ERR_UNMARSHALLING, "write SendCustomData ret failed");
    } else {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(SendCustomData(*customData)),
            ERR_UNMARSHALLING, "write SendCustomData ret failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleStart(MessageParcel& data, MessageParcel& reply)
{
    sptr<AVQueueItem> avQueueItem = data.ReadParcelable<AVQueueItem>();
    AVFileDescriptor avFileDescriptor;
    avFileDescriptor.fd_ = data.ReadFileDescriptor();
    if (avQueueItem == nullptr) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write Start ret failed");
    } else {
        avQueueItem->GetDescription()->SetFdSrc(avFileDescriptor);
        CHECK_AND_PRINT_LOG(reply.WriteInt32(Start(*avQueueItem)), "Write mediaInfoHolder failed");
    }
    if (avFileDescriptor.fd_ < 0) {
        SLOGE("HandleStart read fd is invalid");
    } else {
        close(avFileDescriptor.fd_);
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandlePrepare(MessageParcel& data, MessageParcel& reply)
{
    sptr<AVQueueItem> avQueueItem = data.ReadParcelable<AVQueueItem>();
    if (avQueueItem == nullptr) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write prepare ret failed");
    } else {
        if (data.ReadBool()) {
            SLOGD("Need get fd from proxy");
            AVFileDescriptor avFileDescriptor;
            avFileDescriptor.fd_ = data.ReadFileDescriptor();
            SLOGD("Prepare received fd %{public}d", avFileDescriptor.fd_);
            avQueueItem->GetDescription()->SetFdSrc(avFileDescriptor);
            CHECK_AND_PRINT_LOG(reply.WriteInt32(Prepare(*avQueueItem)), "fd != 0, Write mediaInfoHolder failed");
            if (avQueueItem->GetDescription()->GetFdSrc().fd_ < 0) {
                SLOGE("HandlePrepare read fd is invalid");
            } else {
                close(avQueueItem->GetDescription()->GetFdSrc().fd_);
            }
        } else {
            CHECK_AND_PRINT_LOG(reply.WriteInt32(Prepare(*avQueueItem)), "Write mediaInfoHolder failed");
        }
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetDuration(MessageParcel& data, MessageParcel& reply)
{
    int32_t duration = 0;
    int32_t ret = GetDuration(duration);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_UNMARSHALLING, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(duration), ERR_UNMARSHALLING, "write int32 failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetCastAVPlayBackState(MessageParcel& data, MessageParcel& reply)
{
    AVPlaybackState state;
    int32_t ret = GetCastAVPlaybackState(state);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteParcelable(&state), "write CastAVPlaybackState failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetSupportedDecoders(MessageParcel& data, MessageParcel& reply)
{
    std::vector<std::string> decoderTypes;
    int32_t ret = GetSupportedDecoders(decoderTypes);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteStringVector(decoderTypes), "write GetSupportedDecoders failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetRecommendedResolutionLevel(MessageParcel& data, MessageParcel& reply)
{
    std::string decoderType = data.ReadString();
    CHECK_AND_RETURN_RET_LOG(!decoderType.empty(), ERR_NONE, "decoderType is empty");
    ResolutionLevel resolutionLevel = ResolutionLevel::RESOLUTION_480P;
    int32_t ret = GetRecommendedResolutionLevel(decoderType, resolutionLevel);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        int32_t resolutionLevelInt = static_cast<int32_t>(resolutionLevel);
        CHECK_AND_PRINT_LOG(reply.WriteInt32(resolutionLevelInt), "write CastAVPlaybackState failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetSupportedHdrCapabilities(MessageParcel& data, MessageParcel& reply)
{
    std::vector<HDRFormat> hdrFormats;
    int32_t ret = GetSupportedHdrCapabilities(hdrFormats);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        std::vector<int32_t> hdrFormatsInt;
        for (auto it = hdrFormats.begin(); it != hdrFormats.end(); it++) {
            hdrFormatsInt.emplace_back(static_cast<int32_t>(*it));
        }
        CHECK_AND_PRINT_LOG(reply.WriteInt32Vector(hdrFormatsInt), "write GetSupportedHdrCapabilities failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetSupportedPlaySpeeds(MessageParcel& data, MessageParcel& reply)
{
    std::vector<float> playSpeeds;
    int32_t ret = GetSupportedPlaySpeeds(playSpeeds);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteFloatVector(playSpeeds), "write GetSupportedPlaySpeeds failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetCurrentItem(MessageParcel& data, MessageParcel& reply)
{
    AVQueueItem currentItem;
    int32_t ret = GetCurrentItem(currentItem);
    reply.SetMaxCapacity(defaultIpcCapacity);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_RETURN_RET_LOG(reply.WriteParcelable(&currentItem), ERR_NONE, "Write currentItem failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleSetDisplaySurface(MessageParcel& data, MessageParcel& reply)
{
    AVSESSION_TRACE_SYNC_START("AVSessionControllerStub::HandleSetDisplaySurface");
    int32_t err = PermissionChecker::GetInstance().CheckPermission(PermissionChecker::CHECK_SYSTEM_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("SetDisplaySurface: CheckPermission failed");
        CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(err), ERR_NONE, "write int32 failed");
        return ERR_NONE;
    }

    sptr<IRemoteObject> remoteObj = data.ReadRemoteObject();
    if (remoteObj == nullptr) {
        SLOGE("BufferProducer is null");
        return ERR_NULL_OBJECT;
    }

    sptr<IBufferProducer> producer = iface_cast<IBufferProducer>(remoteObj);

    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    CHECK_AND_RETURN_RET_LOG(pSurface != nullptr, AVSESSION_ERROR, "Surface provider is null");
    auto surfaceInstance = SurfaceUtils::GetInstance();
    CHECK_AND_RETURN_RET_LOG(surfaceInstance != nullptr, AVSESSION_ERROR, "Surface instance is null");
    surfaceInstance->Add(pSurface->GetUniqueId(), pSurface);
    uint64_t uniqueId = pSurface->GetUniqueId();

    auto surfaceId = std::to_string(uniqueId);
    SLOGI("Get surface id uint64_t: %{public}" PRIu64 ", get the string: %{public}s", uniqueId, surfaceId.c_str());
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(SetDisplaySurface(surfaceId)),
        AVSESSION_ERROR, "WriteInt32 result failed");
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleSetCastPlaybackFilter(MessageParcel& data, MessageParcel& reply)
{
    std::string str = data.ReadString();
    if (str.length() != AVPlaybackState::PLAYBACK_KEY_MAX) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write SetCastPlaybackFilter ret failed");
        return ERR_NONE;
    }
    if (str.find_first_not_of("01") != std::string::npos) {
        SLOGI("mask string not all 0 or 1");
        CHECK_AND_PRINT_LOG(reply.WriteInt32(ERR_UNMARSHALLING), "write int32 failed");
        return ERR_NONE;
    }
    AVPlaybackState::PlaybackStateMaskType filter(str);
    CHECK_AND_PRINT_LOG(reply.WriteInt32(SetCastPlaybackFilter(filter)), "write int32 failed");
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleProcessMediaKeyResponse(MessageParcel& data, MessageParcel& reply)
{
    std::string assetId = data.ReadString();
    std::vector<uint8_t> response;
    uint32_t responseSize = static_cast<uint32_t>(data.ReadInt32());
    uint32_t responseMaxLen = 8 * 1024 * 1024;
    CHECK_AND_RETURN_RET_LOG(responseSize < responseMaxLen, AVSESSION_ERROR,
        "The size of response is too large.");
    if (responseSize != 0) {
        const uint8_t *responseBuf = static_cast<const uint8_t *>(data.ReadBuffer(responseSize));
        if (responseBuf == nullptr) {
            SLOGE("AVCastControllerStub::HandleProvideKeyResponse read response failed");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        response.assign(responseBuf, responseBuf + responseSize);
    }
    CHECK_AND_PRINT_LOG(reply.WriteInt32(ProcessMediaKeyResponse(assetId, response)), "write int32 failed");
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleAddAvailableCommand(MessageParcel& data, MessageParcel& reply)
{
    int32_t cmd = data.ReadInt32();
    int32_t ret = AddAvailableCommand(cmd);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "WriteInt32 failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ERR_NONE, "AddAvailableCommand failed");
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleRemoveAvailableCommand(MessageParcel& data, MessageParcel& reply)
{
    int32_t cmd = data.ReadInt32();
    int32_t ret = RemoveAvailableCommand(cmd);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "WriteInt32 failed");
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ERR_NONE, "RemoveAvailableCommand failed");
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleGetValidCommands(MessageParcel& data, MessageParcel& reply)
{
    std::vector<int32_t> cmds;
    int32_t ret = GetValidCommands(cmds);
    CHECK_AND_RETURN_RET_LOG(reply.WriteInt32(ret), ERR_NONE, "write int32 failed");
    if (ret == AVSESSION_SUCCESS) {
        CHECK_AND_PRINT_LOG(reply.WriteInt32Vector(cmds), "write cmd int32 vector failed");
    }
    return ERR_NONE;
}

int32_t AVCastControllerStub::HandleDestroy(MessageParcel& data, MessageParcel& reply)
{
    CHECK_AND_PRINT_LOG(reply.WriteInt32(Destroy()), "write release() ret failed");
    return ERR_NONE;
}
} // namespace OHOS::AVSession
