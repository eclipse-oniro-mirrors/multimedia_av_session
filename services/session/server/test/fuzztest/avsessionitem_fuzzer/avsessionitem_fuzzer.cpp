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

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>

#include "avsession_item.h"
#include "iav_session.h"
#include "iremote_stub.h"
#include "avsession_stub.h"
#include "avsession_callback_proxy.h"
#include "avsession_controller_stub.h"
#include "avsession_service.h"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "avcontrol_command.h"
#include "avsessionitem_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

const int32_t MAX_CODE_TEST  = 21;
const int32_t MAX_CODE_LEN  = 512;
const int32_t MIN_SIZE_NUM = 4;

void AvSessionItemFuzzer::AvSessionItemFuzzerTest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    uint32_t code = *(reinterpret_cast<const uint32_t*>(data));
    if (code >= MAX_CODE_TEST) {
        return;
    }
    std::string tag(reinterpret_cast<const char*>(data), size);
    int32_t type = *reinterpret_cast<const int32_t*>(data);
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    std::string abilityName(reinterpret_cast<const char*>(data), size);

    OHOS::AppExecFwk::ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName(abilityName);

    sptr<AVSessionService> service = new AVSessionService(AVSESSION_SERVICE_ID);
    if (!service) {
        SLOGI("service is null");
        return;
    }
    sptr<IRemoteObject> avSessionItemObj = service->CreateSessionInner(tag, type, elementName);
    sptr<AVSessionItem> avSessionItem = (sptr<AVSessionItem>&)avSessionItemObj;
    if (!avSessionItem) {
        SLOGI("avSessionItem is null");
        return;
    }
    MessageParcel dataMessageParcel;
    MessageParcel reply;
    MessageOption option;
    if (!dataMessageParcel.WriteInterfaceToken(IAVSession::GetDescriptor())) {
        return;
    }
    size -= sizeof(uint32_t);
    dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
    dataMessageParcel.RewindRead(0);
    avSessionItem->OnRemoteRequest(code, dataMessageParcel, reply, option);
}

void OHOS::AVSession::AvSessionItemTest(uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }

    AVPlaybackState avState;
    int32_t state = *(reinterpret_cast<const int32_t *>(data));
    avState.SetState(state);

    AVMetaData metaData;
    std::string assetId(reinterpret_cast<const char *>(data), size);
    metaData.SetAssetId(assetId);

    std::vector<int32_t> cmds;
    int32_t _cmds = *(reinterpret_cast<const int32_t *>(data));
    cmds.push_back(_cmds);

    bool top = *(reinterpret_cast<const bool *>(data));

    AVControlCommand controlCommand;
    int32_t cmd = *(reinterpret_cast<const int32_t *>(data));
    if ((cmd < AVControlCommand::SESSION_CMD_INVALID) || (cmd > AVControlCommand::SESSION_CMD_MAX)) {
        return;
    }
    controlCommand.SetCommand(cmd);

    OutputDeviceInfo info;
    info.isRemote_ = true;
    std::string deviceIds(reinterpret_cast<const char *>(data), size);
    info.deviceIds_.push_back(deviceIds);
    std::string deviceNames(reinterpret_cast<const char *>(data), size);
    info.deviceNames_.push_back(deviceNames);

    AVSessionDescriptor descriptor;
    AVSessionItem avSessionItem(descriptor);

    avSessionItem.GetSessionId();
    avSessionItem.GetAVMetaData(metaData);
    avSessionItem.SetAVMetaData(metaData);
    avSessionItem.GetAVPlaybackState(avState);
    avSessionItem.Activate();
    avSessionItem.Deactivate();
    avSessionItem.IsActive();
    avSessionItem.Destroy();
    avSessionItem.AddSupportCommand(cmd);
    avSessionItem.DeleteSupportCommand(cmd);
    avSessionItem.SetAVPlaybackState(avState);
    avSessionItem.GetPlaybackState();
    avSessionItem.GetMetaData();
    avSessionItem.GetSupportCommand();
    avSessionItem.ExecuteControllerCommand(controlCommand);
    avSessionItem.GetPid();
    avSessionItem.GetUid();
    avSessionItem.GetAbilityName();
    avSessionItem.SetTop(top);
    avSessionItem.SetOutputDevice(info);
    avSessionItem.GetOutputDevice(info);
    avSessionItem.GetRemoteSource();
}

void OHOS::AVSession::AvSessionItemOnRemoteRequest(uint8_t *data, size_t size)
{
    auto avSessionItem = std::make_unique<AvSessionItemFuzzer>();
    if (avSessionItem == nullptr) {
        SLOGI("avSessionItem is null");
        return;
    }
    avSessionItem->AvSessionItemFuzzerTest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AvSessionItemOnRemoteRequest(const_cast<uint8_t*>(data), size);
    OHOS::AVSession::AvSessionItemTest(const_cast<uint8_t*>(data), size);
    return 0;
}