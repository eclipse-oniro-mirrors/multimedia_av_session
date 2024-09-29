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

#include "avsession_log.h"
#include "softbussessionmanager_fuzzer.h"
#include "softbus_session_manager.h"

using namespace std;
namespace OHOS::AVSession {

char g_name[] = "testInfoName";
char g_infoNetworkId[] = "testInfoNetworkId";
char g_infoPkgName[] = "testInfoPkgName";

static const int32_t MAX_CODE_LEN = 512;
static const int32_t MIN_SIZE_NUM = 4;

PeerSocketInfo info = {
    .name = g_name,
    .networkId = g_infoNetworkId,
    .pkgName = g_infoPkgName,
    .dataType = DATA_TYPE_BYTES,
};

class SoftbusSessionListenerDemo : public SoftbusSessionListener {
public:
    void OnBind(int32_t socket, PeerSocketInfo info) override {};
    void OnShutdown(int32_t socket, ShutdownReason reason) override {};
    void OnBytes(int32_t socket, const void *data, int32_t dataLen) override {};
    void OnMessage(int32_t socket, const void *data, int32_t dataLen) override {};
};

void SoftbusSessionManagerFuzzer::SoftbusSessionManagerFuzzTest(uint8_t* data, size_t size)
{
    std::shared_ptr<SoftbusSessionManager> manager_ = std::make_shared<SoftbusSessionManager>();
    std::shared_ptr<SoftbusSessionListenerDemo> softbusSessionListenerDemo =
        std::make_shared<SoftbusSessionListenerDemo>();
    manager_->AddSessionListener(softbusSessionListenerDemo);

    int32_t socket = *reinterpret_cast<const int32_t *>(data);
    manager_->OnBind(socket, info);
    manager_->OnShutdown(socket, ShutdownReason::SHUTDOWN_REASON_LOCAL);

    MessageParcel data_;
    data_.WriteRawData(data, size);

    std::string deviceId(reinterpret_cast<const char*>(data), size);
    manager_->ObtainPeerDeviceId(socket, deviceId);

    data_.RewindRead(0);
    auto obj = std::make_unique<int32_t>(data_.ReadInt32());
    const void *objectId = obj.get();
    unsigned int dataLen = 1;
    manager_->OnBytes(socket, objectId, dataLen);
    manager_->OnBytes(socket, nullptr, dataLen);
    manager_->OnMessage(socket, objectId, dataLen);
    manager_->OnMessage(socket, nullptr, dataLen);

    std::string pkg = "111";
    manager_->Socket(pkg);
    manager_->Shutdown(socket);

    std::string infor_ = "info";
    std::string infor(reinterpret_cast<const char*>(data), size);
    manager_->SendMessage(socket, infor_);
    manager_->SendMessage(socket, infor);
    manager_->SendBytes(socket, infor_);
    manager_->SendBytes(socket, infor);

    info.networkId = nullptr;
    manager_->OnBind(socket, info);

    manager_->AddSessionListener(nullptr);
}

void SoftbusSessionManagerOnRemoteRequest(uint8_t* data, size_t size)
{
    auto softbusSessionManager = std::make_unique<SoftbusSessionManagerFuzzer>();
    if (softbusSessionManager == nullptr) {
        SLOGI("softbusSessionManager is null");
        return;
    }
    softbusSessionManager->SoftbusSessionManagerFuzzTest(data, size);
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return 0;
    }
    /* Run your code on data */
    SoftbusSessionManagerOnRemoteRequest(data, size);
    return 0;
}
}