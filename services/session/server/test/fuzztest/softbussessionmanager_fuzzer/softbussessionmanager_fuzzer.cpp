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
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "avsession_log.h"
#include "softbussessionmanager_fuzzer.h"
#include "softbus_session_manager.h"
#include "securec.h"

using namespace std;
namespace OHOS::AVSession {
static const int32_t MIN_SIZE_NUM = 4;
static const uint8_t *RAW_DATA = nullptr;
static size_t g_dataSize = 0;
static size_t g_pos;

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RAW_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RAW_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

class SoftbusSessionListenerDemo : public SoftbusSessionListener {
public:
    void OnBind(int32_t socket, PeerSocketInfo info) override {};
    void OnShutdown(int32_t socket, ShutdownReason reason) override {};
    void OnBytes(int32_t socket, const void *data, int32_t dataLen) override {};
    void OnMessage(int32_t socket, const void *data, int32_t dataLen) override {};
};

void SoftbusSessionManagerFuzzer::SoftbusSessionManagerFuzzTest(uint8_t* data, size_t size)
{
    FuzzedDataProvider proveider(RAW_DATA, g_dataSize);
    std::shared_ptr<SoftbusSessionManager> manager_ = std::make_shared<SoftbusSessionManager>();
    std::shared_ptr<SoftbusSessionListenerDemo> softbusSessionListenerDemo =
        std::make_shared<SoftbusSessionListenerDemo>();
    manager_->AddSessionListener(softbusSessionListenerDemo);
    int32_t socket = GetData<uint8_t>();
    std::string infoName = std::to_string(GetData<uint8_t>());
    std::string infoNetworkId = std::to_string(GetData<uint8_t>());
    std::string infoPkgName = std::to_string(GetData<uint8_t>());
    PeerSocketInfo info = {
        .name = const_cast<char *>(infoName.c_str()),
        .networkId = const_cast<char *>(infoNetworkId.c_str()),
        .pkgName = const_cast<char *>(infoPkgName.c_str()),
        .dataType = DATA_TYPE_BYTES,
    };
    manager_->OnBind(socket, info);
    manager_->OnShutdown(socket, ShutdownReason::SHUTDOWN_REASON_LOCAL);

    MessageParcel data_;
    data_.WriteRawData(data, size);

    std::string deviceId = std::to_string(GetData<uint8_t>());
    manager_->ObtainPeerDeviceId(socket, deviceId);

    data_.RewindRead(GetData<uint8_t>());
    auto obj = std::make_unique<int32_t>(data_.ReadInt32());
    const void *objectId = obj.get();
    unsigned int dataLen = GetData<unsigned int>();
    manager_->OnBytes(socket, objectId, dataLen);
    manager_->OnBytes(socket, nullptr, dataLen);
    manager_->OnMessage(socket, objectId, dataLen);
    manager_->OnMessage(socket, nullptr, dataLen);

    std::string pkg;
    bool isNUll = GetData<bool>();
    if (!isNUll) {
        pkg = to_string(GetData<uint8_t>());
    }
    auto ret = manager_->Socket(pkg);
    manager_->Bind("localhost", pkg);
    manager_->Shutdown(ret);

    std::string inforOne = std::to_string(GetData<uint8_t>());
    std::string inforTwo = std::to_string(GetData<uint8_t>());
    manager_->SendMessage(socket, inforOne);
    manager_->SendMessage(socket, inforTwo);
    manager_->SendBytes(socket, inforOne);
    manager_->SendBytes(socket, inforTwo);

    info.networkId = nullptr;
    manager_->OnBind(socket, info);

    manager_->AddSessionListener(nullptr);
    std::string sendData = proveider.ConsumeRandomLengthString();
    manager_->SendBytesForNext(socket, sendData);
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
    SLOGI("the maximum length of size should not be verified");
    if ((data == nullptr) || (size < MIN_SIZE_NUM)) {
        return 0;
    }
    RAW_DATA = data;
    g_dataSize = size;
    g_pos = 0;
    /* Run your code on data */
    SoftbusSessionManagerOnRemoteRequest(data, size);
    return 0;
}
}