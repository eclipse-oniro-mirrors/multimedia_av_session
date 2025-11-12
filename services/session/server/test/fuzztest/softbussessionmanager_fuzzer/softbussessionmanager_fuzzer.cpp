/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
static size_t g_totalSize = 0;
static size_t g_sizePos;
static size_t g_dataSize = 0;
static size_t g_pos;
constexpr size_t STRING_MAX_LENGTH = 128;
FuzzedDataProvider provider(RAW_DATA, g_dataSize);

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
    std::string sendData = provider.ConsumeRandomLengthString();
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

void SoftbusSessionManagerFuzzer::SocketFuzzTest()
{
    auto softbusSessionManager = std::make_unique<SoftbusSessionManager>();
    CHECK_AND_RETURN(softbusSessionManager != nullptr);
    std::string pKgName = GetData<bool>() == 0 ? provider.ConsumeRandomLengthString(STRING_MAX_LENGTH) : nullptr;
    softbusSessionManager->Socket(pKgName);
}

void SoftbusSessionManagerFuzzer::BindFuzzTest()
{
    auto softbusSessionManager = std::make_unique<SoftbusSessionManager>();
    CHECK_AND_RETURN(softbusSessionManager != nullptr);
    std::string peerNetworkId = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string pKgName = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    softbusSessionManager->Bind(peerNetworkId, pKgName);
}

void SoftbusSessionManagerFuzzer::SendMessageFuzzTest()
{
    auto softbusSessionManager = std::make_unique<SoftbusSessionManager>();
    CHECK_AND_RETURN(softbusSessionManager != nullptr);
    int32_t socket = provider.ConsumeIntegral<int32_t>();
    std::string data = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    softbusSessionManager->SendMessage(socket, data);
}

void SoftbusSessionManagerFuzzer::SendBytesFuzzTest()
{
    auto softbusSessionManager = std::make_unique<SoftbusSessionManager>();
    CHECK_AND_RETURN(softbusSessionManager != nullptr);
    int32_t socket = provider.ConsumeIntegral<int32_t>();
    std::string data = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    softbusSessionManager->SendBytes(socket, data);
}

void SoftbusSessionManagerFuzzer::SendBytesForNextFuzzTest()
{
    auto softbusSessionManager = std::make_unique<SoftbusSessionManager>();
    CHECK_AND_RETURN(softbusSessionManager != nullptr);
    int32_t socket = provider.ConsumeIntegral<int32_t>();
    std::string data = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    softbusSessionManager->SendBytesForNext(socket, data);
}

void SoftbusSessionManagerFuzzer::OnBindFuzzTest()
{
    auto softbusSessionManager = std::make_unique<SoftbusSessionManager>();
    CHECK_AND_RETURN(softbusSessionManager != nullptr);
    int32_t socket = provider.ConsumeIntegral<int32_t>();
    std::string infoName = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string infoNetworkId = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string infoPkgName = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string infoDataType = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    PeerSocketInfo info = {
        .name = const_cast<char *>(infoName.c_str()),
        .networkId = const_cast<char *>(infoNetworkId.c_str()),
        .pkgName = const_cast<char *>(infoPkgName.c_str()),
        .dataType = DATA_TYPE_BYTES,
    };
    auto softbusSessionListener = std::make_shared<SoftbusSessionListenerDemo>();
    CHECK_AND_RETURN(softbusSessionListener != nullptr);
    softbusSessionManager->AddSessionListener(softbusSessionListener);
    softbusSessionManager->OnBind(socket, info);
}

void SoftbusSessionManagerFuzzer::OnShutdownFuzzTest()
{
    auto softbusSessionManager = std::make_unique<SoftbusSessionManager>();
    CHECK_AND_RETURN(softbusSessionManager != nullptr);
    int32_t socket = provider.ConsumeIntegral<int32_t>();
    int32_t reason = provider.ConsumeIntegralInRange<int32_t>(0, STRING_MAX_LENGTH);
    ShutdownReason Reason = static_cast<ShutdownReason>(reason);
    auto softbusSessionListener = std::make_shared<SoftbusSessionListenerDemo>();
    CHECK_AND_RETURN(softbusSessionListener != nullptr);
    softbusSessionManager->AddSessionListener(softbusSessionListener);
    softbusSessionManager->OnShutdown(socket, Reason);
}

void SoftbusSessionManagerFuzzer::OnMessageFuzzTest()
{
    auto softbusSessionManager = std::make_unique<SoftbusSessionManager>();
    CHECK_AND_RETURN(softbusSessionManager != nullptr);
    int32_t socket = provider.ConsumeIntegral<int32_t>();
    int32_t data = provider.ConsumeIntegral<int32_t>();
    int32_t dataLen = provider.ConsumeIntegral<int32_t>();
    if (dataLen < 0 || dataLen > STRING_MAX_LENGTH) {
        dataLen = 0;
    }
    auto softbusSessionListener = std::make_shared<SoftbusSessionListenerDemo>();
    CHECK_AND_RETURN(softbusSessionListener != nullptr);
    softbusSessionManager->AddSessionListener(softbusSessionListener);
    softbusSessionManager->OnMessage(socket, &data, dataLen);
}

void SoftbusSessionManagerFuzzer::OnBytesFuzzTest()
{
    auto softbusSessionManager = std::make_unique<SoftbusSessionManager>();
    CHECK_AND_RETURN(softbusSessionManager != nullptr);
    int32_t socket = provider.ConsumeIntegral<int32_t>();
    int32_t data = provider.ConsumeIntegral<int32_t>();
    int32_t dataLen = provider.ConsumeIntegral<int32_t>();
    auto softbusSessionListener = std::make_shared<SoftbusSessionListenerDemo>();
    CHECK_AND_RETURN(softbusSessionListener != nullptr);
    softbusSessionManager->AddSessionListener(softbusSessionListener);
    softbusSessionManager->OnBytes(socket, &data, dataLen);
}

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        SLOGE("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

typedef void (*TestFuncs[9])();

TestFuncs g_allFuncs = {
    SoftbusSessionManagerFuzzer::SocketFuzzTest,
    SoftbusSessionManagerFuzzer::BindFuzzTest,
    SoftbusSessionManagerFuzzer::SendMessageFuzzTest,
    SoftbusSessionManagerFuzzer::SendBytesFuzzTest,
    SoftbusSessionManagerFuzzer::SendBytesForNextFuzzTest,
    SoftbusSessionManagerFuzzer::OnBindFuzzTest,
    SoftbusSessionManagerFuzzer::OnShutdownFuzzTest,
    SoftbusSessionManagerFuzzer::OnMessageFuzzTest,
    SoftbusSessionManagerFuzzer::OnBytesFuzzTest,
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }

    // initialize data
    RAW_DATA = rawData;
    g_totalSize = size;
    g_sizePos = 0;

    uint32_t code = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_allFuncs);
    if (len > 0) {
        g_allFuncs[code % len]();
    } else {
        SLOGE("%{public}s: The len length is equal to 0", __func__);
    }

    return true;
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
    FuzzTest(data, size);
    return 0;
}
}