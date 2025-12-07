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

#ifndef OHOS_AVSERVICEPROXY_FUZZER_H
#define OHOS_AVSERVICEPROXY_FUZZER_H

#include <cstdint>
#include <cstddef>
#include "avsession_service_proxy.h"

namespace OHOS::AVSession {
class TestISessionListener : public ISessionListener {
public:
    ErrCode OnSessionCreate(const AVSessionDescriptor& descriptor) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnSessionRelease(const AVSessionDescriptor& descriptor) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnTopSessionChange(const AVSessionDescriptor& descriptor) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnAudioSessionChecked(const int32_t uid) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnDeviceLogEvent(const int32_t eventId, const int64_t param) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnDeviceOffline(const std::string& deviceId) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnDeviceStateChange(const DeviceState& deviceState) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnRemoteDistributedSessionChange(
        const std::vector<sptr<IRemoteObject>>& sessionControllers) override
    {
        return AVSESSION_SUCCESS;
    };

    ErrCode OnActiveSessionChanged(const std::vector<AVSessionDescriptor> &descriptors) override
    {
        return AVSESSION_SUCCESS;
    };

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    };
};

class AVSessionServiceProxyFuzzerTest : public AVSessionServiceProxy {
public:
    explicit AVSessionServiceProxyFuzzerTest(const sptr<IRemoteObject>& impl)
        : AVSessionServiceProxy(impl)
    {}
    sptr<IRemoteObject> GetRemote()
    {
        return Remote();
    }
};
bool AVServiceProxySendRequestTest();

class AVSessionServiceProxyFuzzer {
public:
    AVSessionServiceProxyFuzzer() = default;
    ~AVSessionServiceProxyFuzzer() = default;
    void FuzzDoProxyTaskOne(std::shared_ptr<AVSessionServiceProxyFuzzerTest> avServiceProxy,
        sptr<IRemoteObject> object);
    void FuzzDoProxyTaskTwo(std::shared_ptr<AVSessionServiceProxyFuzzerTest> avServiceProxy);
    void FuzzDoProxyTaskThird(std::shared_ptr<AVSessionServiceProxyFuzzerTest> avServiceProxy);
    void FuzzDoProxyTask(std::shared_ptr<AVSessionServiceProxyFuzzerTest> avServiceProxy, sptr<IRemoteObject> object);
    bool FuzzSendRequest();
};
}
#endif