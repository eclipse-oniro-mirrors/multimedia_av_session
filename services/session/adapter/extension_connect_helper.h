/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef EXTENSION_CONNECT_HELPER_H
#define EXTENSION_CONNECT_HELPER_H

#include <string>
#include "ability_connect_helper.h"

#define AVSESSION_CONNECT_ABILITY_WITH_TYPE 1034
#define AVSESSION_DISCONNECT_ABILITY 1003
#define AVSESSION_EXTENSION_ABILITY_TYPE_SERVICE 3

namespace OHOS::AVSession {
class DesktopLyricCallConnection;
class ExtensionConnectHelper {
public:
    static ExtensionConnectHelper& GetInstance();

    int32_t StartDesktopLyricAbility(const std::string &sessionId, const std::string &handler,
        int32_t userId, std::function<void(int32_t)> cb, bool shouldBeRecreated = false);

    int32_t StopDesktopLyricAbility();

    int32_t UploadDesktopLyricOperationInfo(const std::string &sessionId,
        const std::string &handler, uint32_t sceneCode);

private:
    int32_t ConnectAbilityCommon(const AAFwk::Want &want, sptr<IRemoteObject> connect, int32_t userId);

    int32_t DisconnectAbility(const sptr<IRemoteObject> &connect);

    sptr<IRemoteObject> GetSystemAbility();

private:
    std::mutex desktopLyricConnMutex;
    sptr<DesktopLyricCallConnection> desktopLyricConnection_ = nullptr;

    const std::u16string EXTENSION_MANAGER_INTERFACE_TOKEN = u"ohos.aafwk.ExtensionManager";
};

class DesktopLyricCallConnection : public AbilityConnectionStub {
public:
    explicit DesktopLyricCallConnection(std::function<void(int32_t)> cb, std::string sessionId, std::string handler)
        : callback_(std::move(cb)), sessionId_(std::move(sessionId)), handler_(std::move(handler)) {};
    ~DesktopLyricCallConnection() override;

    void OnAbilityConnectDone(const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject,
        int resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;

    int32_t SendDesktopLyricOperationInfo(const std::string &sessionId,
        const std::string &handler, uint32_t sceneCode);

private:
    std::function<void(int32_t)> callback_;
    std::string sessionId_;
    std::string handler_;
    std::mutex desktopLyricProxyMutex_;
    sptr<IRemoteObject> desktopLyricProxy_ = nullptr;
};
} // namespace OHOS::AVSession
#endif /* EXTENSION_CONNECT_HELPER_H */
