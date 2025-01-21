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

#ifndef OHOS_MIGRATE_AVSESSION_PROXY_H
#define OHOS_MIGRATE_AVSESSION_PROXY_H

#include "softbus/softbus_session_proxy.h"
#include "migrate_avsession_constant.h"
#include "avcontroller_item.h"
#include "avsession_item.h"
#include "json/json.h"
#include "avsession_info.h"

namespace OHOS::AVSession {
class AVSessionService;
class MigrateAVSessionProxy : public SoftbusSessionProxy,
    public std::enable_shared_from_this<MigrateAVSessionProxy> {
public:
    explicit MigrateAVSessionProxy(AVSessionService *ptr, int32_t mode = MSG_HEAD_MODE);
    ~MigrateAVSessionProxy();

    void OnConnectServer(const std::string &deviceId) override;
    void OnDisconnectServer(const std::string &deviceId) override;
    int32_t GetCharacteristic() override;
    void OnBytesReceived(const std::string &deviceId, const std::string &data) override;

    void HandlePlay();
    void HandlePause();
    void HandlePlayNext();
    void HandlePlayPrevious();
    void HandleToggleFavorite(const std::string& mediaId);
    void HandleCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs);
    void GetDistributedSessionControllerList(std::vector<sptr<IRemoteObject>>& controllerList);

private:
    void PrepareSessionFromRemote();
    void PrepareControllerOfRemoteSession(sptr<AVSessionItem> sessionItem);
    void ProcessSessionInfo(Json::Value jsonValue);
    void ProcessMetaData(Json::Value jsonValue);
    void ProcessPlaybackState(Json::Value jsonValue);
    void ProcessValidCommands(Json::Value jsonValue);
    void ProcessBundleImg(std::string bundleIconStr);
    void ProcessMediaImage(std::string mediaImageStr);
    void SendControlCommandMsg(int32_t commandCode, std::string commandArgsStr);
    void SendSpecialKeepAliveData();

    int32_t mMode_;
    std::string deviceId_;
    sptr<AVSessionItem> remoteSession_ = nullptr;
    sptr<AVControllerItem> preSetController_ = nullptr;
    AVSessionService *servicePtr_ = nullptr;
};

class AVSessionObserver : public AVSessionCallback {
public:
    explicit AVSessionObserver(const std::string &playerId, std::weak_ptr<MigrateAVSessionProxy> migrateProxy);
    AVSessionObserver() {}
    ~AVSessionObserver() {}

    void OnPlay() override;
    void OnPause() override;
    void OnStop() override {}
    void OnPlayNext() override;
    void OnPlayPrevious() override;
    void OnFastForward(int64_t time) override {}
    void OnRewind(int64_t time) override {}
    void OnSeek(int64_t time) override {}
    void OnSetSpeed(double speed) override {}
    void OnSetLoopMode(int32_t loopMode) override {}
    void OnToggleFavorite(const std::string& mediaId) override;
    void OnMediaKeyEvent(const MMI::KeyEvent& keyEvent) override {}
    void OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo& outputDeviceInfo) override {}
    void OnCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs) override;
    void OnSkipToQueueItem(int32_t itemId) override {}
    void OnAVCallAnswer() override {}
    void OnAVCallHangUp() override {}
    void OnAVCallToggleCallMute() override {}
    void OnPlayFromAssetId(int64_t assetId) override {}
    void OnCastDisplayChange(const CastDisplayInfo& castDisplayInfo) override {}

private:
    std::weak_ptr<MigrateAVSessionProxy> migrateProxy_;
    std::string playerId_ = "";
};
} // namespace OHOS::AVSession

#endif //OHOS_MIGRATE_AVSESSION_PROXY_H