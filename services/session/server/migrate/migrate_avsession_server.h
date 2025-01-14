/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVSESSION_SERVER_H
#define OHOS_AVSESSION_SERVER_H

#include <map>
#include <mutex>

#include "json/json.h"
#include "app_manager_adapter.h"
#include "avcontroller_item.h"
#include "avsession_info.h"
#include "softbus/softbus_session_server.h"

namespace OHOS::AVSession {
class AVSessionService;
class AVControllerObserver;
constexpr size_t BUFFER_MAX_SIZE = 1024 * 1024;
constexpr size_t DEFAULT_QUALITY = 100;
constexpr int64_t DELAY_TIME = 2000;
constexpr int64_t DELAY_PLAY_COM_TIME = 500;
constexpr int32_t MAX_SESSION_NUMS = 2;
const std::string ANCO_AUDIO_BUNDLE_NAME = "anco_audio";

class MigrateAVSessionServer : public SessionListener, public SoftbusSessionServer,
    public std::enable_shared_from_this<MigrateAVSessionServer> {
public:
    MigrateAVSessionServer() {}
    ~MigrateAVSessionServer() {}

    void OnConnectProxy(const std::string &deviceId) override;
    void OnDisconnectProxy(const std::string &deviceId) override;
    int32_t GetCharacteristic() override;
    void OnBytesReceived(const std::string &deviceId, const std::string &data) override;

    void Init(AVSessionService *ptr);

    void OnSessionCreate(const AVSessionDescriptor &descriptor) override;
    void OnSessionRelease(const AVSessionDescriptor &descriptor) override;
    void OnTopSessionChange(const AVSessionDescriptor &descriptor) override;
    void OnAudioSessionChecked(const int32_t uid) override {}

    void OnMetaDataChange(const std::string &playerId, const AVMetaData &data);
    void OnPlaybackStateChanged(const std::string &playerId, const AVPlaybackState &state);
    void StopObserveControllerChanged(const std::string &deviceId);
    void SendRemoteControllerList(const std::string &deviceId);
    void SendRemoteControllerInfo(const std::string &deviceId, std::string sessionId, std::string msg);
    int32_t GetAllSessionDescriptors(std::vector<AVSessionDescriptor> &descriptors);
    void SendPlayCommand();

private:
    std::map<std::string, sptr<AVControllerItem>> playerIdToControllerMap_;
    std::map<std::string, std::shared_ptr<AVControllerObserver>> playerIdToControllerCallbackMap_;
    std::list<sptr<AVControllerItem>> sortControllerList_;

    void ObserveControllerChanged(const std::string &deviceId);
    void CreateController(const std::string &sessionId);
    void UpdateCache(const std::string &sessionId, sptr<AVControllerItem> avcontroller,
        std::shared_ptr<AVControllerObserver> callback, bool isAdd);
    void ClearCacheBySessionId(const std::string &sessionId);
    int32_t ConvertStateFromSingleToDouble(int32_t state);

    int32_t GetControllerById(const std::string &sessionId, sptr<AVControllerItem> &controller);
    int32_t GetAllControllers(std::vector<sptr<AVControllerItem>> &controller);

    std::string ConvertControllersToStr(std::vector<sptr<AVControllerItem>> avcontrollers);

    std::string ConvertControllerByIdToStr(std::string sessionId);

    Json::Value ConvertControllerToJson(sptr<AVControllerItem> avcontroller);

    Json::Value ConvertMetadataToJson(const AVMetaData &metadata);

    std::string ConvertMetadataInfoToStr(const std::string playerId, int32_t controlCommand,
        const AVMetaData &metadata);

    std::string RebuildPlayState(const AVPlaybackState &playbackState);
    void SortControllers(std::list<sptr<AVControllerItem>> avcontrollerList);

    void ProcControlCommand(const std::string &data);
    void SendCommandProc(const std::string &command, sptr<AVControllerItem> controller);
    void MediaButtonEventProc(const std::string &command, sptr<AVControllerItem> controller);
    void CommandWithExtrasProc(int mediaCommand, const std::string &extrasCommand, const std::string &extras,
        sptr<AVControllerItem> controller);
    void PlaybackCommandDataProc(int mediaCommand, const std::string &extrasCommand, sptr<AVControllerItem> controller);
    void SendSpecialKeepaliveData();
    std::string GetBundleName(std::string sessionId);
    bool CompressToJPEG(const AVMetaData &metadata, std::vector<uint8_t> &outputData);
    void DelaySendMetaData(std::string sessionId);
    bool GetVehicleRelatingState(std::string playerId);

    AVSessionService *servicePtr_ = nullptr;
    bool isSoftbusConnecting_ = false;
    std::string deviceId_;
    std::string topSessionId_;
    std::string lastSessionId_;
    std::string currentMetaAsset_;
    std::recursive_mutex migrateControllerLock_;
    std::recursive_mutex topSessionLock_;
};

class AVControllerObserver : public AVControllerCallback {
public:
    explicit AVControllerObserver(const std::string &playerId) : playerId_(playerId){};
    AVControllerObserver() {};
    ~AVControllerObserver() {};

    void Init(std::weak_ptr<MigrateAVSessionServer> migrateServer);

    void OnSessionDestroy() override;
    void OnPlaybackStateChange(const AVPlaybackState &state) override;
    void OnMetaDataChange(const AVMetaData &data) override;
    void OnAVCallMetaDataChange(const AVCallMetaData &avCallMetaData) override {}
    void OnAVCallStateChange(const AVCallState &avCallState) override {}
    void OnActiveStateChange(bool isActive) override {}
    void OnValidCommandChange(const std::vector<int32_t> &cmds) override {}
    void OnOutputDeviceChange(const int32_t connectionState, const OutputDeviceInfo &outputDeviceInfo) override {}
    void OnSessionEventChange(const std::string &event, const AAFwk::WantParams &args) override {}
    void OnQueueItemsChange(const std::vector<AVQueueItem> &items) override {}
    void OnQueueTitleChange(const std::string &title) override {}
    void OnExtrasChange(const AAFwk::WantParams &extras) override {}

private:
    std::weak_ptr<MigrateAVSessionServer> migrateServer_;
    std::string playerId_ = "";
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_SERVER_H