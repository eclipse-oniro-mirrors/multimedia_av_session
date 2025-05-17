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

#include <chrono>
#include <thread>

#include "migrate_avsession_proxy.h"

#include "avsession_log.h"
#include "avsession_service.h"
#include "softbus/softbus_session_utils.h"
#include "int_wrapper.h"
#include "string_wrapper.h"
#include "bool_wrapper.h"

namespace OHOS::AVSession {

MigrateAVSessionProxy::MigrateAVSessionProxy(AVSessionService *ptr, int32_t mode)
{
    mMode_ = mode;
    servicePtr_ = ptr;
}

MigrateAVSessionProxy::~MigrateAVSessionProxy()
{
    SLOGI("MigrateAVSessionProxy destruct with disconnect process");
    OnDisconnectServer(deviceId_);
}

void MigrateAVSessionProxy::OnConnectServer(const std::string &deviceId)
{
    SLOGI("MigrateAVSessionProxy OnConnectServer:%{public}s", SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    deviceId_ = deviceId;
    SendSpecialKeepAliveData();
    PrepareSessionFromRemote();
    CHECK_AND_RETURN_LOG(servicePtr_ != nullptr, "OnConnectServer find service ptr null!");
    std::vector<sptr<IRemoteObject>> sessionControllers;
    sessionControllers.push_back(preSetController_);
    servicePtr_->NotifyRemoteDistributedSessionControllersChanged(sessionControllers);
}

void MigrateAVSessionProxy::OnDisconnectServer(const std::string &deviceId)
{
    SLOGI("MigrateAVSessionProxy OnDisconnectServer:%{public}s",
        SoftbusSessionUtils::AnonymizeDeviceId(deviceId).c_str());
    deviceId_ = "";
    std::vector<sptr<IRemoteObject>> sessionControllers;
    CHECK_AND_RETURN_LOG(servicePtr_ != nullptr, "OnDisconnectServer find service ptr null!");
    servicePtr_->NotifyRemoteDistributedSessionControllersChanged(sessionControllers);
}

int32_t MigrateAVSessionProxy::GetCharacteristic()
{
    return mMode_;
}

//LCOV_EXCL_START
void MigrateAVSessionProxy::OnBytesReceived(const std::string &deviceId, const std::string &data)
{
    if (data.length() <= MSG_HEAD_LENGTH) {
        SLOGE("OnBytesReceived too short to process");
        return;
    }
    int32_t infoType = data[1];
    SLOGI("OnBytesReceived with infoType: %{public}d", infoType);
    std::string jsonStr = data.substr(MSG_HEAD_LENGTH);
    if (infoType == SYNC_FOCUS_MEDIA_IMAGE) {
        ProcessMediaImage(jsonStr);
        return;
    } else if (infoType == SYNC_FOCUS_BUNDLE_IMG) {
        ProcessBundleImg(jsonStr);
        return;
    }

    cJSON* jsonValue = nullptr;
    if (!SoftbusSessionUtils::TransferStrToJson(jsonStr, jsonValue)) {
        SLOGE("OnBytesReceived parse json fail");
        return;
    }

    switch (infoType) {
        case SYNC_FOCUS_SESSION_INFO:
            ProcessSessionInfo(jsonValue);
            break;
        case SYNC_FOCUS_META_INFO:
            ProcessMetaData(jsonValue);
            break;
        case SYNC_FOCUS_PLAY_STATE:
            ProcessPlaybackState(jsonValue);
            break;
        case SYNC_FOCUS_VALID_COMMANDS:
            ProcessValidCommands(jsonValue);
            break;
        case SYNC_SET_VOLUME_COMMAND:
            ProcessVolumeControlCommand(jsonValue);
            break;
        case SYNC_AVAIL_DEVICES_LIST:
            ProcessAvailableDevices(jsonValue);
            break;
        case SYNC_CURRENT_DEVICE:
            ProcessPreferredOutputDevice(jsonValue);
            break;
        default:
            SLOGE("OnBytesReceived with unknow infoType:%{public}d", infoType);
            break;
    }
    if (jsonValue != nullptr) {
        cJSON_Delete(jsonValue);
    }
}
//LCOV_EXCL_STOP

void MigrateAVSessionProxy::HandlePlay()
{
    SendControlCommandMsg(AVControlCommand::SESSION_CMD_PLAY, DEFAULT_STRING);
}

void MigrateAVSessionProxy::HandlePause()
{
    SendControlCommandMsg(AVControlCommand::SESSION_CMD_PAUSE, DEFAULT_STRING);
}

void MigrateAVSessionProxy::HandlePlayNext()
{
    SendControlCommandMsg(AVControlCommand::SESSION_CMD_PLAY_NEXT, DEFAULT_STRING);
}

void MigrateAVSessionProxy::HandlePlayPrevious()
{
    SendControlCommandMsg(AVControlCommand::SESSION_CMD_PLAY_PREVIOUS, DEFAULT_STRING);
}

void MigrateAVSessionProxy::HandleToggleFavorite(const std::string& mediaId)
{
    SendControlCommandMsg(AVControlCommand::SESSION_CMD_TOGGLE_FAVORITE, mediaId);
}

void MigrateAVSessionProxy::HandleCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs)
{
    SLOGI("HandleCommonCommand with command:%{public}s", commonCommand.c_str());
}

void MigrateAVSessionProxy::GetDistributedSessionControllerList(std::vector<sptr<IRemoteObject>>& controllerList)
{
    CHECK_AND_RETURN_LOG(preSetController_ != nullptr, "GetDistributedSessionControllerList with controller null");
    controllerList.insert(controllerList.begin(), preSetController_);
}

void MigrateAVSessionProxy::PrepareSessionFromRemote()
{
    SLOGI("PrepareSessionFromRemote in");
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = DEFAULT_STRING;
    descriptor.sessionTag_ = DEFAULT_STRING;
    descriptor.sessionType_ = AVSession::SESSION_TYPE_AUDIO;
    descriptor.elementName_.SetBundleName(DEFAULT_STRING);
    descriptor.elementName_.SetAbilityName(DEFAULT_STRING);
    descriptor.isThirdPartyApp_ = false;

    remoteSession_ = new(std::nothrow) AVSessionItem(descriptor);
    CHECK_AND_RETURN_LOG(remoteSession_ != nullptr, "create avsession but get nullptr");
    remoteSession_->SetPid(DEFAULT_NUM);
    remoteSession_->SetUid(DEFAULT_NUM);

    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = AVCastCategory::CATEGORY_REMOTE;
    deviceInfo.deviceId_ = DEFAULT_STRING;
    deviceInfo.deviceName_ = DEFAULT_STRING;
    outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
    remoteSession_->SetOutputDevice(outputDeviceInfo);

    std::weak_ptr<MigrateAVSessionProxy> migrateProxyWeak(shared_from_this());
    std::shared_ptr<AVSessionObserver> callback =
        std::make_shared<AVSessionObserver>(remoteSession_->GetSessionId(), migrateProxyWeak);
    remoteSession_->RegisterAVSessionCallback(callback);
    PrepareControllerOfRemoteSession(remoteSession_);
    SLOGI("PrepareSessionFromRemote done");
}

void MigrateAVSessionProxy::PrepareControllerOfRemoteSession(sptr<AVSessionItem> sessionItem)
{
    CHECK_AND_RETURN_LOG(sessionItem != nullptr, "PrepareControllerOfRemoteSession with remote session null");
    preSetController_ = new(std::nothrow) AVControllerItem(DEFAULT_NUM, sessionItem);
    CHECK_AND_RETURN_LOG(preSetController_ != nullptr, "PrepareControllerOfRemoteSession with controller create null");
    migrateProxyCallback_ = MigrateAVSessionProxyControllerCallback();
    preSetController_->RegisterMigrateAVSessionProxyCallback(migrateProxyCallback_);
    sessionItem->AddController(DEFAULT_NUM, preSetController_);
}

const MigrateAVSessionProxyControllerCallbackFunc MigrateAVSessionProxy::MigrateAVSessionProxyControllerCallback()
{
    return [this](const std::string& extraEvent, AAFwk::WantParams& extras) {
        const auto& it = AUDIO_EVENT_MAPS.find(extraEvent);
        if (it == AUDIO_EVENT_MAPS.end()) {
            SLOGE("extraEvent %{public}s not support", extraEvent.c_str());
            return ERR_COMMAND_NOT_SUPPORT;
        }
        switch (it->second) {
            case AUDIO_NUM_SET_VOLUME:
                SetVolume(extras);
                break;
            case AUDIO_NUM_SELECT_OUTPUT_DEVICE:
                SelectOutputDevice(extras);
                break;
            case AUDIO_NUM_GET_VOLUME:
                GetVolume(extras);
                break;
            case AUDIO_NUM_GET_AVAILABLE_DEVICES:
                GetAvailableDevices(extras);
                break;
            case AUDIO_NUM_GET_PREFERRED_OUTPUT_DEVICE_FOR_RENDERER_INFO:
                GetPreferredOutputDeviceForRendererInfo(extras);
                break;
            case SESSION_NUM_COLD_START_FROM_PROXY:
                ColdStartFromProxy();
                break;
            case SESSION_NUM_SET_MEDIACONTROL_NEED_STATE:
                NotifyMediaControlNeedStateChange(extras);
                break;
            default:
                break;
        }
        return AVSESSION_SUCCESS;
    };
}

void MigrateAVSessionProxy::SetVolume(const AAFwk::WantParams& extras)
{
    SLOGI("proxy send in SetVolume case");
    CHECK_AND_RETURN_LOG(extras.HasParam(AUDIO_SET_VOLUME), "extras not have event");
    auto volume = extras.GetParam(AUDIO_SET_VOLUME);
    AAFwk::IInteger* ao = AAFwk::IInteger::Query(volume);
    CHECK_AND_RETURN_LOG(ao != nullptr, "extras have no value");

    volumeNum_ = OHOS::AAFwk::Integer::Unbox(ao);
    cJSON* value = SoftbusSessionUtils::GetNewCJSONObject();
    if (value == nullptr) {
        SLOGE("get json value fail");
        return;
    }
    if (!SoftbusSessionUtils::AddIntToJson(value, AUDIO_VOLUME, volumeNum_)) {
        SLOGE("AddIntToJson with key:%{public}s|value:%{public}d fail", AUDIO_VOLUME, volumeNum_);
        cJSON_Delete(value);
        return;
    }
    std::string msg = std::string({MSG_HEAD_MODE_FOR_NEXT, SYNC_SET_VOLUME_COMMAND});
    SoftbusSessionUtils::TransferJsonToStr(value, msg);
    cJSON_Delete(value);
    SendByteForNext(deviceId_, msg);
}

void MigrateAVSessionProxy::SelectOutputDevice(const AAFwk::WantParams& extras)
{
    SLOGI("proxy send in SelectOutputDevice case");
    CHECK_AND_RETURN_LOG(extras.HasParam(AUDIO_SELECT_OUTPUT_DEVICE), "extras not have event");
    auto value = extras.GetParam(AUDIO_SELECT_OUTPUT_DEVICE);
    AAFwk::IString* stringValue = AAFwk::IString::Query(value);
    CHECK_AND_RETURN_LOG(stringValue != nullptr, "extras have no value");

    std::string deviceValue = AAFwk::String::Unbox(stringValue);
    std::string msg = std::string({MSG_HEAD_MODE_FOR_NEXT, SYNC_SWITCH_AUDIO_DEVICE_COMMAND});
    SendJsonStringByte(deviceId_, msg + deviceValue);
}

void MigrateAVSessionProxy::GetVolume(AAFwk::WantParams& extras)
{
    SLOGI("proxy send in GetVolume case");
    extras.SetParam(AUDIO_GET_VOLUME, OHOS::AAFwk::Integer::Box(volumeNum_));
}

void MigrateAVSessionProxy::GetAvailableDevices(AAFwk::WantParams& extras)
{
    SLOGI("proxy send in GetAvailableDevices case");
    cJSON* jsonData = MigrateAVSessionServer::ConvertAudioDeviceDescriptorsToJson(availableDevices_);
    CHECK_AND_RETURN_LOG(jsonData != nullptr, "get jsonData nullptr");
    if (cJSON_IsInvalid(jsonData) || cJSON_IsNull(jsonData)) {
        SLOGE("get jsonData invalid");
        cJSON_Delete(jsonData);
        return;
    }
    
    cJSON* jsonArray = cJSON_GetObjectItem(jsonData, MEDIA_AVAILABLE_DEVICES_LIST);
    if (jsonArray == nullptr || cJSON_IsInvalid(jsonArray) || cJSON_IsNull(jsonArray)) {
        SLOGE("get jsonArray invalid");
        cJSON_Delete(jsonData);
        return;
    }
    std::string jsonStr;
    SoftbusSessionUtils::TransferJsonToStr(jsonArray, jsonStr);
    if (jsonStr.empty()) {
        SLOGE("get jsonStr empty");
        cJSON_Delete(jsonData);
        return;
    }
    extras.SetParam(AUDIO_GET_AVAILABLE_DEVICES, OHOS::AAFwk::String::Box(jsonStr));
    cJSON_Delete(jsonData);
}

void MigrateAVSessionProxy::GetPreferredOutputDeviceForRendererInfo(AAFwk::WantParams& extras)
{
    SLOGI("proxy send in GetPreferredOutputDeviceForRendererInfo case");
    cJSON* jsonData = MigrateAVSessionServer::ConvertAudioDeviceDescriptorsToJson(preferredOutputDevice_);
    CHECK_AND_RETURN_LOG(jsonData != nullptr, "get jsonData nullptr");
    if (cJSON_IsInvalid(jsonData) || cJSON_IsNull(jsonData)) {
        SLOGE("get jsonData invalid");
        cJSON_Delete(jsonData);
        return;
    }
    
    cJSON* jsonArray = cJSON_GetObjectItem(jsonData, MEDIA_AVAILABLE_DEVICES_LIST);
    if (jsonArray == nullptr || cJSON_IsInvalid(jsonArray) || cJSON_IsNull(jsonArray)) {
        SLOGE("get jsonArray invalid");
        cJSON_Delete(jsonData);
        return;
    }
    std::string jsonStr;
    SoftbusSessionUtils::TransferJsonToStr(jsonArray, jsonStr);
    if (jsonStr.empty()) {
        SLOGE("get jsonStr empty");
        cJSON_Delete(jsonData);
        return;
    }
    extras.SetParam(AUDIO_GET_PREFERRED_OUTPUT_DEVICE_FOR_RENDERER_INFO, OHOS::AAFwk::String::Box(jsonStr));
    cJSON_Delete(jsonData);
}

void MigrateAVSessionProxy::ColdStartFromProxy()
{
    SLOGI("proxy send in ColdStartFromProxy case with bundleName:%{public}s", elementName_.GetAbilityName().c_str());
    std::string msg = std::string({MSG_HEAD_MODE_FOR_NEXT, COLD_START});

    cJSON* controlMsg = SoftbusSessionUtils::GetNewCJSONObject();
    if (controlMsg == nullptr) {
        SLOGE("get controlMsg fail");
        return;
    }
    if (!SoftbusSessionUtils::AddStringToJson(controlMsg, MIGRATE_BUNDLE_NAME, elementName_.GetAbilityName())) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail", MIGRATE_BUNDLE_NAME,
            elementName_.GetAbilityName().c_str());
        cJSON_Delete(controlMsg);
        return;
    }

    SoftbusSessionUtils::TransferJsonToStr(controlMsg, msg);
    SendByteForNext(deviceId_, msg);
    cJSON_Delete(controlMsg);
}

void MigrateAVSessionProxy::ProcessSessionInfo(cJSON* jsonValue)
{
    CHECK_AND_RETURN_LOG(remoteSession_ != nullptr, "ProcessSessionInfo with remote session null");
    if (jsonValue == nullptr || cJSON_IsInvalid(jsonValue) || cJSON_IsNull(jsonValue)) {
        SLOGE("get jsonValue invalid");
        return;
    }
    std::string sessionId = SoftbusSessionUtils::GetStringFromJson(jsonValue, MIGRATE_SESSION_ID);
    if (sessionId.empty()) {
        sessionId = DEFAULT_STRING;
    }
    std::string bundleName = SoftbusSessionUtils::GetStringFromJson(jsonValue, MIGRATE_BUNDLE_NAME);
    if (bundleName.empty()) {
        sessionId = DEFAULT_STRING;
    }
    size_t insertPos = bundleName.find('|');
    if (insertPos != std::string::npos && insertPos > 0 && insertPos < bundleName.size()) {
        elementName_.SetBundleName(bundleName.substr(0, insertPos));
    } else {
        elementName_.SetBundleName(bundleName);
    }
    std::string abilityName = SoftbusSessionUtils::GetStringFromJson(jsonValue, MIGRATE_ABILITY_NAME);
    if (bundleName.empty()) {
        sessionId = DEFAULT_STRING;
    }
    elementName_.SetAbilityName(abilityName);
    SLOGI("ProcessSessionInfo with sessionId:%{public}s|bundleName:%{public}s end",
        SoftbusSessionUtils::AnonymizeDeviceId(sessionId).c_str(), bundleName.c_str());
    if (sessionId.empty() || sessionId == DEFAULT_STRING || sessionId == EMPTY_SESSION) {
        remoteSession_->Deactivate();
        elementName_.SetAbilityName(elementName_.GetBundleName());
        elementName_.SetBundleName("");
    } else {
        remoteSession_->Activate();
    }
    CHECK_AND_RETURN_LOG(servicePtr_ != nullptr, "ProcessSessionInfo find service ptr null!");
    servicePtr_->NotifyRemoteBundleChange(elementName_.GetBundleName());
    AVPlaybackState playbackState;
    if (AVSESSION_SUCCESS == remoteSession_->GetAVPlaybackState(playbackState)) {
        playbackState.SetState(0);
        playbackState.SetFavorite(false);
        remoteSession_->SetAVPlaybackState(playbackState);
    }
    AVMetaData metaData;
    if (AVSESSION_SUCCESS == remoteSession_->GetAVMetaData(metaData)) {
        metaData.SetWriter(bundleName);
        metaData.SetTitle("");
        metaData.SetArtist("");
        remoteSession_->SetAVMetaData(metaData);
    }
    SendMediaControlNeedStateMsg();
}

bool MigrateAVSessionProxy::CheckMediaAlive()
{
    return !elementName_.GetBundleName().empty();
}

void MigrateAVSessionProxy::ProcessMetaData(cJSON* jsonValue)
{
    CHECK_AND_RETURN_LOG(remoteSession_ != nullptr, "ProcessMetaData with remote session null");
    if (jsonValue == nullptr || cJSON_IsInvalid(jsonValue) || cJSON_IsNull(jsonValue)) {
        SLOGE("get jsonValue invalid");
        return;
    }
    AVMetaData metaData;
    if (AVSESSION_SUCCESS != remoteSession_->GetAVMetaData(metaData)) {
        SLOGE("ProcessMetaData GetAVMetaData fail");
    }

    if (cJSON_HasObjectItem(jsonValue, METADATA_ASSET_ID)) {
        std::string assetId = SoftbusSessionUtils::GetStringFromJson(jsonValue, METADATA_ASSET_ID);
        if (assetId.empty()) {
            assetId = DEFAULT_STRING;
        }
        std::string oldAsset = metaData.GetAssetId();
        if (oldAsset != assetId) {
            metaData.SetTitle("");
            metaData.SetArtist("");
        }
        metaData.SetAssetId(assetId);
    }
    if (cJSON_HasObjectItem(jsonValue, METADATA_TITLE)) {
        std::string title = SoftbusSessionUtils::GetStringFromJson(jsonValue, METADATA_TITLE);
        if (title.empty()) {
            title = DEFAULT_STRING;
        }
        metaData.SetTitle(title);
    }
    if (cJSON_HasObjectItem(jsonValue, METADATA_ARTIST)) {
        std::string artist = SoftbusSessionUtils::GetStringFromJson(jsonValue, METADATA_ARTIST);
        if (artist.empty()) {
            artist = DEFAULT_STRING;
        }
        metaData.SetArtist(artist);
    }

    remoteSession_->SetAVMetaData(metaData);
    SLOGI("ProcessMetaData set title:%{public}s", metaData.GetTitle().c_str());
}

void MigrateAVSessionProxy::ProcessPlaybackState(cJSON* jsonValue)
{
    CHECK_AND_RETURN_LOG(remoteSession_ != nullptr, "ProcessPlaybackState with remote session null");
    if (jsonValue == nullptr || cJSON_IsInvalid(jsonValue) || cJSON_IsNull(jsonValue)) {
        SLOGE("get jsonValue invalid");
        return;
    }

    AVPlaybackState playbackState;
    if (AVSESSION_SUCCESS != remoteSession_->GetAVPlaybackState(playbackState)) {
        SLOGE("ProcessPlaybackState GetAVPlaybackState fail");
    }

    if (cJSON_HasObjectItem(jsonValue, PLAYBACK_STATE)) {
        int state = SoftbusSessionUtils::GetIntFromJson(jsonValue, PLAYBACK_STATE);
        playbackState.SetState(state);
    }
    if (cJSON_HasObjectItem(jsonValue, FAVOR_STATE)) {
        bool isFavor = SoftbusSessionUtils::GetBoolFromJson(jsonValue, FAVOR_STATE);
        playbackState.SetFavorite(isFavor);
    }

    remoteSession_->SetAVPlaybackState(playbackState);
    SLOGI("ProcessPlaybackState set state:%{public}d | isFavor:%{public}d",
        playbackState.GetState(), playbackState.GetFavorite());
}

void MigrateAVSessionProxy::ProcessValidCommands(cJSON* jsonValue)
{
    CHECK_AND_RETURN_LOG(remoteSession_ != nullptr, "ProcessValidCommands with remote session null");
    if (jsonValue == nullptr || cJSON_IsInvalid(jsonValue) || cJSON_IsNull(jsonValue)) {
        SLOGE("get jsonValue invalid");
        return;
    }

    std::vector<int32_t> commands;
    if (cJSON_HasObjectItem(jsonValue, VALID_COMMANDS)) {
        std::string commandsStr = SoftbusSessionUtils::GetStringFromJson(jsonValue, VALID_COMMANDS);
        if (commandsStr.empty()) {
            commandsStr = DEFAULT_STRING;
        }
        for (unsigned long i = 0; i < commandsStr.length(); i++) {
            commands.insert(commands.begin(), static_cast<int>(commandsStr[i] - '0'));
        }
        remoteSession_->SetSupportCommand(commands);
    }

    SLOGI("ProcessValidCommands set cmd size:%{public}d", static_cast<int>(commands.size()));
}

void MigrateAVSessionProxy::ProcessVolumeControlCommand(cJSON* jsonValue)
{
    SLOGI("proxy recv in ProcessVolumeControlCommand case");
    if (jsonValue == nullptr || cJSON_IsInvalid(jsonValue) || cJSON_IsNull(jsonValue)) {
        SLOGE("get jsonValue invalid");
        return;
    }

    if (!cJSON_HasObjectItem(jsonValue, AUDIO_VOLUME)) {
        SLOGE("json parse with error member");
        return;
    }

    volumeNum_ = SoftbusSessionUtils::GetIntFromJson(jsonValue, AUDIO_VOLUME);

    AAFwk::WantParams args;
    args.SetParam(AUDIO_CALLBACK_VOLUME, OHOS::AAFwk::Integer::Box(volumeNum_));
    CHECK_AND_RETURN_LOG(preSetController_ != nullptr, "preSetController_ is nullptr");
    preSetController_->HandleSetSessionEvent(AUDIO_CALLBACK_VOLUME, args);
}

void DevicesJsonArrayToVector(cJSON* jsonArray, AudioDeviceDescriptors& devices)
{
    if (jsonArray == nullptr || cJSON_IsInvalid(jsonArray) || !cJSON_IsArray(jsonArray)) {
        SLOGE("get jsonArray invalid");
        return;
    }
    devices.clear();
    cJSON* jsonObject = nullptr;
    cJSON_ArrayForEach(jsonObject, jsonArray) {
        CHECK_AND_CONTINUE(jsonObject != nullptr && !cJSON_IsInvalid(jsonObject));
        int deviceCategory = SoftbusSessionUtils::GetIntFromJson(jsonObject, AUDIO_DEVICE_CATEGORY);
        int deviceType = SoftbusSessionUtils::GetIntFromJson(jsonObject, AUDIO_DEVICE_TYPE);
        int deviceRole = SoftbusSessionUtils::GetIntFromJson(jsonObject, AUDIO_DEVICE_ROLE);
        std::string networkId = SoftbusSessionUtils::GetStringFromJson(jsonObject, AUDIO_NETWORK_ID);
        networkId = networkId.empty() ? "ERROR_TYPE" : networkId;
        std::string deviceName = SoftbusSessionUtils::GetStringFromJson(jsonObject, AUDIO_DEVICE_NAME);
        deviceName = deviceName.empty() ? "ERROR_TYPE" : deviceName;
        std::string macAddress = SoftbusSessionUtils::GetStringFromJson(jsonObject, AUDIO_MAC_ADDRESS);
        macAddress = macAddress.empty() ? "ERROR_TYPE" : macAddress;

        std::shared_ptr<AudioDeviceDescriptor> device = std::make_shared<AudioDeviceDescriptor>();
        CHECK_AND_RETURN_LOG(device != nullptr, "AudioDeviceDescriptor make shared_ptr is nullptr");
        device->deviceCategory_ = static_cast<AudioStandard::DeviceCategory>(deviceCategory);
        device->deviceType_ = static_cast<AudioStandard::DeviceType>(deviceType);
        device->deviceRole_ = static_cast<AudioStandard::DeviceRole>(deviceRole);
        device->networkId_ = networkId;
        device->deviceName_ = deviceName;
        device->macAddress_ = macAddress;
        devices.push_back(device);
    }
}

void MigrateAVSessionProxy::ProcessAvailableDevices(cJSON* jsonValue)
{
    SLOGI("proxy recv in ProcessAvailableDevices case");

    if (jsonValue == nullptr || cJSON_IsInvalid(jsonValue) || cJSON_IsNull(jsonValue)) {
        SLOGE("get jsonValue invalid");
        return;
    }
    CHECK_AND_RETURN_LOG(cJSON_HasObjectItem(jsonValue, MEDIA_AVAILABLE_DEVICES_LIST), "json parse with error member");
    cJSON* jsonArray = cJSON_GetObjectItem(jsonValue, MEDIA_AVAILABLE_DEVICES_LIST);
    CHECK_AND_RETURN_LOG(jsonArray != nullptr && !cJSON_IsInvalid(jsonArray) && cJSON_IsArray(jsonArray),
        "json object is not array");

    DevicesJsonArrayToVector(jsonArray, availableDevices_);

    std::string jsonStr;
    SoftbusSessionUtils::TransferJsonToStr(jsonArray, jsonStr);
    AAFwk::WantParams args;
    args.SetParam(AUDIO_CALLBACK_AVAILABLE_DEVICES, OHOS::AAFwk::String::Box(jsonStr));
    CHECK_AND_RETURN_LOG(preSetController_ != nullptr, "preSetController_ is nullptr");
    preSetController_->HandleSetSessionEvent(AUDIO_CALLBACK_AVAILABLE_DEVICES, args);
}

void MigrateAVSessionProxy::ProcessPreferredOutputDevice(cJSON* jsonValue)
{
    SLOGI("proxy recv in ProcessPreferredOutputDevice case");

    if (jsonValue == nullptr || cJSON_IsInvalid(jsonValue) || cJSON_IsNull(jsonValue)) {
        SLOGE("get jsonValue invalid");
        return;
    }
    CHECK_AND_RETURN_LOG(cJSON_HasObjectItem(jsonValue, MEDIA_AVAILABLE_DEVICES_LIST), "json parse with error member");
    cJSON* jsonArray = cJSON_GetObjectItem(jsonValue, MEDIA_AVAILABLE_DEVICES_LIST);
    CHECK_AND_RETURN_LOG(jsonArray != nullptr && !cJSON_IsInvalid(jsonArray) && cJSON_IsArray(jsonArray),
        "json object is not array");

    DevicesJsonArrayToVector(jsonArray, preferredOutputDevice_);

    std::string jsonStr;
    SoftbusSessionUtils::TransferJsonToStr(jsonArray, jsonStr);
    AAFwk::WantParams args;
    args.SetParam(AUDIO_CALLBACK_PREFERRED_OUTPUT_DEVICE_FOR_RENDERER_INFO, OHOS::AAFwk::String::Box(jsonStr));
    CHECK_AND_RETURN_LOG(preSetController_ != nullptr, "preSetController_ is nullptr");
    preSetController_->HandleSetSessionEvent(AUDIO_CALLBACK_PREFERRED_OUTPUT_DEVICE_FOR_RENDERER_INFO, args);
}

void MigrateAVSessionProxy::ProcessBundleImg(std::string bundleIconStr)
{
    CHECK_AND_RETURN_LOG(remoteSession_ != nullptr, "ProcessBundleImg with remote session null");
    AVMetaData metaData;
    if (AVSESSION_SUCCESS != remoteSession_->GetAVMetaData(metaData)) {
        SLOGE("ProcessBundleImg GetAVMetaData fail");
    }
    if (metaData.GetAssetId().empty()) {
        metaData.SetAssetId(DEFAULT_STRING);
    }
    std::vector<uint8_t> imgVec(bundleIconStr.begin(), bundleIconStr.end());
    if (imgVec.size() <= 0) {
        SLOGE("ProcessBundleImg with empty img, return");
        return;
    }
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = std::make_shared<AVSessionPixelMap>();
    innerPixelMap->SetInnerImgBuffer(imgVec);
    metaData.SetBundleIcon(innerPixelMap);

    remoteSession_->SetAVMetaData(metaData);
    SLOGI("ProcessBundleImg set img size:%{public}d", static_cast<int>(metaData.GetBundleIcon() == nullptr ?
        -1 : metaData.GetBundleIcon()->GetInnerImgBuffer().size()));
}

void MigrateAVSessionProxy::ProcessMediaImage(std::string mediaImageStr)
{
    CHECK_AND_RETURN_LOG(remoteSession_ != nullptr, "ProcessMediaImage with remote session null");
    size_t insertPos = mediaImageStr.find('|');
    CHECK_AND_RETURN_LOG(insertPos != std::string::npos && insertPos > 0 && insertPos < mediaImageStr.size(),
        "mediaImgStr do not contain assetId, return");
    std::string assetIdForMediaImg = mediaImageStr.substr(0, insertPos);
    mediaImageStr.erase(0, insertPos + 1);
    AVMetaData metaData;
    if (AVSESSION_SUCCESS != remoteSession_->GetAVMetaData(metaData)) {
        SLOGE("ProcessMediaImage GetAVMetaData fail");
    }
    if (metaData.GetAssetId().empty()) {
        metaData.SetAssetId(assetIdForMediaImg);
    }
    metaData.SetPreviousAssetId(assetIdForMediaImg);
    std::vector<uint8_t> imgVec(mediaImageStr.begin(), mediaImageStr.end());
    if (imgVec.size() <= 0) {
        metaData.SetMediaImageUri(DEFAULT_STRING);
        metaData.SetMediaImage(nullptr);
    } else {
        std::shared_ptr<AVSessionPixelMap> innerPixelMap = std::make_shared<AVSessionPixelMap>();
        innerPixelMap->SetInnerImgBuffer(imgVec);
        metaData.SetMediaImageUri("");
        metaData.SetMediaImage(innerPixelMap);
    }
    remoteSession_->SetAVMetaData(metaData);
    SLOGI("ProcessMediaImage set img size:%{public}d", static_cast<int>(metaData.GetMediaImage() == nullptr ?
        -1 : metaData.GetMediaImage()->GetInnerImgBuffer().size()));
}

void MigrateAVSessionProxy::SendControlCommandMsg(int32_t commandCode, std::string commandArgsStr)
{
    SLOGI("SendControlCommandMsg with code:%{public}d", commandCode);
    std::string msg = std::string({MSG_HEAD_MODE_FOR_NEXT, SYNC_COMMAND});

    cJSON* controlMsg = SoftbusSessionUtils::GetNewCJSONObject();
    if (controlMsg == nullptr) {
        SLOGE("get controlMsg fail");
        return;
    }
    if (!SoftbusSessionUtils::AddIntToJson(controlMsg, COMMAND_CODE, commandCode)) {
        SLOGE("AddIntToJson with key:%{public}s|value:%{public}d fail", COMMAND_CODE, commandCode);
        cJSON_Delete(controlMsg);
        return;
    }
    if (!SoftbusSessionUtils::AddStringToJson(controlMsg, COMMAND_ARGS, commandArgsStr)) {
        SLOGE("AddStringToJson with key:%{public}s|value:%{public}s fail", COMMAND_ARGS, commandArgsStr.c_str());
        cJSON_Delete(controlMsg);
        return;
    }

    SoftbusSessionUtils::TransferJsonToStr(controlMsg, msg);
    SendByteForNext(deviceId_, msg);
    cJSON_Delete(controlMsg);
}

void MigrateAVSessionProxy::SendMediaControlNeedStateMsg()
{
    SLOGI("SendMediaControlNeedStateMsg with state:%{public}d", isNeedByMediaControl_);
    std::string msg = std::string({MSG_HEAD_MODE_FOR_NEXT, SYNC_MEDIA_CONTROL_NEED_STATE});

    cJSON* controlMsg = SoftbusSessionUtils::GetNewCJSONObject();
    if (controlMsg == nullptr) {
        SLOGE("get controlMsg fail");
        return;
    }
    if (!SoftbusSessionUtils::AddBoolToJson(controlMsg, NEED_STATE, isNeedByMediaControl_)) {
        SLOGE("AddBoolToJson with key:%{public}s|value:%{public}d fail", NEED_STATE, isNeedByMediaControl_);
        cJSON_Delete(controlMsg);
        return;
    }

    SoftbusSessionUtils::TransferJsonToStr(controlMsg, msg);
    SendByteForNext(deviceId_, msg);
    cJSON_Delete(controlMsg);
}

void MigrateAVSessionProxy::SendSpecialKeepAliveData()
{
    std::thread([this]() {
        while (!this->deviceId_.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(HEART_BEAT_TIME_FOR_NEXT));
            if (!isNeedByMediaControl_) {
                SLOGI("no byte send for client no need");
                continue;
            }
            if (this->deviceId_.empty()) {
                SLOGE("SendSpecialKeepAliveData without deviceId, return");
                return;
            }
            SLOGI("SendSpecialKeepAliveData for deviceId:%{public}s",
                SoftbusSessionUtils::AnonymizeDeviceId(deviceId_).c_str());
            std::string data = std::string({MSG_HEAD_MODE_FOR_NEXT, SYNC_HEARTBEAT});
            SendByteForNext(deviceId_, data);
        }
        SLOGI("SendSpecialKeepAliveData exit");
    }).detach();
}

void MigrateAVSessionProxy::NotifyMediaControlNeedStateChange(AAFwk::WantParams& extras)
{
    CHECK_AND_RETURN_LOG(extras.HasParam(MEDIACONTROL_NEED_STATE), "extras not have NeedState");
    auto value = extras.GetParam(MEDIACONTROL_NEED_STATE);
    AAFwk::IBoolean* boolValue = AAFwk::IBoolean::Query(value);
    CHECK_AND_RETURN_LOG(boolValue != nullptr, "extras have no NeedState after query");
    bool isNeed = OHOS::AAFwk::Boolean::Unbox(boolValue);
    SLOGI("refresh NeedState:%{public}d", isNeed);
    isNeedByMediaControl_ = isNeed;
    SendMediaControlNeedStateMsg();
}

AVSessionObserver::AVSessionObserver(const std::string &playerId, std::weak_ptr<MigrateAVSessionProxy> migrateProxy)
{
    playerId_ = playerId;
    migrateProxy_ = migrateProxy;
}

void AVSessionObserver::OnPlay()
{
    std::shared_ptr<MigrateAVSessionProxy> proxy = migrateProxy_.lock();
    CHECK_AND_RETURN_LOG(proxy != nullptr, "check migrate proxy nullptr!");
    proxy->HandlePlay();
}

void AVSessionObserver::OnPause()
{
    std::shared_ptr<MigrateAVSessionProxy> proxy = migrateProxy_.lock();
    CHECK_AND_RETURN_LOG(proxy != nullptr, "check migrate proxy nullptr!");
    proxy->HandlePause();
}

void AVSessionObserver::OnPlayNext()
{
    std::shared_ptr<MigrateAVSessionProxy> proxy = migrateProxy_.lock();
    CHECK_AND_RETURN_LOG(proxy != nullptr, "check migrate proxy nullptr!");
    proxy->HandlePlayNext();
}

void AVSessionObserver::OnPlayPrevious()
{
    std::shared_ptr<MigrateAVSessionProxy> proxy = migrateProxy_.lock();
    CHECK_AND_RETURN_LOG(proxy != nullptr, "check migrate proxy nullptr!");
    proxy->HandlePlayPrevious();
}

void AVSessionObserver::OnToggleFavorite(const std::string& mediaId)
{
    std::shared_ptr<MigrateAVSessionProxy> proxy = migrateProxy_.lock();
    CHECK_AND_RETURN_LOG(proxy != nullptr, "check migrate proxy nullptr!");
    proxy->HandleToggleFavorite(mediaId);
}

void AVSessionObserver::OnCommonCommand(const std::string& commonCommand, const AAFwk::WantParams& commandArgs)
{
    std::shared_ptr<MigrateAVSessionProxy> proxy = migrateProxy_.lock();
    CHECK_AND_RETURN_LOG(proxy != nullptr, "check migrate proxy nullptr!");
    proxy->HandleCommonCommand(commonCommand, commandArgs);
}
} // namespace OHOS::AVSession