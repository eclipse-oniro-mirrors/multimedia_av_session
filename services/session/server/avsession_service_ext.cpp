/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "avsession_service.h"

#include "migrate_avsession_manager.h"

namespace OHOS::AVSession {
void AVSessionService::SuperLauncher(std::string deviceId, std::string serviceName,
    std::string extraInfo, const std::string& state)
{
    SLOGI("SuperLauncher serviceName: %{public}s, state: %{public}s, no extraInfo for private",
        serviceName.c_str(), state.c_str());

    if (state == "IDLE" && serviceName == "SuperLauncher") {
        MigrateAVSessionManager::GetInstance().ReleaseLocalSessionStub(serviceName);
        if (migrateAVSession_ != nullptr) {
            RemoveInnerSessionListener(migrateAVSession_.get());
        }
    } else if (state == "CONNECTING" && serviceName == "SuperLauncher") {
        if (migrateAVSession_ == nullptr) {
            migrateAVSession_ = std::make_shared<MigrateAVSessionServer>();
        }
        migrateAVSession_->Init(this);
        MigrateAVSessionManager::GetInstance().CreateLocalSessionStub(serviceName, migrateAVSession_);
        AddInnerSessionListener(migrateAVSession_.get());
    }
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    if ((serviceName == "HuaweiCast" || serviceName == "HuaweiCast-Dual") &&
        (state == "IDLE" || state == "CONNECT_SUCC")) {
        castServiceNameMapState_[serviceName] = state;
        isSupportMirrorToStream_ = false;
        castDeviceId_ = "0";
        castDeviceName_ = " ";
        castDeviceType_ = 0;
        std::string info;
        std::string::size_type beginPos = 0;
        std::string::size_type endPos = extraInfo.find(seperator);
        while (endPos != std::string::npos) {
            info = extraInfo.substr(beginPos, endPos - beginPos);
            beginPos = endPos + seperator.size();
            endPos = extraInfo.find(seperator, beginPos);
            SplitExtraInfo(info);
        }
        if (beginPos != extraInfo.length()) {
            info = extraInfo.substr(beginPos);
            SplitExtraInfo(info);
        }
        NotifyMirrorToStreamCast();
    }
#endif
}

void AVSessionService::NotifyMigrateStop(const std::string &deviceId)
{
    if (migrateAVSession_ == nullptr) {
        SLOGI("NotifyMigrateStop without migrate, create new");
        migrateAVSession_ = std::make_shared<MigrateAVSessionServer>();
    }
    std::lock_guard lockGuard(sessionAndControllerLock_);
    migrateAVSession_->StopObserveControllerChanged(deviceId);
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
void AVSessionService::SplitExtraInfo(std::string info)
{
    if (info.find("SUPPORT_MIRROR_TO_STREAM") != std::string::npos && info.find("true") != std::string::npos) {
        isSupportMirrorToStream_ = true;
    }
    if (info.find("deviceId") != std::string::npos && info.find(":") != std::string::npos) {
        std::string::size_type idBeginPos = info.find(":");
        castDeviceId_ = info.substr(idBeginPos + beginAddPos,
            info.length() -idBeginPos - endDecPos); // "deviceId" : "xxxx"
    }
    if (info.find("deviceName") != std::string::npos && info.find(":") != std::string::npos) {
        std::string::size_type nameBeginPos = info.find(":");
        castDeviceName_ = info.substr(nameBeginPos + beginAddPos,
            info.length() - nameBeginPos - endDecPos); // "deviceName" : "xxxx"
    }
    if (info.find("deviceType") != std::string::npos && info.find(":") != std::string::npos) {
        std::string::size_type typeBeginPos = info.find(":");
        std::string tmpType = info.substr(typeBeginPos + typeAddPos, info.length()); // "deviceType" : xxx
        castDeviceType_ = atoi(tmpType.c_str());
    }
}
#endif

void AVSessionService::AddInnerSessionListener(SessionListener *listener)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    innerSessionListeners_.push_back(listener);
}

void AVSessionService::RemoveInnerSessionListener(SessionListener *listener)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    for (auto it = innerSessionListeners_.begin(); it != innerSessionListeners_.end();) {
        if (*it == listener) {
            SLOGI("RemoveInnerSessionListener");
            innerSessionListeners_.erase(it++);
        } else {
            it++;
        }
    }
}
}