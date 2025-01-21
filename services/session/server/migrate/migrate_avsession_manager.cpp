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

#include "migrate_avsession_manager.h"

namespace OHOS::AVSession {
MigrateAVSessionManager& MigrateAVSessionManager::GetInstance()
{
    static MigrateAVSessionManager migrateAVSessionManager;
    return migrateAVSessionManager;
}

void MigrateAVSessionManager::CreateLocalSessionStub(std::string scene, std::shared_ptr<MigrateAVSessionServer> server)
{
    SLOGI("enter CreateLocalSessionStub");
    if ("SuperLauncher-Dual" != scene && migrateSceneNext != scene) {
        SLOGW("CreateLocalSessionStub error, scene: %{public}s", scene.c_str());
        return;
    }
    std::lock_guard lockGuard(migrateServerMapLock_);
    auto it = serverMap_.find(scene);
    if (it != serverMap_.end()) {
        SLOGW("find and return");
        return;
    }
    softBusDistributedDataMgr_->Init();
    IncSoftBusRef();
    softBusDistributedDataMgr_->CreateServer(server);
    serverMap_.insert({ scene, server });
}

void MigrateAVSessionManager::ReleaseLocalSessionStub(std::string scene)
{
    SLOGI("enter ReleaseLocalSessionStub");
    if ("SuperLauncher-Dual" != scene && migrateSceneNext != scene) {
        SLOGW("not ReleaseLocalSessionStub: scene: %{public}s", scene.c_str());
        return;
    }
    std::lock_guard lockGuard(migrateServerMapLock_);
    auto it = serverMap_.find(scene);
    if (it == serverMap_.end()) {
        SLOGW("not find and return");
        return;
    }

    softBusDistributedDataMgr_->ReleaseServer(it->second);
    DecSoftBusRef();
    serverMap_.erase(scene);
}

void MigrateAVSessionManager::CreateRemoteSessionProxy(std::string &networkId, std::string scene,
    std::shared_ptr<MigrateAVSessionProxy> proxy)
{
    SLOGI("enter CreateRemoteSessionProxy");
    if (proxy == nullptr || networkId.c_str() == nullptr || networkId.empty()) {
        SLOGW("CreateRemoteSessionProxy error, invalid params");
        return;
    }
    if ("SuperLauncher-Dual" != scene && migrateSceneNext != scene) {
        SLOGW("CreateRemoteSessionProxy error, scene: %{public}s", scene.c_str());
        return;
    }
    if (proxyMap_.find(scene) != proxyMap_.end()) {
        SLOGW("CreateRemoteSessionProxy error, %{public}s scene already exist", scene.c_str());
        return;
    }
    softBusDistributedDataMgr_->Init();
    refs_++;
    softBusDistributedDataMgr_->CreateProxy(proxy,  networkId, "AVSession");
    proxyMap_.insert({scene, proxy});
}

void MigrateAVSessionManager::ReleaseRemoteSessionProxy(std::string &networkId, std::string scene)
{
    SLOGI("enter ReleaseRemoteSessionProxy");
    if (networkId.c_str() == nullptr || networkId.empty()) {
        SLOGW("ReleaseRemoteSessionProxy error, invalid params");
        return;
    }
    if ("SuperLauncher-Dual" != scene && migrateSceneNext != scene) {
        SLOGW("not ReleaseRemoteSessionProxy: scene: %{public}s", scene.c_str());
        return;
    }
    std::lock_guard lockGuard(migrateServerMapLock_);
    auto it = proxyMap_.find(scene);
    if (it == proxyMap_.end()) {
        SLOGW("not find and return");
        return;
    }
    softBusDistributedDataMgr_->ReleaseProxy(it->second,  networkId);
    DecSoftBusRef();
    proxyMap_.erase(scene);
}

void MigrateAVSessionManager::IncSoftBusRef()
{
    if (refs_ == 0) {
        softBusDistributedDataMgr_->InitSessionServer("AVSession");
    }
    refs_++;
}

// LCOV_EXCL_START
void MigrateAVSessionManager::DecSoftBusRef()
{
    refs_--;
    if (refs_ <= 0) {
        softBusDistributedDataMgr_->DestroySessionServer("AVSession");
        refs_ = 0;
    }
}
// LCOV_EXCL_STOP
} // namespace OHOS::AVSession