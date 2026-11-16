/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_AVSESSION_WHITELIST_CONFIG_MANAGER_H
#define OHOS_AVSESSION_WHITELIST_CONFIG_MANAGER_H

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#ifdef INPUT_REDISTRIBUTE_ENABLE
// Opaque handle returned by libcompconfigclient.z.so (loaded dynamically in the .cpp so av_session
// takes no build-time dependency on compatibility_config_center). Forward-declared here because the
// reader handle is held as a direct class member; the full C ABI mirror (result structs and
// function-pointer aliases) lives in the .cpp to avoid exposing it to every including TU. This must
// stay in the global namespace: CFI hashes a function type from its mangled signature, and the
// upstream declaration lives outside any namespace; declaring it inside OHOS::AVSession changes the
// mangled name and makes every indirect call fail the CFI check.
struct SystemCompConfigReaderHandle;
#endif

namespace OHOS::AVSession {

class AVSessionWhitelistConfigManager {
public:
    // Defined out of line so that every DSO resolves to the same object. DelayedSingleton is a
    // header-only template: once a version script localizes its static member, each DSO keeps its
    // own Copy and the ready state set by AvSessionservice would be invisible to AvSessionItem,
    // silently disabling key fallback.
    static std::shared_ptr<AVSessionWhitelistConfigManager> GetInstance();
    AVSessionWhitelistConfigManager() = default;
    ~AVSessionWhitelistConfigManager();
    bool IsKeyEventSupported(const std::string &bundleName);
#ifdef INPUT_REDISTRIBUTE_ENABLE
    void NotifyCompConfigReady(bool isReady);
    void TryInitReader();
#endif

private:
#ifdef INPUT_REDISTRIBUTE_ENABLE
    bool GetSupportKeyEventFromConfig(const std::string &bundleName);
    bool EnsureReaderReady();
    bool LoadConfigReaderLib();
    void *GetFunction(const std::string &name);
    void ResetReader();

    std::atomic<bool> isCompConfigReady_ {false};
    std::mutex readerMutex_;
    void *libHandle_ = nullptr;
    SystemCompConfigReaderHandle *readerHandle_ = nullptr;
    std::map<std::string, void *> funcCache_;
#endif
    bool IsSystemApp();
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_WHITELIST_CONFIG_MANAGER_H
