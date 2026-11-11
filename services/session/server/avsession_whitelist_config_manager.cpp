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

#include "avsession_whitelist_config_manager.h"

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "avsession_log.h"

#ifdef INPUT_REDISTRIBUTE_ENABLE
#include "cJSON.h"
#include <dlfcn.h>
#include "avsession_event_handler.h"
#include <chrono>
#include <type_traits>

// C ABI exported by libcompconfigclient.z.so, mirrored here so the mirror is visible only to this
// TU and not exposed to every including TU (avoids ODR/redefinition clashes with the upstream
// header). Must stay in the global namespace: CFI hashes a function type from its mangled
// signature, and the upstream declarations live outside any namespace.
struct CompConfigKvEntry {
    const char* key;
    const char* value;
};

struct CompConfigPropertyValueMapResult {
    int32_t ret;
    CompConfigKvEntry* entries;
    int32_t entryCount;
};
#endif

namespace OHOS::AVSession {

#ifdef INPUT_REDISTRIBUTE_ENABLE
namespace {
using CreateFunc = SystemCompConfigReaderHandle* (*)();
using DestroyFunc = void (*)(SystemCompConfigReaderHandle*);
using InitFunc = int32_t (*)(SystemCompConfigReaderHandle*, const char**, int32_t);
using GetConfigFunc = CompConfigPropertyValueMapResult (*)(
    SystemCompConfigReaderHandle*, const char*, const char**, int32_t);
using FreeResultFunc = void (*)(CompConfigPropertyValueMapResult*);
} // namespace
#endif

std::shared_ptr<AVSessionWhitelistConfigManager> AVSessionWhitelistConfigManager::GetInstance()
{
    static std::shared_ptr<AVSessionWhitelistConfigManager> instance =
        std::make_shared<AVSessionWhitelistConfigManager>();
    return instance;
}

#ifdef INPUT_REDISTRIBUTE_ENABLE
namespace {
// Exported by the compatibility_config_center client, see its clients.versionscript.
constexpr const char *COMP_CONFIG_CLIENT_LIB = "/system/lib64/platformsdk/libcompconfigclient.z.so";
constexpr const char *MEDIA_CONTROL_OPTIONS_KEY = "mediaControlOptions";
constexpr const char *ENABLE_SYSTEM_MEDIA_SHORTCUT_KEY = "enableSystemMediashortcut";
// CompConfigClient::CompConfigClientStatus::OK.
constexpr int32_t COMP_CONFIG_OK = 0;

// The mediaControlOptions value is a JSON object, for example
// {"enableSystemMediashortcut": true}. Only the inner enableSystemMediashortcut flag is used.
bool ParseEnableSystemMediashortcut(const char *jsonStr)
{
    CHECK_AND_RETURN_RET_LOG(jsonStr != nullptr, false, "jsonStr is null");
    cJSON *root = cJSON_Parse(jsonStr);
    if (root == nullptr || !cJSON_IsObject(root)) {
        SLOGW("mediaControlOptions is not a valid json object");
        cJSON_Delete(root);
        return false;
    }
    cJSON *item = cJSON_GetObjectItem(root, ENABLE_SYSTEM_MEDIA_SHORTCUT_KEY);
    bool enabled = (item != nullptr) && cJSON_IsBool(item) && cJSON_IsTrue(item);
    cJSON_Delete(root);
    return enabled;
}
} // namespace
#endif

bool AVSessionWhitelistConfigManager::IsKeyEventSupported(const std::string &bundleName)
{
    if (bundleName.empty()) {
        SLOGI("bundleName empty");
        return false;
    }
    if (IsSystemApp()) {
        SLOGI("isSystemApp bundleName: %{public}s", bundleName.c_str());
        return false;
    }
    bool supportKeyEvent = false;
#ifdef INPUT_REDISTRIBUTE_ENABLE
    auto start = std::chrono::steady_clock::now();
    supportKeyEvent = GetSupportKeyEventFromConfig(bundleName);
    auto costMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    SLOGD("GetSupportKeyEventFromConfig cost:%{public}lld ms, bundleName:%{public}s",
        static_cast<long long>(costMs), bundleName.c_str());
#endif
    SLOGI("supportKeyEvent:%{public}d, bundleName: %{public}s", supportKeyEvent, bundleName.c_str());
    return supportKeyEvent;
}

AVSessionWhitelistConfigManager::~AVSessionWhitelistConfigManager()
{
#ifdef INPUT_REDISTRIBUTE_ENABLE
    std::lock_guard<std::mutex> lock(readerMutex_);
    ResetReader();
    if (libHandle_ != nullptr) {
#ifndef TEST_COVERAGE
        dlclose(libHandle_);
#endif
        libHandle_ = nullptr;
    }
    funcCache_.clear();
#endif
}

#ifdef INPUT_REDISTRIBUTE_ENABLE
bool AVSessionWhitelistConfigManager::LoadConfigReaderLib()
{
    if (libHandle_ != nullptr) {
        return true;
    }
    libHandle_ = dlopen(COMP_CONFIG_CLIENT_LIB, RTLD_NOW);
    if (libHandle_ == nullptr) {
        const char *reason = dlerror();
        SLOGW("dlopen %{public}s failed, reason: %{public}s", COMP_CONFIG_CLIENT_LIB,
            reason == nullptr ? "unknown" : reason);
        return false;
    }

    static const char *requiredSymbols[] = {
        "SystemCompConfigReader_Create",
        "SystemCompConfigReader_Destroy",
        "SystemCompConfigReader_Init",
        "SystemCompConfigReader_GetConfig",
        "CompConfigFreePropertyValueMapResult",
    };
    bool symbolsReady = true;
    for (const char *symbol : requiredSymbols) {
        if (GetFunction(symbol) == nullptr) {
            symbolsReady = false;
            break;
        }
    }
    if (!symbolsReady) {
        SLOGW("load compconfig symbols failed");
#ifndef TEST_COVERAGE
        dlclose(libHandle_);
#endif
        libHandle_ = nullptr;
        funcCache_.clear();
        return false;
    }
    return true;
}

void *AVSessionWhitelistConfigManager::GetFunction(const std::string &name)
{
    auto it = funcCache_.find(name);
    if (it != funcCache_.end()) {
        return it->second;
    }
    CHECK_AND_RETURN_RET_LOG(libHandle_ != nullptr, nullptr, "libHandle_ is null");
    void *sym = dlsym(libHandle_, name.c_str());
    if (sym != nullptr) {
        funcCache_[name] = sym;
    }
    return sym;
}

__attribute__((no_sanitize("cfi"))) void AVSessionWhitelistConfigManager::ResetReader()
{
    if (readerHandle_ == nullptr) {
        return;
    }
    auto destroy = reinterpret_cast<DestroyFunc>(GetFunction("SystemCompConfigReader_Destroy"));
    if (destroy != nullptr) {
        destroy(readerHandle_);
    }
    readerHandle_ = nullptr;
}

void AVSessionWhitelistConfigManager::NotifyCompConfigReady(bool isReady)
{
    isCompConfigReady_.store(isReady, std::memory_order_release);
    if (isReady) {
        auto self = GetInstance();
        AVSessionEventHandler::GetInstance().AVSessionPostTask(
            [self]() {
                self->TryInitReader();
            },
            "WarmUpWhitelistReader");
        return;
    }
    std::lock_guard<std::mutex> lock(readerMutex_);
    ResetReader();
}

void AVSessionWhitelistConfigManager::TryInitReader()
{
    std::lock_guard<std::mutex> lock(readerMutex_);
    if (!EnsureReaderReady()) {
        SLOGW("compConfig reader warm up failed");
    }
}

__attribute__((no_sanitize("cfi"))) bool AVSessionWhitelistConfigManager::EnsureReaderReady()
{
    if (readerHandle_ != nullptr) {
        return true;
    }
    // The reader burns its own retry budget on every failed Init, and the bugget cannot be reset,
    // so never touch it before the config service reports its data as ready.
    if (!isCompConfigReady_.load(std::memory_order_acquire)) {
        SLOGI("compConfig service not ready, skip reader init");
        return false;
    }
    if (!LoadConfigReaderLib()) {
        return false;
    }
    auto create = reinterpret_cast<CreateFunc>(GetFunction("SystemCompConfigReader_Create"));
    if (create == nullptr) {
        SLOGW("create function not found");
        return false;
    }
    SystemCompConfigReaderHandle *handle = create();
    if (handle == nullptr) {
        SLOGW("create compConfig reader failed");
        return false;
    }
    auto init = reinterpret_cast<InitFunc>(GetFunction("SystemCompConfigReader_Init"));
    if (init == nullptr) {
        SLOGW("init function not found");
        auto destroy = reinterpret_cast<DestroyFunc>(GetFunction("SystemCompConfigReader_Destroy"));
        if (destroy != nullptr) {
            destroy(handle);
        }
        return false;
    }
    const char *keys[] = {MEDIA_CONTROL_OPTIONS_KEY};
    int32_t ret = init(handle, keys, 1);
    if (ret != COMP_CONFIG_OK) {
        SLOGW("compConfig reader init failed, ret:%{public}d", ret);
        auto destroy = reinterpret_cast<DestroyFunc>(GetFunction("SystemCompConfigReader_Destroy"));
        if (destroy != nullptr) {
            destroy(handle);
        }
        return false;
    }
    readerHandle_ = handle;
    SLOGI("compConfig reader init success");
    return true;
}

__attribute__((no_sanitize("cfi"))) bool AVSessionWhitelistConfigManager::GetSupportKeyEventFromConfig(
    const std::string &bundleName)
{
    if (bundleName.empty()) {
        SLOGI("bundleName empty");
        return false;
    }
    std::lock_guard<std::mutex> lock(readerMutex_);
    if (!EnsureReaderReady()) {
        return false;
    }
    auto getConfig = reinterpret_cast<GetConfigFunc>(GetFunction("SystemCompConfigReader_GetConfig"));
    if (getConfig == nullptr) {
        SLOGW("getConfig function not found");
        return false;
    }
    const char *keys[] = {MEDIA_CONTROL_OPTIONS_KEY};
    CompConfigPropertyValueMapResult result = getConfig(readerHandle_, bundleName.c_str(), keys, 1);
    auto freeResult = reinterpret_cast<FreeResultFunc>(GetFunction("CompConfigFreePropertyValueMapResult"));
    if (result.ret != COMP_CONFIG_OK) {
        SLOGW("GetConfig failed, ret:%{public}d, bundleName:%{public}s", result.ret, bundleName.c_str());
        ResetReader();
        if (freeResult != nullptr) {
            freeResult(&result);
        }
        return false;
    }
    bool supportKeyEvent = false;
    for (int32_t index = 0; index < result.entryCount; ++index) {
        const char *entryKey = result.entries[index].key;
        const char *entryValue = result.entries[index].value;
        if (entryKey == nullptr || entryValue == nullptr) {
            continue;
        }
        if (std::string(entryKey) == MEDIA_CONTROL_OPTIONS_KEY) {
            supportKeyEvent = ParseEnableSystemMediashortcut(entryValue);
            break;
        }
    }
    if (freeResult != nullptr) {
        freeResult(&result);
    }
    return supportKeyEvent;
}
#endif

bool AVSessionWhitelistConfigManager::IsSystemApp()
{
    uint64_t callingTokenId = IPCSkeleton::GetCallingFullTokenID();
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(callingTokenId);
}
} // namespace OHOS::AVSession
