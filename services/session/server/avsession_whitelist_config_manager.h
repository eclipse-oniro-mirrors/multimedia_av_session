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

#include "datashare_helper.h"
#include <map>
#include <mutex>
#include "singleton.h"
#include <string>

namespace OHOS::AVSession {
class AVSessionWhitelistConfigManager : public DelayedSingleton<AVSessionWhitelistConfigManager> {
public:
    AVSessionWhitelistConfigManager () = default;
    ~AVSessionWhitelistConfigManager () = default;
    bool IsKeyEventSupported(const std::string &bundleName);

private:
    std::once_flag settingsDataLoadFlag_;
    std::atomic_bool isSettingsDataLoaded_{ false };
    std::map<std::string, bool> compatibleInfoMap_;

    bool GetSupportKeyEventFromSettings(const std::string &bundleName);
    std::string GetSettingsDataStringValue();
    bool ParseJsonToMap(const std::string &jsonStr, std::map<std::string, bool> &compatibleMap);
    static std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper();
    bool ReleaseDataShareHelper(std::shared_ptr<DataShare::DataShareHelper> &helper);
    bool IsSystemApp();
};
} // namespace OHOS::AVSession
#endif // OHOS_AVSESSION_WHITELIST_CONFIG_MANAGER_H