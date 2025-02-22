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

#ifndef ABILITY_DYNAMIC_INSIGHT_H
#define ABILITY_DYNAMIC_INSIGHT_H

#include "insight_intent_execute_param.h"

namespace OHOS::AVSession {
#define BLUETOOTH_UID 1002

enum class StartPlayType {
    APP = 0,
    BLUETOOTH = 1,
};

const std::map<StartPlayType, std::string> StartPlayTypeToString = {
    {StartPlayType::APP, "app"},
    {StartPlayType::BLUETOOTH, "bluetooth"},
};

class StartPlayInfo {
public:
    StartPlayInfo() = default;
    
    ~StartPlayInfo() = default;

    std::string getBundleName() const
    {
        return bundleName;
    }

    void setBundleName(const std::string& name)
    {
        bundleName = name;
    }
 
    std::string getDeviceId() const
    {
        return deviceId;
    }

    void setDeviceId(const std::string& id)
    {
        deviceId = id;
    }

    nlohmann::json startPlayInfoToJson() const
    {
        nlohmann::json j;
        j["deviceId"] = deviceId;
        j["startPlayBundleName"] = bundleName;
        return j;
    }

private:
    std::string bundleName;

    std::string deviceId;
};
class InsightAdapter {
public:
    static InsightAdapter& GetInsightAdapterInstance();

    ~InsightAdapter();

    __attribute__((no_sanitize("cfi"))) bool IsSupportPlayIntent(const std::string& bundleName,
        std::string& supportModule, std::string& profile);
    
    bool GetPlayIntentParam(const std::string& bundleName, const std::string& assetId,
                            AppExecFwk::InsightIntentExecuteParam &executeParam, const StartPlayInfo startPlayInfo = {},
                            StartPlayType startPlayType = StartPlayType::APP);

    void SetStartPlayInfoToParam(AppExecFwk::WantParams &startPlayInfoParam,
        const StartPlayInfo startPlayInfo, std::shared_ptr<AppExecFwk::WantParams> &wantParam);

    int32_t StartAVPlayback(AppExecFwk::InsightIntentExecuteParam &executeParam);

private:
    InsightAdapter();

    bool CheckBundleSupport(std::string& profile);

    const int32_t getBundleInfoWithHapModule = 0x00000002;

    const int32_t startUserId = 100;

    const int32_t interfaceType = 9;

    const std::string PLAY_MUSICLIST = "PlayMusicList";

    const std::string PLAY_AUDIO = "PlayAudio";
};

}
#endif // ABILITY_DYNAMIC_INSIGHT_H

