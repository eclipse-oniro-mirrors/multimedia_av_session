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
class InsightAdapter {
public:
    static InsightAdapter& GetInsightAdapterInstance();

    ~InsightAdapter();

    __attribute__((no_sanitize("cfi"))) bool IsSupportPlayIntent(const std::string& bundleName,
        std::string& supportModule, std::string& profile);
    
    bool GetPlayIntentParam(const std::string& bundleName, const std::string& assetId,
                            AppExecFwk::InsightIntentExecuteParam &executeParam);

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

