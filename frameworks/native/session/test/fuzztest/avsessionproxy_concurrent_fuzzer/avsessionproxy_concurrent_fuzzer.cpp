/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "avsessionproxy_concurrent_fuzzer.h"

#include <cstdint>
#include <iostream>
#include <memory>

#include "iservice_registry.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "securec.h"
#include "session_listener_client.h"
#include "avsession_manager_impl.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

namespace OHOS::AVSession {

static const uint8_t *RAW_DATA = nullptr;
const size_t THRESHOLD = 10;
static size_t g_dataSize = 0;
static size_t g_pos;
std::shared_ptr<AVSession> avsession_ = nullptr;

void AddSupportCommandFuzzTest(FuzzedDataProvider& provider)
{
    if (avsession_ == nullptr) {
        SLOGE("get avsession nullptr");
        return;
    }
    int32_t cmd = provider.ConsumeIntegral<int32_t>();
    avsession_->AddSupportCommand(cmd);
}

void DeleteSupportCommandFuzzTest(FuzzedDataProvider& provider)
{
    if (avsession_ == nullptr) {
        SLOGE("get avsession nullptr");
        return;
    }
    int32_t cmd = provider.ConsumeIntegral<int32_t>();
    avsession_->DeleteSupportCommand(cmd);
}

void SetAVMetaDataFuzzTest(FuzzedDataProvider& provider)
{
    if (avsession_ == nullptr) {
        SLOGE("get avsession nullptr");
        return;
    }
    AVMetaData metaData;
    uint8_t assetIdData = provider.ConsumeIntegral<int32_t>();
    std::vector<std::string> assetIdStrDatas = {"assetId1", "assetId2", "assetId3"};
    std::string assetIdStr = assetIdStrDatas[assetIdData % assetIdStrDatas.size()];
    metaData.SetAssetId(assetIdStr);
    uint8_t titleData = provider.ConsumeIntegral<int32_t>();
    std::vector<std::string> titleStrDatas = {"title1", "title2", "title3"};
    std::string titleStr = titleStrDatas[titleData % titleStrDatas.size()];
    metaData.SetTitle(titleStr);
    avsession_->SetAVMetaData(metaData);
}

void SetAVPlaybackStateFuzzTest(FuzzedDataProvider& provider)
{
    if (avsession_ == nullptr) {
        SLOGE("get avsession nullptr");
        return;
    }
    AVPlaybackState avState;
    int32_t state = provider.ConsumeIntegral<int32_t>();
    avState.SetState(state);
    avsession_->SetAVPlaybackState(avState);
}

void DestroyFuzzTest(FuzzedDataProvider& provider)
{
    if (avsession_ == nullptr) {
        SLOGE("get avsession nullptr");
        return;
    }

    avsession_->Destroy();
}

void CreateFuzzTest(FuzzedDataProvider& provider)
{
    uint8_t tagData = provider.ConsumeIntegral<int32_t>();
    std::vector<std::string> tagStrDatas = {"tag1", "tag2", "tag3"};
    std::string tagStr = tagStrDatas[tagData % tagStrDatas.size()];
    OHOS::AppExecFwk::ElementName elementName;
    uint8_t bundleNameData = provider.ConsumeIntegral<int32_t>();
    std::vector<std::string> bundleNameStrDatas = {"bundleName1", "bundleName2", "bundleName3"};
    std::string bundleNameStr = bundleNameStrDatas[bundleNameData % bundleNameStrDatas.size()];
    uint8_t abilityNameData = provider.ConsumeIntegral<int32_t>();
    std::vector<std::string> abilityNameStrDatas = {"abilityName1", "abilityName2", "abilityName3"};
    std::string abilityNameStr = abilityNameStrDatas[abilityNameData % abilityNameStrDatas.size()];
    elementName.SetBundleName(bundleNameStr);
    elementName.SetAbilityName(abilityNameStr);
    avsession_ = AVSessionManager::GetInstance().CreateSession(tagStr,
        AVSession::SESSION_TYPE_AUDIO, elementName);
}

bool AVSessionProxyConcurrentFuzzer::FuzzTest(const uint8_t* rawData, size_t size)
{
    // initialize data
    RAW_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;

    FuzzedDataProvider provider(RAW_DATA, g_dataSize);

    auto func = provider.PickValueInArray({
        AddSupportCommandFuzzTest,
        DeleteSupportCommandFuzzTest,
        SetAVMetaDataFuzzTest,
        SetAVPlaybackStateFuzzTest,
        DestroyFuzzTest,
        CreateFuzzTest,
    });
    func(provider);
    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < THRESHOLD) {
        return 0;
    }

    auto avSessionProxyConcurrentFuzzer = std::make_unique<AVSessionProxyConcurrentFuzzer>();
    if (avSessionProxyConcurrentFuzzer == nullptr) {
        return false;
    }
    avSessionProxyConcurrentFuzzer->FuzzTest(data, size);
    return 0;
}
}
