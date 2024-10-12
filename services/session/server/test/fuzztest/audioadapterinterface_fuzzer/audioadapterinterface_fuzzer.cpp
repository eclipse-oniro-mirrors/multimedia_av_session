/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include "audio_adapter.h"
#include "audio_system_manager.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "audioadapterinterface_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;
using OHOS::AudioStandard::AudioRendererChangeInfo;

static const int32_t MAX_CODE_LEN = 512;
static const int32_t MIN_SIZE_NUM = 4;

static const int32_t TEST_CLIENT_UID = 1;
static const int32_t TEST_SESSION_ID = 2;

void OHOS::AVSession::AudioAdapterTest(uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    std::unique_ptr<AudioRendererChangeInfo> info = std::make_unique<AudioRendererChangeInfo>();
    info->clientUID = TEST_CLIENT_UID;
    info->sessionId = TEST_SESSION_ID;
    info->rendererState = AudioStandard::RENDERER_RELEASED;
    AudioRendererChangeInfos infosExpected;
    infosExpected.push_back(std::move(info));
    DeviceChangeAction deviceChangeAction;
    int32_t uid = *(reinterpret_cast<const int32_t *>(data));
    OHOS::AudioStandard::StreamUsage streamUsage {};

    AudioAdapter audioAdapter;
    audioAdapter.MuteAudioStream(uid);
    audioAdapter.MuteAudioStream(TEST_CLIENT_UID);
    audioAdapter.UnMuteAudioStream(uid);
    audioAdapter.UnMuteAudioStream(TEST_CLIENT_UID);
    audioAdapter.GetRendererRunning(uid);
    audioAdapter.PauseAudioStream(uid, streamUsage);
    audioAdapter.OnRendererStateChange(infosExpected);
    audioAdapter.OnDeviceChange(deviceChangeAction);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AudioAdapterTest(const_cast<uint8_t*>(data), size);
    return 0;
}