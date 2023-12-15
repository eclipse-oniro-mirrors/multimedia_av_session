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

static const int32_t MAX_CODE_LEN = 512;
static const int32_t MIN_SIZE_NUM = 4;

void OHOS::AVSession::AudioAdapterTest(uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    int32_t uid = *(reinterpret_cast<const int32_t *>(data));

    AudioStandard::RendererState rendererState;

    AudioAdapter audioAdapter;
    audioAdapter.PauseAudioStream(uid);
    audioAdapter.GetRendererState(uid, rendererState);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AudioAdapterTest(const_cast<uint8_t*>(data), size);
    return 0;
}