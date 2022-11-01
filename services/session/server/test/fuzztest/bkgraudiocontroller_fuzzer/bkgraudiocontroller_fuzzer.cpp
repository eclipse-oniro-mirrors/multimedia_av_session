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

#include "background_audio_controller.h"
#include "bkgraudiocontroller_fuzzer.h"
#include "audio_adapter.h"
#include "avsession_log.h"


using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

const int32_t MAX_CODE_LEN  = 512;
const int32_t MIN_SIZE_NUM = 4;

void OHOS::AVSession::BackGroundAudioControllerTest(uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size > MAX_CODE_LEN) || (size < MIN_SIZE_NUM)) {
        return;
    }
    int32_t uid = *(reinterpret_cast<const int32_t*>(data));

    BackgroundAudioController backGroundAudioController;
    backGroundAudioController.HandleAppBackgroundState(uid);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::BackGroundAudioControllerTest(data, size);
    return 0;
}