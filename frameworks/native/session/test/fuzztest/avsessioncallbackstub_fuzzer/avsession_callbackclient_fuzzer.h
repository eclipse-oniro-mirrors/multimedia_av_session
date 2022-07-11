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

#ifndef OHOS_AVSESSION_CALLBACKCLIENT_FUZZER_H
#define OHOS_AVSESSION_CALLBACKCLIENT_FUZZER_H
#include <cstdint>
#include <cstddef>
#include "avsession_info.h"
namespace OHOS::AVSession {
int32_t AvSessionCallbackClientRemoteRequestTest(uint8_t* data, size_t size);

class AvSessionCallbackClientFuzzer {
public:
    AvSessionCallbackClientFuzzer() = default;
    ~AvSessionCallbackClientFuzzer() = default;
    int32_t FuzzOnRemoteRequest(uint8_t* data, size_t size);
};

class TestAVSessionCallback : public AVSessionCallback {
    void OnPlay() override;
    void OnPause() override;
    void OnStop() override;
    void OnPlayNext() override;
    void OnPlayPrevious() override;
    void OnFastForward() override;
    void OnRewind() override;
    void OnSeek(int64_t time) override;
    void OnSetSpeed(double speed) override;
    void OnSetLoopMode(int32_t loopMode) override;
    void OnToggleFavorite(const std::string& mediald) override;
    void OnMediaKeyEvent(const MMI::KeyEvent& keyEvent) override;
};
}
#endif