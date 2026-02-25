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

#ifndef OHOS_AV_CONTROLLERCALLBACKCLIENT_FUZZER_H
#define OHOS_AV_CONTROLLERCALLBACKCLIENT_FUZZER_H

#include <cstdint>
#include <cstddef>
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS::AVSession {
class AvControllerCallbackClientFuzzer {
public:
    AvControllerCallbackClientFuzzer() = default;
    ~AvControllerCallbackClientFuzzer() = default;

    static void OnSessionDestroyFuzzTest(FuzzedDataProvider &provider);
    static void OnAVCallMetaDataChangeFuzzTest(FuzzedDataProvider &provider);
    static void OnAVCallStateChangeFuzzTest(FuzzedDataProvider &provider);
    static void OnPlaybackStateChangeFuzzTest(FuzzedDataProvider &provider);
    static void OnMetaDataChangeFuzzTest(FuzzedDataProvider &provider);
    static void OnActiveStateChangeFuzzTest(FuzzedDataProvider &provider);
    static void OnValidCommandChangeFuzzTest(FuzzedDataProvider &provider);
    static void OnOutputDeviceChangeFuzzTest(FuzzedDataProvider &provider);
    static void OnSessionEventChangeFuzzTest(FuzzedDataProvider &provider);
    static void OnQueueItemsChangeFuzzTest(FuzzedDataProvider &provider);
    static void OnQueueTitleChangeFuzzTest(FuzzedDataProvider &provider);
    static void OnExtrasChangeFuzzTest(FuzzedDataProvider &provider);
    static void OnCustomDataFuzzTest(FuzzedDataProvider &provider);
    static void OnDesktopLyricVisibilityChangedFuzzTest(FuzzedDataProvider &provider);
    static void OnDesktopLyricStateChangedFuzzTest(FuzzedDataProvider &provider);
    static void OnDesktopLyricEnabledFuzzTest(FuzzedDataProvider &provider);
};
}
#endif // OHOS_AV_CONTROLLERCALLBACKCLIENT_FUZZER_H
