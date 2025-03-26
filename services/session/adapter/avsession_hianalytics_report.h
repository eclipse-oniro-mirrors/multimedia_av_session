/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef AVSESSION_HIANALYTICS_REPORT_H
#define AVSESSION_HIANALYTICS_REPORT_H

#include <string>

#include "avsession_descriptor.h"

namespace OHOS::AVSession {
class AVSessionHiAnalyticsReport {
public:
    static void PublishRecommendInfo(const std::string &bundleName, const std::string &sessionId,
        const std::string &sessionType, const std::string &assetId, const int32_t duration);
    static void PublishCastEvent(const std::string &bundleName, const int32_t castState,
        const DeviceInfo deviceInfo);
    static void PublishCastRecord(const std::string &bundleName, const DeviceInfo deviceInfo);
private:
    static void ConnectHAClient(std::string eventId, std::unordered_map<std::string, std::string> properties);
};
}
#endif // AVSESSION_HIANALYTICS_REPORT_H