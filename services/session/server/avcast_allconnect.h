/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_AVCAST_ALLCONNECT_H
#define OHOS_AVCAST_ALLCONNECT_H

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include <string>

#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_info.h"
#include "allconnect_manager.h"
#include "av_router.h"

namespace OHOS::AVSession {
class CastAllConnectCallback : public CollaborationFwk::CallbackSkeleton {
public:
    explicit CastAllConnectCallback(IAVSessionServiceListener *servicePtr);
    ~CastAllConnectCallback();
    int32_t OnServiceStateChanged(std::string deviceId,
        std::string serviceName, std::string extraInfo, int32_t state, int pid) override;
    int32_t GetCastAllConnectData(std::map<std::string, int32_t>& serviceNameMapState);
private:
    std::map<std::string, int32_t>serviceNameMapState_;
    IAVSessionServiceListener *servicePtr_;
};
} // namespace OHOS::AVSession
#endif //CASTPLUS_CAST_ENGINE_ENABLE
#endif // OHOS_AVCAST_ALLCONNECT_H
