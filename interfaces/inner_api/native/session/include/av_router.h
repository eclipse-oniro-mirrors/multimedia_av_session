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

#ifndef OHOS_AVROUTER_H
#define OHOS_AVROUTER_H

#include <string>
#include "avsession_descriptor.h"
#include "avsession_service.h"

/**
 * @brief Router is a part related to cast media
 * @since 10
 */
namespace OHOS::AVSession {
class AVRouter {
public:
    /**
     * Get AVRouter instance.
     *
     * @return AVRouter instance.
     * @since 10
    */
    static AVRouter& GetInstance();

    /**
     * Get AVRouter instance.
     * 
     * @param { AVSessionService* } servicePtr - The pointer of avsession service.
     * @since 10
    */
    virtual void Init(AVSessionService *servicePtr) = 0;

    /**
     * Get AVRouter instance.
     *
     * @param { AVCastDeviceCapability } castDeviceCapability - The type of device you want to discover.
     * @return { number } Whether the device discovery operation was successful
     * @since 10
    */
    virtual int32_t StartCastDiscovery(int32_t castDeviceCapability) = 0;

    /**
     * Notify Router that the device has been discovered.
     *
     * @param { CastOutputDeviceInfo } castOutputDeviceInfo - Discovered device infos.
     * @return { number } Whether the notify operation was successful
     * @since 10
    */
    virtual int32_t OnDeviceFound(CastOutputDeviceInfo& castOutputDeviceInfo) = 0;

};
} // namespace OHOS::AVSession
#endif // OHOS_AVROUTER_H
