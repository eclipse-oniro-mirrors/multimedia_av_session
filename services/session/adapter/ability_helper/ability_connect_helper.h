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

#ifndef ABILITY_CONNECT_HELPER_H
#define ABILITY_CONNECT_HELPER_H

#include <string>

#include "ability_connect_callback_interface.h"
#include "ability_connect_callback_stub.h"
#include "element_name.h"
#include "want.h"

namespace OHOS::AVSession {
class AbilityConnectHelper : public AAFwk::AbilityConnectionStub {
public:
    AbilityConnectHelper() {};
    virtual ~AbilityConnectHelper() {};

    virtual void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override;
    virtual void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;
};
} // namespace OHOS::AVSession

#ifdef __cplusplus
extern "C" {
#endif

int32_t StartAbilityByCall(const std::string bundleName, const std::string abilityName);

#ifdef __cplusplus
}
#endif
#endif /* ABILITY_CONNECT_HELPER_H */