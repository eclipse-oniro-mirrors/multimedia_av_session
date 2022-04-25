/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_IAVSESSION_CONTROLLER_H
#define OHOS_IAVSESSION_CONTROLLER_H

#include "iremote_broker.h"
#include "avsession_controller.h"

namespace OHOS::AVSession {
class IAVSessionController : public AVSessionController, public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR("ohos.avsession.IAVSessionController");

    enum {
        CONTROLLER_CMD_MAX
    };
};
}
#endif // OHOS_IAVSESSION_CONTROLLER_H