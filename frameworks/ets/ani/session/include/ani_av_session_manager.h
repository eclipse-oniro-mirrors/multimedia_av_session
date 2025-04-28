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

#ifndef OHOS_ANI_AVSESSION_MANAGER_H
#define OHOS_ANI_AVSESSION_MANAGER_H

#include <iostream>
#include <memory>
#include <vector>
#include <chrono>
#include <map>
#include <list>

#include "ani.h"
#include "avsession_log.h"
#include "avsession_trace.h"
#include "avsession_manager.h"
#include "ani_work.h"
#include "ani_av_session.h"
#include "ani_av_session_utils.h"

namespace OHOS::AVSession {
class AVSessionManagerAni {
public:
    static std::map<int32_t, int32_t> errcode_;
    static ani_object CreateAVSession(ani_env *env, ani_object object,
        ani_object createAVSessioncontext, ani_string tag, ani_string type);
    static void HandleServiceStart();
};
} // namespace OHOS::AVSession
#endif // OHOS_ANI_AVSESSION_MANAGER_H
