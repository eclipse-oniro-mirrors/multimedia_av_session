/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <iostream>
#include <array>

#include "ani.h"
#include "ani_av_session.h"
#include "ani_av_session_utils.h"

using namespace OHOS::AVSession;

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (vm == nullptr || ANI_OK != vm->GetEnv(ANI_VERSION_1, &env) || env == nullptr) {
        SLOGE("GetEnv fail! Unsupported %{public}d", ANI_VERSION_1);
        return ANI_ERROR;
    }

    static const char *staticNsName = "@ohos.multimedia.avsession.avSession";
    ani_namespace staticNs;
    if (ANI_OK != env->FindNamespace(staticNsName, &staticNs)) {
        SLOGE("Not found %{public}s", staticNsName);
        return ANI_ERROR;
    }

    std::array staticMethods = {
        ani_native_function {"createAVSessionInner", nullptr,
            reinterpret_cast<void *>(AVSessionAni::Constructor) },
    };

    if (ANI_OK != env->Namespace_BindNativeFunctions(staticNs, staticMethods.data(), staticMethods.size())) {
        SLOGE("Cannot bind native methods to %{public}s", staticNsName);
        return ANI_ERROR;
    };

    ani_status status = AVSessionAni::AVSessionAniInit(env);
    if (status != ANI_OK) {
        SLOGE("AVSessionAniInit fail");
        return status;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}
