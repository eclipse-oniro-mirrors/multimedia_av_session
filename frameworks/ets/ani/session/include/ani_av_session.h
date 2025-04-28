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

#ifndef OHOS_AV_SESSION_ANI_H
#define OHOS_AV_SESSION_ANI_H

#include <iostream>
#include <memory>
#include <chrono>
#include <map>

#include "ani.h"
#include "av_session.h"
#include "avsession_info.h"
#include "avsession_errors.h"
#include "avsession_manager.h"
#include "avcontrol_command.h"
#include "ani_work.h"
#include "ani_av_session_utils.h"
#include "ani_av_session_manager.h"
#include "ani_av_session_callback.h"

namespace OHOS::AVSession {
class AVSessionAni {
public:
    AVSessionAni();
    ~AVSessionAni();

    static ani_status AVSessionAniInit(ani_env *env);
    static ani_object Constructor([[maybe_unused]] ani_env *env, ani_object context, ani_string tag, ani_string type);
    static AVSessionAni* Unwrap(ani_env *env, ani_object object);
    static ani_status NewInstance(ani_env *env, ani_object object,
        std::shared_ptr<AVSession>& nativeSession, std::shared_ptr<AVSessionAni>& aniSession);
    static ani_status ReCreateInstance(std::shared_ptr<AVSession> nativeSession);

    std::string GetSessionTag();
    void SetSessionTag(std::string sessionTag);

    std::string GetSessionType();

    AppExecFwk::ElementName GetSessionElement();
    void SetSessionElement(AppExecFwk::ElementName elementName);

    static ani_ref ThrowErrorAndReturn(ani_env *env, const std::string& message, int32_t errCode);
    static ani_ref ThrowErrorAndReturnByErrCode(ani_env *env, const std::string& message, int32_t errCode);

    using OnEventHandlerType = std::function<ani_status(ani_env*, AVSessionAni*, ani_ref)>;

private:
    static ani_ref GetAllCastDisplays(ani_env *env, ani_object object);
    static ani_ref OnEvent(ani_env *env, ani_object object, ani_string type, ani_object callbackOn);
    static ani_ref Activate(ani_env *env, ani_object object);
    static ani_ref Destroy(ani_env *env, ani_object object);

    static ani_status OnPlay(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback);
    static ani_status OnPause(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback);
    static ani_status OnStop(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback);
    static ani_status OnPlayNext(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback);
    static ani_status OnPlayPrevious(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback);
    static ani_status OnFastForward(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback);
    static ani_status OnRewind(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback);
    static ani_status OnSeek(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback);
    static ani_status OnSetSpeed(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback);
    static ani_status OnToggleFavorite(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback);
    static ani_status OnSkipToQueueItem(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback);
    static ani_status OnAVCallAnswer(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback);
    static ani_status OnAVCallHangUp(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback);
    static ani_status OnAVCallToggleCallMute(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback);
    static ani_status OnPlayFromAssetId(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback);
    static ani_status OnCastDisplayChange(ani_env *env, AVSessionAni *aVSessionAni, ani_ref callback);

    std::string sessionId_ ;
    std::string sessionType_ ;
    std::string sessionTag_ ;
    AppExecFwk::ElementName elementName_;
    std::shared_ptr<AVSession> session_;
    std::shared_ptr<AniAVSessionCallback> callback_;
    static std::map<std::string, OnEventHandlerType> onEventHandlers_;
    static std::shared_ptr<AVSessionAni> aniAVSession_;
};
} // namespace OHOS::AVSession
#endif // OHOS_AV_SESSION_ANI_H
