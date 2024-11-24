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

#ifndef OHOS_CJ_AVSESSION_CAST_CONTROLLER_IMPL_H
#define OHOS_CJ_AVSESSION_CAST_CONTROLLER_IMPL_H

#include <functional>
#include <map>
#include <optional>
#include <string>
#include <mutex>
#include <memory>

#include "singleton.h"
#include "avcast_controller.h"
#include "avsession_errors.h"
#include "cj_avsession_cast_controller_ffi.h"
#include "cj_avsession_cast_controller_callback.h"

namespace OHOS::AVSession {

class CJAVCastControllerBase {
public:
    virtual ~CJAVCastControllerBase() {}
    virtual int32_t SubscribeCallback(int32_t type, CParameters* extras, DoCallFunc doCall) = 0;
    virtual int32_t Start(CAVQueueItem& item) = 0;
    virtual int32_t Prepare(CAVQueueItem& item) = 0;
    virtual int32_t SendControlCommand(CAVSessionCommand& command) = 0;
    virtual int32_t GetAVPlaybackState(CAVPlaybackState& avPlaybackState) = 0;
    virtual int32_t GetCurrentItem(CAVQueueItem& item) = 0;
    virtual int32_t GetValidCommands(CArray& commands) = 0;
    virtual int32_t Release() = 0;
    virtual int32_t ProcessMediaKeyResponse(char*& assetId, CArray& response) = 0;
    virtual bool Exists() = 0;
};

class CJAVCastControllerImpl : public CJAVCastControllerBase {
    friend class CJAVSessionImpl;
protected:
    CJAVCastControllerImpl(std::shared_ptr<AVCastController>& nativeController, const std::string& sessionId);
    static std::shared_ptr<CJAVCastControllerImpl>
        NewInstance(std::shared_ptr<AVCastController>& nativeController, const std::string& sessionId);
    int32_t SetCastPlaybackStateFilter(CParameters* extras);

public:
    ~CJAVCastControllerImpl();
    static std::shared_ptr<CJAVCastControllerBase> GetInstance(const std::string &sessionId);
    int32_t SubscribeCallback(int32_t type, CParameters* extras, DoCallFunc doCall);
    int32_t Start(CAVQueueItem& item);
    int32_t Prepare(CAVQueueItem& item);
    int32_t SendControlCommand(CAVSessionCommand& command);
    int32_t GetAVPlaybackState(CAVPlaybackState& avPlaybackState);
    int32_t GetCurrentItem(CAVQueueItem& item);
    int32_t GetValidCommands(CArray& commands);
    int32_t Release();
    int32_t ProcessMediaKeyResponse(char*& assetId, CArray& response);
    bool Exists() { return true; }

private:
    std::string sessionId_;
    std::shared_ptr<AVCastController> controller_;
    static std::mutex controllerListMutex_;

    static std::mutex callbackMutex_;
    std::shared_ptr<CJAVCastControllerCallback> callback_;

    static std::map<std::string, std::shared_ptr<CJAVCastControllerImpl>> ControllerList_;
};

class CJAVCastControllerInvalidImpl : public CJAVCastControllerBase {
    DECLARE_DELAYED_SINGLETON(CJAVCastControllerInvalidImpl);
public:
    DISALLOW_COPY_AND_MOVE(CJAVCastControllerInvalidImpl);
    int32_t SubscribeCallback(int32_t type, CParameters* extras, DoCallFunc doCall) {return ERR_CONTROLLER_NOT_EXIST; }
    int32_t Start(CAVQueueItem& item) {return ERR_CONTROLLER_NOT_EXIST; }
    int32_t Prepare(CAVQueueItem& item) {return ERR_CONTROLLER_NOT_EXIST; }
    int32_t SendControlCommand(CAVSessionCommand& command) {return ERR_CONTROLLER_NOT_EXIST; }
    int32_t GetAVPlaybackState(CAVPlaybackState& avPlaybackState) {return ERR_CONTROLLER_NOT_EXIST; }
    int32_t GetCurrentItem(CAVQueueItem& item) {return ERR_CONTROLLER_NOT_EXIST; }
    int32_t GetValidCommands(CArray& commands) {return ERR_CONTROLLER_NOT_EXIST; }
    int32_t Release() {return ERR_CONTROLLER_NOT_EXIST; }
    int32_t ProcessMediaKeyResponse(char*& assetId, CArray& response) {return ERR_CONTROLLER_NOT_EXIST; }
    bool Exists() { return false; }
};

#define CJ_CAST_CONTROLLER_INVALID_IMPL OHOS::DelayedSingleton<CJAVCastControllerInvalidImpl>::GetInstance()

} // namespace AVSession::OHOS

#endif // OHOS_CJ_AVSESSION_CAST_CONTROLLER_IMPL_H