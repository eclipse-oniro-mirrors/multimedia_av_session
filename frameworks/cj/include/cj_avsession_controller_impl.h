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

#ifndef OHOS_CJ_AVSESSION_CONTROLLER_IMPL_H
#define OHOS_CJ_AVSESSION_CONTROLLER_IMPL_H

#include <functional>
#include <map>
#include <optional>
#include <string>
#include <mutex>
#include <memory>

#include "singleton.h"
#include "key_event.h"
#include "avsession_controller.h"
#include "avsession_errors.h"
#include "cj_avsession_controller_ffi.h"
#include "cj_avsession_manager_impl.h"
#include "cj_avsession_controller_callback.h"

namespace OHOS::AVSession {
class CJAVSessionControllerBase {
public:
    virtual ~CJAVSessionControllerBase() {}
    virtual int32_t Destroy() = 0;
    virtual int32_t GetAVCallState(CAVCallState& avCallState) = 0;
    virtual int32_t GetAVCallMetaData(CAVCallMetaData& avCallMetadata) = 0;
    virtual int32_t GetAVPlaybackState(CAVPlaybackState& avPlaybackState) = 0;
    virtual int32_t GetAVMetaData(CAVMetaData& avMetadata) = 0;
    virtual int32_t GetOutputDevice(COutputDeviceInfo& outputDeviceInfo) = 0;
    virtual int32_t GetRealPlaybackPosition(int64_t& position) = 0;
    virtual int32_t IsActive(bool& isActive) = 0;
    virtual int32_t GetValidCommands(CArray& commands) = 0;
    virtual int32_t GetAVQueueItems(CArray& items) = 0;
    virtual int32_t GetAVQueueTitle(char*& title) = 0;
    virtual int32_t GetExtras(CArray& extras) = 0;
    virtual int32_t SendCommonCommand(char*& command, CArray& args) = 0;
    virtual int32_t SendControlCommand(CAVSessionCommand& command) = 0;
    virtual int32_t SendAVKeyEvent(CKeyEvent& event) = 0;
    virtual int32_t SkipToQueueItem(int32_t& itemId) = 0;
    virtual bool Exists() = 0;
    virtual int32_t OnEvent(int32_t type, int64_t id) = 0;
    virtual int32_t OffEvent(int32_t type) = 0;
    virtual int32_t OnEventCallMetadataChange(int32_t type, CParameters* filter, int64_t id) = 0;
    virtual int32_t OnEventCallStateChange(int32_t type, CParameters* filter, int64_t id) = 0;
    virtual int32_t OnEventPlaybackStateChange(int32_t type, CParameters* filter, int64_t id) = 0;
    virtual int32_t OnEventMetaDataChang(int32_t type, CParameters* filter, int64_t id) = 0;
};

class CJAVSessionControllerImpl : public CJAVSessionControllerBase {
    friend class CJAVSessionManagerImpl;
private:
    CJAVSessionControllerImpl(std::shared_ptr<AVSessionController>& nativeController);
    static std::shared_ptr<CJAVSessionControllerImpl>
        NewInstance(std::shared_ptr<AVSessionController>& nativeController);
public:
    ~CJAVSessionControllerImpl();
    static std::shared_ptr<CJAVSessionControllerBase> GetInstance(const std::string &sessionId);
    int32_t Destroy();
    int32_t GetAVCallState(CAVCallState& avCallState);
    int32_t GetAVCallMetaData(CAVCallMetaData& avCallMetadata);
    int32_t GetAVPlaybackState(CAVPlaybackState& avPlaybackState);
    int32_t GetAVMetaData(CAVMetaData& avMetadata);
    int32_t GetOutputDevice(COutputDeviceInfo& outputDeviceInfo);
    int32_t GetRealPlaybackPosition(int64_t& position);
    int32_t IsActive(bool& isActive);
    int32_t GetValidCommands(CArray& commands);
    int32_t GetAVQueueItems(CArray& items);
    int32_t GetAVQueueTitle(char*& title);
    int32_t GetExtras(CArray& extras);
    int32_t SendCommonCommand(char*& command, CArray& args);
    int32_t SendControlCommand(CAVSessionCommand& command);
    int32_t SendAVKeyEvent(CKeyEvent& event);
    int32_t SkipToQueueItem(int32_t& itemId);
    bool Exists() { return true; }
    int32_t OnEvent(int32_t type, int64_t id);
    int32_t OffEvent(int32_t type);
    int32_t OnEventCallMetadataChange(int32_t type, CParameters* filter, int64_t id);
    int32_t OnEventCallStateChange(int32_t type, CParameters* filter, int64_t id);
    int32_t OnEventPlaybackStateChange(int32_t type, CParameters* filter, int64_t id);
    int32_t OnEventMetaDataChang(int32_t type, CParameters* filter, int64_t id);
private:
    std::string sessionId_;
    std::shared_ptr<AVSessionController> controller_;
    static std::mutex controllerListMutex_;
    std::shared_ptr<CJAVControllerCallback> callback_;

    static std::map<std::string, std::shared_ptr<CJAVSessionControllerImpl>> ControllerList_;
};

class CJAVSessionControllerInvalidImpl : public CJAVSessionControllerBase {
    DECLARE_DELAYED_SINGLETON(CJAVSessionControllerInvalidImpl);
public:
    DISALLOW_COPY_AND_MOVE(CJAVSessionControllerInvalidImpl);
    int32_t Destroy() { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t GetAVCallState(CAVCallState& avCallState) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t GetAVCallMetaData(CAVCallMetaData& avCallMetadata) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t GetAVPlaybackState(CAVPlaybackState& avPlaybackState) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t GetAVMetaData(CAVMetaData& avMetadata) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t GetOutputDevice(COutputDeviceInfo& outputDeviceInfo) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t GetRealPlaybackPosition(int64_t& position) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t IsActive(bool& isActive) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t GetValidCommands(CArray& commands) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t GetAVQueueItems(CArray& items) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t GetAVQueueTitle(char*& title) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t GetExtras(CArray& extras) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t SendCommonCommand(char*& command, CArray& args) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t SendControlCommand(CAVSessionCommand& command) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t SendAVKeyEvent(CKeyEvent& event) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t SkipToQueueItem(int32_t& itemId) { return ERR_CONTROLLER_NOT_EXIST; }
    bool Exists() { return false; }
    int32_t OnEvent(int32_t type, int64_t id) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t OffEvent(int32_t type) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t OnEventCallMetadataChange(int32_t type, CParameters* filter, int64_t id)
    {
        return ERR_CONTROLLER_NOT_EXIST;
    }
    int32_t OnEventCallStateChange(int32_t type, CParameters* filter, int64_t id) { return ERR_CONTROLLER_NOT_EXIST; }
    int32_t OnEventPlaybackStateChange(int32_t type, CParameters* filter, int64_t id)
    {
        return ERR_CONTROLLER_NOT_EXIST;
    }
    int32_t OnEventMetaDataChang(int32_t type, CParameters* filter, int64_t id) { return ERR_CONTROLLER_NOT_EXIST; }
};

#define CJ_AVSESSION_CONTROLLER_INVALID_IMPL OHOS::DelayedSingleton<CJAVSessionControllerInvalidImpl>::GetInstance()

} // namespace AVSession::OHOS

#endif // OHOS_CJ_AVSESSION_CONTROLLER_IMPL_H