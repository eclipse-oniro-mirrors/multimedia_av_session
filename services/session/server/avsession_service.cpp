/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <sstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <dlfcn.h>
#include <thread>
#include <chrono>
#include <filesystem>
#include <openssl/crypto.h>

#include "accesstoken_kit.h"
#include "account_manager_adapter.h"
#include "app_manager_adapter.h"
#include "audio_adapter.h"
#include "avsession_dynamic_loader.h"
#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_info.h"
#include "device_manager.h"
#include "remote_session_capability_set.h"
#include "remote_session_source_proxy.h"
#include "remote_session_sink_proxy.h"
#include "file_ex.h"
#include "iservice_registry.h"
#include "key_event_adapter.h"
#include "nlohmann/json.hpp"
#include "permission_checker.h"
#include "system_ability_definition.h"
#include "session_stack.h"
#include "avsession_trace.h"
#include "hash_calculator.h"
#include "avsession_dumper.h"
#include "command_send_limit.h"
#include "avsession_sysevent.h"
#include "json_utils.h"
#include "avsession_utils.h"
#include "avcontrol_command.h"
#include "avsession_event_handler.h"
#include "bundle_status_adapter.h"
#include "params_config_operator.h"
#include "notification_content.h"
#include "notification_helper.h"
#include "notification_request.h"
#include "notification_constant.h"
#include "ability_connect_helper.h"
#include "if_system_ability_manager.h"
#include "parameter.h"
#include "parameters.h"
#include "avsession_service.h"
#include "want_agent_helper.h"
#include "avsession_radar.h"

typedef void (*MigrateStubFunc)(std::function<void(std::string, std::string, std::string, std::string)>);
typedef void (*StopMigrateStubFunc)(void);

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
#include "av_router.h"
#include "collaboration_manager.h"
#endif

#if !defined(WINDOWS_PLATFORM) and !defined(MAC_PLATFORM) and !defined(IOS_PLATFORM)
#include <malloc.h>
#endif

using namespace std;
using namespace nlohmann;
using namespace OHOS::AudioStandard;

namespace OHOS::AVSession {

static const std::string AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH = std::string("libavsession_dynamic_insight.z.so");
    
static const int32_t CAST_ENGINE_SA_ID = 65546;
static const int32_t COLLABORATION_SA_ID = 70633;
static const int32_t MINNUM_FOR_NOTIFICATION = 5;
const std::string BOOTEVENT_AVSESSION_SERVICE_READY = "bootevent.avsessionservice.ready";

const std::map<int, int32_t> keyCodeToCommandMap_ = {
    {MMI::KeyEvent::KEYCODE_MEDIA_PLAY_PAUSE, AVControlCommand::SESSION_CMD_PLAY},
    {MMI::KeyEvent::KEYCODE_MEDIA_PLAY, AVControlCommand::SESSION_CMD_PLAY},
    {MMI::KeyEvent::KEYCODE_MEDIA_PAUSE, AVControlCommand::SESSION_CMD_PAUSE},
    {MMI::KeyEvent::KEYCODE_MEDIA_STOP, AVControlCommand::SESSION_CMD_STOP},
    {MMI::KeyEvent::KEYCODE_MEDIA_NEXT, AVControlCommand::SESSION_CMD_PLAY_NEXT},
    {MMI::KeyEvent::KEYCODE_MEDIA_PREVIOUS, AVControlCommand::SESSION_CMD_PLAY_PREVIOUS},
    {MMI::KeyEvent::KEYCODE_MEDIA_REWIND, AVControlCommand::SESSION_CMD_REWIND},
    {MMI::KeyEvent::KEYCODE_MEDIA_FAST_FORWARD, AVControlCommand::SESSION_CMD_FAST_FORWARD},
};

class NotificationSubscriber : public Notification::NotificationLocalLiveViewSubscriber {
    void OnConnected() {}
    void OnDisconnected() {}
    void OnResponse(int32_t notificationId, sptr<Notification::NotificationButtonOption> buttonOption) {}
    void OnDied() {}
};

static const auto NOTIFICATION_SUBSCRIBER = NotificationSubscriber();

REGISTER_SYSTEM_ABILITY_BY_ID(AVSessionService, AVSESSION_SERVICE_ID, true);

AVSessionService::AVSessionService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate)
{
}

AVSessionService::~AVSessionService()
{
    GetUsersManager().ClearCache();
}

void AVSessionService::OnStart()
{
    GetUsersManager().ClearCache();
    CHECK_AND_RETURN_LOG(Publish(this), "publish avsession service failed");
    dumpHelper_ = std::make_unique<AVSessionDumper>();
    CommandSendLimit::GetInstance().StartTimer();

    ParamsConfigOperator::GetInstance().InitConfig();
    auto ret = ParamsConfigOperator::GetInstance().GetValueIntByKey("historicalRecordMaxNum", &maxHistoryNums_);
    if (ret == AVSESSION_ERROR) {
        maxHistoryNums_ = defMaxHistoryNum;
    }

#ifdef ENABLE_BACKGROUND_AUDIO_CONTROL
    backgroundAudioController_.Init(this);
    AddInnerSessionListener(&backgroundAudioController_);
#endif

    AddSystemAbilityListener(MULTIMODAL_INPUT_SERVICE_ID);
    AddSystemAbilityListener(AUDIO_POLICY_SERVICE_ID);
    AddSystemAbilityListener(APP_MGR_SERVICE_ID);
    AddSystemAbilityListener(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
    AddSystemAbilityListener(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    AddSystemAbilityListener(CAST_ENGINE_SA_ID);
    AddSystemAbilityListener(COLLABORATION_SA_ID);
    AddSystemAbilityListener(BLUETOOTH_HOST_SYS_ABILITY_ID);
    AddSystemAbilityListener(MEMORY_MANAGER_SA_ID);
    AddSystemAbilityListener(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);

    PullMigrateStub();
    HISYSEVENT_REGITER;
    HISYSEVENT_BEHAVIOR("SESSION_SERVICE_START", "SERVICE_NAME", "AVSessionService",
        "SERVICE_ID", AVSESSION_SERVICE_ID, "DETAILED_MSG", "avsession service start success");
    if (!system::GetBoolParameter(BOOTEVENT_AVSESSION_SERVICE_READY.c_str(), false)) {
        system::SetParameter(BOOTEVENT_AVSESSION_SERVICE_READY.c_str(), "true");
        SLOGI("set boot avsession service started true");
    }
}

void AVSessionService::OnDump()
{
}

void AVSessionService::OnStop()
{
    StopMigrateStubFunc stopMigrateStub =
        reinterpret_cast<StopMigrateStubFunc>(dlsym(migrateStubFuncHandle_, "StopMigrateStub"));
    if (stopMigrateStub == nullptr) {
        SLOGE("failed to find library, reason: %{public}sn", dlerror());
    } else {
        stopMigrateStub();
    }
#ifndef TEST_COVERAGE
    if (migrateStubFuncHandle_ != nullptr) {
        OPENSSL_thread_stop();
    }
    dlclose(migrateStubFuncHandle_);
#endif
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    CollaborationManager::GetInstance().UnRegisterLifecycleCallback();
#endif
    CommandSendLimit::GetInstance().StopTimer();
    NotifyProcessStatus(false);
    UnSubscribeCommonEvent();
}

EventSubscriber::EventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo, AVSessionService *ptr)
    : EventFwk::CommonEventSubscriber(subscriberInfo)
{
    servicePtr_ = ptr;
}

void EventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    const AAFwk::Want &want = eventData.GetWant();
    std::string action = want.GetAction();
    SLOGI("OnReceiveEvent action:%{public}s.", action.c_str());
    if (servicePtr_ == nullptr) {
        SLOGE("OnReceiveEvent get action:%{public}s with servicePtr_ null", action.c_str());
        return;
    }
    if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) == 0 ||
        action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON) == 0 ||
        action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED) == 0 ||
        action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED) == 0) {
        servicePtr_->HandleScreenStatusChange(action);
    } else if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_USER_FOREGROUND) == 0) {
        int32_t userIdForeground = eventData.GetCode();
        servicePtr_->HandleUserEvent(AVSessionUsersManager::accountEventSwitched, userIdForeground);
    } else if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) == 0) {
        int32_t userIdSwitched = eventData.GetCode();
        servicePtr_->HandleUserEvent(AVSessionUsersManager::accountEventSwitched, userIdSwitched);
    } else if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) == 0) {
        int32_t userId = eventData.GetCode();
        servicePtr_->HandleUserEvent(AVSessionUsersManager::accountEventRemoved, userId);
    } else if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED) == 0) {
        int32_t userId = eventData.GetCode();
        servicePtr_->RegisterBundleDeleteEventForHistory(userId);
    } else if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED) == 0 ||
        action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_LOCKED_BOOT_COMPLETED) == 0) {
        servicePtr_->InitCastEngineService();
    }
}

std::string AVSessionService::GetAVQueueDir(int32_t userId)
{
    return GetUsersManager().GetDirForCurrentUser(userId) + AVQUEUE_FILE_NAME;
}

std::string AVSessionService::GetAVSortDir(int32_t userId)
{
    return GetUsersManager().GetDirForCurrentUser(userId) + SORT_FILE_NAME;
}

void AVSessionService::HandleUserEvent(const std::string &type, const int &userId)
{
    GetUsersManager().NotifyAccountsEvent(type, userId);
    UpdateTopSession(GetUsersManager().GetTopSession());
}

void AVSessionService::HandleScreenStatusChange(std::string event)
{
    std::lock_guard lockGuard(screenStateLock_);

    if (event.compare(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) == 0) {
        SetScreenOn(false);
    } else if (event.compare(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON) == 0) {
        SetScreenOn(true);
    } else if (event.compare(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED) == 0) {
        SetScreenLocked(true);
    } else if (event.compare(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED) == 0) {
        SetScreenLocked(false);
    }
    SLOGI("check screen status with screenOn %{public}d and screenLocked %{public}d",
        static_cast<int>(GetScreenOn()), static_cast<int>(GetScreenLocked()));

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    bool is2in1 = system::GetBoolParameter("const.audio.volume_apply_to_all", false);
    if (!is2in1) {
        return;
    }
    if (GetScreenOn() && !GetScreenLocked()) {
        SLOGI("enable cast check 2in1");
        AVRouter::GetInstance().SetDiscoverable(false);
        AVRouter::GetInstance().SetDiscoverable(true);
    } else {
        SLOGI("disable cast check 2in1");
        AVRouter::GetInstance().SetDiscoverable(false);
    }

#endif
}

void AVSessionService::SetScreenOn(bool on)
{
    std::lock_guard lockGuard(screenStateLock_);
    isScreenOn_ = on;
}

bool AVSessionService::GetScreenOn()
{
    std::lock_guard lockGuard(screenStateLock_);
    return isScreenOn_;
}

void AVSessionService::SetScreenLocked(bool isLocked)
{
    std::lock_guard lockGuard(screenStateLock_);
    isScreenLocked_ = isLocked;
}

bool AVSessionService::GetScreenLocked()
{
    std::lock_guard lockGuard(screenStateLock_);
    return isScreenLocked_;
}

bool AVSessionService::SubscribeCommonEvent()
{
    const std::vector<std::string> events = {
        EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF,
        EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON,
        EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED,
        EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED,
        EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED,
        EventFwk::CommonEventSupport::COMMON_EVENT_USER_FOREGROUND,
        EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED,
        EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED,
        EventFwk::CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED,
        EventFwk::CommonEventSupport::COMMON_EVENT_LOCKED_BOOT_COMPLETED,
    };

    EventFwk::MatchingSkills matchingSkills;
    for (auto event : events) {
        matchingSkills.AddEvent(event);
    }
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    subscriber_ = std::make_shared<EventSubscriber>(subscribeInfo, this);
    return EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
}

bool AVSessionService::UnSubscribeCommonEvent()
{
    bool subscribeResult = false;
    if (subscriber_ != nullptr) {
        subscribeResult = EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_);
        subscriber_ = nullptr;
    }
    SLOGI("UnSubscribeCommonEvent subscribeResult = %{public}d", subscribeResult);

    return subscribeResult;
}

void AVSessionService::PullMigrateStub()
{
    migrateStubFuncHandle_ = dlopen("libavsession_migration.z.so", RTLD_NOW);
    if (migrateStubFuncHandle_ == nullptr) {
        SLOGE("failed to dlopen library, reason: %{public}sn", dlerror());
        return;
    }
    MigrateStubFunc startMigrateStub =
        reinterpret_cast<MigrateStubFunc>(dlsym(migrateStubFuncHandle_, "StartMigrateStub"));
    if (startMigrateStub == nullptr) {
        SLOGE("failed to find library, reason: %{public}sn", dlerror());
        return;
    }
    std::thread([startMigrateStub, this]() {
        SLOGI("create thread to keep MigrateStub");
        startMigrateStub([this](std::string deviceId, std::string serviceName, std::string extraInfo,
            std::string state) { SuperLauncher(deviceId, serviceName, extraInfo, state); });
    }).detach();
}

void AVSessionService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    SLOGI("Receive SA: %{public}d start callback.", systemAbilityId);
    switch (systemAbilityId) {
        case MULTIMODAL_INPUT_SERVICE_ID:
            InitKeyEvent();
            break;
        case AUDIO_POLICY_SERVICE_ID:
            InitAudio();
            break;
        case APP_MGR_SERVICE_ID:
            InitAMS();
            break;
        case DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID:
            InitDM();
            break;
        case BUNDLE_MGR_SERVICE_SYS_ABILITY_ID:
            InitBMS();
            InitRadarBMS();
            break;
        case CAST_ENGINE_SA_ID:
            break;
        case COLLABORATION_SA_ID:
            InitCollaboration();
            break;
        case BLUETOOTH_HOST_SYS_ABILITY_ID:
            CheckBrEnable();
            break;
        case MEMORY_MANAGER_SA_ID:
            NotifyProcessStatus(true);
            break;
        case SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN:
            InitAccountMgr();
            break;
        case COMMON_EVENT_SERVICE_ID:
            InitCommonEventService();
            break;
        default:
            SLOGE("undefined system ability %{public}d", systemAbilityId);
    }
}

void AVSessionService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    if (systemAbilityId == CAST_ENGINE_SA_ID) {
        SLOGI("cast engine ability is removed");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
        for (auto& session : GetContainer().GetAllSessions()) {
            if (session != nullptr) {
                session->OnRemoveCastEngine();
            }
        }
#endif
        isInCast_ = false;
    }
    if (systemAbilityId == BLUETOOTH_HOST_SYS_ABILITY_ID) {
#ifdef BLUETOOTH_ENABLE
        SLOGI("on bluetooth remove ability");
        bluetoothHost_ = &OHOS::Bluetooth::BluetoothHost::GetDefaultHost();
        if (bluetoothHost_ != nullptr && bluetoothObserver != nullptr) {
            bluetoothHost_->DeregisterObserver(bluetoothObserver);
        }
#endif
    }
}

#ifdef BLUETOOTH_ENABLE
DetectBluetoothHostObserver::DetectBluetoothHostObserver(AVSessionService *ptr)
{
    is2in1_ = system::GetBoolParameter("const.audio.volume_apply_to_all", false);
    SLOGI("DetectBluetoothHostObserver, Prop=%{public}d", static_cast<int>(is2in1_));
    servicePtr_ = ptr;
}

void DetectBluetoothHostObserver::OnStateChanged(const int transport, const int status)
{
    SLOGI("transport=%{public}d status=%{public}d", transport, status);
    if (transport != OHOS::Bluetooth::BTTransport::ADAPTER_BREDR) {
        return;
    }
    bool newStatus = (status == OHOS::Bluetooth::BTStateID::STATE_TURN_ON);
    if (newStatus == lastEnabled_) {
        return;
    }
    bool isScreenOn = true;
    if (servicePtr_ != nullptr) {
        isScreenOn = servicePtr_->GetScreenOn();
        SLOGI("isScreenOn=%{public}d", isScreenOn);
    }
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    if (newStatus && is2in1_ && isScreenOn) {
        AVRouter::GetInstance().SetDiscoverable(false);
        AVRouter::GetInstance().SetDiscoverable(true);
    }
#endif
    lastEnabled_ = newStatus;
}
#endif

void AVSessionService::CheckBrEnable()
{
#ifdef BLUETOOTH_ENABLE
    bluetoothHost_ = &OHOS::Bluetooth::BluetoothHost::GetDefaultHost();
    bluetoothObserver = std::make_shared<DetectBluetoothHostObserver>(this);
    if (bluetoothHost_ != nullptr) {
        bluetoothHost_->RegisterObserver(bluetoothObserver);
    }
#endif
}

void AVSessionService::NotifyProcessStatus(bool isStart)
{
    int pid = getpid();
    void *libMemMgrClientHandle = dlopen("libmemmgrclient.z.so", RTLD_NOW);
    if (!libMemMgrClientHandle) {
        SLOGE("dlopen libmemmgrclient library failed");
        return;
    }
    void *notifyProcessStatusFunc = dlsym(libMemMgrClientHandle, "notify_process_status");
    if (!notifyProcessStatusFunc) {
        SLOGE("dlsm notify_process_status failed");
#ifndef TEST_COVERAGE
        if (libMemMgrClientHandle != nullptr) {
            OPENSSL_thread_stop();
        }
        dlclose(libMemMgrClientHandle);
#endif
        return;
    }
    auto notifyProcessStatus = reinterpret_cast<int(*)(int, int, int, int)>(notifyProcessStatusFunc);
    if (isStart) {
        SLOGI("notify to memmgr when av_session is started");
        notifyProcessStatus(pid, saType, 1, AVSESSION_SERVICE_ID); // 1 indicates the service is started
    } else {
        SLOGI("notify to memmgr when av_session is stopped");
        notifyProcessStatus(pid, saType, 0, AVSESSION_SERVICE_ID); // 0 indicates the service is stopped
    }
#ifndef TEST_COVERAGE
    if (libMemMgrClientHandle != nullptr) {
        OPENSSL_thread_stop();
    }
    dlclose(libMemMgrClientHandle);
#endif
}

void AVSessionService::InitKeyEvent()
{
    SLOGI("enter init keyEvent");
    std::vector<int32_t> keyCodes = {
        MMI::KeyEvent::KEYCODE_MEDIA_PLAY,
        MMI::KeyEvent::KEYCODE_MEDIA_PAUSE,
        MMI::KeyEvent::KEYCODE_MEDIA_PLAY_PAUSE,
        MMI::KeyEvent::KEYCODE_MEDIA_STOP,
        MMI::KeyEvent::KEYCODE_MEDIA_NEXT,
        MMI::KeyEvent::KEYCODE_MEDIA_PREVIOUS,
        MMI::KeyEvent::KEYCODE_MEDIA_REWIND,
        MMI::KeyEvent::KEYCODE_MEDIA_FAST_FORWARD,
        MMI::KeyEvent::KEYCODE_HEADSETHOOK,
    };

    KeyEventAdapter::GetInstance().SubscribeKeyEvent(
        keyCodes, [this](const auto& keyEvent) { SendSystemAVKeyEvent(*keyEvent); });
}

void AVSessionService::UpdateTopSession(const sptr<AVSessionItem>& newTopSession)
{
    AVSessionDescriptor descriptor;
    {
        std::lock_guard lockGuard(sessionServiceLock_);
        if (newTopSession == nullptr) {
            if (topSession_ != nullptr) {
                topSession_->SetTop(false);
            }
            topSession_ = nullptr;
            GetUsersManager().SetTopSession(nullptr);
            SLOGI("set topSession to nullptr");
            HISYSEVENT_BEHAVIOR("FOCUS_CHANGE", "DETAILED_MSG", "avsessionservice set topsession to nullptr");
            return;
        }

        SLOGI("uid=%{public}d sessionId=%{public}s", newTopSession->GetUid(),
            AVSessionUtils::GetAnonySessionId(newTopSession->GetSessionId()).c_str());
        if (topSession_ != nullptr) {
            topSession_->SetTop(false);
            HISYSEVENT_BEHAVIOR("FOCUS_CHANGE",
                "OLD_BUNDLE_NAME", topSession_->GetDescriptor().elementName_.GetBundleName(),
                "OLD_MODULE_NAME", topSession_->GetDescriptor().elementName_.GetModuleName(),
                "OLD_ABILITY_NAME", topSession_->GetAbilityName(), "OLD_SESSION_PID", topSession_->GetPid(),
                "OLD_SESSION_UID", topSession_->GetUid(), "OLD_SESSION_ID", topSession_->GetSessionId(),
                "OLD_SESSION_TAG", topSession_->GetDescriptor().sessionTag_,
                "OLD_SESSION_TYPE", topSession_->GetDescriptor().sessionType_,
                "BUNDLE_NAME", newTopSession->GetDescriptor().elementName_.GetBundleName(),
                "MODULE_NAME", newTopSession->GetDescriptor().elementName_.GetModuleName(),
                "ABILITY_NAME", newTopSession->GetAbilityName(), "SESSION_PID", newTopSession->GetPid(),
                "SESSION_UID", newTopSession->GetUid(), "SESSION_ID", newTopSession->GetSessionId(),
                "SESSION_TAG", newTopSession->GetDescriptor().sessionTag_,
                "SESSION_TYPE", newTopSession->GetDescriptor().sessionType_,
                "DETAILED_MSG", "avsessionservice handlefocussession, updatetopsession");
        }
        topSession_ = newTopSession;
        GetUsersManager().SetTopSession(newTopSession);
        topSession_->SetTop(true);
        descriptor = topSession_->GetDescriptor();
    }

    NotifyTopSessionChanged(descriptor);
}

// LCOV_EXCL_START
void AVSessionService::HandleFocusSession(const FocusSessionStrategy::FocusSessionChangeInfo& info)
{
    SLOGI("HandleFocusSession with uid=%{public}d, cur topSession:%{public}s",
        info.uid, (topSession_ == nullptr ? "null" : topSession_->GetBundleName()).c_str());
    std::lock_guard lockGuard(sessionServiceLock_);
    if (topSession_ && topSession_->GetUid() == info.uid) {
        SLOGI("The focusSession is the same as current topSession.");
        if ((topSession_->GetSessionType() == "audio" || topSession_->GetSessionType() == "video") &&
            topSession_->GetUid() != ancoUid) {
            AVSessionService::NotifySystemUI(nullptr, true);
        }
        if (topSession_->GetUid() == ancoUid) {
            int32_t ret = Notification::NotificationHelper::CancelNotification(0);
            SLOGI("CancelNotification for anco ret=%{public}d", ret);
        }
        return;
    }
    std::lock_guard frontLockGuard(sessionFrontLock_);
    std::shared_ptr<std::list<sptr<AVSessionItem>>> sessionListForFront = GetCurSessionListForFront();
    CHECK_AND_RETURN_LOG(sessionListForFront != nullptr, "sessionListForFront ptr nullptr!");
    for (const auto& session : *sessionListForFront) {
        if (session->GetUid() == info.uid &&
            (session->GetSessionType() != "voice_call" && session->GetSessionType() != "video_call")) {
            UpdateTopSession(session);
            if ((topSession_->GetSessionType() == "audio" || topSession_->GetSessionType() == "video") &&
                topSession_->GetUid() != ancoUid) {
                AVSessionService::NotifySystemUI(nullptr, true);
            }
            if (topSession_->GetUid() == ancoUid) {
                int32_t ret = Notification::NotificationHelper::CancelNotification(0);
                SLOGI("CancelNotification for anco ret=%{public}d", ret);
            }
            return;
        }
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
void AVSessionService::RefreshFocusSessionSort(sptr<AVSessionItem> &session)
{
    std::lock_guard sortFileLockGuard(sessionFileLock_);
    std::string oldSortContent;
    if (!LoadStringFromFileEx(GetAVSortDir(), oldSortContent)) {
        SLOGE("LoadStringFromFileEx failed when refresh focus session sort!");
        return;
    }
    nlohmann::json values = json::parse(oldSortContent, nullptr, false);
    CHECK_AND_RETURN_LOG(!values.is_discarded(), "json object is null");
    bool sessionExist = false;
    for (auto value : values) {
        if (!value.contains("bundleName") || !value.contains("abilityName")) {
            SLOGI("not contain bundleName or abilityName, pass");
            continue;
        }
        if (session->GetBundleName() == value["bundleName"] &&
            session->GetAbilityName() == value["abilityName"]) {
            values.erase(std::remove(values.begin(), values.end(), value));
            sessionExist = true;
            break;
        }
    }
    if (sessionExist) {
        nlohmann::json value;
        value["sessionId"] = session->GetSessionId();
        value["bundleName"] = session->GetBundleName();
        value["abilityName"] = session->GetAbilityName();
        value["sessionType"] = session->GetSessionType();
        if (values.size() <= 0) {
            values.push_back(value);
        } else {
            values.insert(values.begin(), value);
        }
    }

    std::string newSortContent = values.dump();
    if (!SaveStringToFileEx(GetAVSortDir(), newSortContent)) {
        SLOGE("SaveStringToFileEx failed when refresh focus session sort!");
    }
}
// LCOV_EXCL_STOP

void AVSessionService::UpdateFrontSession(sptr<AVSessionItem>& sessionItem, bool isAdd)
{
    SLOGI("UpdateFrontSession with bundle=%{public}s isAdd=%{public}d", sessionItem->GetBundleName().c_str(), isAdd);
        std::lock_guard frontLockGuard(sessionFrontLock_);
    std::shared_ptr<std::list<sptr<AVSessionItem>>> sessionListForFront = GetCurSessionListForFront();
    CHECK_AND_RETURN_LOG(sessionListForFront != nullptr, "sessionListForFront ptr nullptr!");
    auto it = std::find(sessionListForFront->begin(), sessionListForFront->end(), sessionItem);
    if (isAdd) {
        if (it != sessionListForFront->end()) {
            SLOGI("sessionListForFront has same session bundle=%{public}s", sessionItem->GetBundleName().c_str());
            return;
        }
        sessionListForFront->push_front(sessionItem);
        if (AudioAdapter::GetInstance().GetRendererRunning(sessionItem->GetUid())) {
            SLOGI("Renderer Running, RepublishNotification for uid=%{public}d", sessionItem->GetUid());
            UpdateTopSession(sessionItem);
            AVSessionDescriptor selectSession = sessionItem->GetDescriptor();
            NotifySystemUI(&selectSession, true);
        }
    } else {
        std::lock_guard lockGuard(sessionServiceLock_);
        if (topSession_.GetRefPtr() == sessionItem.GetRefPtr()) {
            UpdateTopSession(nullptr);
            int32_t ret = Notification::NotificationHelper::CancelNotification(0);
            SLOGI("CancelNotification ret=%{public}d", ret);
        }
        sessionListForFront->remove(sessionItem);
    }
}

// LCOV_EXCL_START
bool AVSessionService::SelectFocusSession(const FocusSessionStrategy::FocusSessionChangeInfo& info)
{
    for (auto& session : GetContainer().GetAllSessions()) {
        if (session->GetDescriptor().sessionTag_ == "RemoteCast" || session->GetUid() != info.uid) {
            continue;
        }
        GetContainer().UpdateSessionSort(session);
        RefreshFocusSessionSort(session);
        std::lock_guard frontLockGuard(sessionFrontLock_);
        std::shared_ptr<std::list<sptr<AVSessionItem>>> sessionListForFront = GetCurSessionListForFront();
        CHECK_AND_RETURN_RET_LOG(sessionListForFront != nullptr, false, "sessionListForFront ptr nullptr!");
        auto it = std::find(sessionListForFront->begin(), sessionListForFront->end(), session);
        if (it != sessionListForFront->end()) {
            SLOGI("Focus session is in sessionListForFront_, need to change order of it.");
            sessionListForFront->remove(session);
            sessionListForFront->push_front(session);
        }
        return true;
    }
    return false;
}
// LCOV_EXCL_STOP

void AVSessionService::InitAudio()
{
    SLOGI("enter");
    AudioAdapter::GetInstance().Init();
    focusSessionStrategy_.Init();
    focusSessionStrategy_.RegisterFocusSessionChangeCallback([this] (const auto& info) {
        HandleFocusSession(info);
    });
    focusSessionStrategy_.RegisterFocusSessionSelector([this] (const auto& info) {
        return SelectFocusSession(info);
    });
    AudioAdapter::GetInstance().AddStreamRendererStateListener([this] (const AudioRendererChangeInfos& infos) {
        OutputDeviceChangeListener(infos);
    });
    AudioAdapter::GetInstance().AddDeviceChangeListener(
        [this] (const std::vector<std::shared_ptr<AudioDeviceDescriptor>> &desc) {
        HandleDeviceChange(desc);
    });
}

sptr <AVSessionItem> AVSessionService::SelectSessionByUid(const AudioRendererChangeInfo& info)
{
    for (const auto& session : GetContainer().GetAllSessions()) {
        if (session != nullptr && session->GetUid() == info.clientUID) {
            return session;
        }
    }
    SLOGI("AudioRendererInfo with uid: %{public}d does not have a corresponding session.", info.clientUID);
    return nullptr;
}

void AVSessionService::OutputDeviceChangeListener(const AudioRendererChangeInfos& infos)
{
}

void AVSessionService::InitAMS()
{
    SLOGI("enter");
    AppManagerAdapter::GetInstance().Init();
    AppManagerAdapter::GetInstance().SetServiceCallbackForAppStateChange([this] (int uid, int state) {
        SLOGD("uid = %{public}d, state = %{public}d", uid, state);
        HandleAppStateChange(uid, state);
    });
}

void AVSessionService::InitDM()
{
    SLOGI("enter");
    auto callback = std::make_shared<AVSessionInitDMCallback>();
    CHECK_AND_RETURN_LOG(callback != nullptr, "no memory");
    int32_t ret = OHOS::DistributedHardware::DeviceManager::GetInstance().InitDeviceManager("av_session", callback);
    CHECK_AND_RETURN_LOG(ret == 0, "InitDeviceManager error ret is %{public}d", ret);
}

void AVSessionService::InitBMS()
{
    std::lock_guard sortFileLockGuard(sessionFileLock_);
    SLOGI("enter");
    BundleStatusAdapter::GetInstance().Init();
    int userId = GetUsersManager().GetCurrentUserId();
    if (userId < 0) {
        SLOGE("InitBMS with userId: %{public}d, not valid, return and wait for InitAccountMgr", userId);
        return;
    }
    RegisterBundleDeleteEventForHistory(userId);
}

void AVSessionService::InitAccountMgr()
{
    SLOGI("InitAccountMgr in");
    GetUsersManager().Init();
    RegisterBundleDeleteEventForHistory();
}

void AVSessionService::InitCommonEventService()
{
    SLOGI("InitCommonEventService in");
    bool ret = SubscribeCommonEvent();
    CHECK_AND_RETURN_LOG(ret, "SubscribeCommonEvent error!");
}

void AVSessionService::InitCollaboration()
{
    SLOGI("InitCollaboration in");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    CollaborationManager::GetInstance().ReadCollaborationManagerSo();
    CollaborationManager::GetInstance().RegisterLifecycleCallback();
#endif
}

void AVSessionService::InitCastEngineService()
{
    SLOGI("InitCastEngineService in");
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    is2in1_ = system::GetBoolParameter("const.audio.volume_apply_to_all", false);
    SLOGI("GetDeviceEnableCast, Prop=%{public}d", static_cast<int>(is2in1_));
    if (is2in1_) {
        SLOGI("startup enable cast check 2in1");
        checkEnableCast(true);
        AVRouter::GetInstance().SetDiscoverable(false);
        AVRouter::GetInstance().SetDiscoverable(true);
    }
#endif
}

void AVSessionService::RegisterBundleDeleteEventForHistory(int32_t userId)
{
    if (userId <= 0) {
        userId = GetUsersManager().GetCurrentUserId();
        SLOGI("do RegisterBundleDeleteEventForHistory with cur userId:%{public}d", userId);
    } else {
        SLOGI("do RegisterBundleDeleteEventForHistory with recv userId:%{public}d", userId);
    }

    std::string oldSortContent;
    if (LoadStringFromFileEx(GetAVSortDir(userId), oldSortContent)) {
        nlohmann::json values = json::parse(oldSortContent, nullptr, false);
        CHECK_AND_RETURN_LOG(!values.is_discarded(), "json object is null");
        auto callback = [this](std::string bundleName, int32_t userId) {
            SLOGI("recv delete bundle:%{public}s at user:%{public}d", bundleName.c_str(), userId);
            DeleteAVQueueInfoRecord(bundleName, userId);
            DeleteHistoricalRecord(bundleName, userId);
        };
        for (auto value : values) {
            if (!BundleStatusAdapter::GetInstance().SubscribeBundleStatusEvent(value["bundleName"], callback, userId)) {
                std::string bundleName = value["bundleName"];
                SLOGE("SubscribeBundleStatusEvent failed for bundle:%{public}s", bundleName.c_str());
            }
        }
    }
}

SessionContainer& AVSessionService::GetContainer()
{
    return GetUsersManager().GetContainer();
}

AVSessionUsersManager& AVSessionService::GetUsersManager()
{
    static AVSessionUsersManager usersManager;
    return usersManager;
}

inline std::shared_ptr<std::list<sptr<AVSessionItem>>> AVSessionService::GetCurSessionListForFront()
{
    return GetUsersManager().GetCurSessionListForFront();
}

std::string AVSessionService::AllocSessionId()
{
    auto curNum = sessionSeqNum_++;
    std::string id = std::to_string(GetCallingPid()) + "-" + std::to_string(GetCallingUid()) + "-" +
                     std::to_string(curNum);

    HashCalculator hashCalculator;
    CHECK_AND_RETURN_RET_LOG(hashCalculator.Init() == AVSESSION_SUCCESS, "", "hash init failed");
    CHECK_AND_RETURN_RET_LOG(hashCalculator.Update(std::vector<uint8_t>(id.begin(), id.end())) == AVSESSION_SUCCESS,
                             "", "hash update failed");
    std::vector<uint8_t> hash;
    CHECK_AND_RETURN_RET_LOG(hashCalculator.GetResult(hash) == AVSESSION_SUCCESS, "", "hash get result failed");

    std::stringstream stream;
    for (const auto byte : hash) {
        stream << std::uppercase << std::hex << std::setfill('0') << std::setw(allocSpace) << static_cast<int>(byte);
    }
    return stream.str();
}

bool AVSessionService::AbilityHasSession(pid_t pid)
{
    std::lock_guard lockGuard(sessionServiceLock_);
    return GetContainer().PidHasSession(pid);
}

sptr<AVControllerItem> AVSessionService::GetPresentController(pid_t pid, const std::string& sessionId)
{
    std::lock_guard lockGuard(sessionServiceLock_);
    auto it = controllers_.find(pid);
    if (it != controllers_.end()) {
        for (const auto& controller: it->second) {
            if (controller != nullptr && controller->HasSession(sessionId)) {
                return controller;
            }
        }
    }
    SLOGI("Not found controller for pid:%{public}d, sessionId:%{public}s.", pid, sessionId.c_str());
    return nullptr;
}

void AVSessionService::NotifySessionCreate(const AVSessionDescriptor& descriptor)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    std::map<pid_t, sptr<ISessionListener>> listenerMap = GetUsersManager().GetSessionListener();
    for (const auto& [pid, listener] : listenerMap) {
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnSessionCreate");
        if (listener != nullptr) {
            listener->OnSessionCreate(descriptor);
        }
    }
    std::map<pid_t, sptr<ISessionListener>> listenerMapForAll = GetUsersManager().GetSessionListenerForAllUsers();
    for (const auto& [pid, listener] : listenerMapForAll) {
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnSessionCreate");
        if (listener != nullptr) {
            listener->OnSessionCreate(descriptor);
        }
    }

    {
        std::lock_guard lockGuard(migrateListenersLock_);
        for (const auto& listener : innerSessionListeners_) {
            if (listener != nullptr) {
                listener->OnSessionCreate(descriptor);
            }
        }
    }
}

void AVSessionService::NotifySessionRelease(const AVSessionDescriptor& descriptor)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    std::map<pid_t, sptr<ISessionListener>> listenerMap = GetUsersManager().GetSessionListener();
    for (const auto& [pid, listener] : listenerMap) {
        if (listener != nullptr) {
            listener->OnSessionRelease(descriptor);
        }
    }
    std::map<pid_t, sptr<ISessionListener>> listenerMapForAll = GetUsersManager().GetSessionListenerForAllUsers();
    for (const auto& [pid, listener] : listenerMapForAll) {
        if (listener != nullptr) {
            listener->OnSessionRelease(descriptor);
        }
    }

    {
        std::lock_guard lockGuard(migrateListenersLock_);
        for (const auto& listener : innerSessionListeners_) {
            if (listener != nullptr) {
                listener->OnSessionRelease(descriptor);
            }
        }
    }
}

void AVSessionService::NotifyTopSessionChanged(const AVSessionDescriptor& descriptor)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    std::map<pid_t, sptr<ISessionListener>> listenerMap = GetUsersManager().GetSessionListener();
    for (const auto& [pid, listener] : listenerMap) {
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnTopSessionChange");
        if (listener != nullptr) {
            listener->OnTopSessionChange(descriptor);
        }
    }
    std::map<pid_t, sptr<ISessionListener>> listenerMapForAll = GetUsersManager().GetSessionListenerForAllUsers();
    for (const auto& [pid, listener] : listenerMapForAll) {
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnTopSessionChange");
        if (listener != nullptr) {
            listener->OnTopSessionChange(descriptor);
        }
    }

    {
        std::lock_guard lockGuard(migrateListenersLock_);
        for (const auto& listener : innerSessionListeners_) {
            if (listener != nullptr) {
                listener->OnTopSessionChange(descriptor);
            }
        }
    }
}

// LCOV_EXCL_START
void AVSessionService::NotifyAudioSessionCheck(const int32_t uid)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    std::map<pid_t, sptr<ISessionListener>> listenerMap = GetUsersManager().GetSessionListener();
    for (const auto& [pid, listener] : listenerMap) {
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnAudioSessionCheck");
        if (listener != nullptr) {
            listener->OnAudioSessionChecked(uid);
        }
    }
    std::map<pid_t, sptr<ISessionListener>> listenerMapForAll = GetUsersManager().GetSessionListenerForAllUsers();
    for (const auto& [pid, listener] : listenerMapForAll) {
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnAudioSessionCheck");
        if (listener != nullptr) {
            listener->OnAudioSessionChecked(uid);
        }
    }
    {
        std::lock_guard lockGuard(migrateListenersLock_);
        for (const auto& listener : innerSessionListeners_) {
            if (listener != nullptr) {
                listener->OnAudioSessionChecked(uid);
            }
        }
    }
}
// LCOV_EXCL_STOP

bool AVSessionService::CheckAncoAudio()
{
    for (const auto& session : GetContainer().GetAllSessions()) {
        if (session->GetBundleName() == "anco_audio") {
            return true;
        }
    }
    return false;
}

// LCOV_EXCL_START
void AVSessionService::HandleCallStartEvent()
{
    SLOGI("Call mediaController player in sink side when cast state is connected.");
    AbilityConnectHelper::GetInstance().StartAbilityForegroundByCall(MEDIA_CONTROL_BUNDLENAME,
        MEDIA_CONTROL_ABILITYNAME);
}
// LCOV_EXCL_STOP

void AVSessionService::ServiceCallback(sptr<AVSessionItem>& sessionItem)
{
    if (sessionItem == nullptr) {
        SLOGE("sessionItem is null when serviceCallback");
        return;
    }
    sessionItem->SetServiceCallbackForRelease([this](AVSessionItem& session) {
        HandleSessionRelease(session.GetDescriptor().sessionId_);
    });
    sessionItem->SetServiceCallbackForAVQueueInfo([this](AVSessionItem& session) {
        AddAvQueueInfoToFile(session);
    });
    sessionItem->SetServiceCallbackForCallStart([this](AVSessionItem& session) {
        HandleCallStartEvent();
    });
    sessionItem->SetServiceCallbackForUpdateSession([this](std::string sessionId, bool isAdd) {
        std::lock_guard lockGuard(sessionServiceLock_);
        sptr<AVSessionItem> session = GetContainer().GetSessionById(sessionId);
        CHECK_AND_RETURN_LOG(session != nullptr, "session not exist for UpdateFrontSession");
        UpdateFrontSession(session, isAdd);
    });
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    sessionItem->SetServiceCallbackForStream([this](std::string sessionId) {
        sptr<AVSessionItem> session = GetContainer().GetSessionById(sessionId);
        uidForAppStateChange_ = session->GetUid();
        if (isSupportMirrorToStream_ &&
            !AppManagerAdapter::GetInstance().IsAppBackground(session->GetUid(), session->GetPid())) {
            MirrorToStreamCast(session);
        }
    });
#endif // CASTPLUS_CAST_ENGINE_ENABLE
}

sptr<AVSessionItem> AVSessionService::CreateNewSession(const std::string& tag, int32_t type, bool thirdPartyApp,
                                                       const AppExecFwk::ElementName& elementName)
{
    SLOGI("%{public}s %{public}d %{public}s %{public}s thirdPartyApp=%{public}d", tag.c_str(), type,
          elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str(), thirdPartyApp);
    AVSessionDescriptor descriptor;
    descriptor.sessionId_ = AllocSessionId();
    if (descriptor.sessionId_.empty()) {
        SLOGE("alloc session id failed");
        return nullptr;
    }
    descriptor.sessionTag_ = tag;
    descriptor.sessionType_ = type;
    descriptor.elementName_ = elementName;
    descriptor.isThirdPartyApp_ = thirdPartyApp;

    sptr<AVSessionItem> result = new(std::nothrow) AVSessionItem(descriptor, GetUsersManager().GetCurrentUserId());
    if (result == nullptr) {
        return nullptr;
    }
    result->SetPid(GetCallingPid());
    result->SetUid(GetCallingUid());
    ServiceCallback(result);

    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = AVCastCategory::CATEGORY_LOCAL;
    deviceInfo.deviceId_ = "0";
    deviceInfo.deviceName_ = "LocalDevice";
    outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
    result->SetOutputDevice(outputDeviceInfo);

    return result;
}

bool AVSessionService::IsParamInvalid(const std::string& tag, int32_t type, const AppExecFwk::ElementName& elementName)
{
    if (tag.empty()) {
        SLOGE("tag is empty when create session");
        return false;
    }
    if (type != AVSession::SESSION_TYPE_AUDIO && type != AVSession::SESSION_TYPE_VIDEO
        && type != AVSession::SESSION_TYPE_VOICE_CALL && type != AVSession::SESSION_TYPE_VIDEO_CALL) {
        SLOGE("type is invalid when create session");
        return false;
    }
    if (elementName.GetBundleName().empty() || elementName.GetAbilityName().empty()) {
        SLOGE("element is invalid when create session");
        return false;
    }
    std::regex nameRegex("[A-Za-z\\w\\.]*");
    if (!std::regex_match(elementName.GetBundleName(), nameRegex)) {
        SLOGE("err regex when create session, bundleName=%{public}s", (elementName.GetBundleName()).c_str());
        return false;
    }
    if (!std::regex_match(elementName.GetAbilityName(), nameRegex)) {
        SLOGE("err regex when create session, abilityName=%{public}s", (elementName.GetAbilityName()).c_str());
        return false;
    }

    return true;
}

int32_t AVSessionService::CreateSessionInner(const std::string& tag, int32_t type, bool thirdPartyApp,
                                             const AppExecFwk::ElementName& elementName,
                                             sptr<AVSessionItem>& sessionItem)
{
    if (!IsParamInvalid(tag, type, elementName)) {
        return ERR_INVALID_PARAM;
    }
    auto pid = GetCallingPid();
    std::lock_guard lockGuard(sessionServiceLock_);
    if (AbilityHasSession(pid)) {
        SLOGE("process %{public}d %{public}s already has one session", pid, elementName.GetAbilityName().c_str());
        return ERR_SESSION_IS_EXIST;
    }

    sptr<AVSessionItem> result = CreateNewSession(tag, type, thirdPartyApp, elementName);
    if (result == nullptr) {
        SLOGE("create new session failed");
        if (dumpHelper_ != nullptr) {
            dumpHelper_->SetErrorInfo("  AVSessionService::CreateSessionInner  create new session failed");
        }
        HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "CALLER_PID", pid, "TAG", tag, "TYPE", type, "BUNDLE_NAME",
            elementName.GetBundleName(), "ERROR_MSG", "avsessionservice createsessioninner create new session failed");
        return ERR_NO_MEMORY;
    }
    if (GetUsersManager().AddSessionForCurrentUser(pid, elementName.GetAbilityName(), result) != AVSESSION_SUCCESS) {
        SLOGE("session num exceed max");
        return ERR_SESSION_EXCEED_MAX;
    }

    HISYSEVENT_ADD_LIFE_CYCLE_INFO(elementName.GetBundleName(),
        AppManagerAdapter::GetInstance().IsAppBackground(GetCallingUid(), GetCallingPid()), type, true);

    NotifySessionCreate(result->GetDescriptor());
    sessionItem = result;
    
    std::lock_guard frontLockGuard(sessionFrontLock_);
    std::shared_ptr<std::list<sptr<AVSessionItem>>> sessionListForFront = GetCurSessionListForFront();
    CHECK_AND_RETURN_RET_LOG(sessionListForFront != nullptr, AVSESSION_ERROR, "sessionListForFront ptr nullptr!");
    auto it = std::find(sessionListForFront->begin(), sessionListForFront->end(), sessionItem);
    if ((type == AVSession::SESSION_TYPE_VOICE_CALL || type == AVSession::SESSION_TYPE_VIDEO_CALL ||
        (tag == "anco_audio" && GetCallingUid() == ancoUid)) && it == sessionListForFront->end()) {
        SLOGI(" front session add voice_call session=%{public}s", sessionItem->GetBundleName().c_str());
        sessionListForFront->push_front(sessionItem);
    }
    return AVSESSION_SUCCESS;
}

sptr<AVSessionItem> AVSessionService::CreateSessionInner(const std::string& tag, int32_t type, bool thirdPartyApp,
                                                         const AppExecFwk::ElementName& elementName)
{
    sptr<AVSessionItem> sessionItem;
    auto res = CreateSessionInner(tag, type, thirdPartyApp, elementName, sessionItem);
    CHECK_AND_RETURN_RET_LOG(res == AVSESSION_SUCCESS, nullptr, "create avSessionItem failed");
    return sessionItem;
}

void AVSessionService::ReportSessionInfo(const sptr <AVSessionItem>& session, int32_t res)
{
    std::string sessionId = "";
    std::string sessionTag = "";
    std::string SessionType = "";
    std::string bundleName = "";
    std::string API_PARAM_STRING = "";
    if (session != nullptr) {
        sessionId = AVSessionUtils::GetAnonySessionId(session->GetDescriptor().sessionId_);
        sessionTag = session->GetDescriptor().sessionTag_;
        SessionType = session->GetSessionType();
        bundleName = session->GetDescriptor().elementName_.GetBundleName();
        API_PARAM_STRING = "abilityName: " +
            session->GetDescriptor().elementName_.GetAbilityName() + ","
            + "moduleName: " + session->GetDescriptor().elementName_.GetModuleName();
    }
    std::string errMsg = (res == AVSESSION_SUCCESS) ? "SUCCESS" : "create session failed";
    HISYSEVENT_BEHAVIOR("SESSION_API_BEHAVIOR",
        "API_NAME", "CreateSession",
        "BUNDLE_NAME", bundleName,
        "SESSION_ID",  sessionId,
        "SESSION_TAG", sessionTag,
        "SESSION_TYPE", SessionType,
        "ERROR_CODE", res,
        "ERROR_MSG", errMsg);
}

int32_t AVSessionService::CreateSessionInner(const std::string& tag, int32_t type,
                                             const AppExecFwk::ElementName& elementName,
                                             sptr<IRemoteObject>& object)
{
    sptr<AVSessionItem> session;
    auto res = CreateSessionInner(tag, type,
        PermissionChecker::GetInstance().CheckPermission(PermissionChecker::CHECK_SYSTEM_PERMISSION),
        elementName, session);
    CHECK_AND_RETURN_RET_LOG(res == AVSESSION_SUCCESS, res, "create session fail");

    std::string supportModule;
    std::string profile;
    if (BundleStatusAdapter::GetInstance().IsSupportPlayIntent(elementName.GetBundleName(), supportModule, profile)) {
        SLOGI("bundleName=%{public}s support play intent, refreshSortFile", elementName.GetBundleName().c_str());
        SaveSessionInfoInFile(session->GetSessionId(), session->GetSessionType(), elementName);
    }

    {
        std::lock_guard lockGuard1(abilityManagerLock_);
        std::string bundleName = session->GetDescriptor().elementName_.GetBundleName();
        std::string abilityName = session->GetDescriptor().elementName_.GetAbilityName();
        auto it = abilityManager_.find(bundleName + abilityName);
        if (it != abilityManager_.end() && it->second != nullptr) {
            it->second->StartAbilityByCallDone(session->GetDescriptor().sessionId_);
        }
    }

    object = session;
    ReportSessionInfo(session, static_cast<int32_t>(res));

    {
        std::lock_guard lockGuard(isAllSessionCastLock_);
        CHECK_AND_RETURN_RET_LOG(isAllSessionCast_, AVSESSION_SUCCESS, "no need to cast");
    }
    CHECK_AND_RETURN_RET_LOG(CastAudioForNewSession(session) == AVSESSION_SUCCESS,
                             AVSESSION_SUCCESS, "cast new session error");
    return res;
}

sptr <IRemoteObject> AVSessionService::CreateSessionInner(const std::string& tag, int32_t type,
                                                          const AppExecFwk::ElementName& elementName)
{
    sptr<IRemoteObject> object;
    auto res = CreateSessionInner(tag, type, elementName, object);
    CHECK_AND_RETURN_RET_LOG(res == AVSESSION_SUCCESS, nullptr, "create session fail");
    return object;
}

// LCOV_EXCL_START
void AVSessionService::SaveSessionInfoInFile(const std::string& sessionId, const std::string& sessionType,
                                             const AppExecFwk::ElementName& elementName)
{
    std::lock_guard sortFileLockGuard(sessionFileLock_);
    SLOGI("refresh sort when session created, bundleName=%{public}s", (elementName.GetBundleName()).c_str());
    std::string oldSortContent;
    if (LoadStringFromFileEx(GetAVSortDir(), oldSortContent)) {
        nlohmann::json values = json::parse(oldSortContent, nullptr, false);
        CHECK_AND_RETURN_LOG(!values.is_discarded(), "sort json object is null");
        if (!values.is_array()) {
            SLOGI("create new json array for SaveSessionInfoInFile");
            values = json::array();
        }
        if (oldSortContent.find(elementName.GetBundleName()) == string::npos) {
            auto callback = [this](std::string bundleName, int32_t userId) {
                SLOGI("recv delete bundle:%{public}s at user:%{public}d", bundleName.c_str(), userId);
                DeleteAVQueueInfoRecord(bundleName, userId);
                DeleteHistoricalRecord(bundleName, userId);
            };
            if (!BundleStatusAdapter::GetInstance().SubscribeBundleStatusEvent(elementName.GetBundleName(),
                callback, GetUsersManager().GetCurrentUserId())) {
                SLOGE("SubscribeBundleStatusEvent failed");
            }
        }
        for (auto value : values) {
            if (elementName.GetBundleName() == value["bundleName"] &&
                elementName.GetAbilityName() == value["abilityName"]) {
                values.erase(std::remove(values.begin(), values.end(), value));
            }
        }
        nlohmann::json value;
        value["sessionId"] = sessionId;
        value["bundleName"] = elementName.GetBundleName();
        value["abilityName"] = elementName.GetAbilityName();
        value["sessionType"] = sessionType;
        if (values.size() <= 0) {
            values.push_back(value);
        } else {
            values.insert(values.begin(), value);
        }
        std::string newSortContent = values.dump();
        SLOGD("SaveSessionInfoInFile::Dump json object finished");
        if (!SaveStringToFileEx(GetAVSortDir(), newSortContent)) {
            SLOGE("SaveStringToFile failed, filename=%{public}s", SORT_FILE_NAME);
        }
    } else {
        SLOGE("LoadStringToFile failed, filename=%{public}s", SORT_FILE_NAME);
    }
}
// LCOV_EXCL_STOP

int32_t AVSessionService::GetAllSessionDescriptors(std::vector<AVSessionDescriptor>& descriptors)
{
    std::lock_guard frontLockGuard(sessionFrontLock_);
    std::shared_ptr<std::list<sptr<AVSessionItem>>> sessionListForFront = GetCurSessionListForFront();
    CHECK_AND_RETURN_RET_LOG(sessionListForFront != nullptr, AVSESSION_ERROR, "sessionListForFront ptr nullptr!");
    for (const auto& session : *sessionListForFront) {
        if (session != nullptr) {
            descriptors.push_back(session->GetDescriptor());
        }
    }
    SLOGI("GetAllSessionDescriptors with size=%{public}d, topSession:%{public}s",
        static_cast<int32_t>(descriptors.size()),
        (topSession_ == nullptr ? "null" : topSession_->GetBundleName()).c_str());
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::GetSessionDescriptorsBySessionId(const std::string& sessionId,
                                                           AVSessionDescriptor& descriptor)
{
    std::lock_guard lockGuard(sessionServiceLock_);
    sptr<AVSessionItem> session = GetContainer().GetSessionById(sessionId);
    CHECK_AND_RETURN_RET_LOG(session != nullptr, AVSESSION_ERROR, "session to be got is not existed");

    auto pid = GetCallingPid();
    if (pid == session->GetPid()) {
        descriptor = session->GetDescriptor();
        return AVSESSION_SUCCESS;
    }
    int32_t err = PermissionChecker::GetInstance().CheckPermission(PermissionChecker::CHECK_SYSTEM_PERMISSION);
    if (err != ERR_NONE) {
        SLOGE("GetSessionDescriptorsBySessionId: CheckPermission failed!");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(),
            "CALLER_PID", GetCallingUid(), "SESSION_ID", sessionId,
            "ERROR_MSG", "avsessionservice getsessiondescriptors by sessionid checkpermission failed");
        return err;
    }
    descriptor = session->GetDescriptor();
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::GetHistoricalSessionDescriptorsFromFile(std::vector<AVSessionDescriptor>& descriptors)
{
    std::string oldSortContent;
    if (!LoadStringFromFileEx(GetAVSortDir(), oldSortContent)) {
        SLOGE("GetHistoricalSessionDescriptorsFromFile read sort fail, Return!");
        return AVSESSION_ERROR;
    }

    nlohmann::json sortValues = json::parse(oldSortContent, nullptr, false);
    CHECK_AND_RETURN_RET_LOG(!sortValues.is_discarded(), AVSESSION_ERROR, "json object is null");
    for (const auto& value : sortValues) {
        if (value["sessionType"] == "video") {
            SLOGI("GetHistoricalSessionDescriptorsFromFile with no video type session.");
            continue;
        }
        AVSessionDescriptor descriptor;
        descriptor.sessionId_ = value["sessionId"];
        descriptor.elementName_.SetBundleName(value["bundleName"]);
        descriptor.elementName_.SetAbilityName(value["abilityName"]);
        descriptor.sessionType_ = AVSession::SESSION_TYPE_AUDIO;
        descriptors.push_back(descriptor);
    }
    if (descriptors.size() == 0 && GetContainer().GetAllSessions().size() == 0) {
        SLOGE("GetHistoricalSessionDescriptorsFromFile read empty, return!");
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::GetHistoricalSessionDescriptors(int32_t maxSize,
                                                          std::vector<AVSessionDescriptor>& descriptors)
{
    std::lock_guard sortFileLockGuard(sessionFileLock_);
    std::vector<AVSessionDescriptor> tempDescriptors;
    GetHistoricalSessionDescriptorsFromFile(tempDescriptors);
    if (maxSize < 0 || maxSize > maxHistoryNums_) {
        maxSize = unSetHistoryNum;
    }
    for (auto iterator = tempDescriptors.begin(); iterator != tempDescriptors.end(); ++iterator) {
        if (descriptors.size() >= (size_t)maxSize) {
            break;
        }
        descriptors.push_back(*iterator);
    }

    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
int32_t AVSessionService::GetHistoricalAVQueueInfos(int32_t maxSize, int32_t maxAppSize,
                                                    std::vector<AVQueueInfo>& avQueueInfos)
{
    std::lock_guard avQueueFileLockGuard(avQueueFileLock_);
    std::string oldAVQueueInfoContent;
    std::vector<AVQueueInfo> tempAVQueueInfos;
    if (!LoadStringFromFileEx(GetAVQueueDir(), oldAVQueueInfoContent)) {
        SLOGE("GetHistoricalAVQueueInfos read avqueueinfo fail, Return!");
        return AVSESSION_ERROR;
    }

    nlohmann::json avQueueValues = json::parse(oldAVQueueInfoContent, nullptr, false);
    CHECK_AND_RETURN_RET_LOG(!avQueueValues.is_discarded(), AVSESSION_ERROR, "json object is null");
    for (const auto& value : avQueueValues) {
        AVQueueInfo avQueueInfo;
        avQueueInfo.SetBundleName(value["bundleName"]);
        avQueueInfo.SetAVQueueName(value["avQueueName"]);
        avQueueInfo.SetAVQueueId(value["avQueueId"]);
        std::shared_ptr<AVSessionPixelMap> avQueuePixelMap = std::make_shared<AVSessionPixelMap>();
        CHECK_AND_RETURN_RET_LOG(value.contains("avQueueImageDir"), AVSESSION_ERROR, "avQueueImageDir not contain");
        CHECK_AND_RETURN_RET_LOG(value.contains("avQueueImageName"), AVSESSION_ERROR, "avQueueImageName not contain");
        AVSessionUtils::ReadImageFromFile(avQueuePixelMap, value["avQueueImageDir"], value["avQueueImageName"]);
        avQueueInfo.SetAVQueueImage(avQueuePixelMap);
        avQueueInfo.SetAVQueueImageUri(value["avQueueImageUri"]);
        tempAVQueueInfos.push_back(avQueueInfo);
    }
    for (auto iterator = tempAVQueueInfos.begin(); iterator != tempAVQueueInfos.end(); ++iterator) {
        avQueueInfos.push_back(*iterator);
    }

    return AVSESSION_SUCCESS;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
bool AVSessionService::SaveAvQueueInfo(std::string& oldContent, const std::string &bundleName,
    const AVMetaData& meta, const int32_t userId)
{
    nlohmann::json values = json::parse(oldContent, nullptr, false);
    CHECK_AND_RETURN_RET_LOG(!values.is_discarded(), false, "avQueue json object is null");
    auto it = values.begin();
    for (auto& value : values) {
        if (bundleName == value["bundleName"] && meta.GetAVQueueId() == value["avQueueId"]) {
            if (meta.GetAVQueueId() == it->at("avQueueId")) {
                return false;
            }
            values.erase(std::remove(values.begin(), values.end(), value));
        }
    }
    if (values.size() >= (size_t)maxAVQueueInfoLen) {
        values.erase(values.end() - 1);
    }

    nlohmann::json value;
    value["bundleName"] = bundleName;
    value["avQueueName"] = meta.GetAVQueueName();
    value["avQueueId"] = meta.GetAVQueueId();
    std::shared_ptr<AVSessionPixelMap> innerPixelMap = meta.GetAVQueueImage();
    if (innerPixelMap != nullptr) {
        std::string fileDir = AVSessionUtils::GetFixedPathName(userId);
        std::string fileName = bundleName + "_" + meta.GetAVQueueId() + AVSessionUtils::GetFileSuffix();
        AVSessionUtils::WriteImageToFile(innerPixelMap, fileDir, fileName);
        innerPixelMap->Clear();
        value["avQueueImageDir"] = fileDir;
        value["avQueueImageName"] = fileName;
    } else {
        value["avQueueImageDir"] = "";
        value["avQueueImageName"] = "";
    }
    value["avQueueImageUri"] = meta.GetAVQueueImageUri();
    if (values.size() <= 0) {
        values.push_back(value);
    } else {
        values.insert(values.begin(), value);
    }
    std::string newContent = values.dump();
    if (!SaveStringToFileEx(GetAVQueueDir(userId), newContent)) {
        SLOGE("SaveStringToFile failed, filename=%{public}s", AVQUEUE_FILE_NAME);
        return false;
    }
    return true;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
void AVSessionService::AddAvQueueInfoToFile(AVSessionItem& session)
{
    // check is this session support playmusiclist intent
    std::lock_guard lockGuard(sessionServiceLock_);
    std::string bundleName = session.GetBundleName();
    std::string supportModule;
    std::string profile;
    if (!BundleStatusAdapter::GetInstance().IsSupportPlayIntent(bundleName, supportModule, profile)) {
        SLOGE("bundleName=%{public}s does not support play intent", bundleName.c_str());
        return;
    }
    AVMetaData meta = session.GetMetaData();
    if (meta.GetAVQueueId().empty() || meta.GetAVQueueName().empty()) {
        SLOGI("AddAvQueueInfoToFile avqueueinfo empty, return");
        DoMetadataImgClean(meta);
        return;
    }
    std::lock_guard avQueueFileLockGuard(avQueueFileLock_);
    std::string oldContent;
    int32_t userId = session.GetUserId();
    SLOGI("AddAvQueueInfoToFile for bundleName:%{public}s,userId:%{public}d", bundleName.c_str(), userId);
    if (!LoadStringFromFileEx(GetAVQueueDir(userId), oldContent)) {
        SLOGE("AddAvQueueInfoToFile read avqueueinfo fail, Return!");
        DoMetadataImgClean(meta);
        return;
    }
    if (!SaveAvQueueInfo(oldContent, bundleName, meta, userId)) {
        SLOGE("SaveAvQueueInfo same avqueueinfo, Return!");
        DoMetadataImgClean(meta);
        return;
    }
    DoMetadataImgClean(meta);
}
// LCOV_EXCL_STOP

void AVSessionService::DoMetadataImgClean(AVMetaData& data)
{
    SLOGI("clear media img in DoMetadataImgClean");
    std::shared_ptr<AVSessionPixelMap> innerQueuePixelMap = data.GetAVQueueImage();
    if (innerQueuePixelMap != nullptr) {
        innerQueuePixelMap->Clear();
    }
    std::shared_ptr<AVSessionPixelMap> innerMediaPixelMap = data.GetMediaImage();
    if (innerMediaPixelMap != nullptr) {
        innerMediaPixelMap->Clear();
    }
}

int32_t AVSessionService::StartAVPlayback(const std::string& bundleName, const std::string& assetId)
{
    std::unique_ptr<AVSessionDynamicLoader> dynamicLoader = std::make_unique<AVSessionDynamicLoader>();
    if (dynamicLoader == nullptr) {
        SLOGI("dynamicLoader is null");
        return AVSESSION_ERROR;
    }

    typedef int32_t (*StartAVPlaybackFunc)(const std::string& bundleName, const std::string& assetId);
    StartAVPlaybackFunc startAVPlayback =
        reinterpret_cast<StartAVPlaybackFunc>(dynamicLoader->GetFuntion(
            AVSESSION_DYNAMIC_INSIGHT_LIBRARY_PATH, "StartAVPlayback"));
    if (startAVPlayback) {
        return (*startAVPlayback)(bundleName, assetId);
    }
    SLOGE("StartAVPlayback fail");
    return AVSESSION_ERROR;
}

bool AVSessionService::IsAudioPlaybackAllowed(const int32_t uid, const int32_t pid)
{
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_AND_RETURN_RET_LOG(mgr != nullptr, true, "SystemAbilityManager is null");
    auto object = mgr->CheckSystemAbility(APP_MGR_SERVICE_ID);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, true, "APP_MAGR_SERVICE is null");
    bool hasSession = GetContainer().UidHasSession(uid);
    bool isBack = AppManagerAdapter::GetInstance().IsAppBackground(uid, pid);
    bool isSystem = PermissionChecker::GetInstance().CheckSystemPermissionByUid(uid);
    SLOGI("uid=%{public}d pid=%{public}d hasSession=%{public}d isBack=%{public}d isSystem=%{public}d", uid,
        pid, hasSession, isBack, isSystem);
    return hasSession || isSystem || !isBack;
}

sptr<AVControllerItem> AVSessionService::CreateNewControllerForSession(pid_t pid, sptr<AVSessionItem>& session)
{
    SLOGI("pid=%{public}d sessionId=%{public}s", pid,
        AVSessionUtils::GetAnonySessionId(session->GetSessionId()).c_str());
    sptr<AVControllerItem> result = new(std::nothrow) AVControllerItem(pid, session, session->GetUserId());
    if (result == nullptr) {
        SLOGE("malloc controller failed");
        return nullptr;
    }
    result->SetServiceCallbackForRelease([this](AVControllerItem& controller) { HandleControllerRelease(controller); });
    session->AddController(pid, result);
    if (AbilityHasSession(pid)) {
        SLOGI("set isfromsession for pid %{public}d", static_cast<int>(pid));
        result->isFromSession_ = true;
    }
    return result;
}

// LCOV_EXCL_START
const nlohmann::json& AVSessionService::GetSubNode(const nlohmann::json& node, const std::string& name)
{
    static const nlohmann::json jsonNull = nlohmann::json::value_t::null;
    if (node.is_discarded() || node.is_null()) {
        SLOGE("json node is invalid");
        return jsonNull;
    }

    if (name.empty()) {
        SLOGE("name is invalid");
        return node;
    }

    auto it = node.find(name);
    if (it == node.end()) {
        SLOGE("%{public}s is not exist in json", name.c_str());
        return jsonNull;
    }
    return *it;
}
// LCOV_EXCL_STOP

bool AVSessionService::IsHistoricalSession(const std::string& sessionId)
{
    {
        std::string sortContent;
        std::lock_guard sortFileLockGuard(sessionFileLock_);
        if (!LoadStringFromFileEx(GetAVSortDir(), sortContent)) {
            SLOGE("IsHistoricalSession read sort failed, filename=%{public}s", SORT_FILE_NAME);
            return false;
        }
        if (sortContent.find(sessionId) == string::npos) {
            SLOGE("IsHistoricalSession find session no sort, sessionId=%{public}s",
                AVSessionUtils::GetAnonySessionId(sessionId).c_str());
            return false;
        }
    }

    auto session = GetContainer().GetSessionById(sessionId);
    if (session != nullptr) {
        SLOGE("IsHistoricalSession find session alive, sessionId=%{public}s",
            AVSessionUtils::GetAnonySessionId(sessionId).c_str());
        return false;
    }
    SLOGE("IsHistoricalSession find session historical, sessionId=%{public}s",
        AVSessionUtils::GetAnonySessionId(sessionId).c_str());
    return true;
}

int32_t AVSessionService::StartDefaultAbilityByCall(std::string& sessionId)
{
    std::string bundleName = DEFAULT_BUNDLE_NAME;
    std::string abilityName = DEFAULT_ABILITY_NAME;
    std::string sortContent;
    {
        std::lock_guard sortFileLockGuard(sessionFileLock_);
        if (!LoadStringFromFileEx(GetAVSortDir(), sortContent)) {
            SLOGE("GetAllSessionDescriptors read sort fail! ");
            return AVSESSION_ERROR;
        }
    }
    if (!sortContent.empty()) {
        nlohmann::json sortValues = json::parse(sortContent, nullptr, false);
        CHECK_AND_RETURN_RET_LOG(!sortValues.is_discarded(), AVSESSION_ERROR, "json object is null");
        for (auto& value : sortValues) {
            CHECK_AND_CONTINUE(!value.is_null() && !value.is_discarded() && value.contains("sessionId"));
            auto session = GetContainer().GetSessionById(value["sessionId"]);
            if (session == nullptr) {
                bundleName = value["bundleName"];
                abilityName = value["abilityName"];
                break;
            } else {
                SLOGE("Default start alive %{public}s", AVSessionUtils::GetAnonySessionId(value["sessionId"]).c_str());
                return AVSESSION_ERROR;
            }
        }
    }
    std::shared_ptr<AbilityManagerAdapter> ability = nullptr;
    {
        std::lock_guard lockGuard(abilityManagerLock_);
        auto it = abilityManager_.find(bundleName + abilityName);
        if (it != abilityManager_.end()) {
            ability = it->second;
        } else {
            ability = std::make_shared<AbilityManagerAdapter>(bundleName, abilityName);
            if (ability == nullptr) {
                return ERR_NO_MEMORY;
            }
            abilityManager_[bundleName + abilityName] = ability;
        }
    }
    if (ability == nullptr) {
        return AVSESSION_ERROR;
    }
    int32_t ret = ability->StartAbilityByCall(sessionId);
    if (ret != ERR_START_ABILITY_IS_RUNNING) {
        abilityManager_.erase(bundleName + abilityName);
    }
    return ret;
}

int32_t AVSessionService::StartAbilityByCall(const std::string& sessionIdNeeded, std::string& sessionId)
{
    std::string content;
    
    {
        std::lock_guard sortFileLockGuard(sessionFileLock_);
        if (!LoadStringFromFileEx(GetAVSortDir(), content)) {
            SLOGE("LoadStringFromFile failed, filename=%{public}s", SORT_FILE_NAME);
            return AVSESSION_ERROR;
        }
    }

    nlohmann::json values = json::parse(content, nullptr, false);
    CHECK_AND_RETURN_RET_LOG(!values.is_null() && !values.is_discarded(), AVSESSION_ERROR, "json object is null");
    std::string bundleName;
    std::string abilityName;
    for (auto& value : values) {
        CHECK_AND_CONTINUE(!value.is_null() && !value.is_discarded() && value.contains("sessionId"));
        if (sessionIdNeeded == value["sessionId"]) {
            bundleName = value["bundleName"];
            abilityName = value["abilityName"];
            break;
        }
    }
    if (bundleName.empty() || abilityName.empty()) {
        SLOGE("Get bundle name & ability name failed, sessionId=%{public}s",
            AVSessionUtils::GetAnonySessionId(sessionIdNeeded).c_str());
        return AVSESSION_ERROR;
    }

    std::shared_ptr<AbilityManagerAdapter> ability = nullptr;
    {
        std::lock_guard lockGuard(abilityManagerLock_);
        auto it = abilityManager_.find(bundleName + abilityName);
        if (it != abilityManager_.end()) {
            ability = it->second;
        } else {
            ability = std::make_shared<AbilityManagerAdapter>(bundleName, abilityName);
            if (ability == nullptr) {
                return ERR_NO_MEMORY;
            }
            abilityManager_[bundleName + abilityName] = ability;
        }
    }
    if (ability == nullptr) {
        return AVSESSION_ERROR;
    }
    int32_t ret = ability->StartAbilityByCall(sessionId);
    if (ret != ERR_START_ABILITY_IS_RUNNING) {
        abilityManager_.erase(bundleName + abilityName);
    }
    return ret;
}
    
int32_t AVSessionService::CreateControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object)
{
    SLOGI("CreateControllerInner for sessionId:%{public}s", AVSessionUtils::GetAnonySessionId(sessionId).c_str());
    sptr<AVSessionItem> session = GetContainer().GetSessionById(sessionId);
    if (session == nullptr) {
        SLOGE("no session id %{public}s", AVSessionUtils::GetAnonySessionId(sessionId).c_str());
        return ERR_SESSION_NOT_EXIST;
    }
    auto pid = GetCallingPid();
    auto existController = GetPresentController(pid, sessionId);
    if (existController != nullptr) {
        SLOGI("Controller is already existed.");
        object = existController;
        return ERR_CONTROLLER_IS_EXIST;
    }
    sptr<AVControllerItem> newController = CreateNewControllerForSession(pid, session);
    if (newController == nullptr) {
        SLOGE("Create new controller failed.");
        return ERR_NO_MEMORY;
    }

    std::lock_guard lockGuard(sessionServiceLock_);
    controllers_[pid].push_back(newController);
    object = newController;

    return AVSESSION_SUCCESS;
}

void AVSessionService::AddSessionListener(pid_t pid, const sptr<ISessionListener>& listener)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    GetUsersManager().AddSessionListener(pid, listener);
}

void AVSessionService::AddSessionListenerForAllUsers(pid_t pid, const sptr<ISessionListener>& listener)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    GetUsersManager().AddSessionListenerForAllUsers(pid, listener);
}

void AVSessionService::RemoveSessionListener(pid_t pid)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    GetUsersManager().RemoveSessionListener(pid);
}

int32_t AVSessionService::RegisterSessionListener(const sptr<ISessionListener>& listener)
{
    SLOGI("Enter RegisterSessionListener process and return current userId");
    AddSessionListener(GetCallingPid(), listener);
    return GetUsersManager().GetCurrentUserId();
}

int32_t AVSessionService::RegisterSessionListenerForAllUsers(const sptr<ISessionListener>& listener)
{
    SLOGI("Enter RegisterSessionListenerForAllUsers process");
    AddSessionListenerForAllUsers(GetCallingPid(), listener);
    return AVSESSION_SUCCESS;
}

// LCOV_EXCL_START
void AVSessionService::HandleEventHandlerCallBack()
{
    SLOGI("handle eventHandler callback isFirstPress_=%{public}d, pressCount_:%{public}d", isFirstPress_, pressCount_);
    AVControlCommand cmd;
    bool shouldColdPlay = false;
    {
        std::lock_guard lockGuard(sessionServiceLock_);
        if (pressCount_ >= THREE_CLICK) {
            cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY_PREVIOUS);
        } else if (pressCount_ == DOUBLE_CLICK) {
            cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY_NEXT);
        } else if (pressCount_ == ONE_CLICK) {
            if (topSession_) {
                auto playbackState = topSession_->GetPlaybackState();
                cmd.SetCommand(playbackState.GetState() == AVPlaybackState::PLAYBACK_STATE_PLAY ?
                    AVControlCommand::SESSION_CMD_PAUSE : AVControlCommand::SESSION_CMD_PLAY);
            } else {
                cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY);
            }
        } else {
            pressCount_ = 0;
            isFirstPress_ = true;
            SLOGI("press invalid return, topSession alive:%{public}d", static_cast<int>(topSession_ != nullptr));
            return;
        }
        SLOGI("HandleEventHandlerCallBack proc cmd=%{public}d", cmd.GetCommand());
        if (!topSession_) {
            shouldColdPlay = true;
            SLOGI("HandleEventHandlerCallBack without topSession_ shouldColdStart=%{public}d", shouldColdPlay);
        } else {
            if (topSession_->GetDescriptor().sessionTag_ == "external_audio") {
                SLOGI("HandleEventHandlerCallBack this is an external audio");
            } else {
                topSession_->ExecuteControllerCommand(cmd);
            }
        }
    }
    if (shouldColdPlay) {
        HandleSystemKeyColdStart(cmd);
    }
    pressCount_ = 0;
    isFirstPress_ = true;
}
// LCOV_EXCL_STOP

int32_t AVSessionService::SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent)
{
    SLOGI("SendSystemAVKeyEvent get key=%{public}d", keyEvent.GetKeyCode());
    if (keyEvent.GetKeyCode() == MMI::KeyEvent::KEYCODE_HEADSETHOOK) {
        pressCount_++;
        SLOGI("isFirstPress_=%{public}d", isFirstPress_);
        if (isFirstPress_) {
            auto ret = AVSessionEventHandler::GetInstance().AVSessionPostTask([this]() {
                HandleEventHandlerCallBack();
            }, "SendSystemAVKeyEvent", CLICK_TIMEOUT);
            CHECK_AND_RETURN_RET_LOG(ret, AVSESSION_ERROR, "init eventHandler failed");
            isFirstPress_ = false;
        }
        return AVSESSION_SUCCESS;
    }
    {
        std::lock_guard lockGuard(sessionServiceLock_);
        if (topSession_) {
            topSession_->HandleMediaKeyEvent(keyEvent);
            return AVSESSION_SUCCESS;
        }
    }
    {
        int cmd = ConvertKeyCodeToCommand(keyEvent.GetKeyCode());
        AVControlCommand controlCommand;
        controlCommand.SetCommand(cmd);
        SLOGI("topSession get nullptr, check if cold start for cmd %{public}d", cmd);
        HandleSystemKeyColdStart(controlCommand);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::ConvertKeyCodeToCommand(int keyCode)
{
    auto iter = keyCodeToCommandMap_.find(keyCode);
    if (iter != keyCodeToCommandMap_.end()) {
        return iter->second;
    } else {
        return AVControlCommand::SESSION_CMD_PLAY;
    }
}

void AVSessionService::HandleSystemKeyColdStart(const AVControlCommand &command)
{
    SLOGI("HandleSystemKeyColdStart cmd=%{public}d without topsession", command.GetCommand());
    // try proc command for first front session
    {
        std::lock_guard frontLockGuard(sessionFrontLock_);
        std::shared_ptr<std::list<sptr<AVSessionItem>>> sessionListForFront = GetCurSessionListForFront();
        CHECK_AND_RETURN_LOG(sessionListForFront != nullptr, "sessionListForFront ptr nullptr!");
        for (const auto& session : *sessionListForFront) {
            if (session->GetSessionType() != "voice_call" && session->GetSessionType() != "video_call") {
                session->ExecuteControllerCommand(command);
                SLOGI("ExecuteCommand %{public}d for front session: %{public}s", command.GetCommand(),
                      session->GetBundleName().c_str());
                return;
            }
        }
    }

    std::vector<AVSessionDescriptor> hisDescriptors;
    GetHistoricalSessionDescriptorsFromFile(hisDescriptors);
    // try start play for first history session
    if (command.GetCommand() == AVControlCommand::SESSION_CMD_PLAY && hisDescriptors.size() != 0) {
        sptr<IRemoteObject> object;
        int32_t ret = StartAVPlayback(hisDescriptors[0].elementName_.GetBundleName(), "");
        SLOGI("Cold play %{public}s, ret=%{public}d", hisDescriptors[0].elementName_.GetBundleName().c_str(), ret);
    } else {
        SLOGI("Cold start command=%{public}d, hisDescriptorsSize=%{public}d return", command.GetCommand(),
              static_cast<int>(hisDescriptors.size()));
    }
}

int32_t AVSessionService::SendSystemControlCommand(const AVControlCommand &command)
{
    {
        std::lock_guard lockGuard(sessionServiceLock_);
        SLOGI("SendSystemControlCommand with cmd:%{public}d, topSession alive:%{public}d",
              command.GetCommand(), static_cast<int>(topSession_ != nullptr));
        if (topSession_) {
            CHECK_AND_RETURN_RET_LOG(CommandSendLimit::GetInstance().IsCommandSendEnable(GetCallingPid()),
                ERR_COMMAND_SEND_EXCEED_MAX, "command excuted number exceed max");
            topSession_->ExecuteControllerCommand(command);
            return AVSESSION_SUCCESS;
        }
    }
    HandleSystemKeyColdStart(command);
    return AVSESSION_SUCCESS;
}

void AVSessionService::AddClientDeathObserver(pid_t pid, const sptr<IClientDeath>& observer,
    const sptr<ClientDeathRecipient> recipient)
{
    std::lock_guard lockGuard(clientDeathLock_);
    clientDeathObservers_[pid] = observer;
    clientDeathRecipients_[pid] = recipient;
}

void AVSessionService::RemoveClientDeathObserver(pid_t pid)
{
    std::lock_guard lockGuard(clientDeathLock_);
    if (clientDeathObservers_.empty()) {
        SLOGE("try remove observer with empty list");
    } else {
        clientDeathObservers_.erase(pid);
    }

    if (clientDeathRecipients_.empty()) {
        SLOGE("try remove recipient with empty list");
    } else {
        clientDeathRecipients_.erase(pid);
    }
}

int32_t AVSessionService::RegisterClientDeathObserver(const sptr<IClientDeath>& observer)
{
    SLOGI("enter ClientDeathObserver register with recipient point");
    auto pid = GetCallingPid();
    sptr<ClientDeathRecipient> recipient =
        new(std::nothrow) ClientDeathRecipient([this, pid]() { OnClientDied(pid); });
    if (recipient == nullptr) {
        SLOGE("New ClientDeathRecipient failed.");
        HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "ERROR_TYPE", "RGS_CLIENT_DEATH_OBSERVER_FAILED",
            "ERROR_INFO", "avsession service register client death observer malloc failed");
        return AVSESSION_ERROR;
    }

    if (!observer->AsObject()->AddDeathRecipient(recipient)) {
        SLOGE("add death recipient failed for %{public}d failed", pid);
        HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "ERROR_TYPE", "RGS_CLIENT_DEATH_FAILED", "CALLING_PID", pid,
            "ERROR_INFO", "avsession service register client death observer, add death recipient failed");
        return AVSESSION_ERROR;
    }

    AddClientDeathObserver(pid, observer, recipient);
    return AVSESSION_SUCCESS;
}

void AVSessionService::ClearClientResources(pid_t pid)
{
    RemoveSessionListener(pid);
    {
        std::lock_guard lockGuard(sessionServiceLock_);
        ClearSessionForClientDiedNoLock(pid);
        ClearControllerForClientDiedNoLock(pid);
    }
    RemoveClientDeathObserver(pid);
}

int32_t AVSessionService::Close(void)
{
    auto pid = GetCallingPid();
    ClearClientResources(pid);
    return AVSESSION_SUCCESS;
}

void AVSessionService::OnClientDied(pid_t pid)
{
    ClearClientResources(pid);
}

// LCOV_EXCL_START
void AVSessionService::DeleteHistoricalRecord(const std::string& bundleName, int32_t userId)
{
    std::lock_guard sortFileLockGuard(sessionFileLock_);
    if (userId <= 0) {
        userId = GetUsersManager().GetCurrentUserId();
    }
    if (!CheckUserDirValid(userId)) {
        SLOGE("DeleteHistoricalRecord target user:%{public}d not valid, return", userId);
        return;
    }
    SLOGI("delete historical record, bundleName=%{public}s, userId=%{public}d", bundleName.c_str(), userId);
    std::string oldContent;
    std::string newContent;
    nlohmann::json values;
    if (!LoadStringFromFileEx(GetAVSortDir(userId), oldContent)) {
        SLOGE("LoadStringFromFile failed, filename=%{public}s", SORT_FILE_NAME);
        return;
    }
    values = json::parse(oldContent, nullptr, false);
    CHECK_AND_RETURN_LOG(!values.is_discarded(), "json object is null");
    for (auto value : values) {
        if (bundleName == value["bundleName"]) {
            values.erase(std::remove(values.begin(), values.end(), value));
            break;
        }
    }
    newContent = values.dump();
    SLOGD("DeleteHistoricalRecord::Dump json object finished");
    if (!SaveStringToFileEx(GetAVSortDir(userId), newContent)) {
        SLOGE("SaveStringToFile failed, filename=%{public}s", SORT_FILE_NAME);
        return;
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
void AVSessionService::DeleteAVQueueInfoRecord(const std::string& bundleName, int32_t userId)
{
    std::lock_guard avQueueFileLockGuard(avQueueFileLock_);
    if (userId <= 0) {
        userId = GetUsersManager().GetCurrentUserId();
    }
    if (!CheckUserDirValid(userId)) {
        SLOGE("DeleteAVQueueInfoRecord target user:%{public}d not valid, return", userId);
        return;
    }
    SLOGI("DeleteAVQueueInfoRecord, bundleName=%{public}s, userId=%{public}d", bundleName.c_str(), userId);
    std::string oldContent;
    std::string newContent;
    nlohmann::json values;
    if (!LoadStringFromFileEx(GetAVQueueDir(userId), oldContent)) {
        SLOGE("LoadStringFromFile failed, filename=%{public}s", AVQUEUE_FILE_NAME);
        return;
    }
    values = json::parse(oldContent, nullptr, false);
    CHECK_AND_RETURN_LOG(!values.is_discarded(), "json object is null");
    for (auto it = values.begin(); it != values.end();) {
        if (it->at("bundleName") == bundleName) {
            std::string avQueueId = it->at("avQueueId");
            std::string fileName = AVSessionUtils::GetFixedPathName(userId) + bundleName + "_" +
                avQueueId + AVSessionUtils::GetFileSuffix();
            AVSessionUtils::DeleteFile(fileName);
            values.erase(it);
        } else {
            ++it;
        }
    }
    newContent = values.dump();
    SLOGD("DeleteAVQueueInfoRecord::Dump json object finished");
    if (!SaveStringToFileEx(GetAVQueueDir(userId), newContent)) {
        SLOGE("SaveStringToFile failed, filename=%{public}s", AVQUEUE_FILE_NAME);
        return;
    }
}
// LCOV_EXCL_STOP

void AVSessionService::HandleSessionRelease(std::string sessionId)
{
    SLOGI("HandleSessionRelease, sessionId=%{public}s", AVSessionUtils::GetAnonySessionId(sessionId).c_str());
    {
        std::lock_guard lockGuard(sessionServiceLock_);
        std::lock_guard frontLockGuard(sessionFrontLock_);
        sptr<AVSessionItem> sessionItem = GetUsersManager().GetContainerFromAll().GetSessionById(sessionId);
        CHECK_AND_RETURN_LOG(sessionItem != nullptr, "Session item is nullptr");
        NotifySessionRelease(sessionItem->GetDescriptor());
        sessionItem->DestroyTask();
        if (topSession_.GetRefPtr() == sessionItem.GetRefPtr()) {
            UpdateTopSession(nullptr);
            int32_t ret = Notification::NotificationHelper::CancelNotification(0);
            SLOGI("topsession release cancelNotification ret=%{public}d", ret);
        }
        if (sessionItem->GetRemoteSource() != nullptr) {
            int32_t ret = CancelCastAudioForClientExit(sessionItem->GetPid(), sessionItem);
            SLOGI("CancelCastAudioForClientExit ret is %{public}d", ret);
        }
        HISYSEVENT_ADD_LIFE_CYCLE_INFO(sessionItem->GetDescriptor().elementName_.GetBundleName(),
            AppManagerAdapter::GetInstance().IsAppBackground(GetCallingUid(), GetCallingPid()),
            sessionItem->GetDescriptor().sessionType_, false);
        GetUsersManager().RemoveSessionForAllUser(sessionItem->GetPid(), sessionItem->GetAbilityName());
        UpdateFrontSession(sessionItem, false);
    }
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    if ((GetUsersManager().GetContainerFromAll().GetAllSessions().size() == 0 ||
        (GetUsersManager().GetContainerFromAll().GetAllSessions().size() == 1 &&
        CheckAncoAudio())) && !is2in1_) {
        SLOGI("call disable cast for no session alive, after session release task");
        checkEnableCast(false);
    }
#endif
}

void AVSessionService::HandleControllerRelease(AVControllerItem& controller)
{
    auto pid = controller.GetPid();
    std::lock_guard lockGuard(sessionServiceLock_);
    auto it = controllers_.find(pid);
    if (it == controllers_.end()) {
        return;
    }
    it->second.remove(&controller);
    if (it->second.empty()) {
        controllers_.erase(pid);
    }
}

std::int32_t AVSessionService::Dump(std::int32_t fd, const std::vector<std::u16string>& args)
{
    if (fd < 0) {
        SLOGE("dump fd invalid");
        return ERR_INVALID_PARAM;
    }

    if (dumpHelper_ == nullptr) {
        SLOGE("dumpHelper_ is nullptr!");
        return ERR_INVALID_PARAM;
    }

    std::vector<std::string> argsInStr;
    for (const auto& arg : args) {
        SLOGI("Dump args: %s", Str16ToStr8(arg).c_str());
        argsInStr.emplace_back(Str16ToStr8(arg));
    }

    std::string result;
    dumpHelper_->Dump(argsInStr, result, *this);
    std::int32_t ret = dprintf(fd, "%s", result.c_str());
    if (ret < 0) {
        SLOGI("dprintf to dump fd failed");
        return ERR_INVALID_PARAM;
    }
    return AVSESSION_SUCCESS;
}

__attribute__((no_sanitize("cfi"))) std::shared_ptr<RemoteSessionCommandProcess> AVSessionService::GetService(
    const std::string& deviceId)
{
    SLOGI("Enter GetService.");
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (mgr == nullptr) {
        SLOGE("GetService failed when GetSystemAbilityManager.");
        return nullptr;
    }
    auto object = mgr->GetSystemAbility(AVSESSION_SERVICE_ID, deviceId);
    if (object == nullptr) {
        SLOGE("GetService failed to get AVSESSION_SERVICE_ID object.");
        return nullptr;
    }
    std::shared_ptr<RemoteSessionCommandProcess> remoteService = std::make_shared<RemoteSessionCommandProcess>(object);
    return remoteService;
}

bool AVSessionService::IsLocalDevice(const std::string& networkId)
{
    std::string localNetworkId;
    CHECK_AND_RETURN_RET_LOG(GetLocalNetworkId(localNetworkId) == AVSESSION_SUCCESS, AVSESSION_ERROR,
                             "GetLocalNetworkId error");
    if (networkId == localNetworkId || networkId == "LocalDevice") {
        SLOGI("This networkId is local device.");
        return true;
    }
    SLOGI("This networkId is not local device.");
    return false;
}

int32_t AVSessionService::GetLocalNetworkId(std::string& networkId)
{
    DistributedHardware::DmDeviceInfo deviceInfo;
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo("av_session", deviceInfo);
    CHECK_AND_RETURN_RET_LOG(ret == 0, ret, "get local deviceInfo failed");
    networkId = deviceInfo.networkId;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::GetTrustedDeviceName(const std::string& networkId, std::string& deviceName)
{
    std::vector<OHOS::DistributedHardware::DmDeviceInfo> deviceList {};
    if (IsLocalDevice(networkId)) {
        deviceName = "LocalDevice";
        return AVSESSION_SUCCESS;
    }
    int32_t ret = GetTrustedDevicesInfo(deviceList);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "get devicesInfo failed");
    for (const auto& device : deviceList) {
        ret = strcmp(device.networkId, networkId.c_str());
        if (ret == 0) {
            deviceName = device.deviceName;
            return AVSESSION_SUCCESS;
        }
    }
    SLOGI("GetTrustedDeviceName is not find this device %{public}.6s", networkId.c_str());
    return AVSESSION_ERROR;
}

int32_t AVSessionService::GetTrustedDevicesInfo(std::vector<OHOS::DistributedHardware::DmDeviceInfo>& deviceList)
{
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetTrustedDeviceList("av_session", "", deviceList);
    CHECK_AND_RETURN_RET_LOG(ret == 0, ret, "get trusted device list failed");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::SetBasicInfo(std::string& sessionInfo)
{
    AVSessionBasicInfo basicInfo;
    basicInfo.metaDataCap_ = AVMetaData::localCapability;
    basicInfo.playBackStateCap_ = AVPlaybackState::localCapability;
    basicInfo.controlCommandCap_ = AVControlCommand::localCapability;
    int32_t ret = GetLocalNetworkId(basicInfo.networkId_);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "GetLocalNetworkId failed");

    ret = JsonUtils::SetSessionBasicInfo(sessionInfo, basicInfo);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "SetDeviceId failed");
    return AVSESSION_SUCCESS;
}

void AVSessionService::SetDeviceInfo(const std::vector<AudioStandard::AudioDeviceDescriptor>& castAudioDescriptors,
    sptr <AVSessionItem>& session)
{
    CHECK_AND_RETURN_LOG(session != nullptr && castAudioDescriptors.size() > 0, "invalid argument");

    OutputDeviceInfo outputDeviceInfo;
    outputDeviceInfo.deviceInfos_.clear();
    int32_t castCategory = AVCastCategory::CATEGORY_LOCAL;
    if (!IsLocalDevice(castAudioDescriptors[0].networkId_)) {
        castCategory = AVCastCategory::CATEGORY_REMOTE;
    }
    for (const auto &audioDescriptor : castAudioDescriptors) {
        DeviceInfo deviceInfo;
        deviceInfo.castCategory_ = castCategory;
        deviceInfo.deviceId_ = std::to_string(audioDescriptor.deviceId_);
        deviceInfo.deviceName_ = audioDescriptor.deviceName_;
        SLOGI("SetDeviceInfo the deviceName is %{public}s", audioDescriptor.deviceName_.c_str());
        outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
    }
    session->SetOutputDevice(outputDeviceInfo);
}

bool AVSessionService::GetAudioDescriptorByDeviceId(
    const std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>>& descriptors,
    const std::string& deviceId,
    AudioStandard::AudioDeviceDescriptor& audioDescriptor)
{
    for (const auto& descriptor : descriptors) {
        if (std::to_string(descriptor->deviceId_) == deviceId) {
            audioDescriptor = *descriptor;
            return true;
        }
    }
    SLOGI("GetAudioDescriptorByDeviceId deviceId:%{public}s is not found in all audio descriptors", deviceId.c_str());
    return false;
}

void AVSessionService::GetDeviceInfo(const sptr <AVSessionItem>& session,
    const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors,
    std::vector<AudioStandard::AudioDeviceDescriptor>& castSinkDescriptors,
    std::vector<AudioStandard::AudioDeviceDescriptor>& cancelSinkDescriptors)
{
    if (descriptors.size() != 1) {
        SLOGI("descriptor size is %{public}d, not support", static_cast<int32_t>(descriptors.size()));
        return;
    }
    castSinkDescriptors.push_back(descriptors[0]);
    OutputDeviceInfo tempOutputDeviceInfo;
    session->GetOutputDevice(tempOutputDeviceInfo);
    // If not in remote, return directly
    if (tempOutputDeviceInfo.deviceInfos_.size() == 0 || tempOutputDeviceInfo.deviceInfos_[0].castCategory_ == 1) {
        SLOGI("castCategory is %{public}d, no need to cancel", tempOutputDeviceInfo.deviceInfos_[0].castCategory_);
        return;
    }
    int32_t ret = GetAudioDescriptor(session->GetDescriptor().outputDeviceInfo_.deviceInfos_[0].deviceId_,
                                     cancelSinkDescriptors);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "get cancelSinkDescriptors failed");
}

int32_t AVSessionService::SelectOutputDevice(const int32_t uid, const AudioDeviceDescriptor& descriptor)
{
    sptr <AudioStandard::AudioRendererFilter> audioFilter = new(std::nothrow) AudioRendererFilter();
    CHECK_AND_RETURN_RET_LOG(audioFilter != nullptr, ERR_NO_MEMORY, "new AudioRendererFilter failed");
    audioFilter->uid = uid;
    audioFilter->rendererInfo.contentType = ContentType::CONTENT_TYPE_MUSIC;
    audioFilter->rendererInfo.streamUsage = StreamUsage::STREAM_USAGE_MEDIA;

    std::vector<std::shared_ptr<AudioDeviceDescriptor>> audioDescriptor;
    auto audioDeviceDescriptor = std::make_shared<AudioDeviceDescriptor>(descriptor);
    CHECK_AND_RETURN_RET_LOG(audioDeviceDescriptor != nullptr, ERR_NO_MEMORY, "audioDeviceDescriptor is nullptr");
    audioDescriptor.push_back(audioDeviceDescriptor);
    SLOGI("select the device %{public}s role is %{public}d, networkId is %{public}.6s",
        descriptor.deviceName_.c_str(), static_cast<int32_t>(descriptor.deviceRole_), descriptor.networkId_.c_str());

    AudioSystemManager *audioSystemMgr = AudioSystemManager::GetInstance();
    CHECK_AND_RETURN_RET_LOG(audioSystemMgr != nullptr, AVSESSION_ERROR, "get AudioSystemManager instance failed");
    int32_t ret = audioSystemMgr->SelectOutputDevice(audioFilter, audioDescriptor);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "SelectOutputDevice failed");

    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::CastAudio(const SessionToken& token,
                                    const std::vector<AudioStandard::AudioDeviceDescriptor>& sinkAudioDescriptors)
{
    std::string sourceSessionInfo;
    int32_t ret = SetBasicInfo(sourceSessionInfo);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetBasicInfo failed");
    sptr<AVSessionItem> session = GetContainer().GetSessionById(token.sessionId);
    CHECK_AND_RETURN_RET_LOG(session != nullptr, ERR_SESSION_NOT_EXIST, "session %{public}s not exist",
                             AVSessionUtils::GetAnonySessionId(token.sessionId).c_str());
    ret = JsonUtils::SetSessionDescriptor(sourceSessionInfo, session->GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetDescriptorInfo failed");
    ret = CastAudioProcess(sinkAudioDescriptors, sourceSessionInfo, session);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CastAudioProcess failed");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::CastAudioProcess(const std::vector<AudioStandard::AudioDeviceDescriptor>& descriptors,
                                           const std::string& sourceSessionInfo,
                                           sptr <AVSessionItem>& session)
{
    std::vector<AudioDeviceDescriptor> castSinkDescriptors;
    std::vector<AudioDeviceDescriptor> cancelSinkDescriptors;
    GetDeviceInfo(session, descriptors, castSinkDescriptors, cancelSinkDescriptors);

    if (cancelSinkDescriptors.size() > 0) {
        int32_t ret = CancelCastAudioInner(cancelSinkDescriptors, sourceSessionInfo, session);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CancelCastAudioInner failed");
    }

    if (castSinkDescriptors.size() > 0) {
        int32_t ret = CastAudioInner(castSinkDescriptors, sourceSessionInfo, session);
        if (ret != AVSESSION_SUCCESS) {
            SLOGE("CastAudioInner failed, try cancel it. ret is %{public}d",
                CancelCastAudioInner(castSinkDescriptors, sourceSessionInfo, session));
            return ret;
        }
    }

    SetDeviceInfo(descriptors, session);
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::CastAudioInner(const std::vector<AudioStandard::AudioDeviceDescriptor>& sinkAudioDescriptors,
                                         const std::string& sourceSessionInfo,
                                         const sptr <AVSessionItem>& session)
{
    CHECK_AND_RETURN_RET_LOG(sinkAudioDescriptors.size() > 0, AVSESSION_ERROR, "sinkDescriptors is empty");
    std::string sourceDevice;
    CHECK_AND_RETURN_RET_LOG(GetLocalNetworkId(sourceDevice) == AVSESSION_SUCCESS, AVSESSION_ERROR,
                             "GetLocalNetworkId failed");
    SLOGI("networkId_: %{public}.6s, role %{public}d", sinkAudioDescriptors[0].networkId_.c_str(),
          static_cast<int32_t>(sinkAudioDescriptors[0].deviceRole_));
    if (IsLocalDevice(sinkAudioDescriptors[0].networkId_)) {
        int32_t ret = SelectOutputDevice(session->GetUid(), sinkAudioDescriptors[0]);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "selectOutputDevice failed");
        return AVSESSION_SUCCESS;
    }

    SLOGI("sinkAudioDescriptors size is %{public}d", static_cast<int32_t>(sinkAudioDescriptors.size()));
    for (const auto& sinkAudioDescriptor : sinkAudioDescriptors) {
        std::string sinkSessionInfo;
        auto service = GetService(sinkAudioDescriptor.networkId_);
        CHECK_AND_RETURN_RET_LOG(service != nullptr, AVSESSION_ERROR, "GetService %{public}s failed",
                                 sinkAudioDescriptor.networkId_.c_str());
        int32_t ret = service->ProcessCastAudioCommand(RemoteServiceCommand::COMMAND_CAST_AUDIO, sourceSessionInfo,
                                                       sinkSessionInfo);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "ProcessCastAudioCommand failed");
        std::string sinkCapability;
        ret = JsonUtils::GetAllCapability(sinkSessionInfo, sinkCapability);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "GetAllCapability failed");
        ret = session->CastAudioToRemote(sourceDevice, sinkAudioDescriptor.networkId_, sinkCapability);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CastAudioToRemote failed");
        HISYSEVENT_BEHAVIOR("SESSION_CAST",
            "BUNDLE_NAME", session->GetDescriptor().elementName_.GetBundleName(),
            "MODULE_NAME", session->GetDescriptor().elementName_.GetModuleName(),
            "ABILITY_NAME", session->GetDescriptor().elementName_.GetAbilityName(),
            "SESSION_PID", session->GetDescriptor().pid_,
            "SESSION_UID", session->GetDescriptor().uid_,
            "SESSION_ID", session->GetDescriptor().sessionId_,
            "SESSION_TAG", session->GetDescriptor().sessionTag_,
            "SESSION_TYPE", session->GetDescriptor().sessionType_,
            "CAST_TYPE", 0,
            "DEST_DEVICE_TYPE", sinkAudioDescriptor.deviceType_,
            "DEST_DEVICE_NAME", sinkAudioDescriptor.deviceName_.c_str(),
            "DEST_DEVICE_ID", sinkAudioDescriptor.deviceId_,
            "DETAILED_MSG", "avsession service cast audio");
        ret = SelectOutputDevice(session->GetUid(), sinkAudioDescriptor);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "selectOutputDevice failed");
    }
    SLOGI("success");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::CancelCastAudioInner(const std::vector<AudioStandard::AudioDeviceDescriptor>& sinkDevices,
                                               const std::string& sourceSessionInfo,
                                               const sptr <AVSessionItem>& session)
{
    SLOGI("cancel sinkDevices size is %{public}d", static_cast<int32_t>(sinkDevices.size()));
    CHECK_AND_RETURN_RET_LOG(!sinkDevices.empty(), AVSESSION_ERROR, "sinkDevices is empty");
    for (const auto& sinkDevice : sinkDevices) {
        if (IsLocalDevice(sinkDevice.networkId_)) {
            SLOGI("cancel Local device %{public}.6s", sinkDevice.networkId_.c_str());
            continue;
        }
        std::string sinkSessionInfo;
        SLOGI("cancel sinkDevices sinkDevice.networkId_ is %{public}.6s", sinkDevice.networkId_.c_str());
        auto service = GetService(sinkDevice.networkId_);
        CHECK_AND_RETURN_RET_LOG(service != nullptr, AVSESSION_ERROR, "GetService %{public}s failed",
                                 sinkDevice.networkId_.c_str());
        int32_t ret = service->ProcessCastAudioCommand(RemoteServiceCommand::COMMAND_CANCEL_CAST_AUDIO,
                                                       sourceSessionInfo, sinkSessionInfo);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "ProcessCastAudioCommand failed");
        ret = session->SourceCancelCastAudio(sinkDevice.networkId_);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SourceCancelCastAudio failed");
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::CastAudioForNewSession(const sptr<AVSessionItem>& session)
{
    SLOGI("new sessionId is %{public}s", AVSessionUtils::GetAnonySessionId(session->GetSessionId()).c_str());
    SessionToken token;
    token.sessionId = session->GetSessionId();
    token.pid = session->GetPid();
    token.uid = session->GetUid();

    int32_t ret = AVSESSION_SUCCESS;
    std::vector<AudioStandard::AudioDeviceDescriptor> castSinkDevices;
    {
        std::lock_guard lockGuard(outputDeviceIdLock_);
        ret = GetAudioDescriptor(outputDeviceId_, castSinkDevices);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "GetAudioDescriptor failed");
    }

    ret = CastAudio(token, castSinkDevices);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CastAudio error, session Id is %{public}s",
                             AVSessionUtils::GetAnonySessionId(token.sessionId).c_str());

    SLOGI("success");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::CastAudioForAll(const std::vector<AudioStandard::AudioDeviceDescriptor>& sinkAudioDescriptors)
{
    CHECK_AND_RETURN_RET_LOG(sinkAudioDescriptors.size() > 0, ERR_INVALID_PARAM, "sinkAudioDescriptors is empty");
    {
        std::lock_guard lockGuard(isAllSessionCastLock_);
        isAllSessionCast_ = false;
        if (!IsLocalDevice(sinkAudioDescriptors[0].networkId_)) {
            isAllSessionCast_ = true;
        }
    }
    for (const auto& session : GetContainer().GetAllSessions()) {
        SessionToken token;
        token.sessionId = session->GetSessionId();
        token.pid = session->GetPid();
        token.uid = session->GetUid();
        SLOGI("cast session %{public}s", token.sessionId.c_str());
        int32_t ret = CastAudio(token, sinkAudioDescriptors);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CastAudio session %{public}s failed",
                                 AVSessionUtils::GetAnonySessionId(token.sessionId).c_str());
        {
            std::lock_guard lockGuard(outputDeviceIdLock_);
            outputDeviceId_ = session->GetDescriptor().outputDeviceInfo_.deviceInfos_[0].deviceId_;
        }
    }

    SLOGI("isAllSessionCast_ %{public}d, outputDeviceId_ is %{public}s", isAllSessionCast_, outputDeviceId_.c_str());
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::ProcessCastAudioCommand(const RemoteServiceCommand command, const std::string& input,
                                                  std::string& output)
{
    SLOGI("ProcessCastAudioCommand command is %{public}d", static_cast<int32_t>(command));
    CHECK_AND_RETURN_RET_LOG(command > COMMAND_INVALID && command < COMMAND_MAX, AVSESSION_ERROR, "invalid command");
    if (command == COMMAND_CAST_AUDIO) {
        int ret = RemoteCastAudioInner(input, output);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "RemoteCastAudioInner error");
        return AVSESSION_SUCCESS;
    }

    int ret = RemoteCancelCastAudioInner(input);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "RemoteCancelCastAudioInner error");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::RemoteCastAudioInner(const std::string& sourceSessionInfo, std::string& sinkSessionInfo)
{
    SLOGI("sourceInfo : %{public}s", sourceSessionInfo.c_str());
    AVSessionDescriptor sourceDescriptor;
    int32_t ret = JsonUtils::GetSessionDescriptor(sourceSessionInfo, sourceDescriptor);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "GetSessionDescriptor failed");

    ret = SetBasicInfo(sinkSessionInfo);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "SetBasicInfo failed");
    AVSessionBasicInfo sinkDeviceInfo;
    ret = JsonUtils::GetSessionBasicInfo(sinkSessionInfo, sinkDeviceInfo);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "GetBasicInfo failed");

    sptr <AVSessionItem> session;
    auto res = CreateSessionInner(sourceDescriptor.sessionTag_, sourceDescriptor.sessionType_,
                                  sourceDescriptor.isThirdPartyApp_, sourceDescriptor.elementName_, session);
    CHECK_AND_RETURN_RET_LOG(res == AVSESSION_SUCCESS, res, "CreateSession failed");

    {
        std::lock_guard lockGuard(castAudioSessionMapLock_);
        castAudioSessionMap_[sourceDescriptor.sessionId_] = session->GetSessionId();
    }

    AVSessionBasicInfo sourceDeviceInfo;
    ret = JsonUtils::GetSessionBasicInfo(sourceSessionInfo, sourceDeviceInfo);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "GetBasicInfo failed");
    std::string sourceCapability;
    ret = JsonUtils::GetAllCapability(sourceSessionInfo, sourceCapability);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "GetAllCapability failed");
    ret = session->CastAudioFromRemote(sourceDescriptor.sessionId_, sourceDeviceInfo.networkId_,
                                       sinkDeviceInfo.networkId_, sourceCapability);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CastAudioFromRemote failed");
    JsonUtils::SetSessionDescriptor(sinkSessionInfo, session->GetDescriptor());
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::RemoteCancelCastAudioInner(const std::string& sessionInfo)
{
    SLOGI("sessionInfo is %{public}s", sessionInfo.c_str());
    AVSessionBasicInfo sourceDeviceInfo;
    int32_t ret = JsonUtils::GetSessionBasicInfo(sessionInfo, sourceDeviceInfo);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "GetBasicInfo failed");
    AVSessionDescriptor sourceDescriptor;
    ret = JsonUtils::GetSessionDescriptor(sessionInfo, sourceDescriptor);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "GetSessionDescriptor failed");

    std::lock_guard lockGuard(castAudioSessionMapLock_);
    auto iter = castAudioSessionMap_.find(sourceDescriptor.sessionId_);
    CHECK_AND_RETURN_RET_LOG(iter != castAudioSessionMap_.end(), AVSESSION_ERROR, "no source session %{public}s",
                             AVSessionUtils::GetAnonySessionId(sourceDescriptor.sessionId_).c_str());
    auto session = GetContainer().GetSessionById(iter->second);
    CHECK_AND_RETURN_RET_LOG(session != nullptr, AVSESSION_ERROR, "no sink session %{public}s",
        AVSessionUtils::GetAnonySessionId(iter->second).c_str());

    ret = session->SinkCancelCastAudio();
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SinkCancelCastAudio failed");
    HandleSessionRelease(session->GetSessionId());
    castAudioSessionMap_.erase(sourceDescriptor.sessionId_);
    SLOGI("cancel source session %{public}s success",
        AVSessionUtils::GetAnonySessionId(sourceDescriptor.sessionId_).c_str());
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::CancelCastAudioForClientExit(pid_t pid, const sptr<AVSessionItem>& session)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, AVSESSION_ERROR, "session is nullptr");
    SLOGI("pid is %{public}d, sessionId is %{public}s", static_cast<int32_t>(pid),
        AVSessionUtils::GetAnonySessionId(session->GetSessionId()).c_str());
    std::string sourceSessionInfo;
    int32_t ret = SetBasicInfo(sourceSessionInfo);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetBasicInfo failed");
    ret = JsonUtils::SetSessionDescriptor(sourceSessionInfo, session->GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetDescriptorInfo failed");

    std::vector<AudioStandard::AudioDeviceDescriptor> cancelSinkDevices;
    ret = GetAudioDescriptor(session->GetDescriptor().outputDeviceInfo_.deviceInfos_[0].deviceId_, cancelSinkDevices);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "GetAudioDescriptor failed");

    ret = CancelCastAudioInner(cancelSinkDevices, sourceSessionInfo, session);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CancelCastAudioInner failed");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::GetAudioDescriptor(const std::string deviceId,
                                             std::vector<AudioStandard::AudioDeviceDescriptor>& audioDeviceDescriptors)
{
    auto audioDescriptors = AudioSystemManager::GetInstance()->GetDevices(ALL_L_D_DEVICES_FLAG);
    AudioDeviceDescriptor audioDescriptor;
    if (GetAudioDescriptorByDeviceId(audioDescriptors, deviceId, audioDescriptor)) {
        audioDeviceDescriptors.push_back(audioDescriptor);
        SLOGI("get audio networkId_ is %{public}.6s", audioDescriptor.networkId_.c_str());
        return AVSESSION_SUCCESS;
    }
    SLOGI("can not get deviceId %{public}s info", deviceId.c_str());
    return AVSESSION_ERROR;
}

void AVSessionService::ClearSessionForClientDiedNoLock(pid_t pid)
{
    SLOGI("clear session in ");
    auto sessions = GetUsersManager().GetContainerFromAll().GetSessionsByPid(pid);
    for (const auto& session : sessions) {
        SLOGI("check session release task for id %{public}s",
            AVSessionUtils::GetAnonySessionId(session->GetSessionId()).c_str());
        HandleSessionRelease(session->GetSessionId());
    }
}

void AVSessionService::ClearControllerForClientDiedNoLock(pid_t pid)
{
    auto it = controllers_.find(pid);
    CHECK_AND_RETURN_LOG(it != controllers_.end(), "no find controller");
    auto controllers = std::move(it->second);
    SLOGI("remove controllers size=%{public}d", static_cast<int>(controllers.size()));
    if (!controllers.empty()) {
        for (const auto& controller : controllers) {
            controller->Destroy();
        }
    }
    it = controllers_.find(pid);
    CHECK_AND_RETURN_LOG(it != controllers_.end(), "no find controller");
    controllers_.erase(pid);
}

ClientDeathRecipient::ClientDeathRecipient(const std::function<void()>& callback)
    : callback_(callback)
{
    SLOGD("construct");
}

void ClientDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& object)
{
    if (callback_) {
        callback_();
    }
}

bool AVSessionService::CheckUserDirValid(int32_t userId)
{
    std::string filePath = GetUsersManager().GetDirForCurrentUser(userId);
    filesystem::path directory(filePath);
    std::error_code errCode;
    if (!filesystem::exists(directory, errCode)) {
        SLOGE("check user dir not exsit %{public}s for user %{public}d, errCode %{public}d",
            filePath.c_str(), userId, static_cast<int>(errCode.value()));
        return false;
    }
    return true;
}

bool AVSessionService::CheckAndCreateDir(const string& filePath)
{
    CHECK_AND_RETURN_RET_LOG(CheckUserDirValid(), false, "check userDir err!");
    filesystem::path directory = filesystem::path(filePath).parent_path();
    if (!filesystem::exists(directory)) {
        SLOGI("check file not exist and try create %{public}s", filePath.c_str());
        CHECK_AND_RETURN_RET_LOG(filesystem::create_directories(directory),
            false, "Failed to create directory");
    }
    return true;
}

bool AVSessionService::LoadStringFromFileEx(const string& filePath, string& content)
{
    SLOGD("file load in for path: %{public}s", filePath.c_str());
    CheckAndCreateDir(filePath);
    ifstream file(filePath.c_str());
    if (!file.is_open()) {
        SLOGD("file not open! try open first ! ");
        file.open(filePath.c_str(), ios::out | ios::app);
        if (!file.is_open()) {
            SLOGE("open file again fail !");
            return false;
        }
    }
    file.seekg(0, ios::end);
    const long fileLength = file.tellg();
    SLOGD("get file length(%{public}ld)!", fileLength);
    if (fileLength > maxFileLength) {
        SLOGE("invalid file length(%{public}ld)!", fileLength);
        return false;
    }
    if (fileLength <= 0) {
        SLOGD("file new create empty ! try set init json ");
        ofstream fileWrite;
        fileWrite.open(filePath.c_str(), ios::out | ios::trunc);
        if (!fileWrite.is_open()) {
            SLOGE("open file in create new failed!");
            file.close();
            return false;
        }
        nlohmann::json emptyValue;
        std::string emptyContent = emptyValue.dump();
        SLOGD("LoadStringFromFileEx::Dump json object finished");
        fileWrite.write(emptyContent.c_str(), emptyContent.length());
        if (fileWrite.fail()) {
            SLOGE("file empty init json fail !");
            file.close();
            fileWrite.close();
            return false;
        }
        fileWrite.close();
    }
    content.clear();
    file.seekg(0, ios::beg);
    copy(istreambuf_iterator<char>(file), istreambuf_iterator<char>(), back_inserter(content));
    file.close();
    return CheckStringAndCleanFile(filePath);
}

bool AVSessionService::SaveStringToFileEx(const std::string& filePath, const std::string& content)
{
    SLOGI("file save in for path:%{public}s, content:%{public}s", filePath.c_str(), content.c_str());
    nlohmann::json checkValues = json::parse(content, nullptr, false);
    CHECK_AND_RETURN_RET_LOG(!checkValues.is_discarded(), false, "recv content discarded");
    ofstream file;
    file.open(filePath.c_str(), ios::out | ios::trunc);
    if (!file.is_open()) {
        SLOGE("open file in save failed!");
        return false;
    }
    if (content.empty()) {
        SLOGE("write content is empty, no need to do write!");
        file.close();
        return true;
    }
    file.write(content.c_str(), content.length());
    if (file.fail()) {
        SLOGE("write content to file failed!");
        file.close();
        return false;
    }
    file.close();
    return CheckStringAndCleanFile(filePath);
}

bool AVSessionService::CheckStringAndCleanFile(const std::string& filePath)
{
    SLOGD("file check for path:%{public}s", filePath.c_str());
    string content {};
    ifstream fileRead(filePath.c_str());
    if (!fileRead.is_open()) {
        SLOGD("file not open! try open first ! ");
        fileRead.open(filePath.c_str(), ios::app);
        if (!fileRead.is_open()) {
            SLOGE("open file again fail !");
            return false;
        }
    }
    content.clear();
    fileRead.seekg(0, ios::beg);
    copy(istreambuf_iterator<char>(fileRead), istreambuf_iterator<char>(), back_inserter(content));
    SLOGD("check content pre clean it: %{public}s", content.c_str());
    nlohmann::json checkValues = json::parse(content, nullptr, false);
    if (checkValues.is_discarded()) {
        SLOGE("check content discarded! content %{public}s", content.c_str());
        ofstream fileWrite;
        fileWrite.open(filePath.c_str(), ios::out | ios::trunc);
        if (!fileWrite.is_open()) {
            SLOGE("open file in create new failed!");
            fileRead.close();
            return false;
        }
        nlohmann::json emptyValue;
        std::string emptyContent = emptyValue.dump();
        SLOGD("LoadStringFromFileEx::Dump json object finished");
        fileWrite.write(emptyContent.c_str(), emptyContent.length());
        if (fileWrite.fail()) {
            SLOGE("file empty init json fail! content %{public}s", content.c_str());
            fileRead.close();
            fileWrite.close();
            return false;
        }
        fileWrite.close();
    }
    fileRead.close();
    return true;
}

std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> AVSessionService::CreateWantAgent(
    const AVSessionDescriptor* histroyDescriptor)
{
    if (histroyDescriptor == nullptr && topSession_ == nullptr) {
        SLOGE("CreateWantAgent error, histroyDescriptor and topSession_ null");
        return nullptr;
    }
    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
    flags.push_back(AbilityRuntime::WantAgent::WantAgentConstant::Flags::UPDATE_PRESENT_FLAG);
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> launWantAgent;
    string bundleName = DEFAULT_BUNDLE_NAME;
    string abilityName = DEFAULT_ABILITY_NAME;
    auto uid = -1;
    auto isCustomer = false;
    if (topSession_ != nullptr) {
        bundleName = topSession_->GetBundleName();
        abilityName = topSession_->GetAbilityName();
        uid = topSession_->GetUid();
        launWantAgent = std::make_shared<AbilityRuntime::WantAgent::WantAgent>(topSession_->GetLaunchAbility());
        auto res = AbilityRuntime::WantAgent::WantAgentHelper::GetWant(launWantAgent, want);
        isCustomer = (res == AVSESSION_SUCCESS) && (bundleName == want->GetElement().GetBundleName());
        SLOGI("CreateWantAgent GetWant res=%{public}d", res);
    }
    if (histroyDescriptor != nullptr) {
        SLOGI("CreateWantAgent with historyDescriptor");
        bundleName = histroyDescriptor->elementName_.GetBundleName();
        abilityName = histroyDescriptor->elementName_.GetAbilityName();
        uid = histroyDescriptor->uid_;
        isCustomer = false;
    }
    SLOGI("CreateWantAgent bundleName %{public}s, abilityName %{public}s, isCustomer %{public}d",
        bundleName.c_str(), abilityName.c_str(), isCustomer);
    if (!isCustomer) {
        AppExecFwk::ElementName element("", bundleName, abilityName);
        want->SetElement(element);
    }
    wants.push_back(want);
    AbilityRuntime::WantAgent::WantAgentInfo wantAgentInfo(
        0,
        AbilityRuntime::WantAgent::WantAgentConstant::OperationType::START_ABILITY,
        flags,
        wants,
        nullptr
    );
    return AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(wantAgentInfo, uid);
}

void AVSessionService::RemoveExpired(std::list<std::chrono::system_clock::time_point> &list,
    const std::chrono::system_clock::time_point &now, int32_t time)
{
    auto iter = list.begin();
    while (iter != list.end()) {
        auto duration = now - static_cast<std::chrono::system_clock::time_point>(*iter);
        int32_t durationInSeconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
        if (std::abs(durationInSeconds) > time) {
            iter = list.erase(iter);
        } else {
            break;
        }
    }
}

// LCOV_EXCL_START
void AVSessionService::NotifySystemUI(const AVSessionDescriptor* historyDescriptor, bool isActiveSession)
{
    is2in1_ = system::GetBoolParameter("const.audio.volume_apply_to_all", false);
    CHECK_AND_RETURN_LOG(!is2in1_, "2in1 not support");
    // flow control
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    RemoveExpired(flowControlPublishTimestampList_, now);
    if (flowControlPublishTimestampList_.size() >= MAX_NOTIFICATION_NUM) {
        SLOGE("PublishNotification Exeed MAX_NOTIFICATION_NUM");
        return;
    }
    flowControlPublishTimestampList_.push_back(now);
    int32_t result = Notification::NotificationHelper::SubscribeLocalLiveViewNotification(NOTIFICATION_SUBSCRIBER);
    CHECK_AND_RETURN_LOG(result == ERR_OK, "create notification subscriber error %{public}d", result);

    Notification::NotificationRequest request;
    std::shared_ptr<Notification::NotificationLocalLiveViewContent> localLiveViewContent =
        std::make_shared<Notification::NotificationLocalLiveViewContent>();
    CHECK_AND_RETURN_LOG(localLiveViewContent != nullptr, "avsession item local live view content nullptr error");
    localLiveViewContent->SetType(SYSTEMUI_LIVEVIEW_TYPECODE_MDEDIACONTROLLER);
    localLiveViewContent->SetTitle(historyDescriptor && !isActiveSession ? "" : "AVSession NotifySystemUI");
    localLiveViewContent->SetText(historyDescriptor && !isActiveSession ? "" : "AVSession NotifySystemUI");

    std::shared_ptr<Notification::NotificationContent> content =
        std::make_shared<Notification::NotificationContent>(localLiveViewContent);
    CHECK_AND_RETURN_LOG(content != nullptr, "avsession item notification content nullptr error");

    auto uid = topSession_ ? topSession_->GetUid() : (historyDescriptor ? historyDescriptor->uid_ : -1);
    request.SetSlotType(Notification::NotificationConstant::SlotType::LIVE_VIEW);
    request.SetNotificationId(0);
    request.SetContent(content);
    request.SetCreatorUid(avSessionUid);
    request.SetUnremovable(true);
    request.SetInProgress(true);
    int32_t userId = GetUsersManager().GetCurrentUserId();
    request.SetCreatorUserId(userId);
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent = CreateWantAgent(historyDescriptor);
    CHECK_AND_RETURN_LOG(wantAgent != nullptr, "wantAgent nullptr error");
    request.SetWantAgent(wantAgent);
    result = Notification::NotificationHelper::PublishNotification(request);
    SLOGI("PublishNotification uid %{public}d, userId %{public}d, result %{public}d", uid, userId, result);
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
void AVSessionService::NotifyDeviceChange()
{
    // historical sessions
    std::vector<AVSessionDescriptor> hisDescriptors;
    GetHistoricalSessionDescriptors(1, hisDescriptors);
    // all sessions
    std::vector<AVSessionDescriptor> activeDescriptors;
    GetAllSessionDescriptors(activeDescriptors);
    // historical avqueueinfos
    std::vector<AVQueueInfo> avQueueInfos;
    GetHistoricalAVQueueInfos(1, 1, avQueueInfos);
    AVSessionDescriptor selectSession;
    if (activeDescriptors.size() != 0 || hisDescriptors.size() == 0 || avQueueInfos.size() == 0) {
        return;
    }
    bool isHisMatch = false;
    for (AVQueueInfo avqueue : avQueueInfos) {
        if (avqueue.GetBundleName() == hisDescriptors[0].elementName_.GetBundleName()) {
            isHisMatch = true;
            break;
        }
    }
    if (!isHisMatch) {
        SLOGI("no match hisAvqueue for %{public}s", hisDescriptors[0].elementName_.GetBundleName().c_str());
        return;
    }
    if (avQueueInfos.size() >= MINNUM_FOR_NOTIFICATION) {
        SLOGI("history bundle name %{public}s", hisDescriptors[0].elementName_.GetBundleName().c_str());
        NotifySystemUI(&(hisDescriptors[0]), false);
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
void AVSessionService::HandleDeviceChange(
    const std::vector<std::shared_ptr<AudioStandard::AudioDeviceDescriptor>> &desc)
{
    for (auto &audioDeviceDescriptor : desc) {
        if (audioDeviceDescriptor->deviceType_ == AudioStandard::DEVICE_TYPE_WIRED_HEADSET ||
            audioDeviceDescriptor->deviceType_ == AudioStandard::DEVICE_TYPE_WIRED_HEADPHONES ||
            audioDeviceDescriptor->deviceType_ == AudioStandard::DEVICE_TYPE_USB_HEADSET ||
            audioDeviceDescriptor->deviceType_ == AudioStandard::DEVICE_TYPE_BLUETOOTH_A2DP) {
            SLOGI("AVSessionService handle pre notify device type %{public}d", audioDeviceDescriptor->deviceType_);
            NotifyDeviceChange();
        }
    }
}
// LCOV_EXCL_STOP

void AVSessionService::InitRadarBMS()
{
    AVSessionRadar::GetInstance().InitBMS();
}

void AVSessionService::ReportStartCastBegin(std::string func, const OutputDeviceInfo& outputDeviceInfo, int32_t uid)
{
    AVSessionRadarInfo info(func);
    info.bundleName_ = BundleStatusAdapter::GetInstance().GetBundleNameFromUid(uid);
    AVSessionRadar::GetInstance().StartCastBegin(outputDeviceInfo, info);
}

void AVSessionService::ReportStartCastEnd(std::string func, const OutputDeviceInfo& outputDeviceInfo,
    int32_t uid, int ret)
{
    AVSessionRadarInfo info(func);
    info.bundleName_ = BundleStatusAdapter::GetInstance().GetBundleNameFromUid(uid);
    if (ret == AVSESSION_SUCCESS) {
        AVSessionRadar::GetInstance().StartCastEnd(outputDeviceInfo, info);
    } else {
        info.errorCode_ = AVSessionRadar::GetRadarErrorCode(ret);
        AVSessionRadar::GetInstance().FailToStartCast(outputDeviceInfo, info);
    }
}
} // namespace OHOS::AVSession
