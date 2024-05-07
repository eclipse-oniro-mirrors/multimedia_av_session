/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"
#include "app_manager_adapter.h"
#include "audio_adapter.h"
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
#include "insight_intent_execute_param.h"
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
#endif

#if !defined(WINDOWS_PLATFORM) and !defined(MAC_PLATFORM) and !defined(IOS_PLATFORM)
#include <malloc.h>
#endif

using namespace std;
using namespace nlohmann;
using namespace OHOS::AudioStandard;

namespace OHOS::AVSession {
static const std::string SOURCE_LIBRARY_PATH = std::string(SYSTEM_LIB_PATH) +
    std::string("platformsdk/libsuspend_manager_client.z.so");
static const std::string MIGRATE_STUB_SOURCE_LIBRARY_PATH = std::string(SYSTEM_LIB_PATH) +
    std::string("libavsession_migration.z.so");
static const int32_t CAST_ENGINE_SA_ID = 65546;

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
    SLOGD("construct");
}

AVSessionService::~AVSessionService()
{
    std::string cachePath(AVSessionUtils::GetCachePathName());
    AVSessionUtils::DeleteCacheFiles(cachePath);
    SLOGD("destroy");
}

void AVSessionService::OnStart()
{
    std::string cachePath(AVSessionUtils::GetCachePathName());
    AVSessionUtils::DeleteCacheFiles(cachePath);
    CHECK_AND_RETURN_LOG(Publish(this), "publish avsession service failed");
    dumpHelper_ = std::make_unique<AVSessionDumper>();
    CHECK_AND_RETURN_LOG(dumpHelper_ != nullptr, "no memory");
    CommandSendLimit::GetInstance().StartTimer();

    ParamsConfigOperator::GetInstance().InitConfig();
    auto ret = ParamsConfigOperator::GetInstance().GetValueIntByKey("historicalRecordMaxNum", &maxHistoryNums);
    if (ret == AVSESSION_ERROR) {
        maxHistoryNums = defMaxHistoryNum;
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

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    auto deviceProp = system::GetParameter("const.product.devicetype", "default");
    SLOGI("GetDeviceType, deviceProp=%{public}s", deviceProp.c_str());
    is2in1_ = strcmp(deviceProp.c_str(), "2in1");
    if (is2in1_ == 0) {
        SLOGI("startup enable cast check 2in1");
        checkEnableCast(true);
        AVRouter::GetInstance().SetDiscoverable(true);
    }
#endif
    PullMigrateStub();
    HISYSEVENT_REGITER;
    HISYSEVENT_BEHAVIOR("SESSION_SERVICE_START", "SERVICE_NAME", "AVSessionService",
        "SERVICE_ID", AVSESSION_SERVICE_ID, "DETAILED_MSG", "avsession service start success");
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
    dlclose(migrateStubFuncHandle_);
    CommandSendLimit::GetInstance().StopTimer();
}

void AVSessionService::PullMigrateStub()
{
    char sourceLibraryRealPath[PATH_MAX] = { 0x00 };
    if (realpath(MIGRATE_STUB_SOURCE_LIBRARY_PATH.c_str(), sourceLibraryRealPath) == nullptr) {
        SLOGE("check libmigrate_avsession_service path failed %{public}s", MIGRATE_STUB_SOURCE_LIBRARY_PATH.c_str());
        return;
    }
    migrateStubFuncHandle_ = dlopen(sourceLibraryRealPath, RTLD_NOW);
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
            CheckInitCast();
            break;
        default:
            SLOGE("undefined system ability %{public}d", systemAbilityId);
    }
}

void AVSessionService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    if (systemAbilityId == CAST_ENGINE_SA_ID) {
        SLOGE("on cast engine remove ability");
        isInCast_ = false;
    }
}

void AVSessionService::CheckInitCast()
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("AVSessionService CheckInitCast in");
    sptr<ISystemAbilityManager> samgrProxy;
    samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        SLOGE("AVSessionService CheckInitCast with samgrProxy null");
        return;
    }
    if (samgrProxy->CheckSystemAbility(CAST_ENGINE_SA_ID) == nullptr) {
        SLOGI("check cast engine has been removed");
    } else {
        SLOGI("check cast engine has been started");
    }
#endif
}

void AVSessionService::InitKeyEvent()
{
    SLOGI("enter");
    std::vector<int32_t> keyCodes = {
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
    if (newTopSession == nullptr) {
        std::lock_guard lockGuard(sessionAndControllerLock_);
        if (topSession_ != nullptr) {
            topSession_->SetTop(false);
        }
        topSession_ = nullptr;
        SLOGI("set topSession to nullptr");
        HISYSEVENT_BEHAVIOR("FOCUS_CHANGE", "DETAILED_MSG", "avsessionservice set topsession to nullptr");
        return;
    }

    SLOGI("uid=%{public}d sessionId=%{public}s", newTopSession->GetUid(),
        AVSessionUtils::GetAnonySessionId(newTopSession->GetSessionId()).c_str());
    AVSessionDescriptor descriptor;
    {
        std::lock_guard lockGuard(sessionAndControllerLock_);
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
        topSession_->SetTop(true);
        descriptor = topSession_->GetDescriptor();
    }
    NotifyTopSessionChanged(descriptor);
}

void AVSessionService::HandleFocusSession(const FocusSessionStrategy::FocusSessionChangeInfo& info)
{
    std::lock_guard lockGuard(sessionAndControllerLock_);
    if (topSession_ && topSession_->GetUid() == info.uid) {
        SLOGI("same session");
        if (topSession_->GetSessionType() == "audio") {
            AVSessionService::NotifySystemUI(nullptr);
        }
        return;
    }
    for (const auto& session : GetContainer().GetAllSessions()) {
        if (session->GetUid() == info.uid) {
            UpdateTopSession(session);
            if (topSession_->GetSessionType() == "audio") {
                AVSessionService::NotifySystemUI(nullptr);
            }
            return;
        }
    }
}

void AVSessionService::RefreshFocusSessionSort(sptr<AVSessionItem> &session)
{
    std::lock_guard sortFileLockGuard(sortFileReadWriteLock_);
    std::string oldSortContent;
    if (!LoadStringFromFileEx(AVSESSION_FILE_DIR + SORT_FILE_NAME, oldSortContent)) {
        SLOGE("SelectFocusSession read sort fail !");
        return;
    }
    nlohmann::json values = json::parse(oldSortContent, nullptr, false);
    CHECK_AND_RETURN_LOG(!values.is_discarded(), "json object is null");
    bool sessionExist = false;
    for (auto value : values) {
        if (session->GetBundleName() == value["bundleName"] &&
            session->GetAbilityName() == value["abilityName"]) {
            values.erase(std::remove(values.begin(), values.end(), value));
            sessionExist = true;
            break;
        }
    }
    if (sessionExist) {
        SLOGI("SelectFocusSession sessionExist, change order");
        if (values.size() >= (size_t)maxHistoryNums) {
            values.erase(values.end() - 1);
        }
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
    SLOGD("SelectFocusSession::Dump json object finished");
    if (!SaveStringToFileEx(AVSESSION_FILE_DIR + SORT_FILE_NAME, newSortContent)) {
        SLOGE("SelectFocusSession save sort fail !");
    }
}


bool AVSessionService::SelectFocusSession(const FocusSessionStrategy::FocusSessionChangeInfo& info)
{
    for (auto& session : GetContainer().GetAllSessions()) {
        if (session->GetDescriptor().sessionTag_ == "RemoteCast") {
            SLOGI("Remote sessions do not need to be saved to history");
            continue;
        }
        if (session->GetUid() != info.uid) {
            continue;
        }
        GetContainer().UpdateSessionSort(session);
        RefreshFocusSessionSort(session);
        return true;
    }
    return false;
}

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
    AudioAdapter::GetInstance().AddDeviceChangeListener([this] (const DeviceChangeAction& deviceChangeAction) {
        HandleDeviceChange(deviceChangeAction);
    });
}

sptr <AVSessionItem> AVSessionService::SelectSessionByUid(const AudioRendererChangeInfo& info)
{
    for (const auto& session : GetContainer().GetAllSessions()) {
        if (session->GetUid() == info.clientUID) {
            return session;
        }
    }
    SLOGI("has no session");
    return nullptr;
}

void AVSessionService::OutputDeviceChangeListener(const AudioRendererChangeInfos& infos)
{
    for (const auto& info : infos) {
        SLOGD("clientUID  is %{public}d, rendererState is %{public}d, deviceId is %{public}d", info->clientUID,
              static_cast<int32_t>(info->rendererState), info->outputDeviceInfo.deviceId);
    }
}

void AVSessionService::InitAMS()
{
    SLOGI("enter");
    AppManagerAdapter::GetInstance().Init();
    AppManagerAdapter::GetInstance().SetServiceCallbackForAppStateChange([this] (int uid, int state) {
        SLOGI("uid = %{public}d, state = %{public}d", uid, state);
        HandleAppStateChange(uid, state);
    });
}

void AVSessionService::HandleAppStateChange(int uid, int state)
{
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("uidForAppStateChange_ = %{public}d", uidForAppStateChange_);
    if (uidForAppStateChange_ == uid && state == static_cast<int>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND)) {
        //first creat session
        if (firstAppStateChangeFlag_) {
            firstAppStateChangeFlag_ = false;
            SLOGI("when first creat session, counts = %{public}d", appStateChangeCounter_);
            appStateChangeCounter_ = foreGroundStateCountZero;
            return;
        }
        //APP_STATE_FOREGROUND To APP_STATE_BACKGROUND
        if (foreToBackFlag_) {
            foreToBackFlag_ = false;
            SLOGI("when fore to back, counts = %{public}d", appStateChangeCounter_);
            appStateChangeCounter_ = foreGroundStateCountOne;
            return;
        }
        appStateChangeCounter_++;
        //APP_STATE_BACKGROUND To APP_STATE_FOREGROUND
        if (appStateChangeCounter_ == foreGroundStateCountTwo) {
            appStateChangeCounter_ = foreGroundStateCountZero;
            SLOGI("enter notifyMirrorToStreamCast by background to foreground state change, and counts = 2");
            NotifyMirrorToStreamCast();
        }
    }
    if (appStateChangeCounter_ == foreGroundStateCountOne &&
        uidForAppStateChange_ == uid && state == static_cast<int>(AppExecFwk::ApplicationState::APP_STATE_BACKGROUND)) {
        foreToBackFlag_ = true;
    }
#endif //CASTPLUS_CAST_ENGINE_ENABLE
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
    std::lock_guard sortFileLockGuard(sortFileReadWriteLock_);
    SLOGI("enter");
    BundleStatusAdapter::GetInstance().Init();
    std::string oldSortContent;
    if (LoadStringFromFileEx(AVSESSION_FILE_DIR + SORT_FILE_NAME, oldSortContent)) {
        nlohmann::json values = json::parse(oldSortContent, nullptr, false);
        CHECK_AND_RETURN_LOG(!values.is_discarded(), "json object is null");
        auto callback = [this](std::string bundleName) {
            DeleteAVQueueInfoRecord(bundleName);
            DeleteHistoricalRecord(bundleName);
        };
        for (auto value : values) {
            if (!BundleStatusAdapter::GetInstance().SubscribeBundleStatusEvent(value["bundleName"], callback)) {
                std::string bundleName = value["bundleName"];
                SLOGE("SubscribeBundleStatusEvent failed for bundle:%{public}s", bundleName.c_str());
            }
        }
    }
}

SessionContainer& AVSessionService::GetContainer()
{
    static SessionStack sessionStack;
    return sessionStack;
}

std::string AVSessionService::AllocSessionId()
{
    auto curNum = sessionSeqNum_++;
    std::string id = std::to_string(GetCallingPid()) + "-" + std::to_string(GetCallingUid()) + "-" +
                     std::to_string(curNum);
    SLOGI("%{public}s", id.c_str());

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
    std::lock_guard lockGuard(sessionAndControllerLock_);
    return GetContainer().PidHasSession(pid);
}

sptr<AVControllerItem> AVSessionService::GetPresentController(pid_t pid, const std::string& sessionId)
{
    std::lock_guard lockGuard(sessionAndControllerLock_);
    auto it = controllers_.find(pid);
    if (it != controllers_.end()) {
        for (const auto& controller: it->second) {
            if (controller->HasSession(sessionId)) {
                return controller;
            }
        }
    }
    SLOGI("not found");
    return nullptr;
}

void AVSessionService::NotifySessionCreate(const AVSessionDescriptor& descriptor)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    for (const auto& listener : innerSessionListeners_) {
        listener->OnSessionCreate(descriptor);
    }
    for (const auto& [pid, listener] : sessionListeners_) {
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnSessionCreate");
        listener->OnSessionCreate(descriptor);
    }
}

void AVSessionService::NotifySessionRelease(const AVSessionDescriptor& descriptor)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    for (const auto& listener : innerSessionListeners_) {
        listener->OnSessionRelease(descriptor);
    }
    for (const auto& [pid, listener] : sessionListeners_) {
        listener->OnSessionRelease(descriptor);
    }
}

void AVSessionService::NotifyTopSessionChanged(const AVSessionDescriptor& descriptor)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    for (const auto& listener : innerSessionListeners_) {
        listener->OnTopSessionChange(descriptor);
    }
    for (const auto& [pid, listener] : sessionListeners_) {
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnTopSessionChange");
        listener->OnTopSessionChange(descriptor);
    }
}

void AVSessionService::NotifyAudioSessionCheck(const int32_t uid)
{
    SLOGI("Start searching for the corresponding callback");
    std::lock_guard lockGuard(sessionListenersLock_);
    for (const auto& listener : innerSessionListeners_) {
        SLOGI("Found inner session listener");
        listener->OnAudioSessionChecked(uid);
    }
    for (const auto& [pid, listener] : sessionListeners_) {
        SLOGI("Found session listener with pid");
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnAudioSessionCheck");
        listener->OnAudioSessionChecked(uid);
    }
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE

void AVSessionService::checkEnableCast(bool enable)
{
    SLOGI("checkEnableCast enable:%{public}d, isInCast:%{public}d", enable, isInCast_);
    if (enable == true && isInCast_ == false) {
        isInCast_ = true;
        AVRouter::GetInstance().Init(this);
    } else if (enable == false && isInCast_ == true) {
        bool hasAncoAudio = false;
        for (const auto& session : GetContainer().GetAllSessions()) {
            if (session->GetBundleName() == "anco_audio") {
                hasAncoAudio = true;
                break;
            }
        }
        CHECK_AND_RETURN_RET_LOG(!((GetContainer().GetAllSessions().size() > 1 ||
            (GetContainer().GetAllSessions().size() == 1 && !hasAncoAudio)) && is2in1_ != 0),
            AVSESSION_SUCCESS, "can not release cast with session alive");
        isInCast_ = AVRouter::GetInstance().Release();
    } else {
        SLOGD("AVRouter Init in nothing change");
    }
    return AVSESSION_SUCCESS;
}

void AVSessionService::ReleaseCastSession()
{
    std::lock_guard lockGuard(sessionAndControllerLock_);
    SLOGI("Start release cast session");
    for (const auto& session : GetContainer().GetAllSessions()) {
        if (session->GetDescriptor().sessionTag_ == "RemoteCast") {
            std::string sessionId = session->GetDescriptor().sessionId_;
            SLOGI("Already has a cast session %{public}s", AVSessionUtils::GetAnonySessionId(sessionId).c_str());
            session->UnRegisterDeviceStateCallback();
            session->StopCastSession();
            session->ReleaseAVCastControllerInner();
            HandleSessionRelease(sessionId);
        }
    }
}

void AVSessionService::CreateSessionByCast(const int64_t castHandle)
{
    SLOGI("AVSessionService CreateSessionByCast in");
    if (isSourceInCast_) {
        AVSessionRadarInfo info("AVSessionService::CreateSessionByCast");
        AVSessionRadar::GetInstance().StartConnect(info);
        SLOGI("Create Cast in source, return");
        return;
    }
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName("castBundleName");
    elementName.SetAbilityName("castAbilityName");
    sptr<AVSessionItem> sinkSession = CreateSessionInner("RemoteCast",
        AVSession::SESSION_TYPE_AUDIO, false, elementName);
    CHECK_AND_RETURN_LOG(sinkSession != nullptr, "CreateSession at sink failed");
    SLOGI("Create Cast sink sessionId %{public}s",
        AVSessionUtils::GetAnonySessionId(sinkSession->GetSessionId()).c_str());
    sinkSession->SetCastHandle(castHandle);
    sinkSession->RegisterDeviceStateCallback();

    HISYSEVENT_BEHAVIOR("SESSION_CAST",
        "BUNDLE_NAME", "castBundleName",
        "ABILITY_NAME", "castAbilityName",
        "SESSION_PID", sinkSession->GetDescriptor().pid_,
        "SESSION_UID", sinkSession->GetDescriptor().uid_,
        "SESSION_ID", sinkSession->GetDescriptor().sessionId_,
        "SESSION_TAG", sinkSession->GetDescriptor().sessionTag_,
        "SESSION_TYPE", sinkSession->GetDescriptor().sessionType_,
        "DETAILED_MSG", "session create from cast+ callback");
}

void AVSessionService::NotifyDeviceAvailable(const OutputDeviceInfo& castOutputDeviceInfo)
{
    AVSessionRadarInfo info("AVSessionService::NotifyDeviceAvailable");
    AVSessionRadar::GetInstance().CastDeviceAvailable(castOutputDeviceInfo, info);

    for (DeviceInfo deviceInfo : castOutputDeviceInfo.deviceInfos_) {
        std::lock_guard lockGuard(castDeviceInfoMapLock_);
        castDeviceInfoMap_[deviceInfo.deviceId_] = deviceInfo;
        for (const auto& session : GetContainer().GetAllSessions()) {
            session->UpdateCastDeviceMap(deviceInfo);
        }
    }
    std::lock_guard lockGuard(sessionListenersLock_);
    for (const auto& listener : innerSessionListeners_) {
        listener->OnDeviceAvailable(castOutputDeviceInfo);
    }
    for (const auto& [pid, listener] : sessionListeners_) {
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnDeviceAvailable");
        listener->OnDeviceAvailable(castOutputDeviceInfo);
    }
}

void AVSessionService::NotifyDeviceOffline(const std::string& deviceId)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    for (const auto& listener : innerSessionListeners_) {
        listener->OnDeviceOffline(deviceId);
    }
    for (const auto& [pid, listener] : sessionListeners_) {
        AVSESSION_TRACE_SYNC_START("AVSessionService::OnDeviceOffline");
        listener->OnDeviceOffline(deviceId);
    }
}

int32_t AVSessionService::StartCast(const SessionToken& sessionToken, const OutputDeviceInfo& outputDeviceInfo)
{
    SLOGI("SessionId is %{public}s", AVSessionUtils::GetAnonySessionId(sessionToken.sessionId).c_str());
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("StartCast: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice StartCast checksystempermission failed");
        return ERR_NO_PERMISSION;
    }

    sptr<AVSessionItem> session = GetContainer().GetSessionById(sessionToken.sessionId);
    CHECK_AND_RETURN_RET_LOG(session != nullptr, ERR_SESSION_NOT_EXIST, "session %{public}s not exist",
        AVSessionUtils::GetAnonySessionId(sessionToken.sessionId).c_str());
    ReportStartCastBegin("AVSessionService::StartCast", outputDeviceInfo, session->GetDescriptor().uid_);
    int32_t ret = session->StartCast(outputDeviceInfo);
    ReportStartCastEnd("AVSessionService::StartCast", outputDeviceInfo, session->GetDescriptor().uid_, ret);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "StartCast failed");
    SLOGD("StartCast set isSourceInCast");
    isSourceInCast_ = true;

#ifdef EFFICIENCY_MANAGER_ENABLE
    int32_t uid = session->GetDescriptor().uid_;
    int32_t pid = session->GetDescriptor().pid_;
    std::string bundleName = BundleStatusAdapter::GetInstance().GetBundleNameFromUid(uid);
    CHECK_AND_RETURN_RET_LOG(bundleName != "", AVSESSION_ERROR, "GetBundleNameFromUid failed");

    char sourceLibraryRealPath[PATH_MAX] = { 0x00 };
    if (realpath(SOURCE_LIBRARY_PATH.c_str(), sourceLibraryRealPath) == nullptr) {
        SLOGE("check libsuspend_manager_client path failed %{public}s", SOURCE_LIBRARY_PATH.c_str());
        return AVSESSION_ERROR;
    }
    void *handle_ = dlopen(sourceLibraryRealPath, RTLD_NOW);
    if (handle_ == nullptr) {
        SLOGE("failed to open library libsuspend_manager_client reaseon %{public}s", dlerror());
        return AVSESSION_ERROR;
    }
    SLOGI("open library libsuspend_manager_client success");
    typedef ErrCode (*handler) (int32_t eventType, int32_t uid, int32_t pid,
        const std::string bundleName, int32_t taskState, int32_t serviceId);
    handler reportContinuousTaskEventEx = reinterpret_cast<handler>(dlsym(handle_, "ReportContinuousTaskEventEx"));
    ErrCode errCode = reportContinuousTaskEventEx(0, uid, pid, bundleName, 1, AVSESSION_SERVICE_ID);
    SLOGI("reportContinuousTaskEventEx done, result: %{public}d", errCode);
    dlclose(handle_);
#endif
    HISYSEVENT_BEHAVIOR("SESSION_CAST",
        "BUNDLE_NAME", session->GetDescriptor().elementName_.GetBundleName(),
        "MODULE_NAME", session->GetDescriptor().elementName_.GetModuleName(),
        "ABILITY_NAME", session->GetDescriptor().elementName_.GetAbilityName(),
        "SESSION_PID", session->GetDescriptor().pid_, "SESSION_UID", session->GetDescriptor().uid_,
        "SESSION_ID", session->GetDescriptor().sessionId_, "SESSION_TAG", session->GetDescriptor().sessionTag_,
        "SESSION_TYPE", session->GetDescriptor().sessionType_, "DETAILED_MSG", "start cast session");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::StopCast(const SessionToken& sessionToken)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("StopCast: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice StopCast checksystempermission failed");
        return ERR_NO_PERMISSION;
    }

    sptr<AVSessionItem> session = GetContainer().GetSessionById(sessionToken.sessionId);
    CHECK_AND_RETURN_RET_LOG(session != nullptr, AVSESSION_SUCCESS, "StopCast: session is not exist");
    CHECK_AND_RETURN_RET_LOG(session->StopCast() == AVSESSION_SUCCESS, AVSESSION_ERROR, "StopCast failed");
    if (session->GetDescriptor().sessionTag_ == "RemoteCast") {
        SLOGI("Stop cast at sink, start destroy sink avsession task");
        HandleSessionRelease(sessionToken.sessionId);
        return AVSESSION_SUCCESS;
    }

#ifdef EFFICIENCY_MANAGER_ENABLE
    SLOGI("Stop register continuous task");
    int32_t uid = session->GetDescriptor().uid_;
    int32_t pid = session->GetDescriptor().pid_;
    std::string bundleName = BundleStatusAdapter::GetInstance().GetBundleNameFromUid(uid);
    CHECK_AND_RETURN_RET_LOG(bundleName != "", AVSESSION_ERROR, "GetBundleNameFromUid failed");

    char sourceLibraryRealPath[PATH_MAX] = { 0x00 };
    if (realpath(SOURCE_LIBRARY_PATH.c_str(), sourceLibraryRealPath) == nullptr) {
        SLOGE("check libsuspend_manager_client path failed %{public}s when stop cast", SOURCE_LIBRARY_PATH.c_str());
        return AVSESSION_ERROR;
    }
    void *handle_ = dlopen(sourceLibraryRealPath, RTLD_NOW);
    if (handle_ == nullptr) {
        SLOGE("failed to open library libsuspend_manager_client when stop cast, reaseon %{public}s", dlerror());
        return AVSESSION_ERROR;
    }
    SLOGI("open library libsuspend_manager_client success when stop cast");
    typedef ErrCode (*handler) (int32_t eventType, int32_t uid, int32_t pid,
        const std::string bundleName, int32_t taskState, int32_t serviceId);
    handler reportContinuousTaskEventEx = reinterpret_cast<handler>(dlsym(handle_, "ReportContinuousTaskEventEx"));
    ErrCode errCode = reportContinuousTaskEventEx(0, uid, pid, bundleName, 2, AVSESSION_SERVICE_ID);
    SLOGI("reportContinuousTaskEventEx done when stop cast, result: %{public}d", errCode);
    dlclose(handle_);
#endif
    return AVSESSION_SUCCESS;
}

void AVSessionService::NotifyMirrorToStreamCast()
{
    if (topSession_ == nullptr) {
        SLOGE("topsession null pointer");
        return;
    }
    if (topSession_->GetSessionType() == "video" &&
        !AppManagerAdapter::GetInstance().IsAppBackground(topSession_->GetUid(), topSession_->GetPid())) {
        MirrorToStreamCast(topSession_);
    }
}

__attribute__((no_sanitize("cfi"))) int32_t AVSessionService::MirrorToStreamCast(sptr<AVSessionItem>& session)
{
    SLOGI("enter MirrorToStreamCast");
    if (is2in1_ != 0) {
        if (castServiceNameMapState_["HuaweiCast"] == deviceStateConnection ||
            castServiceNameMapState_["HuaweiCast-Dual"] == deviceStateConnection) {
            checkEnableCast(true);
            return session->RegisterListenerStreamToCast(castServiceNameMapState_);
        }
    }
    return AVSESSION_SUCCESS;
}
#endif

void AVSessionService::HandleCallStartEvent()
{
    SLOGI("Start handle CallStartEvent");
    AbilityConnectHelper::GetInstance().StartAbilityForegroundByCall(MEDIA_CONTROL_BUNDLENAME,
        MEDIA_CONTROL_ABILITYNAME);
}

sptr<AVSessionItem> AVSessionService::CreateNewSession(const std::string& tag, int32_t type, bool thirdPartyApp,
                                                       const AppExecFwk::ElementName& elementName)
{
    SLOGI("%{public}s %{public}d %{public}s %{public}s", tag.c_str(), type,
          elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
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

    sptr<AVSessionItem> result = new(std::nothrow) AVSessionItem(descriptor);
    if (result == nullptr) {
        return nullptr;
    }
    result->SetPid(GetCallingPid());
    result->SetUid(GetCallingUid());
    result->SetServiceCallbackForRelease([this](AVSessionItem& session) {
        SLOGI("Start handle session release event");
        HandleSessionRelease(session.GetDescriptor().sessionId_);
    });
    result->SetServiceCallbackForAVQueueInfo([this](AVSessionItem& session) {
        AddAvQueueInfoToFile(session);
    });
    result->SetServiceCallbackForCallStart([this](AVSessionItem& session) {
        SLOGI("Start handle call start event for %{public}s",
            AVSessionUtils::GetAnonySessionId(session.GetDescriptor().sessionId_).c_str());
        HandleCallStartEvent();
    });
    SLOGI("success sessionId=%{public}s",  AVSessionUtils::GetAnonySessionId(result->GetSessionId()).c_str());
    {
        std::lock_guard lockGuard(sessionAndControllerLock_);
        if (topSession_ == nullptr) {
            UpdateTopSession(result);
        }
    }

    OutputDeviceInfo outputDeviceInfo;
    DeviceInfo deviceInfo;
    deviceInfo.castCategory_ = AVCastCategory::CATEGORY_LOCAL;
    deviceInfo.deviceId_ = "0";
    deviceInfo.deviceName_ = "LocalDevice";
    outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
    result->SetOutputDevice(outputDeviceInfo);

    return result;
}

sptr <AVSessionItem> AVSessionService::CreateSessionInner(const std::string& tag, int32_t type, bool thirdPartyApp,
                                                          const AppExecFwk::ElementName& elementName)
{
    SLOGI("CreateSessionInner enter");
    CHECK_AND_RETURN_RET_LOG(!tag.empty(), nullptr, "tag is empty");
    CHECK_AND_RETURN_RET_LOG(type == AVSession::SESSION_TYPE_AUDIO || type == AVSession::SESSION_TYPE_VIDEO
        || type == AVSession::SESSION_TYPE_VOICE_CALL, nullptr, "type is invalid");
    CHECK_AND_RETURN_RET_LOG(!elementName.GetBundleName().empty() && !elementName.GetAbilityName().empty(),
        nullptr, "element is invalid");
    std::regex nameRegex("[A-Za-z\\w\\.]*");
    if (!std::regex_match(elementName.GetBundleName(), nameRegex)) {
        SLOGE("CreateSessionInner err regex, bundleName=%{public}s", (elementName.GetBundleName()).c_str());
        return nullptr;
    }
    if (!std::regex_match(elementName.GetAbilityName(), nameRegex)) {
        SLOGE("CreateSessionInner err regex, abilityName=%{public}s", (elementName.GetAbilityName()).c_str());
        return nullptr;
    }
    auto pid = GetCallingPid();
    std::lock_guard lockGuard(sessionAndControllerLock_);
    if (AbilityHasSession(pid)) {
        SLOGI("process %{public}d %{public}s already has one session", pid, elementName.GetAbilityName().c_str());
        return nullptr;
    }

    auto result = CreateNewSession(tag, type, thirdPartyApp, elementName);
    if (result == nullptr) {
        SLOGE("create new session failed");
        dumpHelper_->SetErrorInfo("  AVSessionService::CreateSessionInner  create new session failed");
        HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "CALLER_PID", pid, "TAG", tag, "TYPE", type, "BUNDLE_NAME",
            elementName.GetBundleName(), "ERROR_MSG", "avsessionservice createsessioninner create new session failed");
        return nullptr;
    }
    if (GetContainer().AddSession(pid, elementName.GetAbilityName(), result) != AVSESSION_SUCCESS) {
        SLOGI("session num exceed max");
        return nullptr;
    }
    HISYSEVENT_ADD_LIFE_CYCLE_INFO(elementName.GetBundleName(),
        AppManagerAdapter::GetInstance().IsAppBackground(GetCallingUid(), GetCallingPid()), type, true);

    NotifySessionCreate(result->GetDescriptor());
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    if (type == AVSession::SESSION_TYPE_VIDEO &&
        !AppManagerAdapter::GetInstance().IsAppBackground(GetCallingUid(), GetCallingPid())) {
        uidForAppStateChange_ = result->GetUid();
        firstAppStateChangeFlag_ = true;
        MirrorToStreamCast(result);
    }
#endif //CASTPLUS_CAST_ENGINE_ENABLE
    SLOGI("success");
    return result;
}

sptr <IRemoteObject> AVSessionService::CreateSessionInner(const std::string& tag, int32_t type,
                                                          const AppExecFwk::ElementName& elementName)
{
    auto session = CreateSessionInner(tag, type, !PermissionChecker::GetInstance().CheckSystemPermission(),
                                      elementName);
    CHECK_AND_RETURN_RET_LOG(session != nullptr, session, "session is nullptr");

    std::string supportModule;
    std::string profile;
    if (BundleStatusAdapter::GetInstance().IsSupportPlayIntent(elementName.GetBundleName(), supportModule, profile) ||
        DEFAULT_BUNDLE_NAME == elementName.GetBundleName()) {
        SLOGI("bundleName=%{public}s support play intent, refreshSortFile", elementName.GetBundleName().c_str());
        refreshSortFileOnCreateSession(session->GetSessionId(), session->GetSessionType(), elementName);
    }

    {
        std::lock_guard lockGuard1(abilityManagerLock_);
        std::string bundleName = session->GetDescriptor().elementName_.GetBundleName();
        std::string abilityName = session->GetDescriptor().elementName_.GetAbilityName();
        auto it = abilityManager_.find(bundleName + abilityName);
        if (it != abilityManager_.end()) {
            it->second->StartAbilityByCallDone(session->GetDescriptor().sessionId_);
        }
    }

    {
        std::lock_guard lockGuard(isAllSessionCastLock_);
        SLOGI("isAllSessionCast_ is %{public}d", isAllSessionCast_);
        CHECK_AND_RETURN_RET_LOG(isAllSessionCast_, session, "no need to cast");
    }
    CHECK_AND_RETURN_RET_LOG(CastAudioForNewSession(session) == AVSESSION_SUCCESS, session, "cast new session error");
    return session;
}

void AVSessionService::refreshSortFileOnCreateSession(const std::string& sessionId, const std::string& sessionType,
                                                      const AppExecFwk::ElementName& elementName)
{
    std::lock_guard sortFileLockGuard(sortFileReadWriteLock_);
    SLOGI("refresh sort when session created, bundleName=%{public}s", (elementName.GetBundleName()).c_str());
    std::string oldSortContent;
    if (LoadStringFromFileEx(AVSESSION_FILE_DIR + SORT_FILE_NAME, oldSortContent)) {
        nlohmann::json values = json::parse(oldSortContent, nullptr, false);
        CHECK_AND_RETURN_LOG(!values.is_discarded(), "sort json object is null");
        if (oldSortContent.find(elementName.GetBundleName()) == string::npos) {
            auto callback = [this](std::string bundleName) {
                DeleteAVQueueInfoRecord(bundleName);
                DeleteHistoricalRecord(bundleName);
            };
            if (!BundleStatusAdapter::GetInstance().SubscribeBundleStatusEvent(elementName.GetBundleName(), callback)) {
                SLOGE("SubscribeBundleStatusEvent failed");
            }
        }
        for (auto value : values) {
            if (elementName.GetBundleName() == value["bundleName"] &&
                elementName.GetAbilityName() == value["abilityName"]) {
                values.erase(std::remove(values.begin(), values.end(), value));
            }
        }
        if (values.size() >= (size_t)maxHistoryNums) {
            values.erase(values.end() - 1);
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
        SLOGD("refreshSortFileOnCreateSession::Dump json object finished");
        if (!SaveStringToFileEx(AVSESSION_FILE_DIR + SORT_FILE_NAME, newSortContent)) {
            SLOGE("SaveStringToFile failed, filename=%{public}s", SORT_FILE_NAME);
        }
    } else {
        SLOGE("LoadStringToFile failed, filename=%{public}s", SORT_FILE_NAME);
    }
}

int32_t AVSessionService::GetAllSessionDescriptors(std::vector<AVSessionDescriptor>& descriptors)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("GetAllSessionDescriptors: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice getallsessiondescriptors checksystempermission failed");
        return ERR_NO_PERMISSION;
    }

    std::lock_guard lockGuard(sessionAndControllerLock_);
    for (const auto& session: GetContainer().GetAllSessions()) {
        descriptors.push_back(session->GetDescriptor());
    }
    for (const auto& desc: descriptors) {
        SLOGD("desc=%{public}s", desc.elementName_.GetBundleName().c_str());
    }
    SLOGI("size=%{public}d", static_cast<int32_t>(descriptors.size()));
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::GetSessionDescriptorsBySessionId(const std::string& sessionId,
                                                           AVSessionDescriptor& descriptor)
{
    std::lock_guard lockGuard(sessionAndControllerLock_);
    sptr<AVSessionItem> session = GetContainer().GetSessionById(sessionId);
    CHECK_AND_RETURN_RET_LOG(session != nullptr, AVSESSION_ERROR, "session not exist");

    SLOGI("find descriptor by id %{public}s",  AVSessionUtils::GetAnonySessionId(sessionId).c_str());
    auto pid = GetCallingPid();
    if (pid == session->GetPid()) {
        descriptor = session->GetDescriptor();
        return AVSESSION_SUCCESS;
    }
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("GetSessionDescriptorsBySessionId: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(),
            "CALLER_PID", pid, "SESSION_ID", sessionId,
            "ERROR_MSG", "avsessionservice getsessiondescriptors by sessionid checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    descriptor = session->GetDescriptor();
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::GetHistoricalSessionDescriptorsFromFile(std::vector<AVSessionDescriptor>& descriptors)
{
    std::string oldSortContent;
    if (!LoadStringFromFileEx(AVSESSION_FILE_DIR + SORT_FILE_NAME, oldSortContent)) {
        SLOGE("GetHistoricalSessionDescriptorsFromFile read sort fail, Return!");
        return AVSESSION_ERROR;
    }

    nlohmann::json sortValues = json::parse(oldSortContent, nullptr, false);
    CHECK_AND_RETURN_RET_LOG(!sortValues.is_discarded(), AVSESSION_ERROR, "json object is null");
    for (const auto& value : sortValues) {
        if (value["sessionType"] == "video") {
            SLOGI("GetHistoricalSessionDescriptorsFromFile with no video type session");
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
        SLOGE("GetHistoricalSessionDescriptorsFromFile read empty, return default!");
        AVSessionDescriptor descriptor;
        descriptor.sessionId_ = DEFAULT_SESSION_ID;
        descriptor.elementName_.SetBundleName(DEFAULT_BUNDLE_NAME);
        descriptor.elementName_.SetAbilityName(DEFAULT_ABILITY_NAME);
        descriptor.sessionType_ = AVSession::SESSION_TYPE_AUDIO;
        descriptors.push_back(descriptor);
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::GetHistoricalSessionDescriptors(int32_t maxSize,
                                                          std::vector<AVSessionDescriptor>& descriptors)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("GetAllSessionDescriptors: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice GetHistoricalSessionDescriptors checksystempermission failed");
        return ERR_NO_PERMISSION;
    }

    std::lock_guard lockGuard(sessionAndControllerLock_);
    std::lock_guard sortFileLockGuard(sortFileReadWriteLock_);

    std::vector<AVSessionDescriptor> tempDescriptors;
    GetHistoricalSessionDescriptorsFromFile(tempDescriptors);
    if (maxSize < 0 || maxSize > maxHistoryNums) {
        maxSize = unSetHistoryNum;
    }
    for (auto iterator = tempDescriptors.begin(); iterator != tempDescriptors.end(); ++iterator) {
        if (descriptors.size() >= (size_t)maxSize) {
            break;
        }
        descriptors.push_back(*iterator);
    }
    SLOGI("get historical session size=%{public}d", static_cast<int>(descriptors.size()));
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::GetHistoricalAVQueueInfos(int32_t maxSize, int32_t maxAppSize,
                                                    std::vector<AVQueueInfo>& avQueueInfos)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("GetHistoricalAVQueueInfos: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice GetHistoricalAVQueueInfos checksystempermission failed");
        return ERR_NO_PERMISSION;
    }

    std::lock_guard avQueueFileLockGuard(avQueueFileReadWriteLock_);
    std::string oldAVQueueInfoContent;
    std::vector<AVQueueInfo> tempAVQueueInfos;
    if (!LoadStringFromFileEx(AVSESSION_FILE_DIR + AVQUEUE_FILE_NAME, oldAVQueueInfoContent)) {
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
        AVSessionUtils::ReadImageFromFile(avQueuePixelMap, value["avQueueImage"]);
        avQueueInfo.SetAVQueueImage(avQueuePixelMap);
        avQueueInfo.SetAVQueueImageUri(value["avQueueImageUri"]);
        tempAVQueueInfos.push_back(avQueueInfo);
    }
    for (auto iterator = tempAVQueueInfos.begin(); iterator != tempAVQueueInfos.end(); ++iterator) {
        avQueueInfos.push_back(*iterator);
    }
    SLOGI("get historical avqueueinfo size=%{public}d", static_cast<int>(avQueueInfos.size()));
    return AVSESSION_SUCCESS;
}

bool AVSessionService::SaveAvQueueInfo(std::string& oldContent, const std::string &bundleName, const AVMetaData& meta)
{
    nlohmann::json values = json::parse(oldContent, nullptr, false);
    CHECK_AND_RETURN_RET_LOG(!values.is_discarded(), false, "avQueue json object is null");
    auto it = values.begin();
    for (auto& value : values) {
        if (bundleName == value["bundleName"] && meta.GetAVQueueId() == value["avQueueId"]) {
            if (meta.GetAVQueueId() == it->at("avQueueId")) {
                SLOGI("SaveAvQueueInfo avqueue=%{public}s is first, return", meta.GetAVQueueId().c_str());
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
        std::string fileName = AVSessionUtils::GetFixedPathName() + bundleName + "_" +
            meta.GetAVQueueId() + AVSessionUtils::GetFileSuffix();
        AVSessionUtils::WriteImageToFile(innerPixelMap, fileName);
        innerPixelMap->Clear();
        value["avQueueImage"] = fileName;
    } else {
        value["avQueueImage"] = "";
    }
    value["avQueueImageUri"] = meta.GetAVQueueImageUri();
    if (values.size() <= 0) {
        values.push_back(value);
    } else {
        values.insert(values.begin(), value);
    }
    std::string newContent = values.dump();
    SLOGD("SaveAvQueueInfo::Dump json object finished");
    if (!SaveStringToFileEx(AVSESSION_FILE_DIR + AVQUEUE_FILE_NAME, newContent)) {
        SLOGE("SaveStringToFile failed, filename=%{public}s", AVQUEUE_FILE_NAME);
        return false;
    }
    return true;
}

void AVSessionService::AddAvQueueInfoToFile(AVSessionItem& session)
{
    SLOGD("add queueinfo to file in");
    // check is this session support playmusiclist intent
    std::lock_guard lockGuard(sessionAndControllerLock_);
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
        return;
    }
    std::lock_guard avQueueFileLockGuard(avQueueFileReadWriteLock_);
    std::string oldContent;
    if (!LoadStringFromFileEx(AVSESSION_FILE_DIR + AVQUEUE_FILE_NAME, oldContent)) {
        SLOGE("AddAvQueueInfoToFile read avqueueinfo fail, Return!");
        return;
    }
    if (!SaveAvQueueInfo(oldContent, bundleName, meta)) {
        SLOGE("SaveAvQueueInfo same avqueueinfo, Return!");
        return;
    }
    SLOGD("add queueinfo to file done");
}

int32_t AVSessionService::StartAVPlayback(const std::string& bundleName, const std::string& assetId)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("StartAVPlayback: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice StartAVPlayback checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    // get execute param
    AppExecFwk::InsightIntentExecuteParam executeParam;
    bool isSupport = BundleStatusAdapter::GetInstance().GetPlayIntentParam(bundleName, assetId, executeParam);
    if (!isSupport || executeParam.insightIntentName_.empty()) {
        SLOGE("StartAVPlayback GetPlayIntentParam fail, Return!");
        return AVSESSION_ERROR;
    }
    int32_t ret = AbilityConnectHelper::GetInstance().StartAVPlayback(executeParam);
    if (ret != AVSESSION_SUCCESS) {
        SLOGE("StartAVPlayback fail: %{public}d", ret);
    }
    return ret;
}

sptr<AVControllerItem> AVSessionService::CreateNewControllerForSession(pid_t pid, sptr<AVSessionItem>& session)
{
    SLOGI("pid=%{public}d sessionId=%{public}s", pid,
        AVSessionUtils::GetAnonySessionId(session->GetSessionId()).c_str());
    sptr<AVControllerItem> result = new(std::nothrow) AVControllerItem(pid, session);
    if (result == nullptr) {
        SLOGE("malloc controller failed");
        return nullptr;
    }
    result->SetServiceCallbackForRelease([this](AVControllerItem& controller) { HandleControllerRelease(controller); });
    session->AddController(pid, result);
    return result;
}

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

bool AVSessionService::IsHistoricalSession(const std::string& sessionId)
{
    {
        std::string sortContent;
        std::lock_guard sortFileLockGuard(sortFileReadWriteLock_);
        if (!LoadStringFromFileEx(AVSESSION_FILE_DIR + SORT_FILE_NAME, sortContent)) {
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
        std::lock_guard sortFileLockGuard(sortFileReadWriteLock_);
        if (!LoadStringFromFileEx(AVSESSION_FILE_DIR + SORT_FILE_NAME, sortContent)) {
            SLOGE("GetAllSessionDescriptors read sort fail! ");
            return AVSESSION_ERROR;
        }
    }

    if (!sortContent.empty()) {
        nlohmann::json sortValues = json::parse(sortContent, nullptr, false);
        CHECK_AND_RETURN_RET_LOG(!sortValues.is_discarded(), AVSESSION_ERROR, "json object is null");
        for (auto& value : sortValues) {
            auto session = GetContainer().GetSessionById(value["sessionId"]);
            if (session == nullptr) {
                bundleName = value["bundleName"];
                abilityName = value["abilityName"];
                break;
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
    int32_t ret = ability->StartAbilityByCall(sessionId);

    std::lock_guard lockGuard(abilityManagerLock_);
    if (ret != ERR_START_ABILITY_IS_RUNNING) {
        abilityManager_.erase(bundleName + abilityName);
    }
    return ret;
}

int32_t AVSessionService::StartAbilityByCall(const std::string& sessionIdNeeded, std::string& sessionId)
{
    std::string content;
    
    {
        std::lock_guard sortFileLockGuard(sortFileReadWriteLock_);
        if (!LoadStringFromFileEx(AVSESSION_FILE_DIR + SORT_FILE_NAME, content)) {
            SLOGE("LoadStringFromFile failed, filename=%{public}s", SORT_FILE_NAME);
            return AVSESSION_ERROR;
        }
    }

    nlohmann::json values = json::parse(content, nullptr, false);
    CHECK_AND_RETURN_RET_LOG(!values.is_discarded(), AVSESSION_ERROR, "json object is null");
    std::string bundleName;
    std::string abilityName;
    for (auto& value : values) {
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
    int32_t ret = ability->StartAbilityByCall(sessionId);

    std::lock_guard lockGuard(abilityManagerLock_);
    if (ret != ERR_START_ABILITY_IS_RUNNING) {
        abilityManager_.erase(bundleName + abilityName);
    }
    return ret;
}
    
int32_t AVSessionService::CreateControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("CreateControllerInner: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(),
            "CALLER_PID", GetCallingPid(), "SESSION_ID", sessionId,
            "ERROR_MSG", "avsessionservice createcontrollerinner checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    std::string sessionIdInner;
    if (sessionId == "default") {
        auto ret = StartDefaultAbilityByCall(sessionIdInner);
        if (ret != AVSESSION_SUCCESS) {
            SLOGE("StartDefaultAbilityByCall failed: %{public}d", ret);
            return ret;
        }
    } else {
        if (IsHistoricalSession(sessionId)) {
            auto ret = StartAbilityByCall(sessionId, sessionIdInner);
            if (ret != AVSESSION_SUCCESS) {
                SLOGE("StartAbilityByCall failed: %{public}d", ret);
                return ret;
            }
        } else {
            sessionIdInner = sessionId;
        }
    }
    auto pid = GetCallingPid();
    std::lock_guard lockGuard(sessionAndControllerLock_);
    auto controllerAlreadyExist = GetPresentController(pid, sessionIdInner);
    if (controllerAlreadyExist != nullptr) {
        SLOGI("controller already exist, try pass instance and return exist");
        object = controllerAlreadyExist;
        return ERR_CONTROLLER_IS_EXIST;
    }

    auto session = GetContainer().GetSessionById(sessionIdInner);
    if (session == nullptr) {
        SLOGE("no session id %{public}s", AVSessionUtils::GetAnonySessionId(sessionIdInner).c_str());
        return ERR_SESSION_NOT_EXIST;
    }

    auto result = CreateNewControllerForSession(pid, session);
    if (result == nullptr) {
        SLOGE("create new controller failed");
        return ERR_NO_MEMORY;
    }

    controllers_[pid].push_back(result);
    object = result;
    SLOGI("success");
    return AVSESSION_SUCCESS;
}

#ifdef CASTPLUS_CAST_ENGINE_ENABLE
int32_t AVSessionService::GetAVCastControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object)
{
    SLOGI("Start get cast controller");
    auto session = GetContainer().GetSessionById(sessionId);
    CHECK_AND_RETURN_RET_LOG(session != nullptr, AVSESSION_ERROR, "StopCast: session is not exist");
    auto result = session->GetAVCastControllerInner();
    CHECK_AND_RETURN_RET_LOG(result != nullptr, AVSESSION_ERROR, "GetAVCastControllerInner failed");
    object = result;
    return AVSESSION_SUCCESS;
}
#endif

void AVSessionService::AddSessionListener(pid_t pid, const sptr<ISessionListener>& listener)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    sessionListeners_[pid] = listener;
}

void AVSessionService::RemoveSessionListener(pid_t pid)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    sessionListeners_.erase(pid);
}

int32_t AVSessionService::RegisterSessionListener(const sptr<ISessionListener>& listener)
{
    SLOGI("Enter RegisterSessionListener process");
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("RegisterSessionListener: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice registersessionlistener checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    AddSessionListener(GetCallingPid(), listener);
    return AVSESSION_SUCCESS;
}

void AVSessionService::HandleEventHandlerCallBack()
{
    SLOGI("handle eventHandler callback isFirstPress_=%{public}d", isFirstPress_);
    AVControlCommand cmd;
    std::lock_guard lockGuard(sessionAndControllerLock_);
    if (pressCount_ >= THREE_CLICK && topSession_) {
        cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY_PREVIOUS);
        if (topSession_->GetDescriptor().sessionTag_ == "external_audio") {
            SLOGI("HandleEventHandlerCallBack this is an external audio");
        } else {
            topSession_->ExecuteControllerCommand(cmd);
        }
    } else if (pressCount_ == DOUBLE_CLICK && topSession_) {
        cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY_NEXT);
        if (topSession_->GetDescriptor().sessionTag_ == "external_audio") {
            SLOGI("HandleEventHandlerCallBack this is an external audio");
        } else {
            topSession_->ExecuteControllerCommand(cmd);
        }
    } else if (pressCount_ == ONE_CLICK) {
        SLOGI("HandleEventHandlerCallBack on ONE_CLICK ");
        if (!topSession_) {
            SLOGI("HandleEventHandlerCallBack ONE_CLICK without topSession_");
            sptr<IRemoteObject> object;
            int32_t ret = CreateControllerInner("default", object);
            SLOGI("HandleEventHandlerCallBack ONE_CLICK !topSession_ ret : %{public}d", static_cast<int32_t>(ret));
        }
        if (topSession_) {
            SLOGI("HandleEventHandlerCallBack ONE_CLICK with topSession_ ");
            auto playbackState = topSession_->GetPlaybackState();
            if (playbackState.GetState() == AVPlaybackState::PLAYBACK_STATE_PLAY) {
                cmd.SetCommand(AVControlCommand::SESSION_CMD_PAUSE);
            } else {
                cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY);
            }
            if (topSession_->GetDescriptor().sessionTag_ == "external_audio") {
                SLOGI("HandleEventHandlerCallBack this is an external audio");
            } else {
                topSession_->ExecuteControllerCommand(cmd);
            }
        }
    } else {
        SLOGI("press invalid");
    }
    pressCount_ = 0;
    isFirstPress_ = true;
}

int32_t AVSessionService::SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("SendSystemAVKeyEvent: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "KEY_CODE", keyEvent.GetKeyCode(), "KEY_ACTION", keyEvent.GetKeyAction(),
            "ERROR_MSG", "avsessionservice sendsystemavkeyevent checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    SLOGI("key=%{public}d", keyEvent.GetKeyCode());
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
    std::lock_guard lockGuard(sessionAndControllerLock_);
    if (topSession_) {
        topSession_->HandleMediaKeyEvent(keyEvent);
    } else {
        SLOGI("topSession is nullptr");
    }
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::SendSystemControlCommand(const AVControlCommand &command)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("SendSystemControlCommand: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(),
            "CALLER_PID", GetCallingPid(), "CMD", command.GetCommand(),
            "ERROR_MSG", "avsessionservice sendsystemcontrolcommand checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    SLOGI("cmd=%{public}d", command.GetCommand());
    std::lock_guard lockGuard(sessionAndControllerLock_);
    if (topSession_) {
        CHECK_AND_RETURN_RET_LOG(CommandSendLimit::GetInstance().IsCommandSendEnable(GetCallingPid()),
            ERR_COMMAND_SEND_EXCEED_MAX, "command excuted number exceed max");
        topSession_->ExecuteControllerCommand(command);
    } else if (command.GetCommand() == AVControlCommand::SESSION_CMD_PLAY) {
        SLOGI("SendSystemControlCommand code start without topSession_");
        sptr<IRemoteObject> object;
        int32_t ret = CreateControllerInner("default", object);
        SLOGI("SendSystemControlCommand code start ret : %{public}d", static_cast<int32_t>(ret));
    }
    return AVSESSION_SUCCESS;
}

void AVSessionService::AddClientDeathObserver(pid_t pid, const sptr<IClientDeath>& observer)
{
    std::lock_guard lockGuard(clientDeathObserversLock_);
    clientDeathObservers_[pid] = observer;
}

void AVSessionService::RemoveClientDeathObserver(pid_t pid)
{
    std::lock_guard lockGuard(clientDeathObserversLock_);
    if (clientDeathObservers_.empty()) {
        SLOGE("try remove observer with empty list");
        return;
    }
    clientDeathObservers_.erase(pid);
}

int32_t AVSessionService::RegisterClientDeathObserver(const sptr<IClientDeath>& observer)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("RegisterClientDeathObserver: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice RegisterClientDeathObserver checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    SLOGI("enter ClientDeathObserver register");
    auto pid = GetCallingPid();
    auto* recipient = new(std::nothrow) ClientDeathRecipient([this, pid]() { OnClientDied(pid); });
    if (recipient == nullptr) {
        SLOGE("malloc failed");
        HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "ERROR_TYPE", "RGS_CLIENT_DEATH_OBSERVER_FAILED",
            "ERROR_INFO", "avsession service register client death observer malloc failed");
        return AVSESSION_ERROR;
    }

    if (!observer->AsObject()->AddDeathRecipient(recipient)) {
        SLOGE("add death recipient for %{public}d failed", pid);
        HISYSEVENT_FAULT("CONTROL_COMMAND_FAILED", "ERROR_TYPE", "RGS_CLIENT_DEATH_FAILED", "CALLING_PID", pid,
            "ERROR_INFO", "avsession service register client death observer, add death recipient failed");
        return AVSESSION_ERROR;
    }

    AddClientDeathObserver(pid, observer);
    return AVSESSION_SUCCESS;
}

void AVSessionService::ClearClientResources(pid_t pid)
{
    RemoveSessionListener(pid);
    {
        std::lock_guard lockGuard(sessionAndControllerLock_);
        ClearSessionForClientDiedNoLock(pid);
        ClearControllerForClientDiedNoLock(pid);
    }
    SLOGI("remove ClientDeathObserver to %{public}d", pid);
    RemoveClientDeathObserver(pid);
}

int32_t AVSessionService::Close(void)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("Close: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
                            "ERROR_MSG", "avsessionservice Close checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    auto pid = GetCallingPid();
    SLOGI("pid=%{public}d", pid);
    ClearClientResources(pid);
    return AVSESSION_SUCCESS;
}

void AVSessionService::OnClientDied(pid_t pid)
{
    SLOGI("pid=%{public}d", pid);
    ClearClientResources(pid);
}

void AVSessionService::DeleteHistoricalRecord(const std::string& bundleName)
{
    std::lock_guard sortFileLockGuard(sortFileReadWriteLock_);
    SLOGI("delete historical record, bundleName=%{public}s", bundleName.c_str());
    std::string oldContent;
    std::string newContent;
    nlohmann::json values;
    if (!LoadStringFromFileEx(AVSESSION_FILE_DIR + SORT_FILE_NAME, oldContent)) {
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
    if (!SaveStringToFileEx(AVSESSION_FILE_DIR + SORT_FILE_NAME, newContent)) {
        SLOGE("SaveStringToFile failed, filename=%{public}s", SORT_FILE_NAME);
        return;
    }
}

void AVSessionService::DeleteAVQueueInfoRecord(const std::string& bundleName)
{
    std::lock_guard avQueueFileLockGuard(avQueueFileReadWriteLock_);
    SLOGI("DeleteAVQueueInfoRecord, bundleName=%{public}s", bundleName.c_str());
    std::string oldContent;
    std::string newContent;
    nlohmann::json values;
    if (!LoadStringFromFileEx(AVSESSION_FILE_DIR + AVQUEUE_FILE_NAME, oldContent)) {
        SLOGE("LoadStringFromFile failed, filename=%{public}s", AVQUEUE_FILE_NAME);
        return;
    }
    values = json::parse(oldContent, nullptr, false);
    CHECK_AND_RETURN_LOG(!values.is_discarded(), "json object is null");
    for (auto it = values.begin(); it != values.end();) {
        if (it->at("bundleName") == bundleName) {
            std::string avQueueId = it->at("avQueueId");
            std::string fileName = AVSessionUtils::GetFixedPathName() + bundleName + "_" +
                avQueueId + AVSessionUtils::GetFileSuffix();
            AVSessionUtils::DeleteFile(fileName);
            values.erase(it);
        } else {
            ++it;
        }
    }
    newContent = values.dump();
    SLOGD("DeleteAVQueueInfoRecord::Dump json object finished");
    if (!SaveStringToFileEx(AVSESSION_FILE_DIR + AVQUEUE_FILE_NAME, newContent)) {
        SLOGE("SaveStringToFile failed, filename=%{public}s", AVQUEUE_FILE_NAME);
        return;
    }
}

void AVSessionService::HandleSessionRelease(std::string sessionId)
{
    SLOGI("HandleSessionRelease, sessionId=%{public}s", AVSessionUtils::GetAnonySessionId(sessionId).c_str());
    std::lock_guard lockGuard(sessionAndControllerLock_);

    sptr<AVSessionItem> sessionItem = GetContainer().GetSessionById(sessionId);
    CHECK_AND_RETURN_LOG(sessionItem != nullptr, "Session item is nullptr");
    NotifySessionRelease(sessionItem->GetDescriptor());
    sessionItem->DestroyTask();
    if (topSession_.GetRefPtr() == sessionItem.GetRefPtr()) {
        SLOGD("Top session is released session");
        UpdateTopSession(nullptr);
    }
    if (sessionItem->GetRemoteSource() != nullptr) {
        int32_t ret = CancelCastAudioForClientExit(sessionItem->GetPid(), sessionItem);
        SLOGI("CancelCastAudioForClientExit ret is %{public}d", ret);
    } else {
        SLOGI("GetContainer has no this session");
    }
    HISYSEVENT_ADD_LIFE_CYCLE_INFO(sessionItem->GetDescriptor().elementName_.GetBundleName(),
        AppManagerAdapter::GetInstance().IsAppBackground(GetCallingUid(), GetCallingPid()),
        sessionItem->GetDescriptor().sessionType_, false);
    SLOGI("HandleSessionRelease, remove session: sessionId=%{public}s",
        AVSessionUtils::GetAnonySessionId(sessionId).c_str());
    GetContainer().RemoveSession(sessionItem->GetPid(), sessionItem->GetAbilityName());
#ifdef CASTPLUS_CAST_ENGINE_ENABLE
    if (GetContainer().GetAllSessions().size() == 0 && is2in1_ != 0) {
        SLOGI("call disable cast for no session alive");
        checkEnableCast(false);
    }
#endif
}

void AVSessionService::HandleControllerRelease(AVControllerItem& controller)
{
    auto pid = controller.GetPid();
    std::lock_guard lockGuard(sessionAndControllerLock_);
    auto it = controllers_.find(pid);
    if (it == controllers_.end()) {
        return;
    }
    SLOGI("remove controller");
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
    SLOGI("enter");
    auto mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (mgr == nullptr) {
        SLOGE("failed to get sa mgr");
        return nullptr;
    }
    auto object = mgr->GetSystemAbility(AVSESSION_SERVICE_ID, deviceId);
    if (object == nullptr) {
        SLOGE("failed to get service");
        return nullptr;
    }
    SLOGI("check remoteService create");
    std::shared_ptr<RemoteSessionCommandProcess> remoteService = std::make_shared<RemoteSessionCommandProcess>(object);
    SLOGI("check remoteService create done");
    return remoteService;
}

bool AVSessionService::IsLocalDevice(const std::string& networkId)
{
    std::string localNetworkId;
    CHECK_AND_RETURN_RET_LOG(GetLocalNetworkId(localNetworkId) == AVSESSION_SUCCESS, AVSESSION_ERROR,
                             "GetLocalNetworkId error");
    if (networkId == localNetworkId || networkId == "LocalDevice") {
        SLOGI("local device");
        return true;
    }
    SLOGI("not local device");
    return false;
}

int32_t AVSessionService::GetLocalNetworkId(std::string& networkId)
{
    SLOGI("GetLocalNetworkId");
    DistributedHardware::DmDeviceInfo deviceInfo;
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo("av_session", deviceInfo);
    CHECK_AND_RETURN_RET_LOG(ret == 0, ret, "get local deviceInfo failed");
    networkId = deviceInfo.networkId;
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::GetTrustedDeviceName(const std::string& networkId, std::string& deviceName)
{
    SLOGI("GetTrustedDeviceName");
    std::vector<OHOS::DistributedHardware::DmDeviceInfo> deviceList {};
    if (IsLocalDevice(networkId)) {
        deviceName = "LocalDevice";
        return AVSESSION_SUCCESS;
    }
    int32_t ret = GetTrustedDevicesInfo(deviceList);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "get devicesInfo failed");
    SLOGI("deviceList size is %{public}d", static_cast<int32_t>(deviceList.size()));
    for (const auto& device : deviceList) {
        SLOGI("device networkId is %{public}.6s", device.networkId);
        ret = strcmp(device.networkId, networkId.c_str());
        if (ret == 0) {
            deviceName = device.deviceName;
            SLOGI("deviceName is %{public}s", deviceName.c_str());
            return AVSESSION_SUCCESS;
        }
    }
    SLOGI("can not find this device %{public}.6s", networkId.c_str());
    return AVSESSION_ERROR;
}

int32_t AVSessionService::GetTrustedDevicesInfo(std::vector<OHOS::DistributedHardware::DmDeviceInfo>& deviceList)
{
    SLOGI("GetTrustedDevicesInfo");
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
    SLOGI("castAudioDescriptors size is %{public}d", static_cast<int32_t>(castAudioDescriptors.size()));
    SLOGI("session id is %{public}s", AVSessionUtils::GetAnonySessionId(session->GetSessionId()).c_str());

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
        SLOGI("deviceName is %{public}s", audioDescriptor.deviceName_.c_str());
        SLOGI("deviceId is %{public}d", audioDescriptor.deviceId_);
        outputDeviceInfo.deviceInfos_.emplace_back(deviceInfo);
    }
    session->SetOutputDevice(outputDeviceInfo);
}

bool AVSessionService::GetAudioDescriptorByDeviceId(const std::vector<sptr<AudioStandard::AudioDeviceDescriptor>>&
    descriptors, const std::string& deviceId,
    AudioStandard::AudioDeviceDescriptor& audioDescriptor)
{
    for (const auto& descriptor : descriptors) {
        if (std::to_string(descriptor->deviceId_) == deviceId) {
            audioDescriptor = *descriptor;
            SLOGI("deviceId is %{public}d, networkId is %{public}.6s", audioDescriptor.deviceId_,
                  audioDescriptor.networkId_.c_str());
            return true;
        }
    }
    SLOGI("deviceId is %{public}s, not found in all audio descriptor", deviceId.c_str());
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
    SLOGI("cast to deviceId %{public}d, networkId_ is %{public}.6s", descriptors[0].deviceId_,
          descriptors[0].networkId_.c_str());

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
    SLOGI("uid is %{public}d", uid);
    sptr <AudioStandard::AudioRendererFilter> audioFilter = new(std::nothrow) AudioRendererFilter();
    CHECK_AND_RETURN_RET_LOG(audioFilter != nullptr, ERR_NO_MEMORY, "new AudioRendererFilter failed");
    audioFilter->uid = uid;
    audioFilter->rendererInfo.contentType = ContentType::CONTENT_TYPE_MUSIC;
    audioFilter->rendererInfo.streamUsage = StreamUsage::STREAM_USAGE_MEDIA;

    std::vector<sptr<AudioDeviceDescriptor>> audioDescriptor;
    auto audioDeviceDescriptor = new(std::nothrow) AudioDeviceDescriptor(descriptor);
    CHECK_AND_RETURN_RET_LOG(audioDeviceDescriptor != nullptr, ERR_NO_MEMORY, "audioDeviceDescriptor is nullptr");
    audioDescriptor.push_back(audioDeviceDescriptor);
    SLOGI("select the device %{public}s id %{public}d role is %{public}d, networkId is %{public}.6s",
          descriptor.deviceName_.c_str(), descriptor.deviceId_, static_cast<int32_t>(descriptor.deviceRole_),
          descriptor.networkId_.c_str());

    AudioSystemManager *audioSystemMgr = AudioSystemManager::GetInstance();
    CHECK_AND_RETURN_RET_LOG(audioSystemMgr != nullptr, AVSESSION_ERROR, "get AudioSystemManager instance failed");
    int32_t ret = audioSystemMgr->SelectOutputDevice(audioFilter, audioDescriptor);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "SelectOutputDevice failed");

    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::CastAudio(const SessionToken& token,
                                    const std::vector<AudioStandard::AudioDeviceDescriptor>& sinkAudioDescriptors)
{
    SLOGI("sessionId is %{public}s", AVSessionUtils::GetAnonySessionId(token.sessionId).c_str());
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("CastAudio: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
                            "ERROR_MSG", "avsessionservice CastAudio checksystempermission failed");
        return ERR_NO_PERMISSION;
    }

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
    SLOGI("start");
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
    SLOGI("start");
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
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("CastAudioForAll: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
                            "ERROR_MSG", "avsessionservice CastAudioForAll checksystempermission failed");
        return ERR_NO_PERMISSION;
    }

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
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("ProcessCastAudioCommand: CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice ProcessCastAudioCommand checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    SLOGI("ProcessCastAudioCommand is %{public}d", static_cast<int32_t>(command));
    CHECK_AND_RETURN_RET_LOG(command > COMMAND_INVALID && command < COMMAND_MAX, AVSESSION_ERROR, "invalid command");
    if (command == COMMAND_CAST_AUDIO) {
        int ret = RemoteCastAudioInner(input, output);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "RemoteCastAudioInner error");
        return AVSESSION_SUCCESS;
    }

    int ret = RemoteCancelCastAudioInner(input);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "RemoteCancelCastAudioInner error");
    SLOGI("success");
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

    sptr <AVSessionItem> session = CreateSessionInner(sourceDescriptor.sessionTag_, sourceDescriptor.sessionType_,
                                                      sourceDescriptor.isThirdPartyApp_,
                                                      sourceDescriptor.elementName_);
    SLOGI("source sessionId_ %{public}s", AVSessionUtils::GetAnonySessionId(sourceDescriptor.sessionId_).c_str());
    CHECK_AND_RETURN_RET_LOG(session != nullptr, AVSESSION_ERROR, "CreateSession failed");
    SLOGI("sink deviceId %{public}s", AVSessionUtils::GetAnonySessionId(session->GetSessionId()).c_str());

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
    SLOGI("CastAudioFromRemote success");
    JsonUtils::SetSessionDescriptor(sinkSessionInfo, session->GetDescriptor());
    SLOGI("sinkSessionInfo : %{public}s", sinkSessionInfo.c_str());
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
        SLOGI("get audio deviceId %{public}d, networkId_ is %{public}.6s", audioDescriptor.deviceId_,
              audioDescriptor.networkId_.c_str());
        return AVSESSION_SUCCESS;
    }
    SLOGI("can not get deviceId %{public}s info", deviceId.c_str());
    return AVSESSION_ERROR;
}

void AVSessionService::ClearSessionForClientDiedNoLock(pid_t pid)
{
    SLOGI("clear session in ");
    auto sessions = GetContainer().GetSessionsByPid(pid);
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

bool AVSessionService::LoadStringFromFileEx(const string& filePath, string& content)
{
    std::lock_guard lockGuard(fileCheckLock_);
    SLOGI("file load in for path: %{public}s", filePath.c_str());
    ifstream file(filePath.c_str());
    if (!file.is_open()) {
        SLOGD("file not open! try open first ! ");
        file.open(filePath.c_str(), ios::app);
        if (!file.is_open()) {
            SLOGE("open file again fail !");
            return false;
        }
    }
    file.seekg(0, ios::end);
    const long fileLength = file.tellg();
    SLOGI("get file length(%{public}ld)!", fileLength);
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
    std::lock_guard lockGuard(fileCheckLock_);
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
    SLOGI("file check for path:%{public}s", filePath.c_str());
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
    SLOGI("check content pre clean it: %{public}s", content.c_str());
    nlohmann::json checkValues = json::parse(content, nullptr, false);
    if (checkValues.is_discarded()) {
        SLOGE("check content discarded!");
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
            SLOGE("file empty init json fail !");
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

void AVSessionService::NotifySystemUI(const AVSessionDescriptor* historyDescriptor)
{
    auto deviceProp = system::GetParameter("const.product.devicetype", "default");
    CHECK_AND_RETURN_LOG(strcmp(deviceProp.c_str(), "2in1") != 0, "2in1 not support");
    int32_t result = Notification::NotificationHelper::SubscribeLocalLiveViewNotification(NOTIFICATION_SUBSCRIBER);
    CHECK_AND_RETURN_LOG(result == ERR_OK, "create notification subscriber error %{public}d", result);

    Notification::NotificationRequest request;
    std::shared_ptr<Notification::NotificationLocalLiveViewContent> localLiveViewContent =
        std::make_shared<Notification::NotificationLocalLiveViewContent>();
    CHECK_AND_RETURN_LOG(localLiveViewContent != nullptr, "avsession item local live view content nullptr error");
    localLiveViewContent->SetType(SYSTEMUI_LIVEVIEW_TYPECODE_MDEDIACONTROLLER);
    localLiveViewContent->SetTitle(historyDescriptor ? "" : "AVSession NotifySystemUI");
    localLiveViewContent->SetText(historyDescriptor ? "" : "AVSession NotifySystemUI");

    std::shared_ptr<Notification::NotificationContent> content =
        std::make_shared<Notification::NotificationContent>(localLiveViewContent);
    CHECK_AND_RETURN_LOG(content != nullptr, "avsession item notification content nullptr error");

    auto uid = topSession_ ? topSession_->GetUid() : static_cast<int32_t>(getuid());
    request.SetSlotType(Notification::NotificationConstant::SlotType::LIVE_VIEW);
    request.SetNotificationId(0);
    request.SetContent(content);
    request.SetCreatorUid(uid);
    request.SetUnremovable(true);
    request.SetInProgress(true);
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent = CreateWantAgent(historyDescriptor);
    CHECK_AND_RETURN_LOG(wantAgent != nullptr, "wantAgent nullptr error");
    request.SetWantAgent(wantAgent);
    result = Notification::NotificationHelper::PublishNotification(request);
    SLOGI("AVSession service PublishNotification uid %{public}d, result %{public}d", uid, result);
}

void AVSessionService::NotifyDeviceChange(const DeviceChangeAction& deviceChangeAction)
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
    for (AVSessionDescriptor session : hisDescriptors) {
        if (session.elementName_.GetBundleName() == avQueueInfos[0].GetBundleName()) {
            selectSession = session;
            break;
        }
    }
    if (deviceChangeAction.type == AudioStandard::CONNECT) {
        SLOGI("history bundle name %{public}s", selectSession.elementName_.GetBundleName().c_str());
        NotifySystemUI(&selectSession);
    }
}

void AVSessionService::HandleDeviceChange(const DeviceChangeAction& deviceChangeAction)
{
    SLOGI("AVSessionService HandleDeviceChange");
    for (auto &audioDeviceDescriptor : deviceChangeAction.deviceDescriptors) {
        SLOGI("AVSessionService HandleDeviceChange device type %{public}d", audioDeviceDescriptor->deviceType_);
        if (audioDeviceDescriptor->deviceType_ == AudioStandard::DEVICE_TYPE_WIRED_HEADSET ||
            audioDeviceDescriptor->deviceType_ == AudioStandard::DEVICE_TYPE_WIRED_HEADPHONES ||
            audioDeviceDescriptor->deviceType_ == AudioStandard::DEVICE_TYPE_USB_HEADSET ||
            audioDeviceDescriptor->deviceType_ == AudioStandard::DEVICE_TYPE_BLUETOOTH_A2DP) {
            NotifyDeviceChange(deviceChangeAction);
        }
    }
}

void AVSessionService::InitRadarBMS()
{
    SLOGI("InitRadarBMS");
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
