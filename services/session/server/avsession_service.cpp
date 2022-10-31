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

#include "avsession_service.h"
#include <sstream>
#include <iomanip>
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

#if !defined(WINDOWS_PLATFORM) and !defined(MAC_PLATFORM) and !defined(IOS_PLATFORM)
#include <malloc.h>
#endif

using namespace nlohmann;
using namespace OHOS::AudioStandard;
namespace OHOS::AVSession {
REGISTER_SYSTEM_ABILITY_BY_ID(AVSessionService, AVSESSION_SERVICE_ID, true);

AVSessionService::AVSessionService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate)
{
    SLOGD("construct");
}

AVSessionService::~AVSessionService()
{
    std::string cachePath(CACHE_PATH_NAME);
    AVSessionUtils::DeleteCacheFiles(cachePath);
    SLOGD("destroy");
}

void AVSessionService::OnStart()
{
    std::string cachePath(CACHE_PATH_NAME);
    AVSessionUtils::DeleteCacheFiles(cachePath);
    if (!Publish(this)) {
        SLOGE("publish avsession service failed");
    }
    dumpHelper_ = std::make_unique<AVSessionDumper>();
    CommandSendLimit::GetInstance().StartTimer();

#ifdef ENABLE_BACKGROUND_AUDIO_CONTROL
    backgroundAudioController_.Init();
    AddInnerSessionListener(&backgroundAudioController_);
#endif
    AddSystemAbilityListener(MULTIMODAL_INPUT_SERVICE_ID);
    AddSystemAbilityListener(AUDIO_POLICY_SERVICE_ID);
    AddSystemAbilityListener(APP_MGR_SERVICE_ID);
    AddSystemAbilityListener(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
    HISYSEVENT_REGITER;
    HISYSEVENT_BEHAVIOR("SESSION_SERVICE_START", "SERVICE_NAME", "AVSessionService",
        "SERVICE_ID", AVSESSION_SERVICE_ID, "DETAILED_MSG", "avsession service start success");
}

void AVSessionService::OnDump()
{
}

void AVSessionService::OnStop()
{
    CommandSendLimit::GetInstance().StopTimer();
}

void AVSessionService::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
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
        default:
            SLOGE("undefined system ability %{public}d", systemAbilityId);
    }
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

void AVSessionService::UpdateTopSession(const sptr<AVSessionItem> &newTopSession)
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

    SLOGI("uid=%{public}d sessionId=%{public}s", newTopSession->GetUid(), newTopSession->GetSessionId().c_str());
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

void AVSessionService::HandleFocusSession(const FocusSessionStrategy::FocusSessionChangeInfo &info)
{
    std::lock_guard lockGuard(sessionAndControllerLock_);
    if (topSession_ && topSession_->GetUid() == info.uid) {
        SLOGI("same session");
        return;
    }
    for (const auto& session : GetContainer().GetAllSessions()) {
        if (session->GetUid() == info.uid) {
            UpdateTopSession(session);
            return;
        }
    }
}

bool AVSessionService::SelectFocusSession(const FocusSessionStrategy::FocusSessionChangeInfo &info)
{
    for (const auto& session : GetContainer().GetAllSessions()) {
        if (session->GetUid() == info.uid) {
            SLOGI("true");
            return true;
        }
    }
    SLOGI("false");
    return false;
}

void AVSessionService::InitAudio()
{
    SLOGI("enter");
    AudioAdapter::GetInstance().Init();
    focusSessionStrategy_.Init();
    focusSessionStrategy_.RegisterFocusSessionChangeCallback([this] (const auto &info) {
        HandleFocusSession(info);
    });
    focusSessionStrategy_.RegisterFocusSessionSelector([this] (const auto& info) {
        return SelectFocusSession(info);
    });
    AudioAdapter::GetInstance().AddStreamRendererStateListener([this] (const AudioRendererChangeInfos &infos) {
        OutputDeviceChangeListener(infos);
    });
}

sptr <AVSessionItem> AVSessionService::SelectSessionByUid(const AudioRendererChangeInfo &info)
{
    for (const auto &session : GetContainer().GetAllSessions()) {
        if (session->GetUid() == info.clientUID) {
            return session;
        }
    }
    SLOGI("has no session");
    return nullptr;
}

void AVSessionService::OutputDeviceChangeListener(const AudioRendererChangeInfos &infos)
{
    for (const auto &info : infos) {
        SLOGI("clientUID  is %{public}d, rendererState is %{public}d, deviceId is %{public}d", info->clientUID,
              static_cast<int32_t>(info->rendererState), info->outputDeviceInfo.deviceId);
    }
}

void AVSessionService::InitAMS()
{
    SLOGI("enter");
    AppManagerAdapter::GetInstance().Init();
}

void AVSessionService::InitDM()
{
    SLOGI("enter");
    auto callback = std::make_shared<AVSessionInitDMCallback>();
    int32_t ret = OHOS::DistributedHardware::DeviceManager::GetInstance().InitDeviceManager("av_session", callback);
    CHECK_AND_RETURN_LOG(ret == 0, "InitDeviceManager error ret is %{public}d", ret);
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
        stream << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    return stream.str();
}

bool AVSessionService::AbilityHasSession(pid_t pid, const std::string& abilityName)
{
    std::lock_guard lockGuard(sessionAndControllerLock_);
    return GetContainer().GetSession(pid, abilityName) != nullptr;
}

sptr<AVControllerItem> AVSessionService::GetPresentController(pid_t pid, const std::string& sessionId)
{
    std::lock_guard lockGuard(sessionAndControllerLock_);
    auto it = controllers_.find(pid);
    if (it != controllers_.end()) {
        for (const auto &controller: it->second) {
            if (controller->HasSession(sessionId)) {
                return controller;
            }
        }
    }
    SLOGE("not found");
    return nullptr;
}

void AVSessionService::NotifySessionCreate(const AVSessionDescriptor &descriptor)
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

void AVSessionService::NotifySessionRelease(const AVSessionDescriptor &descriptor)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    for (const auto& listener : innerSessionListeners_) {
        listener->OnSessionRelease(descriptor);
    }
    for (const auto& [pid, listener] : sessionListeners_) {
        listener->OnSessionRelease(descriptor);
    }
}

void AVSessionService::NotifyTopSessionChanged(const AVSessionDescriptor &descriptor)
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

sptr<AVSessionItem> AVSessionService::CreateNewSession(const std::string &tag, int32_t type, bool thirdPartyApp,
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
    result->SetServiceCallbackForRelease([this](AVSessionItem& session) { HandleSessionRelease(session); });
    SLOGI("success sessionId=%{public}s", result->GetSessionId().c_str());
    {
        std::lock_guard lockGuard(sessionAndControllerLock_);
        if (topSession_ == nullptr) {
            UpdateTopSession(result);
        }
    }

    OutputDeviceInfo deviceInfo {};
    deviceInfo.isRemote_ = false;
    deviceInfo.deviceIds_.push_back("0");
    deviceInfo.deviceNames_.push_back("LocalDevice");
    result->SetOutputDevice(deviceInfo);

    return result;
}

sptr <AVSessionItem> AVSessionService::CreateSessionInner(const std::string& tag, int32_t type, bool thirdPartyApp,
                                                          const AppExecFwk::ElementName &elementName)
{
    SLOGI("enter");
    auto pid = GetCallingPid();
    std::lock_guard lockGuard(sessionAndControllerLock_);
    if (AbilityHasSession(pid, elementName.GetAbilityName())) {
        SLOGE("process %{public}d %{public}s already has one session", pid, elementName.GetAbilityName().c_str());
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
        SLOGE("session num exceed max");
        return nullptr;
    }
    HISYSEVENT_ADD_LIFE_CYCLE_INFO(elementName.GetBundleName(),
        AppManagerAdapter::GetInstance().IsAppBackground(GetCallingUid()), type, true);
    {
        std::lock_guard lockGuard1(abilityManagerLock_);
        std::string bundleName = result->GetDescriptor().elementName_.GetBundleName();
        std::string abilityName = result->GetDescriptor().elementName_.GetAbilityName();
        auto it = abilityManager_.find(bundleName + abilityName);
        if (it != abilityManager_.end()) {
            it->second->StartAbilityByCallDone(result->GetDescriptor().sessionId_);
        }
    }

    NotifySessionCreate(result->GetDescriptor());
    SLOGI("success");
    return result;
}

sptr <IRemoteObject> AVSessionService::CreateSessionInner(const std::string &tag, int32_t type,
                                                          const AppExecFwk::ElementName &elementName)
{
    auto session = CreateSessionInner(tag, type, !PermissionChecker::GetInstance().CheckSystemPermission(),
                                      elementName);
    CHECK_AND_RETURN_RET_LOG(session != nullptr, session, "session is nullptr");
    SLOGI("isAllSessionCast_ is %{public}d", isAllSessionCast_);
    CHECK_AND_RETURN_RET_LOG(isAllSessionCast_, session, "no need to cast");
    CHECK_AND_RETURN_RET_LOG(CastAudioForNewSession(session) == AVSESSION_SUCCESS, session, "cast new session error");
    return session;
}

int32_t AVSessionService::GetAllSessionDescriptors(std::vector<AVSessionDescriptor> &descriptors)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice getallsessiondescriptors checksystempermission failed");
        return ERR_NO_PERMISSION;
    }

    std::lock_guard lockGuard(sessionAndControllerLock_);
    for (const auto& session: GetContainer().GetAllSessions()) {
        descriptors.push_back(session->GetDescriptor());
    }
    SLOGI("size=%{public}d", static_cast<int>(descriptors.size()));
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::GetSessionDescriptorsBySessionId(const std::string& sessionId,
                                                           AVSessionDescriptor& descriptor)
{
    std::lock_guard lockGuard(sessionAndControllerLock_);
    sptr<AVSessionItem> session = GetContainer().GetSessionById(sessionId);
    CHECK_AND_RETURN_RET_LOG(session != nullptr, AVSESSION_ERROR, "session not exist");

    auto pid = GetCallingPid();
    if (pid == session->GetPid()) {
        descriptor = session->GetDescriptor();
        return AVSESSION_SUCCESS;
    }
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(),
            "CALLER_PID", pid, "SESSION_ID", sessionId,
            "ERROR_MSG", "avsessionservice getsessiondescriptors by sessionid checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    descriptor = session->GetDescriptor();
    return AVSESSION_SUCCESS;
}

sptr<AVControllerItem> AVSessionService::CreateNewControllerForSession(pid_t pid, sptr<AVSessionItem> &session)
{
    SLOGI("pid=%{public}d sessionId=%{public}s", pid, session->GetSessionId().c_str());
    sptr<AVControllerItem> result = new(std::nothrow) AVControllerItem(pid, session);
    if (result == nullptr) {
        SLOGE("malloc controller failed");
        return nullptr;
    }
    result->SetServiceCallbackForRelease([this](AVControllerItem& controller) { HandleControllerRelease(controller); });
    session->AddController(pid, result);
    return result;
}

const nlohmann::json &AVSessionService::GetSubNode(const nlohmann::json &node, const std::string &name)
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

int32_t AVSessionService::StartDefaultAbilityByCall(std::string& sessionId)
{
    std::string content;
    if (!LoadStringFromFile(AVSESSION_FILE_DIR + ABILITY_FILE_NAME, content)) {
        SLOGE("LoadStringFromFile failed, filename=%{public}s", ABILITY_FILE_NAME);
    }
    std::string bundleName = DEFAULT_BUNDLE_NAME;
    std::string abilityName = DEFAULT_ABILITY_NAME;

    nlohmann::json value = json::parse(content, nullptr, false);
    auto &node1 = GetSubNode(value, "bundleName");
    auto &node2 = GetSubNode(value, "abilityName");
    if (!node1.is_null() && !node2.is_null() && node1.is_string() && node2.is_string()) {
        bundleName = node1;
        abilityName = node2;
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
    abilityManager_.erase(bundleName + abilityName);
    return ret;
}

int32_t AVSessionService::CreateControllerInner(const std::string& sessionId, sptr<IRemoteObject>& object)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("CheckSystemPermission failed");
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
        sessionIdInner = sessionId;
    }
    auto pid = GetCallingPid();
    std::lock_guard lockGuard(sessionAndControllerLock_);
    if (GetPresentController(pid, sessionIdInner) != nullptr) {
        SLOGI("controller already exist");
        return ERR_CONTROLLER_IS_EXIST;
    }

    auto session = GetContainer().GetSessionById(sessionIdInner);
    if (session == nullptr) {
        SLOGE("no session id %{public}s", sessionIdInner.c_str());
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

void AVSessionService::AddSessionListener(pid_t pid, const sptr<ISessionListener> &listener)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    sessionListeners_[pid] = listener;
}

void AVSessionService::RemoveSessionListener(pid_t pid)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    sessionListeners_.erase(pid);
}

void AVSessionService::AddInnerSessionListener(SessionListener *listener)
{
    std::lock_guard lockGuard(sessionListenersLock_);
    innerSessionListeners_.push_back(listener);
}

int32_t AVSessionService::RegisterSessionListener(const sptr<ISessionListener>& listener)
{
    SLOGI("enter");
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "ERROR_MSG", "avsessionservice registersessionlistener checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    AddSessionListener(GetCallingPid(), listener);
    return AVSESSION_SUCCESS;
}

void AVSessionService::HandleEventHandlerCallBack()
{
    SLOGI("handle eventHandler callback");
    AVControlCommand cmd;
    if (pressCount_ >= THREE_CLICK && topSession_) {
        cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY_PREVIOUS);
        topSession_->ExecuteControllerCommand(cmd);
    } else if (pressCount_ == DOUBLE_CLICK && topSession_) {
        cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY_NEXT);
        topSession_->ExecuteControllerCommand(cmd);
    } else if (pressCount_ == ONE_CLICK && topSession_) {
        auto playbackState = topSession_->GetPlaybackState();
        if (playbackState.GetState() == AVPlaybackState::PLAYBACK_STATE_PLAYING) {
            cmd.SetCommand(AVControlCommand::SESSION_CMD_PAUSE);
        } else {
            cmd.SetCommand(AVControlCommand::SESSION_CMD_PLAY);
        }
        topSession_->ExecuteControllerCommand(cmd);
    }
    pressCount_ = 0;
    isFirstPress = true;
}

int32_t AVSessionService::SendSystemAVKeyEvent(const MMI::KeyEvent& keyEvent)
{
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
            "KEY_CODE", keyEvent.GetKeyCode(), "KEY_ACTION", keyEvent.GetKeyAction(),
            "ERROR_MSG", "avsessionservice sendsystemavkeyevent checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    SLOGI("key=%{public}d", keyEvent.GetKeyCode());
    if (keyEvent.GetKeyCode() == MMI::KeyEvent::KEYCODE_HEADSETHOOK) {
        pressCount_++;
        if (isFirstPress) {
            auto ret = AVSessionEventHandler::GetInstance().AVSessionPostTask([this]() {
                HandleEventHandlerCallBack();
            }, "SendSystemAVKeyEvent", CLICK_TIMEOUT);
            CHECK_AND_RETURN_RET_LOG(ret, AVSESSION_ERROR, "init eventHandler failed");
            isFirstPress = false;
        }
        return AVSESSION_SUCCESS;
    }
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
        SLOGE("CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(),
            "CALLER_PID", GetCallingPid(), "CMD", command.GetCommand(),
            "ERROR_MSG", "avsessionservice sendsystemcontrolcommand checksystempermission failed");
        return ERR_NO_PERMISSION;
    }
    SLOGI("cmd=%{public}d", command.GetCommand());
    if (topSession_) {
        CHECK_AND_RETURN_RET_LOG(CommandSendLimit::GetInstance().IsCommandSendEnable(GetCallingPid()),
            ERR_COMMAND_SEND_EXCEED_MAX, "command excuted number exceed max");
        topSession_->ExecuteControllerCommand(command);
    }
    return AVSESSION_SUCCESS;
}

void AVSessionService::AddClientDeathObserver(pid_t pid, const sptr<IClientDeath> &observer)
{
    std::lock_guard lockGuard(clientDeathObserversLock_);
    clientDeathObservers_[pid] = observer;
}

void AVSessionService::RemoveClientDeathObserver(pid_t pid)
{
    std::lock_guard lockGuard(clientDeathObserversLock_);
    clientDeathObservers_.erase(pid);
}

int32_t AVSessionService::RegisterClientDeathObserver(const sptr<IClientDeath>& observer)
{
    SLOGI("enter");
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

void AVSessionService::OnClientDied(pid_t pid)
{
    SLOGI("pid=%{public}d", pid);
    RemoveSessionListener(pid);
    RemoveClientDeathObserver(pid);

    std::lock_guard lockGuard(sessionAndControllerLock_);
    ClearSessionForClientDiedNoLock(pid);
    ClearControllerForClientDiedNoLock(pid);
#if !defined(WINDOWS_PLATFORM) and !defined(MAC_PLATFORM) and !defined(IOS_PLATFORM)
#if defined(__BIONIC__)
    mallopt(M_PURGE, 0);
#endif
#endif
}

void AVSessionService::HandleSessionRelease(AVSessionItem &session)
{
    SLOGI("sessionId=%{public}s", session.GetSessionId().c_str());
    NotifySessionRelease(session.GetDescriptor());
    auto sessionPtr = GetContainer().GetSessionById(session.GetSessionId());
    if (session.GetRemoteSource() != nullptr && sessionPtr != nullptr) {
        int32_t ret = CancelCastAudioForClientExit(session.GetPid(), sessionPtr);
        SLOGI("CancelCastAudioForClientExit ret is %{public}d", ret);
    } else {
        SLOGI("GetContainer has no this session");
    }
    std::lock_guard lockGuard(sessionAndControllerLock_);
    GetContainer().RemoveSession(session.GetPid(), session.GetAbilityName());
    if (topSession_.GetRefPtr() == &session) {
        UpdateTopSession(nullptr);
    }
    nlohmann::json value;
    value["bundleName"] = session.GetDescriptor().elementName_.GetBundleName();
    value["abilityName"] = session.GetDescriptor().elementName_.GetAbilityName();
    std::string content = value.dump();
    if (!SaveStringToFile(AVSESSION_FILE_DIR + ABILITY_FILE_NAME, content)) {
        SLOGE("SaveStringToFile failed, filename=%{public}s", ABILITY_FILE_NAME);
    }
    HISYSEVENT_ADD_LIFE_CYCLE_INFO(session.GetDescriptor().elementName_.GetBundleName(),
        AppManagerAdapter::GetInstance().IsAppBackground(GetCallingUid()),
        session.GetDescriptor().sessionType_, false);
}

void AVSessionService::HandleControllerRelease(AVControllerItem &controller)
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

std::int32_t AVSessionService::Dump(std::int32_t fd, const std::vector<std::u16string> &args)
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
    for (const auto &arg : args) {
        SLOGD("Dump args: %s", Str16ToStr8(arg).c_str());
        argsInStr.emplace_back(Str16ToStr8(arg));
    }

    std::string result;
    dumpHelper_->Dump(argsInStr, result, *this);
    std::int32_t ret = dprintf(fd, "%s", result.c_str());
    if (ret < 0) {
        SLOGE("dprintf to dump fd failed");
        return ERR_INVALID_PARAM;
    }
    return AVSESSION_SUCCESS;
}

sptr <RemoteSessionCommandProcess> AVSessionService::GetService(const std::string& deviceId)
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
    auto remoteService = iface_cast<RemoteSessionCommandProcess>(object);
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

int32_t AVSessionService::GetTrustedDeviceName(const std::string &networkId, std::string& deviceName)
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
    for (const auto &device : deviceList) {
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

int32_t AVSessionService::SetBasicInfo(std::string &sessionInfo)
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

void AVSessionService::SetCastDeviceInfo(const std::vector<AudioStandard::AudioDeviceDescriptor> &castAudioDescriptors,
                                         sptr <AVSessionItem> &session)
{
    CHECK_AND_RETURN_LOG(session != nullptr && castAudioDescriptors.size() > 0, "invalid argument");
    SLOGI("castAudioDescriptors size is %{public}d", static_cast<int32_t>(castAudioDescriptors.size()));
    SLOGI("session id is %{public}s", session->GetSessionId().c_str());

    OutputDeviceInfo outputDeviceInfo;

    outputDeviceInfo.deviceNames_.clear();
    outputDeviceInfo.deviceIds_.clear();

    for (const auto &audioDescriptor : castAudioDescriptors) {
        outputDeviceInfo.deviceNames_.push_back(audioDescriptor.deviceName_);
        outputDeviceInfo.deviceIds_.push_back(std::to_string(audioDescriptor.deviceId_));
        SLOGI("deviceName is %{public}s", audioDescriptor.deviceName_.c_str());
        SLOGI("deviceId is %{public}d", audioDescriptor.deviceId_);
    }
    outputDeviceInfo.isRemote_ = false;
    if (!IsLocalDevice(castAudioDescriptors[0].networkId_)) {
        outputDeviceInfo.isRemote_ = true;
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

void AVSessionService::GetCastDeviceInfo(const sptr <AVSessionItem>& session,
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

    OutputDeviceInfo deviceInfo;
    session->GetOutputDevice(deviceInfo);
    if (!deviceInfo.isRemote_) {
        SLOGI("isRemote_ is %{public}d, no need to cancel", deviceInfo.isRemote_);
        return;
    }
    int32_t ret = GetAudioDescriptor(session, session->GetDescriptor().outputDeviceInfo_.deviceIds_[0],
                                     cancelSinkDescriptors);
    CHECK_AND_RETURN_LOG(ret == AVSESSION_SUCCESS, "get cancelSinkDescriptors failed");
}

int32_t AVSessionService::SelectOutputDevice(const int32_t uid, const AudioDeviceDescriptor& descriptor)
{
    SLOGI("uid is %{public}d", uid);
    sptr <AudioStandard::AudioRendererFilter> audioFilter = new(std::nothrow) AudioRendererFilter();
    audioFilter->uid = uid;
    audioFilter->rendererInfo.contentType = ContentType::CONTENT_TYPE_MUSIC;
    audioFilter->rendererInfo.streamUsage = StreamUsage::STREAM_USAGE_MEDIA;

    std::vector<sptr < AudioDeviceDescriptor>> audioDescriptor;
    auto audioDeviceDescriptor = new(std::nothrow) AudioDeviceDescriptor(descriptor);
    CHECK_AND_RETURN_RET_LOG(audioDeviceDescriptor != nullptr, AVSESSION_ERROR, "audioDeviceDescriptor is nullptr");
    audioDescriptor.push_back(audioDeviceDescriptor);
    SLOGI("select the device %{public}s id %{public}d role is %{public}d, networkId is %{public}.6s",
          descriptor.deviceName_.c_str(), descriptor.deviceId_, static_cast<int32_t>(descriptor.deviceRole_),
          descriptor.networkId_.c_str());

    AudioSystemManager *audioSystemMgr = AudioSystemManager::GetInstance();
    int32_t ret = audioSystemMgr->SelectOutputDevice(audioFilter, audioDescriptor);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, AVSESSION_ERROR, "SelectOutputDevice failed");

    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::CastAudio(const SessionToken &token,
                                    const std::vector<AudioStandard::AudioDeviceDescriptor>& sinkAudioDescriptors)
{
    SLOGI("sessionId is %{public}s", token.sessionId.c_str());
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
                            "ERROR_MSG", "avsessionservice CastAudio checksystempermission failed");
        return ERR_NO_PERMISSION;
    }

    std::string sourceSessionInfo;
    int32_t ret = SetBasicInfo(sourceSessionInfo);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetBasicInfo failed");
    sptr <AVSessionItem> session = GetContainer().GetSessionById(token.sessionId);
    CHECK_AND_RETURN_RET_LOG(session != nullptr, ERR_SESSION_NOT_EXIST, "session %{public}s not exist",
                             token.sessionId.c_str());
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
    GetCastDeviceInfo(session, descriptors, castSinkDescriptors, cancelSinkDescriptors);

    if (cancelSinkDescriptors.size() > 0) {
        int32_t ret = CancelCastAudioInner(cancelSinkDescriptors, sourceSessionInfo, session);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CancelCastAudioInner failed");
    }

    if (castSinkDescriptors.size() > 0) {
        int32_t ret = CastAudioInner(castSinkDescriptors, sourceSessionInfo, session);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CastAudioInner failed");
    }

    SetCastDeviceInfo(descriptors, session);
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
        isAllSessionCast_ = false;
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

int32_t AVSessionService::CastAudioForNewSession(const sptr <AVSessionItem>& session)
{
    SLOGI("new sessionId is %{public}s", session->GetSessionId().c_str());
    SessionToken token;
    token.sessionId = session->GetSessionId();
    token.pid = session->GetPid();
    token.uid = session->GetUid();

    std::vector<AudioStandard::AudioDeviceDescriptor> castSinkDevices;
    int32_t ret = GetAudioDescriptor(session, outputDeviceId_, castSinkDevices);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "GetAudioDescriptor failed");

    ret = CastAudio(token, castSinkDevices);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CastAudio error, session Id is %{public}s",
                             token.sessionId.c_str());

    SLOGI("success");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::CastAudioForAll(const std::vector<AudioStandard::AudioDeviceDescriptor>& sinkAudioDescriptors)
{
    SLOGI("session size is %{public}d", static_cast<int32_t>(GetContainer().GetAllSessions().size()));
    if (!PermissionChecker::GetInstance().CheckSystemPermission()) {
        SLOGE("CheckSystemPermission failed");
        HISYSEVENT_SECURITY("CONTROL_PERMISSION_DENIED", "CALLER_UID", GetCallingUid(), "CALLER_PID", GetCallingPid(),
                            "ERROR_MSG", "avsessionservice CastAudioForAll checksystempermission failed");
        return ERR_NO_PERMISSION;
    }

    for (const auto& session : GetContainer().GetAllSessions()) {
        SessionToken token;
        token.sessionId = session->GetSessionId();
        token.pid = session->GetPid();
        token.uid = session->GetUid();
        SLOGI("cast session %{public}s", token.sessionId.c_str());
        int32_t ret = CastAudio(token, sinkAudioDescriptors);
        CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CastAudio session %{public}s failed",
                                 token.sessionId.c_str());
        outputDeviceId_ = session->GetDescriptor().outputDeviceInfo_.deviceIds_[0];
    }
    if (!IsLocalDevice(sinkAudioDescriptors[0].networkId_)) {
        isAllSessionCast_ = true;
    }
    SLOGI("isAllSessionCast_ %{public}d, outputDeviceId_ is %{public}s", isAllSessionCast_, outputDeviceId_.c_str());
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::ProcessCastAudioCommand(const RemoteServiceCommand command, const std::string& input,
                                                  std::string& output)
{
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
    SLOGI("source sessionId_ %{public}s", sourceDescriptor.sessionId_.c_str());
    CHECK_AND_RETURN_RET_LOG(session != nullptr, AVSESSION_ERROR, "CreateSession failed");
    SLOGI("sink deviceId %{public}s", session->GetSessionId().c_str());

    castAudioSessionMap_[sourceDescriptor.sessionId_] = session->GetSessionId();

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
    auto iter = castAudioSessionMap_.find(sourceDescriptor.sessionId_);
    CHECK_AND_RETURN_RET_LOG(iter != castAudioSessionMap_.end(), AVSESSION_ERROR, "no source session %{public}s",
                             sourceDescriptor.sessionId_.c_str());
    auto session = GetContainer().GetSessionById(iter->second);
    CHECK_AND_RETURN_RET_LOG(session != nullptr, AVSESSION_ERROR, "no sink session %{public}s", iter->second.c_str());

    ret = session->SinkCancelCastAudio();
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SinkCancelCastAudio failed");
    ClearSessionNoLock(session->GetSessionId());
    castAudioSessionMap_.erase(sourceDescriptor.sessionId_);
    SLOGI("cancel source session %{public}s success", sourceDescriptor.sessionId_.c_str());
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::CancelCastAudioForClientExit(pid_t pid, const sptr<AVSessionItem>& session)
{
    CHECK_AND_RETURN_RET_LOG(session != nullptr, AVSESSION_ERROR, "session is nullptr");
    SLOGI("pid is %{public}d, sessionId is %{public}s", static_cast<int32_t>(pid), session->GetSessionId().c_str());
    std::string sourceSessionInfo;
    int32_t ret = SetBasicInfo(sourceSessionInfo);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetBasicInfo failed");
    ret = JsonUtils::SetSessionDescriptor(sourceSessionInfo, session->GetDescriptor());
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "SetDescriptorInfo failed");

    std::vector<AudioStandard::AudioDeviceDescriptor> cancelSinkDevices;
    ret = GetAudioDescriptor(session, session->GetDescriptor().outputDeviceInfo_.deviceIds_[0], cancelSinkDevices);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "GetAudioDescriptor failed");

    ret = CancelCastAudioInner(cancelSinkDevices, sourceSessionInfo, session);
    CHECK_AND_RETURN_RET_LOG(ret == AVSESSION_SUCCESS, ret, "CancelCastAudioInner failed");
    return AVSESSION_SUCCESS;
}

int32_t AVSessionService::GetAudioDescriptor(const sptr<AVSessionItem>& session, const std::string deviceId,
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
    auto sessions = GetContainer().RemoveSession(pid);
    for (const auto& session : sessions) {
        if (topSession_ == session) {
            UpdateTopSession(nullptr);
        }
        if (session->GetRemoteSource() != nullptr) {
            int32_t ret = CancelCastAudioForClientExit(pid, session);
            SLOGI("CancelCastAudioForClientExit ret is %{public}d", ret);
        }
        SLOGI("remove sessionId=%{public}s", session->GetSessionId().c_str());
        session->Destroy();
    }
}

void AVSessionService::ClearSessionNoLock(const std::string& sessionId)
{
    auto session = GetContainer().RemoveSession(sessionId);
    if (topSession_ == session) {
        UpdateTopSession(nullptr);
    }
    SLOGI("remove sessionId=%{public}s", session->GetSessionId().c_str());
    session->Destroy();
}

void AVSessionService::ClearControllerForClientDiedNoLock(pid_t pid)
{
    auto it = controllers_.find(pid);
    if (it != controllers_.end()) {
        auto controllers = std::move(it->second);
        SLOGI("remove controllers size=%{public}d", static_cast<int>(controllers.size()));
        controllers_.erase(it);
        if (!controllers.empty()) {
            for (const auto& controller : controllers) {
                controller->Destroy();
            }
        }
    }
}

ClientDeathRecipient::ClientDeathRecipient(const std::function<void()>& callback)
    : callback_(callback)
{
    SLOGD("construct");
}

void ClientDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    if (callback_) {
        callback_();
    }
}
} // namespace OHOS::AVSession