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
#include "avsession_sysevent.h"

#if !defined(WINDOWS_PLATFORM) and !defined(MAC_PLATFORM) and !defined(IOS_PLATFORM)
#include <malloc.h>
#endif

using namespace nlohmann;

namespace OHOS::AVSession {
REGISTER_SYSTEM_ABILITY_BY_ID(AVSessionService, AVSESSION_SERVICE_ID, true);

AVSessionService::AVSessionService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate)
{
    SLOGD("construct");
}

AVSessionService::~AVSessionService()
{
    SLOGD("destroy");
}

void AVSessionService::OnStart()
{
    if (!Publish(this)) {
        SLOGE("publish avsession service failed");
    }
    dumpHelper_ = std::make_unique<AVSessionDumper>();

#ifdef ENABLE_BACKGROUND_AUDIO_CONTROL
    backgroundAudioController_.Init();
    AddInnerSessionListener(&backgroundAudioController_);
#endif
    AddSystemAbilityListener(MULTIMODAL_INPUT_SERVICE_ID);
    AddSystemAbilityListener(AUDIO_POLICY_SERVICE_ID);
    AddSystemAbilityListener(APP_MGR_SERVICE_ID);
    HISYSEVENT_REGITER;
    HISYSEVENT_BEHAVIOR("SESSION_SERVICE_START", "SERVICE_NAME", "AVSessionService",
        "SERVICE_ID", AVSESSION_SERVICE_ID, "DETAILED_MSG", "avsession service start success");
}

void AVSessionService::OnDump()
{
}

void AVSessionService::OnStop()
{
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
        }
        topSession_ = newTopSession;
        topSession_->SetTop(true);
        descriptor = topSession_->GetDescriptor();
    }
    HISYSEVENT_BEHAVIOR("FOCUS_CHANGE", "BUNDLE_NAME", descriptor.elementName_.GetBundleName(),
        "MODULE_NAME", descriptor.elementName_.GetModuleName(),
        "ABILITY_NAME", descriptor.elementName_.GetAbilityName(), "SESSION_PID", descriptor.pid_,
        "SESSION_UID", descriptor.uid_, "SESSION_ID", descriptor.sessionId_,
        "SESSION_TAG", descriptor.sessionTag_, "SESSION_TYPE", descriptor.sessionType_,
        "DETAILED_MSG", "avsessionservice updatetopsession");
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
            HISYSEVENT_BEHAVIOR("FOCUS_CHANGE",
                "OLD_BUNDLE_NAME", topSession_->GetDescriptor().elementName_.GetBundleName(),
                "OLD_MODULE_NAME", topSession_->GetDescriptor().elementName_.GetModuleName(),
                "OLD_ABILITY_NAME", topSession_->GetAbilityName(), "OLD_SESSION_PID", topSession_->GetPid(),
                "OLD_SESSION_UID", topSession_->GetUid(), "OLD_SESSION_ID", topSession_->GetSessionId(),
                "OLD_SESSION_TAG", topSession_->GetDescriptor().sessionTag_,
                "OLD_SESSION_TYPE", topSession_->GetDescriptor().sessionType_,
                "BUNDLE_NAME", session->GetDescriptor().elementName_.GetBundleName(),
                "MODULE_NAME", session->GetDescriptor().elementName_.GetModuleName(),
                "ABILITY_NAME", session->GetAbilityName(), "SESSION_PID", session->GetPid(),
                "SESSION_UID", session->GetUid(), "SESSION_ID", session->GetSessionId(),
                "SESSION_TAG", session->GetDescriptor().sessionTag_,
                "SESSION_TYPE", session->GetDescriptor().sessionType_,
                "DETAILED_MSG", "avsessionservice handlefocussession, updatetopsession");
            UpdateTopSession(session);
            return;
        }
    }
}

bool AVSessionService::SelectFocusSession(const FocusSessionStrategy::FocusSessionChangeInfo &info)
{
    for (const auto& session : GetContainer().GetAllSessions()) {
        if (session->GetUid() == info.uid) {
            HISYSEVENT_BEHAVIOR("FOCUS_CHANGE",
                "BUNDLE_NAME", session->GetDescriptor().elementName_.GetBundleName(),
                "MODULE_NAME", session->GetDescriptor().elementName_.GetModuleName(),
                "ABILITY_NAME", session->GetAbilityName(), "SESSION_PID", session->GetPid(),
                "SESSION_UID", session->GetUid(), "SESSION_ID", session->GetSessionId(),
                "DETAILED_MSG", "avsessionservice selectfocussession, true");
            SLOGI("true");
            return true;
        }
    }
    SLOGI("false");
    HISYSEVENT_BEHAVIOR("FOCUS_CHANGE", "FOCUS_SESSION_UID", info.uid,
        "DETAILED_MSG", "avsessionservice selectfocussession, false");
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
}

void AVSessionService::InitAMS()
{
    SLOGI("enter");
    AppManagerAdapter::GetInstance().Init();
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
    HISYSEVENT_BEHAVIOR("FOCUS_CHANGE", "BUNDLE_NAME", descriptor.elementName_.GetBundleName(),
        "MODULE_NAME", descriptor.elementName_.GetModuleName(),
        "ABILITY_NAME", descriptor.elementName_.GetAbilityName(), "SESSION_PID", descriptor.pid_,
        "SESSION_UID", descriptor.uid_, "SESSION_ID", descriptor.sessionId_,
        "SESSION_TAG", descriptor.sessionTag_, "SESSION_TYPE", descriptor.sessionType_,
        "DETAILED_MSG", "avsessionservice notifytopsessionchanged");
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
    descriptor.thirdPartyApp = thirdPartyApp;

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
    return result;
}

sptr<IRemoteObject> AVSessionService::CreateSessionInner(const std::string& tag, int32_t type,
                                                         const AppExecFwk::ElementName& elementName)
{
    SLOGI("enter");
    auto pid = GetCallingPid();
    std::lock_guard lockGuard(sessionAndControllerLock_);
    if (AbilityHasSession(pid, elementName.GetAbilityName())) {
        SLOGE("process %{public}d %{public}s already has one session", pid, elementName.GetAbilityName().c_str());
        return nullptr;
    }

    auto result = CreateNewSession(tag, type, !PermissionChecker::GetInstance().CheckSystemPermission(), elementName);
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

int32_t AVSessionService::GetAllSessionDescriptors(std::vector<AVSessionDescriptor>& descriptors)
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

void AVSessionService::ClearSessionForClientDiedNoLock(pid_t pid)
{
    auto sessions = GetContainer().RemoveSession(pid);
    for (const auto& session : sessions) {
        if (topSession_ == session) {
            UpdateTopSession(nullptr);
        }
        SLOGI("remove sessionId=%{public}s", session->GetSessionId().c_str());
        session->Destroy();
    }
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