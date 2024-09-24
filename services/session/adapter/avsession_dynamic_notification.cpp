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
 
#include "avsession_log.h"
#include "avsession_errors.h"
#include "avsession_descriptor.h"
#include "notification_content.h"
#include "notification_helper.h"
#include "notification_request.h"
#include "notification_constant.h"
#include "want_agent_helper.h"
#include "os_account_manager.h"

namespace OHOS {
namespace AVSession {
using namespace std;

const int32_t SYSTEMUI_LIVEVIEW_TYPECODE_MDEDIACONTROLLER = 2;
const int32_t AVSESSION_UID = 6700;
 
class NotificationSubscriber : public Notification::NotificationLocalLiveViewSubscriber {
    void OnConnected() {}
    void OnDisconnected() {}
    void OnResponse(int32_t notificationId, sptr<Notification::NotificationButtonOption> buttonOption) {}
    void OnDied() {}
};
 
static const auto NOTIFICATION_SUBSCRIBER = NotificationSubscriber();
 
// Notification Interface
extern "C" void NotifySystemUI(const AVSessionDescriptor* historyDescriptor,
    int32_t uid, bool isActiveSession,
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent)
{
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

    request.SetSlotType(Notification::NotificationConstant::SlotType::LIVE_VIEW);
    request.SetNotificationId(0);
    request.SetContent(content);
    request.SetCreatorUid(AVSESSION_UID);
    request.SetUnremovable(true);
    request.SetInProgress(true);
    int32_t userId;
    auto res = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    request.SetCreatorUserId((res == 0) ? userId : 0);
    request.SetWantAgent(wantAgent);
    result = Notification::NotificationHelper::PublishNotification(request);
    SLOGI("PublishNotification uid %{public}d, userId %{public}d, result %{public}d", uid, userId, result);
}
 
extern "C" int32_t CancelNotification(int32_t notificationId)
{
    int32_t ret = Notification::NotificationHelper::CancelNotification(notificationId);
    return ret;
}
 
}
} // namespace OHOS::AVSession
