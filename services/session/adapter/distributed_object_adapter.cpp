/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "distributed_object_adapter.h"
#include "avsession_log.h"
#include "avsession_errors.h"
#include "objectstore_errors.h"

namespace OHOS::AVSession {
DistributedObjectAdapter::AVSessionObjectWatcher::AVSessionObjectWatcher(const ObjectCallbackType &callback)
{
    callback_ = callback;
}

void DistributedObjectAdapter::AVSessionObjectWatcher::OnChanged(const std::string &name,
                                                                 const std::vector<std::string> &keys)
{
    if (callback_) {
        callback_(keys);
    }
}

DistributedObjectAdapter::AVSessionStatusNotifier::AVSessionStatusNotifier(const ObjectDisconnectNotifier &notifier)
{
    notifier_ = notifier;
}

void DistributedObjectAdapter::AVSessionStatusNotifier::OnChanged(const std::string &name,
                                                                  const std::string &networkId,
                                                                  const std::string &onlineStatus)
{
    SLOGI("%{public}.3s %{public}s", networkId.c_str(), onlineStatus.c_str());
    if (onlineStatus == "offline" && notifier_) {
        notifier_(networkId);
    }
}

DistributedObjectAdapter::DistributedObjectAdapter(const std::string& name)
    : name_(name)
{
    SLOGI("construct");
}

DistributedObjectAdapter::~DistributedObjectAdapter()
{
    SLOGI("destroy");
    if (object_ != nullptr) {
        ObjectStore::DistributedObjectStore::GetInstance(AVSESSION_NAME)->DeleteObject(name_);
    }
}

int32_t DistributedObjectAdapter::CreateObject()
{
    object_ = ObjectStore::DistributedObjectStore::GetInstance(AVSESSION_NAME)->CreateObject(name_);
    if (object_ == nullptr) {
        SLOGE("failed");
        return AVSESSION_ERROR;
    }
    SLOGI("success");
    return AVSESSION_SUCCESS;
}

int32_t DistributedObjectAdapter::PutData(const std::string &key, std::vector<uint8_t> &data)
{
    if (object_ == nullptr) {
        SLOGE("object is nullptr");
        return AVSESSION_ERROR;
    }

    return object_->PutComplex(key, data) == ObjectStore::SUCCESS ? AVSESSION_SUCCESS : AVSESSION_ERROR;
}

int32_t DistributedObjectAdapter::GetData(const std::string &key, std::vector<uint8_t> &data)
{
    if (object_ == nullptr) {
        SLOGE("object is nullptr");
        return AVSESSION_ERROR;
    }

    return object_->GetComplex(key, data) == ObjectStore::SUCCESS ? AVSESSION_SUCCESS : AVSESSION_ERROR;
}

void DistributedObjectAdapter::SetCallback(const ObjectCallbackType &callback)
{
    if (object_ == nullptr) {
        SLOGE("object is nullptr");
        return;
    }
    ObjectStore::DistributedObjectStore::GetInstance()->Watch(
        object_, std::make_shared<AVSessionObjectWatcher>(callback));
}

void DistributedObjectAdapter::SetDisconnectNotifier(const ObjectDisconnectNotifier &notifer)
{
    if (object_ == nullptr) {
        SLOGE("object is nullptr");
        return;
    }
    ObjectStore::DistributedObjectStore::GetInstance()->SetStatusNotifier(
        std::make_shared<AVSessionStatusNotifier>(notifer));
}
}