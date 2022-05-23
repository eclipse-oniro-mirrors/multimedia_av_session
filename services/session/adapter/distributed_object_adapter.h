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

#ifndef AVSESSION_DISTRIBUTEDOBJECT_ADAPTER_H
#define AVSESSION_DISTRIBUTEDOBJECT_ADAPTER_H

#include "distributed_objectstore.h"
#include "avmeta_data.h"

namespace OHOS::AVSession {
class DistributedObjectAdapter {
public:
    using ObjectCallbackType = std::function<void(const std::vector<std::string>& keys)>;
    using ObjectDisconnectNotifier = std::function<void(const std::string& deviceId)>;

    explicit DistributedObjectAdapter(const std::string& name);

    ~DistributedObjectAdapter();

    int32_t CreateObject();

    int32_t PutData(const std::string& key, std::vector<uint8_t>& data);

    int32_t GetData(const std::string& key, std::vector<uint8_t>& data);

    void SetCallback(const ObjectCallbackType& callback);

    void SetDisconnectNotifier(const ObjectDisconnectNotifier& notifer);

    class AVSessionObjectWatcher : public ObjectStore::ObjectWatcher {
    public:
        explicit AVSessionObjectWatcher(const ObjectCallbackType& callback);
        void OnChanged(const std::string &name, const std::vector<std::string> &keys) override;
        virtual ~AVSessionObjectWatcher() = default;
    private:
        ObjectCallbackType callback_;
    };

    class AVSessionStatusNotifier : public ObjectStore::StatusNotifier {
    public:
        explicit AVSessionStatusNotifier(const ObjectDisconnectNotifier& notifier);
        void OnChanged(const std::string &name, const std::string &networkId,
                       const std::string &onlineStatus) override;
        virtual ~AVSessionStatusNotifier() = default;
    private:
        ObjectDisconnectNotifier notifier_;
    };

private:
    ObjectStore::DistributedObject *object_ {};
    std::string name_;

    static inline const char AVSESSION_NAME[] = "ohos.avsession";
    static inline const char DOBJECT_KEY_META[] = "meta";
    static inline const char DOBJECT_KEY_STATE[] = "state";
    static inline const char DOBJECT_KEY_CMD[] = "cmd";
};


}
#endif // AVSESSION_DISTRIBUTEDOBJECT_ADAPTER_H