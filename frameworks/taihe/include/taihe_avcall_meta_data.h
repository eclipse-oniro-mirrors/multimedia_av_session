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

#ifndef TAIHE_AVCALL_META_DATA_H
#define TAIHE_AVCALL_META_DATA_H

#include "avcall_meta_data.h"
#include "taihe_headers.h"

namespace ANI::AVSession {
using namespace taihe;
using namespace ohos::multimedia::avsession::avSession;

class TaiheAVCallMetaData {
public:
    static int32_t ConvertFilter(string_view filter, OHOS::AVSession::AVCallMetaData::AVCallMetaMaskType &mask);
    static int32_t ConvertFilter(array<string> filter, OHOS::AVSession::AVCallMetaData::AVCallMetaMaskType &mask);

    static int32_t GetCallMetadata(CallMetadata const &in, OHOS::AVSession::AVCallMetaData &out);
    static int32_t SetCallMetadata(const OHOS::AVSession::AVCallMetaData &in, CallMetadata &out);
    static CallMetadata CreateUndefinedCallMetadata();

    using GetterType = std::function<int32_t(CallMetadata const &in, OHOS::AVSession::AVCallMetaData &out)>;
    using SetterType = std::function<int32_t(const OHOS::AVSession::AVCallMetaData &in, CallMetadata &out)>;

private:
    static int32_t GetName(CallMetadata const &in, OHOS::AVSession::AVCallMetaData &out);
    static int32_t SetName(const OHOS::AVSession::AVCallMetaData &in, CallMetadata &out);

    static int32_t GetPhoneNumber(CallMetadata const &in, OHOS::AVSession::AVCallMetaData &out);
    static int32_t SetPhoneNumber(const OHOS::AVSession::AVCallMetaData &in, CallMetadata &out);

    static int32_t GetMediaImage(CallMetadata const &in, OHOS::AVSession::AVCallMetaData &out);
    static int32_t SetMediaImage(const OHOS::AVSession::AVCallMetaData &in, CallMetadata &out);

    static std::map<std::string, GetterType> getterMap_;
    static std::map<int32_t, SetterType> setterMap_;
    static std::pair<std::string, int32_t> filterMap_[OHOS::AVSession::AVCallMetaData::AVCALL_META_KEY_MAX];
};
} // namespace ANI::AVSession
#endif // TAIHE_AVCALL_META_DATA_H