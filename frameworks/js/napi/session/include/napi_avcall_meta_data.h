/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_NAPI_AVCALL_META_DATA_H
#define OHOS_NAPI_AVCALL_META_DATA_H

#include "avcall_meta_data.h"
#include "napi/native_api.h"

namespace OHOS::AVSession {
class NapiAVCallMetaData {
public:
    static napi_status ConvertFilter(napi_env env, napi_value filter, AVCallMetaData::AVCallMetaMaskType& mask);

    static napi_status GetValue(napi_env env, napi_value in, AVCallMetaData& out);
    static napi_status SetValue(napi_env env, const AVCallMetaData& in, napi_value& out);

    using GetterType = std::function<napi_status(napi_env, napi_value in, AVCallMetaData& out)>;
    using SetterType = std::function<napi_status(napi_env env, const AVCallMetaData& in, napi_value& out)>;

private:
    static napi_status SetUndefinedMeta(napi_env env, napi_value& meta);

    static napi_status GetName(napi_env env, napi_value in, AVCallMetaData& out);
    static napi_status SetName(napi_env env, const AVCallMetaData& in, napi_value& out);

    static napi_status GetPhoneNumber(napi_env env, napi_value in, AVCallMetaData& out);
    static napi_status SetPhoneNumber(napi_env env, const AVCallMetaData& in, napi_value& out);

    static napi_status GetMediaImage(napi_env env, napi_value in, AVCallMetaData& out);
    static napi_status SetMediaImage(napi_env env, const AVCallMetaData& in, napi_value& out);
    static napi_status SetMediaImageUri(napi_env env, const AVCallMetaData& in, napi_value& out);

    static std::map<std::string, GetterType> getterMap_;
    static std::map<int32_t, SetterType> setterMap_;
    static std::pair<std::string, int32_t> filterMap_[AVCallMetaData::AVCALL_META_KEY_MAX];

    static constexpr int GETTER_INDEX = 0;
    static constexpr int SETTER_INDEX = 1;
    static constexpr int ENUM_INDEX = 2;
};
}
#endif // OHOS_NAPI_AVCALL_META_DATA_H
