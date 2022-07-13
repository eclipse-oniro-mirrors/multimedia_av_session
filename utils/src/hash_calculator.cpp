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

#include "hash_calculator.h"

namespace OHOS::AVSession {
HashCalculator::~HashCalculator()
{
    if (context_ != nullptr) {
        delete context_;
        context_ = nullptr;
    }
}

int32_t HashCalculator::Init()
{
    context_ = new(std::nothrow) SHA256_CTX;
    if (context_ == nullptr) {
        return ERR_NO_MEMORY;
    }

    if (SHA256_Init(context_) == 0) {
        SLOGE("sha init failed");
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int HashCalculator::Update(const std::vector<uint8_t> &value)
{
    if (context_ == nullptr) {
        return AVSESSION_ERROR;
    }
    if (SHA256_Update(context_, value.data(), value.size()) == 0) {
        SLOGE("update failed");
        return AVSESSION_ERROR;
    }
    return AVSESSION_SUCCESS;
}

int HashCalculator::GetResult(std::vector<uint8_t> &value)
{
    if (context_ == nullptr) {
        return AVSESSION_ERROR;
    }

    value.resize(SHA256_DIGEST_LENGTH);
    if (SHA256_Final(value.data(), context_) == 0) {
        SLOGE("get result failed");
        return AVSESSION_ERROR;
    }

    return AVSESSION_SUCCESS;
}
}