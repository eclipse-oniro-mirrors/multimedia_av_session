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

#include <iostream>
#include "avsession_log.h"
#include "avsession_errors.h"
#include "system_ability_definition.h"
#include "avsession_service.h"
#include "avsessionservice_fuzzer.h"
using namespace std;
using namespace OHOS;
using namespace OHOS::AVSession;

const int32_t MAX_CODE_LEN  = 512;

int32_t AVSessionServiceFuzzer::OnRemoteRequest(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return AVSESSION_ERROR;
    }
    if (size > MAX_CODE_LEN) {
		return AVSESSION_ERROR;
	}
    MessageParcel dataMessageParcel;
    auto localDescriptor = IAVSessionService::GetDescriptor();
	if (!dataMessageParcel.WriteInterfaceToken(localDescriptor)) {
		return AVSESSION_ERROR;
	}

	uint32_t code = *(reinterpret_cast<const uint32_t*>(data));

	size -= sizeof(uint32_t);

	dataMessageParcel.WriteBuffer(data + sizeof(uint32_t), size);
	dataMessageParcel.RewindRead(0);
    sptr<AVSessionService> mAVSessionService = new AVSessionService(AVSESSION_SERVICE_ID);

    MessageParcel reply;
    MessageOption option;
    mAVSessionService->OnStart();
    int32_t ret = mAVSessionService->OnRemoteRequest(code, dataMessageParcel, reply, option);
    mAVSessionService->OnStop();
    return ret;
}

int32_t OHOS::AVSession::AVSessionServiceRemoteRequestTest(uint8_t* data, size_t size)
{
    auto avSessionService = std::make_unique<AVSessionServiceFuzzer>();
    if (avSessionService == nullptr) {
        cout << "avSessionServiceFuzzer is null" << endl;
        return AVSESSION_ERROR;
    }
    return avSessionService->OnRemoteRequest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AVSession::AVSessionServiceRemoteRequestTest(data, size);
    return 0;
}