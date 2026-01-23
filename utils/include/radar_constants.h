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

#ifndef OHOS_AV_SESSION_RADAR_CONSTANTS_H
#define OHOS_AV_SESSION_RADAR_CONSTANTS_H

#include <cstdint>
#include <string>

namespace OHOS::AVSession {
enum class TriggerMode : int32_t {
    UNKNOWN = -1,
    MEDIA_CONTROL = 0,
    APPLICATION = 1,
};

enum class BizScene : int32_t {
    CAST_DISCOVERY = 1,
    CAST_START,
    CAST_CONTROL,
    CAST_END
};

enum class StageResult : int32_t {
    IDLE = 0,
    SUCCESS,
    FAIL,
    CANCEL,
};

enum class BizState : int32_t {
    BEGIN = 1,
    END,
};

enum class TrustState : int32_t {
    UNKNOWN = 0,
    TRUST,
    NO_TRUST,
};

enum class CastDiscoveryStage : int32_t {
    START = 1,
    DISPLAY,
    STOP,
};

enum class CastStartStage : int32_t {
    START = 1,
    CONNECT,
    STARTED,
};

enum class CastControlStage : int32_t {
    SEND_COMMAND = 1,
    RECV_COMMAND,
};

enum class CastStopStage : int32_t {
    STOP_BEGIN = 1,
    STOP_END,
};

enum class TrustStatus : int32_t {
    UNKOWN = 0,
    TRUST = 1,
    UNTRUST = 2,
};

constexpr uint8_t AV_SESSION_SYSTEM_ID = 226;
constexpr uint8_t AV_SESSION_MODULE_ID = 18;

namespace {
const char* AVSESSION_CAST_BEHAVIOR = "AVSESSION_CAST_BEHAVIOR";

const char* ORG_PKG = "ORG_PKG";
const char* HOST_PKG = "HOST_PKG";
const char* TO_CALL_PKG = "TO_CALL_PKG";
const char* TRIGGER_MODE = "TRIGGER_MODE";
const char* FUNC = "FUNC";

const char* BIZ_SCENE = "BIZ_SCENE";
const char* BIZ_STAGE = "BIZ_STAGE";

const char* STAGE_RES = "STAGE_RES";
const char* BIZ_STATE = "BIZ_STATE";
const char* ERROR_CODE = "ERROR_CODE";

const char* DISCOVERY_DEVICE_LIST = "DISCOVERY_DEVICE_LIST";
const char* LOCAL_UDID = "LOCAL_UDID";
const char* LOCAL_NET_ID = "LOCAL_NET_ID";
const char* LOCAL_DEV_TYPE = "LOCAL_DEV_TYPE";
const char* PEER_UDID = "PEER_UDID";
const char* PEER_BT_MAC = "PEER_BT_MAC";
const char* PEER_NET_ID = "PEER_NET_ID";
const char* PEER_DEV_TYPE = "PEER_DEV_TYPE";
const char* PEER_DEV_NAME = "PEER_DEV_NAME";
const char* IS_TRUST = "IS_TRUST";
const char* LOCAL_SESS_NAME = "LOCAL_SESS_NAME";
const char* PEER_SESS_NAME = "PEER_SESS_NAME";
const char* SOURCE_TYPE = "SOURCE_TYPE";

const std::string DEV_PHONE = "00E";
const std::string DEV_LAPTOP = "00C";
const std::string AVSESSION_PKG_NAME = "av_session";
const std::string CAST_ENGINE_PKG = "cast_engine_service";
const std::string MEDIA_CONTROL_PKG = "mediacontroller";
}
constexpr uint32_t DEVICE_ID_MIN_LEN = 10;

enum class SoftBusErrNo {
    SOFTBUS_CONN_PASSIVE_TYPE_HML_NUM_LIMITED_CONFLICT = -425917431,
    SOFTBUS_CONN_PASSIVE_TYPE_P2P_GO_GC_CONFLICT = -425917435,
    SOFTBUS_CONN_PASSIVE_TYPE_STA_P2P_HML_555_CONFLICT = -425917437,
    SOFTBUS_CONN_PASSIVE_TYPE_STA_P2P_HML_525_CONFLICT = -425917439,
    SOFTBUS_CONN_PASSIVE_TYPE_STA_P2P_HML_255_CONFLICT = -425917441,
    SOFTBUS_CONN_PASSIVE_TYPE_STA_P2P_HML_225_CONFLICT = -425917443,
    SOFTBUS_CONN_PASSIVE_TYPE_STA_P2P_HML_55_CONFLICT = -425917445,
    SOFTBUS_CONN_PV2_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE = -425917814,
    SOFTBUS_CONN_PV1_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE = -425917848,
};
} // namespace OHOS::AVSession

#endif // OHOS_AV_SESSION_RADAR_CONSTANTS_H