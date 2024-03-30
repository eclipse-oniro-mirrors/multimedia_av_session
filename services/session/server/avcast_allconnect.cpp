#include "avcast_allconnect.h"

namespace OHOS::AVSession {
CastAllConnectCallback::CastAllConnectCallback()
{
    SLOGI("CastAllConnectCallback constructor");
}
CastAllConnectCallback::~CastAllConnectCallback()
{
    SLOGI("CastAllConnectCallback destruct");
}
int32_t CastAllConnectCallback::OnServiceStateChanged(std::string deviceId, std::string serviceName, std::string extraInfo, int32_t state, int pid)
{
    SLOGI("deviceId = %{public}s, serviceName = %{public}s, state = %{public}d", deviceId.c_str(), serviceName.c_str(), state);
    serviceName_ = serviceName;
    state_ = state;
    return AVSESSION_SUCCESS;
}

int32_t CastAllConnectCallback::GetCastAllConnectData(std::string& serviceName, int32_t& state)
{
    if(serviceName_ == "NULL" || state_ == -1) {
        SLOGE("OnServiceStateChanged not callback");
        return AVSESSION_ERROR;
    }
    serviceName = serviceName_;
    state = state_;
    return AVSESSION_SUCCESS;
}
}