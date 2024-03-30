#include <string>

#include "avsession_errors.h"
#include "avsession_log.h"
#include "avsession_info.h"
#include "allconnect_manager.h"

namespace OHOS::AVSession {
class CastAllConnectCallback : public CollaborationFwk::CallbackSkeleton {
public:
    CastAllConnectCallback();
    ~CastAllConnectCallback();
    int32_t OnServiceStateChanged(std::string deviceId, std::string serviceName, std::string extraInfo, int32_t state, int pid) override;
    int32_t GetCastAllConnectData(std::string& serviceName, int32_t& state);
private:
    std::string serviceName_ = "NULL";
    int32_t state_ = -1;
};
}