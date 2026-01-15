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

#ifndef SOFTBUS_SESSION_MANAGER_H
#define SOFTBUS_SESSION_MANAGER_H

#include <string>
#include <mutex>
#include <map>

#include "avsession_dynamic_loader.h"

namespace OHOS::AVSession {
typedef enum {
    DATA_TYPE_MESSAGE = 1,         /**< Message */
    DATA_TYPE_BYTES,               /**< Bytes */
    DATA_TYPE_FILE,                /**< File */
    DATA_TYPE_RAW_STREAM,          /**< Raw data stream */
    DATA_TYPE_VIDEO_STREAM,        /**< Video data stream */
    DATA_TYPE_AUDIO_STREAM,        /**< Audio data stream */
    DATA_TYPE_SLICE_STREAM,        /**< Video slice stream */
    DATA_TYPE_RAW_STREAM_ENCRYPED, /**< Encryped raw stream data */
    DATA_TYPE_D2D_MESSAGE = 10,    /**< D2D Message */
    DATA_TYPE_D2D_VOICE = 11,      /**< D2D Voice */
    DATA_TYPE_BUTT,
} SoftbusTransDataType;

typedef struct {
    char *name;              /**< Peer socket name, maximum length 255 bytes */
    char *networkId;         /**< Peer network ID, maximum length 64 bytes */
    char *pkgName;           /**< Peer package name, maximum length 64 bytes */
    SoftbusTransDataType dataType;  /**< Data type of peer socket*/
    char *accountId;         /**< Peer accountId, maximum length 64 bytes */
    void *extraData;         /**< Peer extradata, maximum length 5 bytes */
    uint32_t dataLen;        /**< Peer dataLen, maximum 5 */
} SoftbusPeerSocketInfo;

typedef enum {
    SHUTDOWN_REASON_UNKNOWN,       /**< Shutdown for unknown reason */
    SHUTDOWN_REASON_LOCAL,         /**< Shutdown by local process */
    SHUTDOWN_REASON_PEER,          /**< Shutdown by peer process */
    SHUTDOWN_REASON_LNN_CHANGED,   /**< Shutdown for LNN changed */
    SHUTDOWN_REASON_CONN_CHANGED,  /**< Shutdown for CONN Changed */
    SHUTDOWN_REASON_TIMEOUT,       /**< Shutdown for timeout */
    SHUTDOWN_REASON_SEND_FILE_ERR, /**< Shutdown for sending file error */
    SHUTDOWN_REASON_RECV_FILE_ERR, /**< Shutdown for receiving file error */
    SHUTDOWN_REASON_RECV_DATA_ERR, /**< Shutdown for receiving data error */
    SHUTDOWN_REASON_UNEXPECTED,    /**< Shutdown for unexpected reason */
    SHUTDOWN_REASON_SERVICE_DIED,  /**< Shutdown for death service */
    SHUTDOWN_REASON_LNN_OFFLINE,   /**< Shutdown for offline */
    SHUTDOWN_REASON_LINK_DOWN,     /**< Shutdown for link down */
    SHUTDOWN_REASON_USER_SWICTH,   /**< Shutdown for user switch */
    SHUTDOWN_REASON_PRIVILEGE_SHUTDOWN, /**< Shutdown for privilege shutdown */
} SoftbusShutdownReason;

typedef struct DynamicSocketCallbackFunc {
    void (*OnBind)(int32_t socket, SoftbusPeerSocketInfo info);
    void (*OnShutdown)(int32_t socket, SoftbusShutdownReason reason);
    void (*OnBytes)(int socket, const void *data, unsigned int dataLen);
    void (*OnMessage)(int socket, const void *data, unsigned int dataLen);
} DynamicSocketCallbackFunc;

class SoftbusSessionListener {
public:
#ifdef DSOFTBUS_ENABLE
    virtual void OnBind(int32_t socket, SoftbusPeerSocketInfo info) = 0;
    virtual void OnShutdown(int32_t socket, SoftbusShutdownReason reason) = 0;
#endif
    virtual void OnBytes(int32_t socket, const void *data, int32_t dataLen) = 0;
    virtual void OnMessage(int32_t socket, const void *data, int32_t dataLen) = 0;
    virtual ~SoftbusSessionListener() = default;
};

class SoftbusSessionManager {
public:
    static SoftbusSessionManager& GetInstance();

    int32_t Socket(const std::string &pkgName);

#ifdef DSOFTBUS_ENABLE
    int32_t Bind(const std::string &peerNetworkId, const std::string &pkgName);

    void Shutdown(int32_t socket);
#endif

    int32_t SendMessage(int32_t socket, const std::string &data);

    int32_t SendBytes(int32_t socket, const std::string &data);

    int32_t SendBytesForNext(int32_t socket, const std::string &data);

    int32_t ObtainPeerDeviceId(int32_t socket, std::string &deviceId);

    void AddSessionListener(std::shared_ptr<SoftbusSessionListener> softbusSessionListener);

#ifdef DSOFTBUS_ENABLE
    /* *
     * Callback adaptation for session channel opened.
     *
     * @param socket socket
     */
    void OnBind(int32_t socket, SoftbusPeerSocketInfo info);

    /* *
     * Callback adaptation for session channel closed.
     *
     * @param socket socket
     */
    void OnShutdown(int32_t socket, SoftbusShutdownReason reason);
#endif

    /* *
     * Callback adaptation for data received by the session channel.
     *
     * @param socket socket
     * @param data data received by the session channel
     */
    void OnMessage(int32_t socket, const void *data, int32_t dataLen);
    void OnBytes(int32_t socket, const void *data, int32_t dataLen);

private:
    std::recursive_mutex socketLock_;

    std::vector<std::shared_ptr<SoftbusSessionListener>> sessionListeners_;
    std::map<int32_t, std::string> mMap_;

    std::unique_ptr<AVSessionDynamicLoader> dynamicLoader = std::make_unique<AVSessionDynamicLoader>();
};
} // namespace OHOS::AVSession

#endif // SOFTBUS_SESSION_MANAGER_H
