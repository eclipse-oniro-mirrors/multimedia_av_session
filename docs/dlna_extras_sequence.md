# DLNA投播自定义扩展参数 - 从NAPI到Cast+的时序图

## 时序图

```mermaid
sequenceDiagram
    participant JSApp as JS应用
    participant NAPI as NapiAVCastController
    participant Controller as AVCastControllerProxy<br/>(IPC Client)
    participant IPC as IPC Binder
    participant Stub as AVCastControllerStub<br/>(IPC Server)
    participant Item as AVCastControllerItem
    participant Player as HwCastStreamPlayer
    participant StreamPlayer as IStreamPlayer
    participant CastEngine as Cast+引擎

    JSApp->>NAPI: castController.start(avQueueItem)<br/>AVQueueItem包含extras(WantParams)

    rect rgb(230, 245, 255)
        Note over JSApp,NAPI: 1. NAPI层 - 参数解析
        NAPI->>NAPI: inputParser<br/>NapiUtils::GetValue(env, argv, avQueueItem_)<br/>解析JS对象为AVQueueItem<br/>extras存入AVMediaDescription
    end

    rect rgb(255, 245, 230)
        Note over NAPI,Controller: 2. 异步执行
        NAPI->>NAPI: executor<br/>castController_->Start(avQueueItem_)
        NAPI->>Controller: Start(AVQueueItem)
    end

    rect rgb(230, 255, 230)
        Note over Controller,IPC: 3. IPC代理 - 序列化发送
        Controller->>Controller: parcel.WriteInterfaceToken()
        Controller->>Controller: parcel.WriteParcelable(&avQueueItem)<br/>AVQueueItem序列化(Parcel)
        Controller->>IPC: SendRequest(CAST_CONTROLLER_CMD_START)
    end

    rect rgb(255, 230, 245)
        Note over IPC,Stub: 4. IPC Stub - 反序列化
        IPC->>Stub: HandleStart(data, reply)
        Stub->>Stub: data.ReadParcelable<AVQueueItem>()<br/>反序列化AVQueueItem<br/>extras从Parcel恢复为WantParams
        Stub->>Item: Start(*avQueueItem)
    end

    rect rgb(245, 245, 230)
        Note over Item: 5. 服务端 - 补充投播信息
        Item->>Item: buildExtraCastInfo(avQueueItem)
        Item->>Item: SetQueueItemDataSrc(avQueueItem)
        Item->>Item: 补充appName等
        Item->>Player: castControllerProxy_->Start(avQueueItem)
    end

    rect rgb(230, 230, 255)
        Note over Player: 6. 构建Cast媒体信息
        Player->>Player: Start(AVQueueItem)
        Player->>Player: buildCastInfo(mediaDescription, mediaInfo)<br/>填充mediaId/mediaUrl等字段
        Player->>Player: buildCastExtraInfo(mediaDescription, mediaInfo)
        Player->>Player: mediaDescription->GetExtras()<br/>获取WantParams
        Player->>Player: GetDlnaExtrasFromWantParams(extras)
        Note over Player: 遍历DlnaExtrasKey::DIDL_LITE<br/>和DlnaExtrasKey::CURRENT_URI_METADATA<br/>从WantParams提取字符串值<br/>cJSON序列化为JSON字符串
        Player->>Player: mediaInfo.extrasData = JSON字符串
    end

    rect rgb(255, 230, 230)
        Note over Player,CastEngine: 7. 投递到Cast+引擎
        alt 相同媒体(仅play)
            Player->>StreamPlayer: Play()
            StreamPlayer->>CastEngine: 继续播放当前媒体
        else 新媒体(Load+Play)
            Player->>StreamPlayer: Play(mediaInfo)<br/>携带extrasData
            StreamPlayer->>CastEngine: 解析extrasData JSON<br/>提取DIDL-Lite和CurrentURIMetadata<br/>执行DLNA投播
        end
    end

    CastEngine-->>JSApp: 投播结果回调
```

## 数据流转说明

| 阶段 | 数据结构 | 说明 |
|------|---------|------|
| JS应用 → NAPI | `AVQueueItem`(JS对象) | extras作为WantParams存储在AVMediaDescription中 |
| NAPI → IPC Proxy | `AVQueueItem`(C++对象) | 通过`NapiUtils::GetValue`解析JS对象为Native对象 |
| IPC Proxy → IPC Stub | `MessageParcel`(序列化) | AVQueueItem通过Parcel序列化传输，extras作为WantParams序列化 |
| IPC Stub → Item | `AVQueueItem`(C++对象) | 从Parcel反序列化恢复AVQueueItem |
| Item → Player | `AVQueueItem`(C++对象) | 补充appName等额外信息后传递 |
| Player内部 | `WantParams` → `std::string` | `GetDlnaExtrasFromWantParams`将WantParams转为JSON字符串 |
| Player → Cast+ | `CastEngine::MediaInfo` | extrasData字段携带DLNA参数JSON |

## DLNA Extras JSON格式示例

```json
{
    "DIDL-Lite": "<DIDL-Lite xmlns=\"urn:schemas-upnp-org:DIDL-Lite\">...</DIDL-Lite>",
    "CurrentURIMetadata": "<DIDL-Lite xmlns=\"urn:schemas-upnp-org:DIDL-Lite\">...</DIDL-Lite>"
}
```

## 关键源文件

| 组件 | 文件路径 |
|------|---------|
| NAPI入口 | `frameworks/js/napi/session/src/napi_avcast_controller.cpp:240` |
| ExtraKey枚举导出 | `frameworks/js/napi/session/src/napi_avsession_enum.cpp` |
| IPC Proxy | `services/session/ipc/proxy/avcast_controller_proxy.cpp:78` |
| IPC Stub | `services/session/ipc/stub/avcast_controller_stub.cpp:96` |
| 服务端Item | `services/session/server/avcast_controller_item.cpp:235` |
| StreamPlayer | `services/session/server/hw_cast_stream_player.cpp:203` |
| DLNA解析 | `services/session/server/hw_cast_stream_player.cpp:340` |
| 常量定义 | `interfaces/inner_api/native/session/include/avsession_info.h` |
