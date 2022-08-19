# 媒体会话管理

AVSession（Audio & Video Session，媒体会话管理）提供媒体播控相关功能的接口，使应用可以高效地在不同媒体之间完成切换。

> **说明：**
>
> 本模块首批接口从API version 9开始支持。后续版本的新增接口，采用上角标单独标记接口的起始版本。

## 导入模块

```js
import avsession from '@ohos.multimedia.avsession';
```

## avsession.createAVSession

createAVSession(context: Context, tag: string, type: AVSessionType): Promise\<AVSession>

创建会话对象。使用Promise异步回调。

一个Ability只能存在一个会话，重复创建会失败。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名 | 类型                            | 必填 | 说明                           |
| ------ | ------------------------------- | ---- | ------------------------------ |
| tag    | string                          | 是   | 会话的自定义名称。             |
| type   | [AVSessionType](#avsessiontype) | 是   | 会话类型，当前支持音频和视频。 |


**返回值：**

| 类型                              | 说明                                                         |
| --------------------------------- | ------------------------------------------------------------ |
| Promise<[AVSession](#avsession)\> | Promise对象。返回会话实例对象，可用于获取会话ID，并发送元数据、播放状态、按键事件等操作。 |

**示例：**

```js
import featureAbility from '@ohos.ability.featureAbility';

let session;
let tag = "createNewSession";
let type = "audio";
let context = featureAbility.getContext();

await avsession.createAVSession(context, tag, type).then((avsession) => {
    session = avsession;
    console.info('createAVSession : SUCCESS : sessionId = ' + session.sessionId);
}).catch((err) => {
    console.info('createAVSession : ERROR : ' + err.message);
});
```

## avsession.createAVSession

createAVSession(context: Context, tag: string, type: AVSessionType, callback: AsyncCallback\<AVSession>): void

创建会话对象。使用callback异步回调。

一个Ability只能存在一个会话，重复创建会失败。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                    | 必填 | 说明                                                         |
| -------- | --------------------------------------- | ---- | ------------------------------------------------------------ |
| tag      | string                                  | 是   | 会话的自定义名称。                                           |
| type     | [AVSessionType](#avsessiontype)         | 是   | 会话类型，当前支持音频和视频。                               |
| callback | AsyncCallback<[AVSession](#avsession)\> | 是   | 回调函数。回调返回会话实例对象，可用于获取会话ID，并发送元数据、播放状态、按键事件等操作。 |

**示例：**

```js
import featureAbility from '@ohos.ability.featureAbility';

let session;
let tag = "createNewSession";
let type = "audio";
let context = featureAbility.getContext();

await avsession.createAVSession(context, tag, type, function (err, avsession) {
    if (err.code == 0) {
        session = avsession;
        console.info('createAVSession : SUCCESS : sessionId = ' + session.sessionId);
    } else {
        console.info('createAVSession : ERROR : ' + err.message);
    }
});
```

## avsession.getAllSessionDescriptors

getAllSessionDescriptors(): Promise\<Array\<Readonly\<AVSessionDescriptor>>>

获取所有会话的相关描述。使用Promise异步回调。

**需要权限：** ohos.permission.MANAGE_MEDIA_RESOURCES，仅系统应用可用。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**返回值：**

| 类型                                                         | 说明                                          |
| ------------------------------------------------------------ | --------------------------------------------- |
| Promise\<Array\<Readonly\<[AVSessionDescriptor](#avsessiondescriptor)\>\>\> | Promise对象。返回所有的会话的描述的只读对象。 |

**示例：**

```js
avsession.getAllSessionDescriptors().then((descriptors) => {
    console.info('getAllSessionDescriptors : SUCCESS : descriptors.length : ' + descriptors.length);
    if(descriptors.length > 0 ){
        console.info('getAllSessionDescriptors : SUCCESS : descriptors[0].isActive : ' + descriptors[0].isActive);
        console.info('getAllSessionDescriptors : SUCCESS : descriptors[0].type : ' + descriptors[0].type);
        console.info('getAllSessionDescriptors : SUCCESS : descriptors[0].sessionTag : ' + descriptors[0].sessionTag);
    }
}).catch((err) => {
    console.info('getAllSessionDescriptors : ERROR : '+err.message);
});
```

## avsession.getAllSessionDescriptors

getAllSessionDescriptors(callback: AsyncCallback\<Array\<Readonly\<AVSessionDescriptor>>>): void

获取所有会话的相关描述。使用callback异步回调。

**需要权限：** ohos.permission.MANAGE_MEDIA_RESOURCES，仅系统应用可用。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                                         | 必填 | 说明                                       |
| -------- | ------------------------------------------------------------ | ---- | ------------------------------------------ |
| callback | AsyncCallback<Array<Readonly<[AVSessionDescriptor](#avsessiondescriptor)\>\>\> | 是   | 回调函数。返回所有的会话的描述的只读对象。 |

**示例：**

```js
avsession.getAllSessionDescriptors(function (err, descriptors) {
    if (err.code == 0) {
        console.info('getAllSessionDescriptors : SUCCESS : descriptors.length : ' + descriptors.length);
        if(descriptors.length > 0 ){
            console.info('getAllSessionDescriptors : SUCCESS : descriptors[0].isActive : ' + descriptors[0].isActive);
            console.info('getAllSessionDescriptors : SUCCESS : descriptors[0].type : ' + descriptors[0].type);
            console.info('getAllSessionDescriptors : SUCCESS : descriptors[0].sessionTag : ' + descriptors[0].sessionTag);
        }
    } else {
        console.info('getAllSessionDescriptors : ERROR : '+err.message);
    }
});
```

## avsession.createController

createController(sessionId: string): Promise\<AVSessionController>

根据会话ID创建会话控制器，可以创建多个会话控制器。使用Promise异步回调。

**需要权限：** ohos.permission.MANAGE_MEDIA_RESOURCES，仅系统应用可用。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名    | 类型   | 必填 | 说明     |
| --------- | ------ | ---- | -------- |
| sessionId | string | 是   | 会话ID。 |


**返回值：**

| 类型                                                  | 说明                                                         |
| ----------------------------------------------------- | ------------------------------------------------------------ |
| Promise<[AVSessionController](#avsessioncontroller)\> | Promise对象。返回会话控制器实例，可获得会话ID，并对会话进行发送命令，获取元数据、播放状态、按键事件等操作。 |

**示例：**

```js
let controller;
await avsession.createController(session.sessionId).then((avcontroller) => {
    controller = avcontroller;
    console.info('createController : SUCCESS : ' + controller.sessionId);
}).catch((err) => {
    console.info('createController : ERROR : ' + err.message);
});
```

## avsession.createController

createController(sessionId: string, callback: AsyncCallback\<AVSessionController>): void

根据会话ID创建会话控制器，可以创建多个会话控制器。使用callback异步回调。

**需要权限：** ohos.permission.MANAGE_MEDIA_RESOURCES，仅系统应用可用。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名    | 类型                                                        | 必填 | 说明                                                         |
| --------- | ----------------------------------------------------------- | ---- | ------------------------------------------------------------ |
| sessionId | string                                                      | 是   | 会话ID。                                                     |
| callback  | AsyncCallback<[AVSessionController](#avsessioncontroller)\> | 是   | 回调函数。返回会话控制器实例，可获得会话ID，并对会话进行发送命令，获取元数据、播放状态、按键事件等操作。 |

**示例：**

```js
let controller;
await avsession.createController(session.sessionId, function (err, avcontroller) {
    if (err.code == 0) {
        controller = avcontroller;
        console.info('createController : SUCCESS : ' + controller.sessionId);
    } else {
        console.info('createController : ERROR : '+err.message);
    }
});
```

## avsession.castAudio

castAudio(session: SessionToken | 'all', audioDevices: Array<audio.AudioDeviceDescriptor>): Promise\<void>

发送AudioDeviceDescriptor列表。使用Promise异步回调。

需要导入`ohos.multimedia.audio`模块获取AudioDeviceDescriptor的相关描述。

**需要权限：** ohos.permission.MANAGE_MEDIA_RESOURCES，仅系统应用可用。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名       | 类型                                                         | 必填 | 说明                                                         |
| ------------ | ------------------------------------------------------------ | ---- | ------------------------------------------------------------ |
| session      | [SessionToken](#sessiontoken) &#124; 'all'                   | 是   | 会话令牌。SessionToken表示单个token；字符串`'all'`指所有token。 |
| audioDevices | Array\<[audio.AudioDeviceDescriptor](js-apis-audio.md#audiodevicedescriptor)\> | 是   | 媒体的设备的描述列表。                                       |

**返回值：**

| 类型           | 说明                          |
| -------------- | ----------------------------- |
| Promise<void\> | Promise回调表示成功还是失败。 |

**示例：**

```js
import audio from '@ohos.multimedia.audio';

var audioManager = audio.getAudioManager();
var audioDevices;
await audioManager.getDevices(audio.DeviceFlag.OUTPUT_DEVICES_FLAG).then((data) => {
    audioDevices = data;
    console.log('Promise returned to indicate that the device list is obtained.');
});

avsession.castAudio('all', audioDevices).then(() => {
    console.info('createController : SUCCESS');
}).catch((err) => {
    console.info('createController : ERROR : ' + err.message);
});
```

## avsession.castAudio

castAudio(session: SessionToken | 'all', audioDevices: Array<audio.AudioDeviceDescriptor>, callback: AsyncCallback\<void>): void

发送AudioDeviceDescriptor列表。使用callback异步回调。

需要导入`ohos.multimedia.audio`模块获取AudioDeviceDescriptor的相关描述。

**需要权限：** ohos.permission.MANAGE_MEDIA_RESOURCES，仅系统应用可用。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名       | 类型                                                         | 必填 | 说明                                                         |
| ------------ | ------------------------------------------------------------ | ---- | ------------------------------------------------------------ |
| session      | [SessionToken](#sessiontoken) &#124; 'all'                   | 是   | 会话令牌。SessionToken表示单个token；字符串`'all'`指所有token。 |
| audioDevices | Array\<[audio.AudioDeviceDescriptor](js-apis-audio.md#audiodevicedescriptor)\> | 是   | 媒体的设备的描述列表。                                       |
| callback     | AsyncCallback<void\>                                         | 是   | 回调函数。发送失败将获取err错误对象。                        |

**示例：**

```js
import audio from '@ohos.multimedia.audio';

var audioManager = audio.getAudioManager();
var audioDevices;
await audioManager.getDevices(audio.DeviceFlag.OUTPUT_DEVICES_FLAG).then((data) => {
    audioDevices = data;
    console.log('Promise returned to indicate that the device list is obtained.');
});

avsession.castAudio('all', audioDevices, function (err) {
    if (err.code == 0) {
        console.info('castAudio : SUCCESS ');
    } else {
        console.info('castAudio : ERROR : '+err.message);
    }
});
```

## avsession.on('sessionCreated' | 'sessionDestroyed')

on(type: 'sessionCreated' | 'sessionDestroyed', callback: (session: AVSessionDescriptor) => void): void

会话的创建和销毁的监听事件。

**需要权限：** ohos.permission.MANAGE_MEDIA_RESOURCES，仅系统应用可用。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                                         | 必填 | 说明                                                         |
| -------- | ------------------------------------------------------------ | ---- | ------------------------------------------------------------ |
| type     | string                                                       | 是   | 事件回调类型，支持的事件为：<br/>- `'sessionCreated'`：会话创建事件，检测到会话创建时触发。<br/>- `'sessionDestroyed'`：会话销毁事件，检测到会话销毁时触发。 |
| callback | (session: [AVSessionDescriptor](#avsessiondescriptor)) => void | 是   | 回调函数。参数为会话相关描述。                               |

**示例：**

```js
avsession.on('sessionCreated', (descriptor) => {
    console.info('on sessionCreated : isActive : ' + descriptors.isActive);
    console.info('on sessionCreated : type : ' + descriptors.type);
    console.info('on sessionCreated : sessionTag : ' + descriptors.sessionTag);
});

avsession.on('sessionDestroyed', (descriptor) => {
    console.info('on sessionDestroyed : isActive : ' + descriptors.isActive);
    console.info('on sessionDestroyed : type : ' + descriptors.type);
    console.info('on sessionDestroyed : sessionTag : ' + descriptors.sessionTag);
});
```

## avsession.on('topSessionChanged')

on(type: 'topSessionChanged', callback: (session: AVSessionDescriptor) => void): void

最新会话的变化的监听事件。

**需要权限：** ohos.permission.MANAGE_MEDIA_RESOURCES，仅系统应用可用。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                                         | 必填 | 说明                                                         |
| -------- | ------------------------------------------------------------ | ---- | ------------------------------------------------------------ |
| type     | string                                                       | 是   | 事件回调类型，支持事件`'topSessionChanged'`：最新会话的变化事件，检测到最新的会话改变时触发。 |
| callback | (session: [AVSessionDescriptor](#avsessiondescriptor)) => void | 是   | 回调函数。参数为会话相关描述。                               |

**示例：**

```js
avsession.on('topSessionChanged', (descriptor) => {
    console.info('on topSessionChanged : isActive : ' + descriptors.isActive);
    console.info('on topSessionChanged : type : ' + descriptors.type);
    console.info('on topSessionChanged : sessionTag : ' + descriptors.sessionTag);
});
```

## avsession.on('sessionServiceDied')

on(type: 'sessionServiceDied', callback: () => void): void

监听会话的服务死亡事件。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                 | 必填 | 说明                                                         |
| -------- | -------------------- | ---- | ------------------------------------------------------------ |
| type     | string               | 是   | 事件回调类型，支持事件`'sessionServiceDied'`：会话服务死亡事件，检测到会话的服务死亡时触发。 |
| callback | callback: () => void | 是   | 回调函数。                                                   |

**示例：**

```js
avsession.on('sessionServiceDied', () => {
    console.info('on sessionServiceDied  : session is  Died ');
});
```

## avsession.off('sessionServiceDied')

off(type: 'sessionServiceDied'): void

会话服务死亡监听的关闭，关闭后，不再进行相关on方法的回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名 | 类型   | 必填 | 说明                                                         |
| ------ | ------ | ---- | ------------------------------------------------------------ |
| type   | string | 是   | 事件回调类型，支持事件`'sessionServiceDied'`：会话服务死亡事件。 |

**示例：**

```js
avsession.off('sessionServiceDied');
```

## avsession.off('sessionCreated' | 'sessionDestroyed' | 'topSessionChanged')

off(type: 'sessionCreated' | 'sessionDestroyed' | 'topSessionChanged'): void

会话对象相关监听的关闭，关闭后，不在进行相关on的回调。

**需要权限：** ohos.permission.MANAGE_MEDIA_RESOURCES，仅系统应用可用。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名 | 类型   | 必填 | 说明                                                         |
| ------ | ------ | ---- | ------------------------------------------------------------ |
| type   | string | 是   | 事件回调类型，支持的事件为：<br/>- `'sessionCreated'`：会话创建事件。<br/>- `'sessionDestroyed'`：会话销毁事件。<br/>- `'topSessionChanged'`：最新会话的变化事件。 |

**示例：**

```js
avsession.off('sessionCreated');
avsession.off('sessionDestroyed');
avsession.off('topSessionChanged');
```

## avsession.sendSystemAVKeyEvent

sendSystemAVKeyEvent(event: KeyEvent): Promise\<void>

发送会话相关的按键事件。使用Promise异步回调。

**需要权限：** ohos.permission.MANAGE_MEDIA_RESOURCES，仅系统应用可用。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名 | 类型                            | 必填 | 说明       |
| ------ | ------------------------------- | ---- | ---------- |
| event  | [KeyEvent](js-apis-keyevent.md) | 是   | 按键事件。 |

**返回值：**

| 类型           | 说明                          |
| -------------- | ----------------------------- |
| Promise<void\> | Promise回调表示成功还是失败。 |

**示例：**

```js

let keyItem = {code:0x49, pressedTime:123456789, deviceId:0};
let event = {action:2, key:keyItem, keys:[keyItem]};

avsession.sendSystemAVKeyEvent(event).then(() => {
    console.info('sendSystemAVKeyEvent Successfully');
}).catch((err) => {
    console.info('sendSystemAVKeyEvent : ERROR : '+ err.message);
});

```

## avsession.sendSystemAVKeyEvent

sendSystemAVKeyEvent(event: KeyEvent, callback: AsyncCallback\<void>): void

发送会话相关的按键事件。使用callback异步回调。

**需要权限：** ohos.permission.MANAGE_MEDIA_RESOURCES，仅系统应用可用。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                                         | 必填 | 说明                                  |
| -------- | ------------------------------------------------------------ | ---- | ------------------------------------- |
| event    | [KeyEvent](https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis/js-apis-keyevent.md) | 是   | 按键事件。                            |
| callback | AsyncCallback<void\>                                         | 是   | 回调函数。发送失败将获取err错误对象。 |

**示例：**

```js
let keyItem = {code:0x49, pressedTime:123456789, deviceId:0};
let event = {action:2, key:keyItem, keys:[keyItem]};

avsession.sendSystemAVKeyEvent(event, function (err) {
    if (err.code == 0) {
        console.info('sendSystemAVKeyEvent : SUCCESS ');
    } else {
        console.info('sendSystemAVKeyEvent : ERROR : '+ err.message);
    }
});
```

## avsession.sendSystemControlCommand

sendSystemControlCommand(command: AVControlCommand): Promise\<void>

发送会话相关的控制命令。使用Promise异步回调。

**需要权限：** ohos.permission.MANAGE_MEDIA_RESOURCES，仅系统应用可用。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名  | 类型                                  | 必填 | 说明                                |
| ------- | ------------------------------------- | ---- | ----------------------------------- |
| command | [AVControlCommand](#avcontrolcommand) | 是   | AVSession的相关命令和命令相关参数。 |

**返回值：**

| 类型           | 说明                          |
| -------------- | ----------------------------- |
| Promise<void\> | Promise回调表示成功还是失败。 |

**示例：**

```js
let avcommand = {command:'play'};
// let avcommand = {command:'pause'};
// let avcommand = {command:'stop'};
// let avcommand = {command:'playNext'};
// let avcommand = {command:'playPrevious'};
// let avcommand = {command:'fastForward'};
// let avcommand = {command:'rewind'};
// let avcommand = {command:'seek', parameter:10};
// let avcommand = {command:'setSpeed', parameter:2.6};
// let avcommand = {command:'setLoopMode', parameter:avsession.LoopMode.LOOP_MODE_SINGLE};
// let avcommand = {command:'toggleFavorite', parameter:"false"};
avsession.sendSystemControlCommand(avcommand).then(() => {
    console.info('sendSystemControlCommand successfully');
}).catch((err) => {
    console.info('sendSystemControlCommand : ERROR : '+ err.message);
});
```

## avsession.sendSystemControlCommand

sendSystemControlCommand(command: AVControlCommand, callback: AsyncCallback\<void>): void

发送会话相关的控制命令。使用callback异步回调。

**需要权限：** ohos.permission.MANAGE_MEDIA_RESOURCES，仅系统应用可用。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                  | 必填 | 说明                                  |
| -------- | ------------------------------------- | ---- | ------------------------------------- |
| command  | [AVControlCommand](#avcontrolcommand) | 是   | AVSession的相关命令和命令相关参数。   |
| callback | AsyncCallback<void\>                  | 是   | 回调函数。发送失败将获取err错误对象。 |

**示例：**

```js
let avcommand = {command:'play'};
// let avcommand = {command:'pause'};
// let avcommand = {command:'stop'};
// let avcommand = {command:'playNext'};
// let avcommand = {command:'playPrevious'};
// let avcommand = {command:'fastForward'};
// let avcommand = {command:'rewind'};
// let avcommand = {command:'seek', parameter:10};
// let avcommand = {command:'setSpeed', parameter:2.6};
// let avcommand = {command:'setLoopMode', parameter:avsession.LoopMode.LOOP_MODE_SINGLE};
// let avcommand = {command:'toggleFavorite', parameter:"false"};
avsession.sendSystemControlCommand(avcommand, function (err) {
    if (err.code == 0) {
        console.info('sendSystemControlCommand  successfully');
    } else {
        console.info('sendSystemControlCommand  : ERROR : ' + err.message);
    }
});
```

## AVSession

调用[avsession.createAVSession](#avsessioncreateavsession)后，返回会话的实例，获得会话ID，可对会话进行发送命令，发送元数据，播放状态，按键事件的操作。

### 属性

**系统能力：** SystemCapability.Multimedia.AVSession.Core


| 名称      | 类型   | 可读 | 可写 | 说明                          |
| :-------- | :----- | :--- | :--- | :---------------------------- |
| sessionId | string | 是   | 否   | AVSession对象唯一的会话标识。 |


**示例：**
```js
let sessionId = session.sessionId;
```

### setAVMetadata

setAVMetadata(data: AVMetadata): Promise\<void>

设置会话元数据。使用Promise异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名 | 类型                      | 必填 | 说明         |
| ------ | ------------------------- | ---- | ------------ |
| data   | [AVMetadata](#avmetadata) | 是   | 会话元数据。 |

**返回值：**

| 类型           | 说明                          |
| -------------- | ----------------------------- |
| Promise<void\> | Promise回调表示成功还是失败。 |

**示例：**

```js
let metadata  = {
    assetId: "121278",
    title: "lose yourself",
    artist: "Eminem",
    author: "ST",
    album: "Slim shady",
    writer: "ST",
    composer: "ST",
    duration: 2222,
    mediaImage: "https://www.example.com/example.jpg",
    subtitle: "8 Mile",
    description: "Rap",
    lyric: "https://www.example.com/example.lrc",
    previousAssetId: "121277",
    nextAssetId: "121279",
};
session.setAVMetadata(metadata).then(() => {
    console.info('setAVMetadata successfully');
}).catch((err) => {
    console.info('setAVMetadata : ERROR : '+err.message);
});
```

### setAVMetadata

setAVMetadata(data: AVMetadata, callback: AsyncCallback\<void>): void

设置会话元数据。使用callback异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                      | 必填 | 说明                                  |
| -------- | ------------------------- | ---- | ------------------------------------- |
| data     | [AVMetadata](#avmetadata) | 是   | 会话元数据。                          |
| callback | AsyncCallback<void\>      | 是   | 回调函数。设置失败将获取err错误对象。 |

**示例：**

```js
let metadata  = {
    assetId: "121278",
    title: "lose yourself",
    artist: "Eminem",
    author: "ST",
    album: "Slim shady",
    writer: "ST",
    composer: "ST",
    duration: 2222,
    mediaImage: "https://www.example.com/example.jpg",
    subtitle: "8 Mile",
    description: "Rap",
    lyric: "https://www.example.com/example.lrc",
    previousAssetId: "121277",
    nextAssetId: "121279",
};
session.setAVMetadata(metadata, function (err) {
    if (err.code == 0) {
        console.info('setAVMetadata successfully');
    } else {
        console.info('setAVMetadata : ERROR : ' + err.message);
    }
});
```

### setAVPlaybackState

setAVPlaybackState(state: AVPlaybackState): Promise\<void>

设置会话播放状态。使用Promise异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名 | 类型                                | 必填 | 说明                                           |
| ------ | ----------------------------------- | ---- | ---------------------------------------------- |
| data   | [AVPlaybackState](#avplaybackstate) | 是   | 会话播放状态，包括状态、倍数、循环模式等信息。 |

**返回值：**

| 类型           | 说明                          |
| -------------- | ----------------------------- |
| Promise<void\> | Promise回调表示成功还是失败。 |

**示例：**

```js
let PlaybackState = {
    state:avsession.PlaybackState.PLAYBACK_STATE_PLAY,
    speed: 1.0,
    position:{elapsedTime:10, updateTime:(new Date()).getTime()},
    bufferedTime:1000,
    loopMode:avsession.LoopMode.LOOP_MODE_SINGLE,
    isFavorite:true,
};
session.setAVPlaybackState(PlaybackState).then(() => {
    console.info('setAVPlaybackState successfully');
}).catch((err) => {
    console.info('setAVPlaybackState : ERROR : '+err.message);
});
```

### setAVPlaybackState

setAVPlaybackState(state: AVPlaybackState, callback: AsyncCallback\<void>): void

设置会话播放状态。使用callback异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                | 必填 | 说明                                           |
| -------- | ----------------------------------- | ---- | ---------------------------------------------- |
| data     | [AVPlaybackState](#avplaybackstate) | 是   | 会话播放状态，包括状态、倍数、循环模式等信息。 |
| callback | AsyncCallback<void\>                | 是   | 回调函数。设置失败将获取err错误对象。          |

**示例：**

```js
let PlaybackState = {
    state:avsession.PlaybackState.PLAYBACK_STATE_PLAY,
    speed: 1.0,
    position:{elapsedTime:10, updateTime:(new Date()).getTime()},
    bufferedTime:1000,
    loopMode:avsession.LoopMode.LOOP_MODE_SINGLE,
    isFavorite:true,
};
session.setAVPlaybackState(PlaybackState, function (err) {
    if (err.code == 0) {
        console.info('setAVPlaybackState successfully');
    } else {
        console.info('setAVPlaybackState : ERROR : ' + err.message);
    }
});
```

### setLaunchAbility

setLaunchAbility(ability: WantAgent): Promise\<void>

设置一个WantAgent用于拉起会话的Ability。使用Promise异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名  | 类型                              | 必填 | 说明                                                        |
| ------- | --------------------------------- | ---- | ----------------------------------------------------------- |
| ability | [WantAgent](js-apis-wantAgent.md) | 是   | 应用的相关属性信息，如bundleName，abilityName，deviceId等。 |

**返回值：**

| 类型           | 说明                          |
| -------------- | ----------------------------- |
| Promise<void\> | Promise回调表示成功还是失败。 |

**示例：**

```js
import WantAgent from '@ohos.wantAgent';

//WantAgentInfo对象
var wantAgentInfo = {
    wants: [
        {
            deviceId: "deviceId",
            bundleName: "com.neu.setResultOnAbilityResultTest1",
            abilityName: "com.example.test.MainAbility",
            action: "action1",
            entities: ["entity1"],
            type: "MIMETYPE",
            uri: "key={true,true,false}",
            parameters:
                {
                    mykey0: 2222,
                    mykey1: [1, 2, 3],
                    mykey2: "[1, 2, 3]",
                    mykey3: "ssssssssssssssssssssssssss",
                    mykey4: [false, true, false],
                    mykey5: ["qqqqq", "wwwwww", "aaaaaaaaaaaaaaaaa"],
                    mykey6: true,
                }
        }
    ],
    operationType: WantAgent.OperationType.START_ABILITIES,
    requestCode: 0,
    wantAgentFlags:[WantAgent.WantAgentFlags.UPDATE_PRESENT_FLAG]
}

WantAgent.getWantAgent(wantAgentInfo).then((agent) => {
    session.setLaunchAbility(WantAgent).then(() => {
        console.info('setLaunchAbility successfully');
    }).catch((err) => {
        console.info('setLaunchAbility : ERROR : '+err.message);
    });
});
```

### setLaunchAbility

setLaunchAbility(ability: WantAgent, callback: AsyncCallback\<void>): void

设置一个WantAgent用于拉起会话的Ability。使用callback异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                              | 必填 | 说明                                                        |
| -------- | --------------------------------- | ---- | ----------------------------------------------------------- |
| ability  | [WantAgent](js-apis-wantAgent.md) | 是   | 应用的相关属性信息，如bundleName，abilityName，deviceId等。 |
| callback | AsyncCallback<void\>              | 是   | 回调函数                                                    |

**示例：**

```js
import WantAgent from '@ohos.wantAgent';

//WantAgentInfo对象
var wantAgentInfo = {
    wants: [
        {
            deviceId: "deviceId",
            bundleName: "com.neu.setResultOnAbilityResultTest1",
            abilityName: "com.example.test.MainAbility",
            action: "action1",
            entities: ["entity1"],
            type: "MIMETYPE",
            uri: "key={true,true,false}",
            parameters:
                {
                    mykey0: 2222,
                    mykey1: [1, 2, 3],
                    mykey2: "[1, 2, 3]",
                    mykey3: "ssssssssssssssssssssssssss",
                    mykey4: [false, true, false],
                    mykey5: ["qqqqq", "wwwwww", "aaaaaaaaaaaaaaaaa"],
                    mykey6: true,
                }
        }
    ],
    operationType: WantAgent.OperationType.START_ABILITIES,
    requestCode: 0,
    wantAgentFlags:[WantAgent.WantAgentFlags.UPDATE_PRESENT_FLAG]
}

WantAgent.getWantAgent(wantAgentInfo).then((agent) => {
    session.setLaunchAbility(agent, function (err) {
        if (err.code == 0) {
            console.info('setLaunchAbility successfully');
        } else {
            console.info('setLaunchAbility : ERROR : ' + err.message);   
        }
    });
});
```

### setAudioStreamId

setAudioStreamId(streamIds: Array\<number>): Promise\<void>

设置音频流ID。使用Promise异步回调。

标识此会话控制的音频流，如果设置了多个流，这些流将在强制转换操作期间同时强制转换到远程端。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名    | 类型           | 必填 | 说明           |
| --------- | -------------- | ---- | -------------- |
| streamIds | Array<number\> | 是   | 媒体流ID列表。 |

**返回值：**

| 类型           | 说明                          |
| -------------- | ----------------------------- |
| Promise<void\> | Promise回调表示成功还是失败。 |

**示例：**

```js
session.setAudioStreamId(['1111','22222']).then(() => {
    console.info('setAudioStreamId successfully');
}).catch((err) => {
    console.info('setAudioStreamId : ERROR : '+err.message);
});
```

### setAudioStreamId

setAudioStreamId(streamIds: Array\<number>, callback: AsyncCallback\<void>): void

设置音频流id。使用callback异步回调。

标识此会话控制的音频流，如果设置了多个流，这些流将在强制转换操作期间同时强制转换到远程端。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名    | 类型                 | 必填 | 说明           |
| --------- | -------------------- | ---- | -------------- |
| streamIds | Array<number\>       | 是   | 媒体流ID列表。 |
| callback  | AsyncCallback<void\> | 是   | 回调函数。     |

**示例：**

```js
session.setAudioStreamId(['1111','22222'], function (err) {
    if (err.code == 0) {
        console.info('setAudioStreamId successfully');
    } else {
        console.info('setAudioStreamId : ERROR : '+err.message);
    }
});
```

### getController

getController(): Promise\<AVSessionController>

通过会话获取控制器。使用Promise异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**返回值：**

| 类型                                                 | 说明                          |
| ---------------------------------------------------- | ----------------------------- |
| Promise<[AVSessionController](#avsessioncontroller)> | Promise对象。返回会话控制器。 |

**示例：**

```js
session.getController().then((avcontroller) => {
    controller = avcontroller;
    console.info('getController : SUCCESS : sessionid : ' + controller.sessionId);
}).catch((err) => {
    console.info('getController : ERROR : '+err.message);
});
```

### getController

getController(callback: AsyncCallback\<AVSessionController>): void

通过会话获取控制器。使用callback异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                                        | 必填 | 说明                       |
| -------- | ----------------------------------------------------------- | ---- | -------------------------- |
| callback | AsyncCallback<[AVSessionController](#avsessioncontroller)\> | 是   | 回调函数，返回会话控制器。 |

**示例：**

```js
session.getController(function (err, avcontroller) {
    if (err.code == 0) {
        controller = avcontroller;
        console.info('getController : SUCCESS : sessionid : ' + controller.sessionId);
    } else {
        console.info('getController : ERROR : ' + err.message);
    }
});
```

### getOutputDevice

getOutputDevice(): Promise\<OutputDeviceInfo>

通过会话获取分布式设备信息。使用Promise异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**返回值：**

| 类型                                           | 说明                              |
| ---------------------------------------------- | --------------------------------- |
| Promise<[OutputDeviceInfo](#outputdeviceinfo)> | Promise对象。返回分布式设备信息。 |

**示例：**

```js
session.getOutputDevice().then((outputDeviceInfo) => {
    console.info('getOutputDevice : SUCCESS : isRemote : ' + outputDeviceInfo.isRemote);
}).catch((err) => {
    console.info('getOutputDevice : ERROR : '+err.message);
});
```

### getOutputDevice

getOutputDevice(callback: AsyncCallback\<OutputDeviceInfo>): void

通过会话获取分布式设备相关信息。使用callback异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                                  | 必填 | 说明                           |
| -------- | ----------------------------------------------------- | ---- | ------------------------------ |
| callback | AsyncCallback<[OutputDeviceInfo](#outputdeviceinfo)\> | 是   | 回调函数，返回分布式设备信息。 |

**示例：**

```js
session.getOutputDevice(function (err, outputDeviceInfo) {
    if (err.code == 0) {
        console.info('getOutputDevice : SUCCESS : isRemote : ' + outputDeviceInfo.isRemote);
    } else {
        console.info('getOutputDevice : ERROR : '+err.message); 
    }
});
```

### activate

activate(): Promise\<void>

激活会话，激活后可正常使用会话。使用Promise异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**返回值：**

| 类型           | 说明                          |
| -------------- | ----------------------------- |
| Promise<void\> | Promise回调表示成功还是失败。 |

**示例：**

```js
session.activate().then(() => {
    console.info('activate : SUCCESS ');
}).catch((err) => {
    console.info('activate : ERROR : '+err.message);
});
```

### activate

activate(callback: AsyncCallback\<void>): void

激活会话，激活后可正常使用会话。使用callback异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                 | 必填 | 说明       |
| -------- | -------------------- | ---- | ---------- |
| callback | AsyncCallback<void\> | 是   | 回调函数。 |

**示例：**

```js
session.activate(function (err) {
    if (err.code == 0) {
        console.info('activate : SUCCESS ');
    } else {
        console.info('activate : ERROR : '+err.message);
    }
});
```

### deactivate

deactivate(): Promise\<void>

禁用当前会话。使用Promise异步回调。

禁用当前会话的功能，可通过[activate](#activate)恢复。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**返回值：**

| 类型           | 说明                          |
| -------------- | ----------------------------- |
| Promise<void\> | Promise回调表示成功还是失败。 |

**示例：**

```js
session.deactivate().then(() => {
    console.info('deactivate : SUCCESS ');
}).catch((err) => {
    console.info('deactivate : ERROR : '+err.message);
});
```

### deactivate

deactivate(callback: AsyncCallback\<void>): void

禁用当前会话。使用callback异步回调。

禁用当前会话的功能，可通过[activate](#activate)恢复。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                 | 必填 | 说明       |
| -------- | -------------------- | ---- | ---------- |
| callback | AsyncCallback<void\> | 是   | 回调函数。 |

**示例：**

```js
session.deactivate(function (err) {
    if (err.code == 0) {
        console.info('deactivate : SUCCESS ');
    } else {
        console.info('deactivate : ERROR : '+err.message);
    }
});
```

### destroy

destroy(): Promise\<void>

销毁当前会话，使当前会话完全失效。使用Promise异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**返回值：**

| 类型           | 说明                          |
| -------------- | ----------------------------- |
| Promise<void\> | Promise回调表示成功还是失败。 |

**示例：**

```js
session.destroy().then(() => {
    console.info('destroy : SUCCESS ');
}).catch((err) => {
    console.info('destroy : ERROR : '+err.message);
});
```

### destroy

destroy(callback: AsyncCallback\<void>): void

销毁当前会话，使当前会话完全失效。使用callback异步回调。


**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                 | 必填 | 说明       |
| -------- | -------------------- | ---- | ---------- |
| callback | AsyncCallback<void\> | 是   | 回调函数。 |

**示例：**

```js
session.destroy(function (err) {
    if (err.code == 0) {
        console.info('destroy : SUCCESS ');
    } else {
        console.info('destroy : ERROR : '+err.message);
    }
});
```

### on('play'|'pause'|'stop'|'playNext'|'playPrevious'|'fastForward'|'rewind')

on(type: 'play'|'pause'|'stop'|'playNext'|'playPrevious'|'fastForward'|'rewind', callback: () => void): void

设置播放命令监听事件。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                 | 必填 | 说明                                                         |
| -------- | -------------------- | ---- | ------------------------------------------------------------ |
| type     | string               | 是   | 事件回调类型，支持的事件包括：`'play'`，`'pause'`，`'stop'`，` 'playNext'`，` 'playPrevious'`， `'fastForward'`，` 'rewind'`。<br/>当对应的播放命令被发送到会话时，触发该事件。 |
| callback | callback: () => void | 是   | 回调函数。                                                   |

**示例：**

```js
avsession.on('play', () => {
    console.info('on play entry');
});
avsession.on('pause', () => {
    console.info('on pause entry');
});
avsession.on('stop', () => {
    console.info('on stop entry');
});
avsession.on('playNext', () => {
    console.info('on playNext entry');
});
avsession.on('playPrevious', () => {
    console.info('on playPrevious entry');
});
avsession.on('fastForward', () => {
    console.info('on fastForward entry');
});
avsession.on('rewind', () => {
    console.info('on rewind entry');
});
```

### on('seek')

on(type: 'seek', callback: (time: number) => void): void

设置跳转节点监听事件。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                   | 必填 | 说明                                                         |
| -------- | ---------------------- | ---- | ------------------------------------------------------------ |
| type     | string                 | 是   | 事件回调类型，支持事件`'seek'`：当跳转节点命令被发送到会话时，触发该事件。 |
| callback | (time: number) => void | 是   | 回调函数，参数time是时间节点，单位为毫秒。                   |

**示例：**

```js
session.on('seek', (time) => {
    console.info('on seek entry time : ' + time);
});
```

### on('setSpeed')

on(type: 'setSpeed', callback: (speed: number) => void): void

设置播放速率的监听事件。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                    | 必填 | 说明                                                         |
| -------- | ----------------------- | ---- | ------------------------------------------------------------ |
| type     | string                  | 是   | 事件回调类型，支持事件`'setSpeed'`：当设置播放速率的命令被发送到会话时，触发该事件。 |
| callback | (speed: number) => void | 是   | 回调方法，参数speed是播放倍速。                              |

**示例：**

```js
session.on('setSpeed', (speed) => {
    console.info('on setSpeed speed : ' + speed);
});
```

### on('setLoopMode')

on(type: 'setLoopMode', callback: (mode: LoopMode) => void): void

设置循环模式的监听事件。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                  | 必填 | 说明                                                         |
| -------- | ------------------------------------- | ---- | ------------------------------------------------------------ |
| type     | string                                | 是   | 事件回调类型，支持事件`'setLoopMode'`：当设置循环模式的命令被发送到会话时，触发该事件。 |
| callback | (mode: [LoopMode](#loopmode)) => void | 是   | 回调方法，参数mode是循环模式。                               |

**示例：**

```js
session.on('setLoopMode', (mode) => {
    console.info('on setLoopMode mode : ' + mode);
});
```

### on('toggleFavorite')

on(type: 'toggleFavorite', callback: (assetId: string) => void): void

设置是否收藏的监听事件

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                      | 必填 | 说明                                                         |
| -------- | ------------------------- | ---- | ------------------------------------------------------------ |
| type     | string                    | 是   | 事件回调类型，支持事件`'toggleFavorite'`：当是否收藏的命令被发送到会话时，触发该事件。 |
| callback | (assetId: string) => void | 是   | 回调方法，参数assetId是媒体ID。                              |

**示例：**

```js
session.on('toggleFavorite', (assetId) => {
    console.info('on toggleFavorite mode : ' + assetId);
});
```

### on('handleKeyEvent')

on(type: 'handleKeyEvent', callback: (event: KeyEvent) => void): void

设置按键事件的监听事件

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                                         | 必填 | 说明                                                         |
| -------- | ------------------------------------------------------------ | ---- | ------------------------------------------------------------ |
| type     | string                                                       | 是   | 事件回调类型，支持事件`'handleKeyEvent'`：当按键事件被发送到会话时，触发该事件。 |
| callback | (event: [KeyEvent](https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis/js-apis-keyevent.md)) => void | 是   | 回调方法，参数event是按键事件。                              |

**示例：**

```js
session.on('handleKeyEvent', (event) => {
    console.info('on handleKeyEvent event : ' + event);
});
```

### on('outputDeviceChanged')

on(type: 'outputDeviceChanged', callback: (device: OutputDeviceInfo) => void): void

设置分布式设备变化的监听事件。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                                    | 必填 | 说明                                                         |
| -------- | ------------------------------------------------------- | ---- | ------------------------------------------------------------ |
| type     | string                                                  | 是   | 事件回调类型，支持事件`'outputDeviceChanged'`：当分布式设备变化时，触发该事件。 |
| callback | (device: [OutputDeviceInfo](#outputdeviceinfo)) => void | 是   | 回调方法，参数device是设备相关信息。                         |

**示例：**

```js
session.on('outputDeviceChanged', (device) => {
    console.info('on outputDeviceChanged device isRemote : ' + device.isRemote);
});
```

### off

off(type: 'play' | 'pause' | 'stop' | 'playNext' | 'playPrevious' | 'fastForward' | 'rewind' | 'seek' | 'setSpeed' | 'setLoopMode' | 'toggleFavorite' | 'handleKeyEvent' | 'outputDeviceChanged'): void

会话相关监听的关闭，关闭后，不再进行相关on回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名 | 类型   | 必填 | 说明                                                         |
| ------ | ------ | ---- | ------------------------------------------------------------ |
| type   | string | 是   | 关闭对应的监听事件，支持的事件包括：` 'play'`，` 'pause'`，`'stop'`， `'playNext'`，` 'playPrevious'`， ` 'fastForward'`，` 'rewind'`，`'seek'`， `'setSpeed'`，` 'setLoopMode'`，` 'toggleFavorite'`， `'handleKeyEvent' `， `'outputDeviceChanged'`。 |

**示例：**

```js
session.off('play');
session.off('pause');
session.off('stop');
session.off('playNext');
session.off('playPrevious');
session.off('fastForward');
session.off('rewind');
session.off('seek');
session.off('setSpeed');
session.off('setLoopMode');
session.off('toggleFavorite');
session.off('handleKeyEvent');
session.off('outputDeviceChanged');
```

## AVSessionController

调用[avsession.createController](#avsessioncreatecontroller)后，返回会话控制器实例，获得会话ID，然后可对会话进行发送命令，获取元数据，播放状态，按键事件等操作。

### 属性

**系统能力：** SystemCapability.Multimedia.AVSession.Core


| 名称      | 类型   | 可读 | 可写 | 说明                                    |
| :-------- | :----- | :--- | :--- | :-------------------------------------- |
| sessionId | string | 是   | 否   | AVSessionController对象唯一的会话标识。 |


**示例：**
```js
let sessionId;
await avsession.createController(session.sessionId).then((controller) => {
    sessionId = controller.sessionId;
}).catch((err) => {
    console.info('createController : ERROR : ' + err.message);
});
```

### getAVPlaybackState

getAVPlaybackState(): Promise\<AVPlaybackState>

获取当前播放状态相关属性。使用Promise异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**返回值：**

| 类型                                          | 说明                        |
| --------------------------------------------- | --------------------------- |
| Promise<[AVPlaybackState](#avplaybackstate)\> | Promise对象。返回播放状态。 |

**示例：**
```js
controller.getAVPlaybackState().then((playbackState) => {
    console.info('getAVPlaybackState : SUCCESS : state : ' + playbackState.state);
}).catch((err) => {
    console.info('getAVPlaybackState : ERROR : ' + err.message);
});
```

### getAVPlaybackState

getAVPlaybackState(callback: AsyncCallback\<AVPlaybackState>): void

获取当前播放状态相关属性。使用callback异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                                | 必填 | 说明                         |
| -------- | --------------------------------------------------- | ---- | ---------------------------- |
| callback | AsyncCallback<[AVPlaybackState](#avplaybackstate)\> | 是   | 回调函数，返回当前播放状态。 |

**示例：**
```js
controller.getAVPlaybackState(function (err, playbackState) {
    if (err.code == 0) {
        console.info('getAVPlaybackState : SUCCESS : state : ' + playbackState.state);
    } else {
        console.info('getAVPlaybackState : ERROR : ' + err.message);
    }
});
```

### getAVMetadata

getAVMetadata(): Promise\<AVMetadata>

获取会话元数据。使用Promise异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**返回值：**

| 类型                                | 说明                          |
| ----------------------------------- | ----------------------------- |
| Promise<[AVMetadata](#avmetadata)\> | Promise对象，返回会话元数据。 |

**示例：**
```js
controller.getAVMetadata().then((metadata) => {
    console.info('getAVMetadata : SUCCESS : assetId : ' + metadata.assetId);
}).catch((err) => {
    console.info('getAVMetadata : ERROR : ' + err.message);
});
```

### getAVMetadata

getAVMetadata(callback: AsyncCallback\<AVMetadata>): void

获取会话元数据。使用callback异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                      | 必填 | 说明                       |
| -------- | ----------------------------------------- | ---- | -------------------------- |
| callback | AsyncCallback<[AVMetadata](#avmetadata)\> | 是   | 回调函数，返回会话元数据。 |

**示例：**
```js
controller.getAVMetadata(function (err, metadata) {
    if (err.code == 0) {
        console.info('getAVMetadata : SUCCESS : assetId : ' + metadata.assetId);
    } else {
        console.info('getAVMetadata : ERROR : ' + err.message);
    }
});
```

### getOutputDevice

getOutputDevice(): Promise\<OutputDeviceInfo>

获取分布式设备信息。使用Promise异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**返回值：**

| 类型                                            | 说明                              |
| ----------------------------------------------- | --------------------------------- |
| Promise<[OutputDeviceInfo](#outputdeviceinfo)\> | Promise对象，返回分布式设备信息。 |

**示例：**
```js
controller.getOutputDevice().then((deviceInfo) => {
    console.info('getOutputDevice : SUCCESS : isRemote : ' + deviceInfo.isRemote);
}).catch((err) => {
    console.info('getOutputDevice : ERROR : ' + err.message);
});
```

### getOutputDevice

getOutputDevice(callback: AsyncCallback\<OutputDeviceInfo>): void

获取分布式设备信息。使用callback异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                                  | 必填 | 说明                           |
| -------- | ----------------------------------------------------- | ---- | ------------------------------ |
| callback | AsyncCallback<[OutputDeviceInfo](#outputdeviceinfo)\> | 是   | 回调函数，返回分布式设备信息。 |

**示例：**

```js
controller.getOutputDevice(function (err, deviceInfo) {
    if (err.code == 0) {
        console.info('getOutputDevice : SUCCESS : isRemote : ' + deviceInfo.isRemote);
    } else {
        console.info('getOutputDevice : ERROR : ' + err.message);
    }
});
```

### sendAVKeyEvent

sendAVKeyEvent(event: KeyEvent): Promise\<void>

发送按键事件到会话。使用Promise异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名 | 类型                                                         | 必填 | 说明       |
| ------ | ------------------------------------------------------------ | ---- | ---------- |
| event  | [KeyEvent](https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis/js-apis-keyevent.md) | 是   | 按键事件。 |

**返回值：**

| 类型           | 说明                          |
| -------------- | ----------------------------- |
| Promise<void\> | Promise回调表示成功还是失败。 |

**示例：**

```js
let keyItem = {code:0x49, pressedTime:123456789, deviceId:0};
let event = {action:2, key:keyItem, keys:[keyItem]};

controller.sendAVKeyEvent(event).then(() => {
    console.info('sendAVKeyEvent Successfully');
}).catch((err) => {
    console.info('sendAVKeyEvent : ERROR : '+ err.message);
});
```

### sendAVKeyEvent

sendAVKeyEvent(event: KeyEvent, callback: AsyncCallback\<void>): void

发送按键事件到会话。使用callback异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                                         | 必填 | 说明       |
| -------- | ------------------------------------------------------------ | ---- | ---------- |
| event    | [KeyEvent](https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis/js-apis-keyevent.md) | 是   | 按键事件。 |
| callback | AsyncCallback<void\>                                         | 是   | 回调方法。 |

**示例：**

```js
let keyItem = {code:0x49, pressedTime:123456789, deviceId:0};
let event = {action:2, key:keyItem, keys:[keyItem]};

controller.sendAVKeyEvent(event, function (err) {
    if (err.code == 0) {
        console.info('sendAVKeyEvent Successfully');
    } else {
        console.info('sendAVKeyEvent : ERROR : '+err.message);
    }
});
```

### getLaunchAbility

getLaunchAbility(): Promise\<WantAgent>

获取应用在会话中保存的WantAgent对象。使用Promise异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**返回值：**

| 类型                                        | 说明                                                         |
| ------------------------------------------- | ------------------------------------------------------------ |
| Promise<[WantAgent](js-apis-wantAgent.md)\> | Promise对象，返回在[setLaunchAbility](#setlaunchability)保存的对象，包括应用的相关属性信息，如bundleName，abilityName，deviceId等。 |

**示例：**

```js
import WantAgent from '@ohos.wantAgent';

controller.getLaunchAbility().then((wantAgent) => {
    console.info('getLaunchAbility : SUCCESS : wantAgent : ' + wantAgent);
}).catch((err) => {
    console.info('getLaunchAbility : ERROR : '+ err.message);
});
```

### getLaunchAbility

getLaunchAbility(callback: AsyncCallback\<WantAgent>): void

获取应用在会话中保存的WantAgent对象。使用callback异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                              | 必填 | 说明                                                         |
| -------- | ------------------------------------------------- | ---- | ------------------------------------------------------------ |
| callback | AsyncCallback<[WantAgent](js-apis-wantAgent.md)\> | 是   | 回调函数。返回在[setLaunchAbility](#setlaunchability)保存的对象，包括应用的相关属性信息，如bundleName，abilityName，deviceId等。 |

**示例：**

```js
import WantAgent from '@ohos.wantAgent';

controller.getLaunchAbility(function (err, wantAgent) {
    if (err.code == 0) {
        console.info('getLaunchAbility : SUCCESS : wantAgent : ' + wantAgent);
    } else {
        console.info('getLaunchAbility : ERROR : '+err.message);
    }
});
```

### getRealPlaybackPositionSync

getRealPlaybackPositionSync(): number

获取当前媒体的最后播放时间点。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**返回值：**

| 类型   | 说明               |
| ------ | ------------------ |
| number | 时间节点，毫秒数。 |

**示例：**

```js
let time = controller.getRealPlaybackPositionSync();
```

### isActive

isActive(): Promise\<boolean>

获取会话是否被激活。使用Promise异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**返回值：**

| 类型              | 说明                                                         |
| ----------------- | ------------------------------------------------------------ |
| Promise<boolean\> | Promise对象，返回会话是否为激活状态，true表示被激活，false表示禁用。 |

**示例：**

```js
controller.isActive().then((isactive) => {
    console.info('isActive : SUCCESS : isactive : ' + isactive);
}).catch((err) => {
    console.info('isActive : ERROR : '+err.message);
});
```

### isActive

isActive(callback: AsyncCallback\<boolean>): void

获取会话是否被激活。使用callback异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                    | 必填 | 说明                                                         |
| -------- | ----------------------- | ---- | ------------------------------------------------------------ |
| callback | AsyncCallback<boolean\> | 是   | 回调函数，返回会话是否为激活状态，true表示被激活，false表示禁用。 |

**示例：**

```js
controller.isActive(function (err, isActive) {
    if (err.code == 0) {
        console.info('isActive : SUCCESS : isactive : ' + isActive);
    } else {
        console.info('isActive : ERROR : '+ err.message);
    }
});
```

### destroy

destroy(): Promise\<void>

销毁当前控制器，销毁后当前控制器不可再用。使用Promise异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**返回值：**

| 类型           | 说明                          |
| -------------- | ----------------------------- |
| Promise<void\> | Promise回调表示成功还是失败。 |

**示例：**

```js
controller.destroy().then(() => {
    console.info('destroy : SUCCESS ');
}).catch((err) => {
    console.info('destroy : ERROR : '+ err.message);
});
```

### destroy

destroy(callback: AsyncCallback\<void>): void

销毁当前控制器，销毁后当前控制器不可再用。使用callback异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                 | 必填 | 说明       |
| -------- | -------------------- | ---- | ---------- |
| callback | AsyncCallback<void\> | 是   | 回调函数。 |

**示例：**

```js
controller.destroy(function (err) {
    if (err.code == 0) {
        console.info('destroy : SUCCESS ');
    } else {
        console.info('destroy : ERROR : '+ err.message);
    }
});
```

### getValidCommands

getValidCommands(): Promise\<Set\<AVControlCommandType>>

获取有效命令。使用Promise异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**返回值：**

| 类型                                                         | 说明                              |
| ------------------------------------------------------------ | --------------------------------- |
| Promise<Set<[AVControlCommandType](#avcontrolcommandtype)\>\> | Promise对象。返回有效命令的集合。 |

**示例：**

```js
controller.getValidCommands.then((validCommands) => {
    console.info('getValidCommands : SUCCESS : size : ' + validCommands.size);
    console.info('getValidCommands : SUCCESS : validCommands : ' + validCommands.values());
}).catch((err) => {
    console.info('getValidCommands : ERROR : '+ err.message);
});
```

### getValidCommands

getValidCommands(callback: AsyncCallback\<Set\<AVControlCommandType>>): void

获取有效命令。使用callback异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                                         | 必填 | 说明                           |
| -------- | ------------------------------------------------------------ | ---- | ------------------------------ |
| callback | AsyncCallback\<Set\<[AVControlCommandType](#avcontrolcommandtype)\>\> | 是   | 回调函数，返回有效命令的集合。 |

**示例：**

```js
controller.getValidCommands(function (err, validCommands) {
    if (err.code == 0) {
        console.info('getValidCommands : SUCCESS : size : ' + validCommands.size);
        console.info('getValidCommands : SUCCESS : validCommands : ' + validCommands.values());
    } else {
        console.info('getValidCommands : ERROR : '+ err.message);
    }
});
```

### sendControlCommand

sendControlCommand(command: AVControlCommand): Promise\<void>

通过会话控制器发送命令到会话。使用Promise异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 名称    | 类型                                  | 必填 | 说明                           |
| ------- | ------------------------------------- | ---- | ------------------------------ |
| command | [AVControlCommand](#avcontrolcommand) | 是   | 会话的相关命令和命令相关参数。 |

**返回值：**

| 类型           | 说明                          |
| -------------- | ----------------------------- |
| Promise<void\> | Promise回调表示成功还是失败。 |

**示例：**

```js
let avcommand = {command:'play'};
// let avcommand = {command:'pause'};
// let avcommand = {command:'stop'};
// let avcommand = {command:'playNext'};
// let avcommand = {command:'playPrevious'};
// let avcommand = {command:'fastForward'};
// let avcommand = {command:'rewind'};
// let avcommand = {command:'seek', parameter:10};
// let avcommand = {command:'setSpeed', parameter:2.6};
// let avcommand = {command:'setLoopMode', parameter:avsession.LoopMode.LOOP_MODE_SINGLE};
// let avcommand = {command:'toggleFavorite', parameter:"false"};
controller.sendControlCommand(avcommand).then(() => {
    console.info('sendControlCommand successfully');
}).catch((err) => {
    console.info('sendControlCommand : ERROR : '+ err.message);
});
```

### sendControlCommand

sendControlCommand(command: AVControlCommand, callback: AsyncCallback\<void>): void

异步通过会话控制器发送命令到会话。使用callback异步回调。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                  | 必填 | 说明                           |
| -------- | ------------------------------------- | ---- | ------------------------------ |
| command  | [AVControlCommand](#avcontrolcommand) | 是   | 会话的相关命令和命令相关参数。 |
| callback | AsyncCallback<void\>                  | 是   | 回调函数。                     |

**示例：**

```js
let avcommand = {command:'play'};
// let avcommand = {command:'pause'};
// let avcommand = {command:'stop'};
// let avcommand = {command:'playNext'};
// let avcommand = {command:'playPrevious'};
// let avcommand = {command:'fastForward'};
// let avcommand = {command:'rewind'};
// let avcommand = {command:'seek', parameter:10};
// let avcommand = {command:'setSpeed', parameter:2.6};
// let avcommand = {command:'setLoopMode', parameter:avsession.LoopMode.LOOP_MODE_SINGLE};
// let avcommand = {command:'toggleFavorite', parameter:"false"};
controller.sendControlCommand(avcommand, function (err) {
    if (err.code == 0) {
        console.info('sendControlCommand successfully');
    } else {
        console.info('sendControlCommand : ERROR : '+ err.message);
    }
});
```

### on('metadataChanged')

on(type: 'metadataChanged', filter: Set\<keyof AVMetadata> | 'all', callback: (data: AVMetadata) => void)

设置元数据变化的监听事件。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                                         | 必填 | 说明                                                         |
| -------- | ------------------------------------------------------------ | ---- | ------------------------------------------------------------ |
| type     | string                                                       | 是   | 事件回调类型，支持事件`'metadataChanged'`：当元数据变化时，触发该事件。 |
| filter   | Set\<keyof&nbsp;[AVMetadata](#avmetadata)\>&nbsp;&#124;&nbsp;'all' | 是   | 'all' 表示关注元数据所有字段变化；Set<keyof&nbsp;[AVMetadata](#avmetadata)\> 表示关注set中的字段。 |
| callback | (data: [AVMetadata](#avmetadata)) => void                    | 是   | 回调函数，参数data是变化后的元数据。                         |

**示例：**

```js
controller.on('metadataChanged', 'all', (metadata) => {
    console.info('on metadataChanged assetId : ' + metadata.assetId);
});

let filterKeys = new Set();
filterKeys.add("assetId");
filterKeys.add("title");
filterKeys.add("description");
controller.on('metadataChanged', filterKeys, (metadata) => {
    console.info('on metadataChanged assetId : ' + metadata.assetId);
});
```

### on('playbackStateChanged')

on(type: 'playbackStateChanged', filter: Set\<keyof AVPlaybackState> | 'all', callback: (state: AVPlaybackState) => void)

设置播放状态变化的监听事件。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                                         | 必填 | 说明                                                         |
| -------- | ------------------------------------------------------------ | ---- | ------------------------------------------------------------ |
| type     | string                                                       | 是   | 事件回调类型，支持事件`'playbackStateChanged'`：当播放状态变化时，触发该事件。 |
| filter   | Set\<keyof&nbsp;[AVPlaybackState](#avplaybackstate)\>&nbsp;&#124;&nbsp;'all' | 是   | 'all' 表示关注播放状态所有字段变化；Set<keyof&nbsp;[AVPlaybackState](#avplaybackstate)\> 表示关注set中的字段。 |
| callback | (state: [AVPlaybackState](#avplaybackstate)) => void         | 是   | 回调函数，参数state是变化后的播放状态。                      |

**示例：**

```js
controller.on('AVPlaybackState', 'all', (playbackState) => {
    console.info('on AVPlaybackState state : ' + playbackState.state);
});

let filterKeys = new Set();
filterKeys.add("state");
filterKeys.add("speed");
filterKeys.add("loopMode");
controller.on('AVPlaybackState', filterKeys, (playbackState) => {
    console.info('on AVPlaybackState state : ' + playbackState.state);
});
```

### on('sessionDestroyed')

on(type: 'sessionDestroyed', callback: () => void)

会话的销毁的监听事件。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型       | 必填 | 说明                                                         |
| -------- | ---------- | ---- | ------------------------------------------------------------ |
| type     | string     | 是   | 事件回调类型，支持事件`'sessionDestroyed'`：当检测到会话销毁时，触发该事件）。 |
| callback | () => void | 是   | 回调函数。                                                   |

**示例：**

```js
controller.on('sessionDestroyed', () => {
    console.info('on sessionDestroyed : SUCCESS ');
});
```

### on('activeStateChanged')

on(type: 'activeStateChanged', callback: (isActive: boolean) => void)

会话的激活状态的监听事件。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                        | 必填 | 说明                                                         |
| -------- | --------------------------- | ---- | ------------------------------------------------------------ |
| type     | string                      | 是   | 事件回调类型，支持事件`'activeStateChanged'`：当检测到会话的激活状态发生改变时，触发该事件。 |
| callback | (isActive: boolean) => void | 是   | 回调函数。参数isActive表示会话是否被激活。                   |

**示例：**

```js
controller.on('activeStateChanged', (isActive) => {
    console.info('on activeStateChanged : SUCCESS : isActive ' + isActive);
});
```

### on('validCommandChanged')

on(type: 'validCommandChanged', callback: (commands: Set\<AVControlCommandType>) => void)

会话的有效命令监听事件。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                                         | 必填 | 说明                                                         |
| -------- | ------------------------------------------------------------ | ---- | ------------------------------------------------------------ |
| type     | string                                                       | 是   | 事件回调类型，支持事件`'activeStateChanged'`：当检测到会话的合法命令发生改变时，触发该事件。 |
| callback | (commands: Set<[AVControlCommandType](#avcontrolcommandtype)\>) => void | 是   | 回调函数。参数commands是有效命令的集合。                     |

**示例：**

```js
controller.on('validCommandChanged', (validCommands) => {
    console.info('validCommandChanged : SUCCESS : size : ' + validCommands.size);
    console.info('validCommandChanged : SUCCESS : validCommands : ' + validCommands.values());
});
```

### on('outputDeviceChanged')

on(type: 'outputDeviceChanged', callback: (device: OutputDeviceInfo) => void): void

设置分布式设备变化的监听事件。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名   | 类型                                                    | 必填 | 说明                                                         |
| -------- | ------------------------------------------------------- | ---- | ------------------------------------------------------------ |
| type     | string                                                  | 是   | 事件回调类型，支持事件为`'outputDeviceChanged'`：当分布式设备变化时，触发该事件）。 |
| callback | (device: [OutputDeviceInfo](#outputdeviceinfo)) => void | 是   | 回调函数，参数device是设备相关信息。                         |

**示例：**

```js
controller.on('outputDeviceChanged', (device) => {
    console.info('on outputDeviceChanged device isRemote : ' + device.isRemote);
});
```

### off

off(type: 'metadataChanged'|'playbackStateChanged'|'sessionDestroyed'|'activeStateChanged'|'validCommandChanged'|'outputDeviceChanged'): void

控制器能够设置的监听事件的关闭操作。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

**参数：**

| 参数名 | 类型   | 必填 | 说明                                                         |
| ------ | ------ | ---- | ------------------------------------------------------------ |
| type   | string | 是   | 关闭对应的监听事件，支持的事件包括：`'metadataChanged'` ，`'playbackStateChanged'`，`'sessionDestroyed'` ，`'activeStateChanged'`，`'validCommandChanged'`，`'outputDeviceChanged'`。 |

**示例：**

```js
controller.off('metadataChanged');
controller.off('playbackStateChanged');
controller.off('sessionDestroyed');
controller.off('activeStateChanged');
controller.off('validCommandChanged');
controller.off('outputDeviceChanged');
```

## SessionToken

会话令牌的信息。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

| 名称      | 类型   | 必填 | 说明         |
| :-------- | :----- | :--- | :----------- |
| sessionId | string | 是   | 会话ID       |
| pid       | number | 是   | 会话的进程ID |
| uid       | number | 是   | 用户ID       |

## AVSessionType
当前会话支持的会话类型。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

| 名称  | 类型   | 说明 |
| ----- | ------ | ---- |
| audio | string | 音频 |
| video | string | 视频 |

## AVSessionDescriptor

会话的相关描述信息。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

| 名称         | 类型                                                         | 可读 | 可写 | 说明                                                |
| ------------ | ------------------------------------------------------------ | ---- | --------------------------------------------------- | --------------------------------------------------- |
| sessionId    | string                                                       | 是  | 否 | 会话ID                                              |
| type         | [AVSessionType](#avsessiontype)                              | 是   | 否  | 会话类型                                            |
| sessionTag   | string                                                       | 是   | 否  | 会话的自定义名称                                    |
| elementName  | [ElementName](js-apis-bundle-ElementName.md)                 | 是   | 否  | 会话所属应用的信息（包含bundleName、abilityName等） |
| isActive     | boolean                                                      | 是   | 否  | 会话是否被激活                                      |
| isTopSession | boolean                                                      | 是   | 否  | 会话是否为最新的会话                                |
| outputDevice | [OutputDeviceInfo](#outputdeviceinfo)                        | 是   | 否  | 分布式设备相关信息                                  |

## AVControlCommandType

会话可传递的命令。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

| 名称           | 类型   | 说明         |
| -------------- | ------ | ------------ |
| play           | string | 播放         |
| pause          | string | 暂停         |
| stop           | string | 停止         |
| playNext       | string | 下一首       |
| playPrevious   | string | 上一首       |
| fastForward    | string | 快进         |
| rewind         | string | 快退         |
| seek           | string | 跳转某一节点 |
| setSpeed       | string | 设置播放倍速 |
| setLoopMode    | string | 设置循环模式 |
| toggleFavorite | string | 是否收藏     |

## AVControlCommand

会话接受的命令的对象描述。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

| 名称      | 类型                                              | 必填 | 说明           |
| --------- | ------------------------------------------------- | ---- | -------------- |
| command   | [AVControlCommandType](#avcontrolcommandtype)     | 是   | 命令           |
| parameter | [LoopMode](#loopmode) &#124; string &#124; number | 否   | 命令对应的参数 |

## AVMetadata

媒体元数据的相关属性。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

| 名称            | 类型                                                       | 必填 | 说明                                                         |
| --------------- | ---------------------------------------------------------- | ---- | ------------------------------------------------------------ |
| assetId         | string                                                     | 是   | 媒体ID。                                                     |
| title           | string                                                     | 否   | 标题。                                                       |
| artist          | string                                                     | 否   | 艺术家。                                                     |
| author          | string                                                     | 否   | 专辑作者。                                                   |
| album           | string                                                     | 否   | 专辑名称。                                                   |
| writer          | string                                                     | 否   | 词作者。                                                     |
| composer        | string                                                     | 否   | 作曲者。                                                     |
| duration        | string                                                     | 否   | 媒体时长，单位毫秒（ms）。                                   |
| mediaImage      | [image.PixelMap](js-apis-image.md#pixelmap7) &#124; string | 否   | 图片的像素数据或者图片路径地址，路径格式: 本地路径:fd://XXX和 file://XXX，网络路径：http://XXX 和https://XXX |
| publishDate     | Date                                                       | 否   | 发行日期。                                                   |
| subtitle        | string                                                     | 否   | 子标题。                                                     |
| description     | string                                                     | 否   | 媒体描述。                                                   |
| lyric           | string                                                     | 否   | 歌词文件路径地址，路径格式: 本地路径:fd://XXX和file://XXX，网络路径：http://XXX和https://XXX |
| previousAssetId | string                                                     | 否   | 上一首媒体ID。                                               |
| nextAssetId     | string                                                     | 否   | 下一首媒体ID。                                               |

## AVPlaybackState

媒体播放状态的相关属性。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

| 名称         | 类型                                  | 必填 | 说明     |
| ------------ | ------------------------------------- | ---- | -------- |
| state        | [PlaybackState](#playbackstate)       | 否   | 播放状态 |
| speed        | number                                | 否   | 播放倍速 |
| position     | [PlaybackPosition](#playbackposition) | 否   | 播放位置 |
| bufferedTime | number                                | 否   | 缓冲时间 |
| loopMode     | [LoopMode](#loopmode)                 | 否   | 循环模式 |
| isFavorite   | boolean                               | 否   | 是否收藏 |

## PlaybackPosition

媒体播放位置的相关属性。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

| 名称        | 类型   | 必填 | 说明               |
| ----------- | ------ | ---- | ------------------ |
| elapsedTime | number | 是   | 已用时间，单位毫秒（ms）。 |
| updateTime  | number | 是   | 更新时间，单位毫秒（ms）。 |

## OutputDeviceInfo

分布式设备的相关信息。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

| 名称       | 类型           | 必填 | 说明                   |
| ---------- | -------------- | ---- | ---------------------- |
| isRemote   | boolean        | 是   | 设备是否连接。         |
| deviceId   | Array<string\> | 是   | 分布式设备的ID集合。   |
| deviceName | Array<string\> | 是   | 分布式设备的名称集合。 |

## PlaybackState

表示媒体播放状态的枚举。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

| 名称                        | 值   | 说明         |
| --------------------------- | ---- | ------------ |
| PLAYBACK_STATE_INITIAL      | 0    | 初始状态 |
| PLAYBACK_STATE_PREPARE      | 1    | 正在缓冲     |
| PLAYBACK_STATE_PLAY         | 2    | 正在播放     |
| PLAYBACK_STATE_PAUSE        | 3    | 暂停         |
| PLAYBACK_STATE_FAST_FORWARD | 4    | 快进         |
| PLAYBACK_STATE_REWIND       | 5    | 快退         |
| PLAYBACK_STATE_STOP         | 6    | 停止         |


## LoopMode

表示媒体播放循环模式的枚举。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

| 名称               | 值   | 说明     |
| ------------------ | ---- | -------- |
| LOOP_MODE_SEQUENCE | 0    | 顺序播放 |
| LOOP_MODE_SINGLE   | 1    | 单曲循环 |
| LOOP_MODE_LIST     | 2    | 表单循环 |
| LOOP_MODE_SHUFFLE  | 3    | 随机播放 |

## AVSessionErrorCode

会话发生错误时的错误码。

**系统能力：** SystemCapability.Multimedia.AVSession.Core

| 名称                           | 值      | 说明               |
| ------------------------------ | ------- | ------------------ |
| ERR_CODE_UNKNOWN               | 6600100 | 未知错误           |
| ERR_CODE_SERVICE_EXCEPTION     | 6600101 | 服务异常           |
| ERR_CODE_SESSION_NOT_EXIST     | 6600102 | 会话不存在         |
| ERR_CODE_CONTROLLER_NOT_EXIST  | 6600103 | 控制器不存在       |
| ERR_CODE_REMOTE_CONNECTION_ERR | 6600104 | 分布式设备连接失败 |
| ERR_CODE_COMMAND_INVALID       | 6600105 | 命令非法           |