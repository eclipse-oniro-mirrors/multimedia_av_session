# 播控框架仓库协作指南

## 适用范围

本仓库是 OpenHarmony 多媒体播控框架（AVSession），为系统提供统一的媒体播控能力。当三方应用在系统上运行时，用户可通过系统播控中心对本端和组网内远端音视频应用的播放行为进行控制，并展示相关播放信息。

仓库主要围绕以下职责组织：

1. API 和 ABI 接口定义（C 接口、C++ 内部 API、NAPI/CJ/Taihe 绑定）。
2. 客户端代理实现（会话、控制器、投播控制器）。
3. 系统服务、IPC 接口和系统能力（SAID=3010）。
4. 基础播控（会话、焦点、后台音频、多用户）、音视频投播（AVRouter、Cast+、PCM、HiPlay）和分布式播控（Source/Sink、软总线、会话迁移）。

播控框架分为三大模块：

| 模块 | 职责 | 关键能力 |
|------|------|----------|
| **基础播控** | 本地音视频会话的创建、管理、控制和状态同步 | 会话生命周期、焦点策略、后台音频控制、多用户隔离 |
| **音视频投播** | 将本地媒体投播到远端设备（投屏、投音） | 设备发现、投播路由、流式播放、PCM 投播、HiPlay 协同 |
| **分布式播控** | 组网内设备间的会话同步、迁移和控制 | Source/Sink 同步、软总线通信、会话迁移（MigrateWithNext/SuperLauncher） |

## 仓库目录

- `interfaces/`：对外 Kit（C 接口）和内部 API（C++ 头文件）声明。
- `frameworks/`：原生客户端代理、NAPI、CJ、Taihe 绑定和公共数据结构实现。
- `services/session/server/`：系统服务核心实现（会话项、控制器项、会话栈、焦点策略、后台音频控制、多用户管理、投播路由器、投播控制器、PCM 投播、分布式 Source/Sink、软总线、会话迁移）。
- `services/session/ipc/`：IPC 通信（接口定义、IDL 回调、Proxy 代理、Stub 桩）。
- `services/session/adapter/`：外部依赖适配（音频、应用管理、权限、按键、协同、分布式对象、插件库）。
- `services/etc/`：服务配置和部署资源。
- `avpicker/`、`avinputcastpicker/`、`avvolumepanel/`：投播设备选择和音量面板 UI 组件。
- `sa_profile/`：播控系统能力注册配置（SAID=3010）。
- `utils/`：公共工具库。
- `tools/`：AVSession 管理工具。
- `test/`：测试资源和测试目标。
- `docs/`：播控框架知识库。

知识库入口见 [docs/知识库索引.md](docs/知识库索引.md)。

## 任务路由

| 任务或修改路径 | 必读文档和源码入口 |
| --- | --- |
| 修改会话创建、激活、销毁、元数据或播放状态同步 | [基础播控.md](docs/Basic-PlayBack-Control/基础播控.md)、`interfaces/inner_api/native/session/include/avsession_manager.h`、`services/session/server/avsession_item.cpp` |
| 修改控制器、控制命令、按键事件或元数据过滤 | [基础播控.md](docs/Basic-PlayBack-Control/基础播控.md)、`interfaces/inner_api/native/session/include/avsession_controller.h`、`services/session/server/avcontroller_item.cpp` |
| 修改焦点、中断、TopSession 选择或会话栈 | [基础播控.md](docs/Basic-PlayBack-Control/基础播控.md)、`services/session/server/focus_session_strategy.cpp`、`services/session/server/session_stack.cpp` |
| 修改后台音频静音、前台恢复或应用状态监听 | [基础播控.md](docs/Basic-PlayBack-Control/基础播控.md)、`services/session/server/background_audio_controller.cpp` |
| 修改多用户隔离、账户切换或车机多音区 | [基础播控.md](docs/Basic-PlayBack-Control/基础播控.md)、`services/session/server/avsession_users_manager.cpp` |
| 修改投播路由、castHandle 编码、设备发现或投播启动 | [音视频投播.md](docs/AV-BroadCast/音视频投播.md)、`services/session/server/avrouter_impl.cpp` |
| 修改投播控制器、控制命令转发或状态回调 | [音视频投播.md](docs/AV-BroadCast/音视频投播.md)、`services/session/server/avcast_controller_item.cpp` |
| 修改 Cast+ 引擎对接、流播放器、状态映射或数据源 | [音视频投播.md](docs/AV-BroadCast/音视频投播.md)、`services/session/server/hw_cast_provider.cpp`、`services/session/server/hw_cast_stream_player.cpp` |
| 修改 PCM 投播、HiPlay 或 URLCasting 协同 | [音视频投播.md](docs/AV-BroadCast/音视频投播.md)、`services/session/server/pcm_cast_session.cpp`、`services/session/adapter/collaboration_manager_hiplay.cpp` |
| 修改分布式数据对象同步、Source/Sink 或能力集 | [分布式播控.md](docs/Migrate-PlayBack-Control/分布式播控.md)、`services/session/server/remote/` |
| 修改软总线通信、Socket 建链或数据传输 | [分布式播控.md](docs/Migrate-PlayBack-Control/分布式播控.md)、`services/session/server/softbus/` |
| 修改会话迁移、MigrateWithNext 或 SuperLauncher 流转 | [分布式播控.md](docs/Migrate-PlayBack-Control/分布式播控.md)、`services/session/server/migrate/`、`services/session/server/avsession_service_ext.cpp` |
| 修改 IPC、系统能力、IDL、代理或 Stub | [架构与构建说明.md](docs/架构与构建说明.md)、[安全与隐私.md](docs/Security-Privacy/安全与隐私.md)、对应 `services/session/ipc/base/`、`proxy/`、`stub/`、`idl/` |
| 修改 NAPI、C 接口、CJ、Taihe 或 OHAVSession 绑定 | [架构与构建说明.md](docs/架构与构建说明.md)、`frameworks/js/napi/session/`、`interfaces/kits/c/`、`frameworks/native/ohavsession/` |
| 修改构建、功能开关、配置或系统能力注册 | [架构与构建说明.md](docs/架构与构建说明.md)、`bundle.json`、`config.gni`、`sa_profile/`、相关 `BUILD.gn` |
| 修改测试、故障诊断、日志、Trace 或 Dump | [测试与故障诊断.md](docs/Testing/测试与故障诊断.md)、`services/session/server/test/`、`hisysevent.yaml` |
| 修改权限校验、身份验证或信任边界 | [安全与隐私.md](docs/Security-Privacy/安全与隐私.md)、`services/session/adapter/`（权限相关） |

当任务描述、日志或代码出现 `AVSession`、`AVSessionController`、`AVRouter`、`castHandle`、`HwCastProvider`、`PcmCastSession`、`RemoteSessionSource`、`RemoteSessionSink`、`SoftbusSession`、`MigrateAVSession`、`FocusSessionStrategy`、`BackgroundAudioController`、`SessionStack`、`topSession`、`IPC`、`IDL`、`SAID=3010`、`分布式`、`软总线`、`迁移`、`SuperLauncher`、`MigrateWithNext`、`HiPlay`、`PCM 投播`、`投播路由` 或 `功能开关` 时，必须先打开知识库中的对应主题文档，再定位实现。

编辑前必须先说明：任务类别、已阅读的文档、涉及的公共契约或源码路径、发现的状态/权限/兼容性约束，以及计划执行的验证项。没有完成这一步，不应直接修改文件。

## 修改要求

- 修改实现前，应先阅读相关 `BUILD.gn`、公共头文件、IPC IDL、服务接口和测试目标。
- 公共 API 变更必须同步检查接口、原生客户端、多语言绑定（NAPI/CJ/Taihe）、IPC 定义、服务端实现和测试。
- 必须保持会话和控制器生命周期约束。会话需遵循创建、激活、运行、停用、销毁的状态机；控制器需绑定会话，会话销毁后控制器不可用。每个边界都要校验状态、会话标识、调用方身份和服务可用性。
- 播控框架属于全局协调层。焦点、TopSession、后台音频、多用户、投播路由或分布式同步的变化可能影响不同应用的会话和播放行为。
- 会话数据具有敏感性。禁止新增包含 PCM 内容、媒体元数据原始令牌、设备地址、远端网络标识或未脱敏应用数据的日志。
- `config.gni` 及相关 `.gni` 文件是可选功能的配置来源。
- IPC 修改必须同步代理端和 Stub 端，保持序列化顺序和接口码兼容，并补充失败路径测试。只有 `SERVICE_CMD_SEND_COMMAND_TO_REMOTE` 允许跨设备 RPC，其余 IPC 接口仅限本地调用。
- 分布式数据对象单条数据上限 `RECEIVE_DATA_SIZE_MAX = 500KB`；控制器回调 IPC 容量 `ipcincapacity 1024`；投播控制器默认 1MB。修改序列化时不得突破这些边界。
- 优先复用仓库已有的校验宏、错误码、日志风格、生命周期和线程模型。

## 高风险边界

- 公共 API 的签名、重载、错误码、版本标记和既有行为不得无理由改变；新增接口或字段必须评估 ABI、绑定层和兼容性。C 接口和 OHAVSession 封装受版本脚本（`*.versionscript`）约束。
- IDL、代理、Stub、序列化顺序和接口码属于协议边界，不能只修改单端，也不能复用不兼容的接口码。`AvsessionSeviceInterfaceCode`、`IAVCastController` 命令码和回调 IDL 方法顺序均为兼容性契约。
- `bundle.json`、`config.gni`、`sa_profile/av_session.json`、`hisysevent.yaml` 和版本脚本必须以仓库中的源文件为准，不直接修改生成产物替代源配置。
- 权限、UID、PID、令牌 ID、账户、远端设备授权和隐私状态属于信任边界；无法确认调用方身份或用途时必须失败关闭并保留原状态。Stub 层每个 Handle 方法均经过 `PermissionChecker::CheckPermission` 校验。
- 不得执行未经确认的破坏性命令、设备刷写、系统分区修改或大范围删除；涉及真实设备或组网迁移时先说明影响范围并等待确认。
- 修改第三方依赖（Cast+ 引擎、软总线、分布式数据对象、协同服务库、Cast+ 引擎开关）许可证、公共符号、持久化配置或跨版本协议前，必须先说明影响并请求确认。
- 会话数量上限 `SESSION_NUM_MAX = 50`，超限返回 `ERR_SESSION_EXCEED_MAX`；修改容器逻辑时不得破坏上限和内存回收（栈空延迟 240s 写 `/proc/<pid>/reclaim`）。

## 验证要求

针对局部修改，优先执行对应的 GN 目标和单元测试。跨越会话、控制器、投播、分布式或 IPC 边界的修改，还应检查相关模糊测试和服务级测试。构建环境不可用时，必须说明未执行的命令、原因、替代检查和残余风险。

最小验证矩阵：

| 变更类型 | 至少验证 |
| --- | --- |
| 仅文档或注释 | Markdown 链接、路径和格式检查；`git diff --check` |
| 会话/控制器/焦点/后台音频/多用户 | `services/session/server/test/` 对应目标，覆盖正常、非法状态、重复调用、会话不存在和服务不可用 |
| 投播路由/控制器/Cast+/PCM/HiPlay | `avrouter_test`、`avcast_controller_*_test`、`hw_cast_*_test`、`pcm_cast_*` 路径和设备连接/断开/恢复场景 |
| 分布式 Source/Sink/软总线/迁移 | `remote_session_*_test`、`softbus_session_*_test`、`migrate_avsession_*_test` 和组网建链/断连/恢复场景 |
| IPC、IDL、回调或序列化 | 代理/Stub/服务端联调、非法输入和服务死亡测试，以及对应 `test/fuzztest/` |
| 公共绑定或 API | NAPI、C 接口、CJ、Taihe 或 OHAVSession 对应测试，并检查 ABI、版本脚本和错误码 |
| 功能开关或构建配置 | 开启和关闭路径、依赖缺失降级路径，以及对应 GN 目标 |

重点验证：

- 会话生命周期（创建、激活、停用、销毁）和控制器与销毁会话的交互；
- 焦点策略中的 TopSession 选择、延迟停止（5s）和会话栈排序；
- 后台音频静音与前台恢复；
- 多用户隔离和账户切换；
- 投播路由 castHandle 编解码、设备发现/离线和服务死亡恢复；
- 投播控制器状态回调过滤和有效命令变化；
- 分布式数据对象同步、断连通知和能力集掩码过滤；
- 软总线建链重试（5 次/500ms）和迁移心跳（CROSS 180s / NEXT 30s/3600s）；
- IPC、配置解析、回调和服务入口的模糊测试；
- OpenHarmony 构建流程。

## 错误码（AVSessionErrorCode）

| 错误码 | 值 | 含义 |
|--------|-----|------|
| ERR_CODE_SERVICE_EXCEPTION | 6600101 | 服务异常 |
| SESSION_NOT_EXIST | 6600102 | 会话不存在 |
| CONTROLLER_NOT_EXIST | 6600103 | 控制器不存在 |
| COMMAND_INVALID | 6600105 | 命令无效 |
| SESSION_INACTIVE | 6600106 | 会话未激活 |
| MESSAGE_OVERLOAD | 6600107 | 消息过载 |

定义位置：`interfaces/inner_api/native/session/include/avsession_info.h:1231`

## 构建与静态检查

- 构建命令必须从完整 OpenHarmony 源码根目录执行，不能在本仓库子目录执行。
- 整体构建命令：

  ```sh
  ./build.sh --product-name rk3568 --ccache --build-target make_all
  ```

- 仅构建本组件的命令：

  ```sh
  ./build.sh --product-name rk3568 --ccache --build-target av_session
  ```

- 若产品名或构建参数因环境不同而变化，必须以用户指定值或当前源码根目录的构建配置为准。
- 静态检查至少执行：

  ```sh
  git diff --check
  ```

- 涉及 C/C++ 时，还必须执行仓库规定的格式检查和静态检查。

## 文档要求

- 文档以设计规格和实现边界为主，避免堆积过细的代码描述。
- 优先说明不变量、状态、所有权、安全、隐私和失败行为，再列源码入口。
- 源码路径使用仓库相对路径。
- 依赖功能开关的行为必须明确写出开关名称（见 `config.gni`）。
- 新增知识文档后，必须更新对应的主题索引。
- 推断出的行为不能直接描述为稳定的公共 API 契约。

## 常见误区

- 不能把 `services/session/server` 的服务端实现与 `frameworks/native` 的客户端代理混为同一层；修改一侧时要检查另一侧的调用契约。
- 不能只修改某一个语言绑定或某一个 IPC 端点；公共接口、代理、Stub、服务实现和测试必须一起核对。
- 不能因为功能开关（如 `av_session_enable_dsoftbus`、`multimedia_av_session_enable_data_object`）默认关闭就跳过关闭路径、依赖缺失和服务恢复验证。
- 不能把主题文档中的推断、示例链路或当前实现细节直接当作公共 API 保证。
- 不能把投播路由（AVRouter）和投播控制器（AVCastControllerItem）混为同一层；前者负责路由和 castHandle 管理，后者负责控制命令转发和状态回调。
- 不能把分布式数据对象同步（remote 目录）和软总线通信（softbus 目录）混为同一通道；前者用于 Source/Sink 会话状态同步，后者用于会话迁移数据传输。

## 完成定义

任务只有同时满足以下条件才算完成：修改范围与需求一致；公共 API、IPC、权限、配置和依赖影响已检查；对应最小验证矩阵已执行；新增知识文档已更新索引；工作区无意外改动。最终回复必须列出修改文件、验证命令及结果、未执行项及原因、剩余风险和是否需要后续人工确认。
