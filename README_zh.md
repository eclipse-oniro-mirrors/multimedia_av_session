# 会话组件<a name="ZH-CN_TOPIC_0000001147574647"></a>

-   [简介](#section1158716411637)
-   [目录](#section161941989596)
-   [相关仓](#section1533973044317)

## 简介<a name="section1158716411637"></a>

媒体组件为开发者提供一套简单易于理解的接口，能够使得开发者方便接入系统并使用系统的媒体资源。

媒体组件包含了音视频、媒体存储等相关媒体业务，提供以下常用功能：

-   音频播放和录制。
-   视频播放和录制。

**图 1**  媒体组件架构图<a name="fig99659301300"></a>  


![](figures/zh-cn_image_0000001105973932.png)

## 目录<a name="section161941989596"></a>

仓目录结构如下：

```
/foundation/multimedia/avsession_standard  # 会话部件业务代码
├── frameworks                             # 框架代码
│   ├── innerkitsimpl                      # native框架实现
│   └── kitsimpl                           # js框架实现
├── interfaces                             # 外部接口层
│   ├── innerkits                          # native外部接口文件
│   └── kits                               # js外部接口文件
├── sa_profile
├── services                               # 服务实现
│   ├── etc
│   ├── include                            # 服务对外头文件
│   └── session
│       ├── binder
│       ├── client
│       └── server
│           └── remote
├── utils                                  # 会话部件公共库
└── ohos.build                             # 编译文件
```

## 相关仓<a name="section1533973044317"></a>

媒体组件仓：multimedia\avsession_standard

