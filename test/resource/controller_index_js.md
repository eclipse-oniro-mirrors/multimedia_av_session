# 播控中心demo

1.导入模块
```js
import audio from '@ohos.multimedia.audio'
import WantAgent from '@ohos.wantAgent';
import process from '@ohos.process';
import KeyEvent from '@ohos.multimodalInput.keyEvent';
import PlayerModel from '../../common/PlayerModel.js';
import AVSessionManager from '@ohos.multimedia.avsession';
import RemoteDeviceModel from '../../../model/RemoteDeviceModel.js';
import featureAbility from '@ohos.ability.featureAbility';
import wantAgent from '@ohos.wantAgent';
import display from '@ohos.display';
import image from '@ohos.multimedia.image';
```

2.demo代码
```js
var DEVICE_LIST_LOCALHOST;
export default {
    // 定义变量，请开发者根据实际情况使用
    data: {
        title: 'title',
        artist: 'artist',
        audioUrl: 'common/images/pause.png',
        index: 0,
        loopModIndex: 0,
        audioPlayer: undefined,
        isSwitching: false,
        audioManager: undefined,
        isCallingDefault:false,
        volume: 0,
        avSessionCtrl: undefined,
        CenterSupportCmd: new Set(),
        ValidCmd: new Set(),
        CurrentTime: 0,
        CurrentTimeOn:'0:00',
        isPlaying: false,
        deviceArr:[],
        backImg: 'common/images/bg-tv.jpg',
        musicIcon: 'common/images/music_oh.png',
        selectDevice: 'common/images/ic_hop.svg',
        remoteDeviceModel: new RemoteDeviceModel(),
        showOrHide: false,
        deviceList: [],
        deviceId:[],
        deviceName:[],
        collectBtn: 'button_release',
        SetLoopModeBtn: 'button_release',
        SetSpeedBtn: 'button_release',
        SetSpeed: 'x' + 1,
        SetLoopMode: 'common/images/ic_public_list_cycle.png',
        SetLoopIconArray: [
            'common/images/ic_public_list_cycle.png',
            'common/images/ic_public_single_cycle.png',
            'common/images/ic_public_order_play.png',
            'common/images/ic_public_random.png'
        ],
        SetLoopParam: [
            AVSessionManager.LoopMode.LOOP_MODE_SEQUENCE,
            AVSessionManager.LoopMode.LOOP_MODE_SINGLE,
            AVSessionManager.LoopMode.LOOP_MODE_LIST,
            AVSessionManager.LoopMode.LOOP_MODE_SHUFFLE
        ],
        SetSpeedArray: [
            1.0,
            2.0,
            0.5
        ],
        SpeedIndex: 0,
        AVSessionCon: undefined,
        music_lyric: undefined,
        controllerMap: new Map(),
        container: '',
        containerCenter: '',
        deviceInf: '',
        deviceIdNew:'',
        duration28:0,
        duration128:0,
        duration256:0,
        musicName: '',
        musicAuthor: '',
        musicLyric:'',
        controlSection: '',
        deviceListClass: '',
        deviceListItem: '',
        deviceItemTitle: '',
        deviceItemRadio: '',
        bell_div:'',
        slider_value:'',
        slider:'',
        duration:0,
        duration68:true,
        musicValue:0,
        intervalID:0,
        durationMin:'',
        count:0,
        logList: ['日志'],
        context:null
    },
    
    // 日志
    log(log) {
        this.logList.unshift(this.logList.length + ': ' + JSON.stringify(log));
    },
    onInit() {

        //横竖屏幕适配
        display.getDefaultDisplay((err, data) => {
            if ( data.width > data.height ) {
                console.info('AVSessionController[IndexPage] getDefaultDisplay direction is horizontal.[width]' + data.width + '[height]' + data.height);
                this.container         = 'h_container';
                this.containerCenter   = 'h_container_center';
                this.deviceInf         = 'h_device_inf';
                this.musicName         = 'h_music_name';
                this.musicAuthor       = 'h_music_author';
                this.musicLyric        = 'h_music_lyric'
                this.controlSection    = 'h_control_section';
                this.deviceListClass   = 'h_device_list';
                this.deviceListItem    = 'h_device_list_item';
                this.deviceItemTitle   = 'h_device_item_title';
                this.deviceItemRadio   = 'h_device_item_radio';
                this.bell_div          = 'h_bell_div';
                this.slider_value      = 'h_slider_value';
                this.slider            = 'h_slider';
            } else {
                console.info('AVSessionController[IndexPage] getDefaultDisplay direction is vertical.[width]' + data.width + '[height]' + data.height);
                this.container         = 'v_container';
                this.containerCenter   = 'v_container_center';
                this.deviceInf         = 'v_device_inf';
                this.musicName         = 'v_music_name';
                this.musicAuthor       = 'v_music_author';
                this.musicLyric        = 'v_music_lyric'
                this.controlSection    = 'v_control_section';
                this.deviceListClass   = 'v_device_list';
                this.deviceListItem    = 'v_device_list_item';
                this.deviceItemTitle   = 'v_device_item_title';
                this.deviceItemRadio   = 'v_device_item_radio';
                this.bell_div          = 'v_bell_div';
                this.slider_value      = 'v_slider_value ';
                this.slider            = 'v_slider ';
            }
        });
    
         // 获取会话描述符，创建控制器
        AVSessionManager.getAllSessionDescriptors().then((descriptors) => {
            this.log('getAllSessionDescriptors success');
            console.info('getAllSessionDescriptors: '+descriptors);
            descriptors.forEach((descriptor) => {
                if (descriptor.isActive) {
                    this.log('isActive success');
                    console.info('[ttt] AVSessionController[IndexPage] getAllSessionDescriptors session ${tag} is active' + descriptor.sessionTag);
                    this.AVSessionCon = AVSessionManager.createController(descriptor.sessionId).then((controller) => {
                        this.controllerMap.set(descriptor.sessionId, controller);
                        this.log('createController success');
                        console.info('[ttt] AVSessionController[IndexPage] getAllSessionDescriptors this.avSessionCtrl session success %s, %s', this.avSessionCtrl, controller);
                        if (descriptor.isTopSession) {
                            this.avSessionCtrl = controller;
                            console.info('[ttt] AVSessionController[IndexPage] getAllSessionDescriptors session success.[%d]', descriptor.sessionId);
                        } else {
                            console.info('[ttt] AVSessionController[IndexPage] getAllSessionDescriptors session.isTopSession is not [%d] topSession.', descriptor.sessionId);
                        }
                    }, e => {
                        console.error('[ttt] AVSessionController[IndexPage] getAllSessionDescriptors createController' + descriptor.sessionTag + ' is '+ e.code);
                    })
                } else {
                    console.error('[ttt] AVSessionController[IndexPage] getAllSessionDescriptors descriptor.isActive is ' + descriptor.isActive);
                }
            })
        }, e => {
            console.error('[ttt] AVSessionController[IndexPage] getAllSessionDescriptors error' +  ' is ' + e.message);
        });

        // 注册会话创建监听
        AVSessionManager.on('sessionCreate', (descriptor) => {
            this.log('sessionCreate success');
            if (descriptor == undefined) {
                console.error('[ttt] AVSessionController[IndexPage] sessionCreate session is error');
                return;
            } else {
                // 获取会话描述符
                console.info('[ttt] AVSessionController[IndexPage] sessionCreate start create' + descriptor.sessionTag);
                this.AVSessionCon = AVSessionManager.createController(descriptor.sessionId).then((controller) => {
                    this.controllerMap.set(descriptor.sessionId, controller);
    
                    if (descriptor.isTopSession) {
                        this.avSessionCtrl = controller;
                        this.onShow();
                        console.info('[ttt] AVSessionController[IndexPage] sessionCreate this.avSessionCtrl session success %s, %s', this.avSessionCtrl, controller);
                    } else {
                        console.info('[ttt] AVSessionController[IndexPage] sessionCreate session.isTopSession is not topSession.');
                    }
                }, e => {
                    console.error('[ttt] AVSessionController[IndexPage] sessionCreate this.avSessionCtrl createController');
                })
            }
        })

        // Register the system's highest priority session change listening
        AVSessionManager.on('topSessionChange', (descriptor) => {
            this.log('topSessionChange success');
            if (descriptor == undefined) {
                console.error('[ttt] AVSessionController[IndexPage] topSessionChange session is error');
                return;
            } else {
                // 获取会话播放状态信息
                let avsession = this.avSessionCtrl;
                if (avsession != undefined) {
                    avsession.getAVPlaybackState().then((playState) => {
                        this.count = 0;
                        let avPlaybackState = playState.state;
                        this.CurrentTime = avsession.getRealPlaybackPositionSync();
                        this.log('CurrentTime: '+this.CurrentTime);
                        console.info('[ttt] AVSessionController[IndexPage] topSessionChange CurrentTime:' + this.CurrentTime)
                        console.info('[ttt] AVSessionController[IndexPage] topSessionChange playState:' + playState.state)
                        if (avPlaybackState == AVSessionManager.PlaybackState.PLAYBACK_STATE_PLAY) {
                            avsession.sendControlCommand({command:'pause'});
                            this.isPlaying = false;
                            clearInterval(this.intervalID);
                            this.audioUrl = 'common/images/pause.png';
                            console.info('[ttt] AVSessionController[IndexPage] topSessionChange speed:' + playState.speed)
                        }
                    });
                    avsession = undefined;
                }
    
                if (descriptor.isTopSession) {
                    this.avSessionCtrl = this.controllerMap.get(descriptor.sessionId);
                    console.info('[ttt] AVSessionController[IndexPage] topSessionChange session success.[%d]', descriptor.sessionId);
                } else {
                    console.info('[ttt] AVSessionController[IndexPage] topSessionChange session.isTopSession is not [%d] topSession.', descriptor.sessionId);
                }
            }
        })

        // 注册系统会话销毁监听
        AVSessionManager.on('sessionDestroy', (descriptor) => {
            this.log('sessionDestroy success.');
            if (descriptor == undefined) {
                console.error('[ttt] AVSessionController[IndexPage] sessionDestroy session is error');
                return;
            } else if(descriptor.isTopSession) {
                if (this.avSessionCtrl != undefined) {
                    this.avSessionCtrl = undefined;
                }
                clearInterval(this.intervalID);
                this.count = 0;
                this.controllerMap.delete(descriptor.sessionId);
                this.collectBtn = 'button_release';
                this.loopModIndex = 0;
                this.SetLoopMode = this.SetLoopIconArray[this.loopModIndex];
                this.SpeedIndex = 0;
                this.SetSpeed = 'x' + this.SetSpeedArray[this.SpeedIndex];
                this.isPlaying = false;
                this.audioUrl = 'common/images/pause.png';
                this.artist = "artist";
                this.title = "title";
                this.music_lyric = "lyric";
            }
            console.info('[ttt] AVSessionController[IndexPage] sessionDestroy session [%d] success.', descriptor.sessionId);
        });

        // 初始化设备列表(分布式)
        DEVICE_LIST_LOCALHOST = {
            id: 'localDev',
            name: this.$t('strings.localDev'),
        };
        this.deviceList = [DEVICE_LIST_LOCALHOST];
    },
    
    async onShow() {
        await this.AVSessionCon;
        this.audioManager = await audio.getAudioManager();
        this.context = await featureAbility.getContext();
        console.info('[ttt] AVSessionController[IndexPage] onShow this.avSessionCtrl end %s', this.avSessionCtrl);
        if (this.avSessionCtrl != undefined) {
            // 获取会话元数据
            this.avSessionCtrl.getAVMetadata().then((data) => {
                console.info('getAVMetadata success');
                this.log('getAVMetadata success');
                this.artist = data.artist
                this.title = data.title
                this.music_lyric = data.lyric
                this.duration = data.duration;
                if(data.duration >= 68000 && data.duration <128000){
                    this.duration68 = true;
                    this.duration28 = false;
                    this.duration128 = false;
                    this.duration256 = false;
                } else if(data.duration < 68000){
                    this.duration28 = true;
                    this.duration68 = false;
                    this.duration128 = false;
                    this.duration256 = false;
                } else if(data.duration >= 128000 && data.duration < 256000){
                    this.duration28 = false;
                    this.duration68 = false;
                    this.duration128 = true;
                    this.duration256 = false;
                } else if(data.duration >= 256000){
                    this.duration28 = false;
                    this.duration68 = false;
                    this.duration128 = false;
                    this.duration256 = true;
                }
                let muv = this.duration/1000;
                let minutes = Math.floor(muv / 60);
                let seconds = muv % 60;
                if(seconds.toString().length < 2) {
                    seconds = '0' + seconds.toString();
                }
                this.durationMin = minutes.toString() + ':' + seconds.toString();
                this.backImg = data.mediaImage;
                console.info('[ttt] AVSessionController[IndexPage] artist:' + this.artist)
                console.info('[ttt] AVSessionController[IndexPage] title:' + this.title)
                console.info('[ttt] AVSessionController[IndexPage] music_lyric:' + this.music_lyric)
            })

            // 获取会话播放状态信息
            this.avSessionCtrl.getAVPlaybackState().then((playState) => {
                console.info('getAVPlaybackState success');
                this.log('getAVPlaybackState success');
                let avPlaybackState = playState.state;
                this.CurrentTime = this.avSessionCtrl.getRealPlaybackPositionSync();
                this.log('CurrentTime: '+this.CurrentTime);
                console.info('[ttt] AVSessionController[IndexPage] CurrentTime:' + this.CurrentTime)
                this.log('sendcontrolcommand success');
                console.info('sendcontrolcommand success');
                this.musicValue = Math.floor(this.CurrentTime);
                let muv = this.musicValue/1000;
                let minutes = Math.floor(muv / 60);
                let seconds = muv % 60;
                if(seconds.toString().length < 2) {
                    seconds = '0' + seconds.toString();
                }
                this.CurrentTimeOn = minutes.toString() + ':' + seconds.toString();
                console.info('[ttt] AVSessionController[IndexPage] 播放状态:' + playState.state)
                console.info('[ttt] AVSessionController[IndexPage] 当前播放速度:' + playState.speed)
                if (avPlaybackState == AVSessionManager.PlaybackState.PLAYBACK_STATE_PLAY) {
                    this.isPlaying = true;
                    this.onUpdateMusicSlider();
                    this.audioUrl = 'common/images/play.png';
                } else {
                    clearInterval(this.intervalID);
                    this.isPlaying = false;
                    this.audioUrl = 'common/images/pause.png';
                }

                let avPlaybackSpeed = playState.speed;
                console.info('[ttt] AVSessionController[IndexPage] AVSessionCtrl playbackStateChange callback speed %s', avPlaybackSpeed);
                if (avPlaybackSpeed != undefined) {
                    this.SpeedIndex = avPlaybackSpeed
                    this.SetSpeed = 'x' + this.SetSpeedArray[avPlaybackSpeed];
                }
    
                let isFavorite = playState.isFavorite;
                console.info('[ttt] AVSessionController[IndexPage] AVSessionCtrl playbackStateChange callback isFavorite %s', isFavorite);
                // 发送收藏指令
                if (isFavorite != undefined) {
                    if (isFavorite == true) {
                        this.collectBtn = 'button_press';
                    } else if (isFavorite == false) {
                        this.collectBtn = 'button_release';
                    }
                }
    
                let avPlaybackLoopMode = playState.loopMode;
                console.info('[ttt] AVSessionController[IndexPage] AVSessionCtrl playbackStateChange callback loopMode %s', avPlaybackLoopMode);
                if (avPlaybackLoopMode != undefined) {
                    this.loopModIndex = avPlaybackLoopMode;
                    this.SetLoopMode = this.SetLoopIconArray[avPlaybackLoopMode];
                }
    
                let position = playState.position;
                console.info('[ttt] AVSessionController[IndexPage] AVSessionCtrl playbackStateChange callback position %s', position);
                if (position != undefined) {
                    if(this.count == 0) {
                        if(this.isPlaying){
                            // 发送播放控制命令
                            this.avSessionCtrl.sendControlCommand({command:'play'});
                            this.log('sendcontrolcommand success');
                            console.info('sendcontrolcommand success');
                        }
                        this.count++;
                        this.musicValue = position.elapsedTime;
                        let muv = this.musicValue/1000;
                        let minutes = Math.floor(muv / 60);
                        let seconds = muv % 60;
                        if(seconds.toString().length < 2) {
                            seconds = '0' + seconds.toString();
                        }
                        this.CurrentTimeOn = minutes.toString() + ':' + seconds.toString();
                    }
                }
            });

            // 获取有效命令集
            this.avSessionCtrl.getValidCommands().then((command) => {
                this.log('getValidCommands success');
                for ( let c of this.CenterSupportCmd) {
                    if (command.has(c)) {
                        this.ValidCmd.add(c);
                    }
                }
            });
    
            // 注册元数据更新监听
            this.avSessionCtrl.on('metadataChange', 'all', (data) => {
                this.log('metadataChange success');
                console.info('metadataChange success');
                if (data == undefined) {
                    console.info('[ttt] AVSessionController[IndexPage] AVSessionCtrl data is undefined.');
                    return;
                }
                console.info('[ttt] AVSessionController[IndexPage] AVSessionCtrl metadataChange callback.');
                this.artist = data.artist?data.artist:this.artist;
                this.title = data.title?data.title:this.title;
                this.music_lyric = data.lyric;
                this.avSessionCtrl.getAVMetadata().then((data1) => {
    
                    this.artist = data1.artist;
                    this.title = data1.title;
                    this.music_lyric = data1.lyric;
                    this.duration = data1.duration;
                    if(data.duration >= 68000 && data.duration <128000){
                        this.duration68 = true;
                        this.duration28 = false;
                        this.duration128 = false;
                        this.duration256 = false;
                    } else if(data.duration < 68000){
                        this.duration28 = true;
                        this.duration68 = false;
                        this.duration128 = false;
                        this.duration256 = false;
                    } else if(data.duration >= 128000 && data.duration < 256000){
                        this.duration28 = false;
                        this.duration68 = false;
                        this.duration128 = true;
                        this.duration256 = false;
                    } else if(data.duration >= 256000){
                        this.duration28 = false;
                        this.duration68 = false;
                        this.duration128 = false;
                        this.duration256 = true;
                    }
                    let muv = this.duration/1000;
                    let minutes = Math.floor(muv / 60);
                    let seconds = muv % 60;
                    if(seconds.toString().length < 2) {
                        seconds = '0' + seconds.toString();
                    }
                    this.durationMin = minutes.toString() + ':' + seconds.toString();
                    this.backImg = data1.mediaImage;
                    this.onUpdateMusicSlider();
                })
    
            });

            // 注册会话销毁监听
            this.avSessionCtrl.on('sessionDestroy', () => {
                this.log('AVSessionController destroy success');
                console.info('[ttt] AVSessionController[IndexPage] AVSessionCtrl sessionDestroy callback.');
            });

            // 注册播放状态更新监听
            this.avSessionCtrl.on('playbackStateChange', 'all', (state) => {
                this.log('playbackStateChange success');
                let avPlaybackState = state.state;
                console.info('[ttt] AVSessionController[IndexPage] AVSessionCtrl playbackStateChange callback state %s', avPlaybackState);
                if (avPlaybackState != undefined) {
                    this.CurrentTime = this.avSessionCtrl.getRealPlaybackPositionSync();
                    this.log('CurrentTime: '+this.CurrentTime);
                    this.musicValue = this.CurrentTime;
                    let muv = this.musicValue/1000;
                    let minutes = Math.floor(muv / 60);
                    let seconds = muv % 60;
                    if(seconds.toString().length < 2) {
                        seconds = '0' + seconds.toString();
                    }
                    this.CurrentTimeOn = minutes.toString() + ':' + seconds.toString();
                    console.info('[ttt] AVSessionController[IndexPage] playbackStateChange CurrentTime:' + this.CurrentTime)
                    if (avPlaybackState == AVSessionManager.PlaybackState.PLAYBACK_STATE_PLAY) {
                        this.isPlaying = true;
                        this.audioUrl = 'common/images/play.png';
                        this.onUpdateMusicSlider();
                        console.info('[ttt] AVSessionController[IndexPage] playbackStateChange callback play.');
                    } else {
                        clearInterval(this.intervalID);
                        this.isPlaying = false;
                        this.audioUrl = 'common/images/pause.png';
                        console.info('[ttt] AVSessionController[IndexPage] playbackStateChange callback pause.');
                    }
                }
    
                let avPlaybackSpeed = state.speed;
                console.info('[ttt] AVSessionController[IndexPage] AVSessionCtrl playbackStateChange callback speed %s', avPlaybackSpeed);
                if (avPlaybackSpeed != undefined) {
                    this.SpeedIndex = avPlaybackSpeed
                    this.SetSpeed = 'x' + this.SetSpeedArray[avPlaybackSpeed];
                }
    
                let isFavorite = state.isFavorite;
                console.info('[ttt] AVSessionController[IndexPage] AVSessionCtrl playbackStateChange callback isFavorite %s', isFavorite);
                // 发送收藏指令
                if (isFavorite != undefined) {
                    if (isFavorite == true) {
                        this.collectBtn = 'button_press';
                    } else if (isFavorite == false) {
                        this.collectBtn = 'button_release';
                    }
                }
    
                let avPlaybackLoopMode = state.loopMode;
                console.info('[ttt] AVSessionController[IndexPage] AVSessionCtrl playbackStateChange callback loopMode %s', avPlaybackLoopMode);
                if (avPlaybackLoopMode != undefined) {
                    this.loopModIndex = avPlaybackLoopMode;
                    this.SetLoopMode = this.SetLoopIconArray[avPlaybackLoopMode];
                }
    
                let position = state.position;
    
                console.info('[ttt] AVSessionController[IndexPage] AVSessionCtrl playbackStateChange callback position %s', position);
                if (position != undefined) {
                    this.musicValue = position.elapsedTime;
                    let muv = this.musicValue/1000;
                    let minutes = Math.floor(muv / 60);
                    let seconds = muv % 60;
                    if(seconds.toString().length < 2) {
                        seconds = '0' + seconds.toString();
                    }
                    this.CurrentTimeOn = minutes.toString() + ':' + seconds.toString();
                }
            });
    
            // 4.controller 'active state changed' callback.
            this.avSessionCtrl.on('activeStateChange', (isActive) => {
                this.log('activeStateChange success');
    
                if (isActive == undefined) {
                    console.info('[ttt] AVSessionController[IndexPage] AVSessionCtrl state is undefined.');
                    return;
                }
                console.info('[ttt] AVSessionController[IndexPage] AVSessionCtrl activeStateChange callback.');
                if (isActive) {
                    console.info('[ttt] AVSessionController[IndexPage] 按键高亮.');
                } else {
                    console.info('[ttt] AVSessionController[IndexPage] 按键无效.');
                }
            });
    
            // 注册会话支持的命令变更监听
            this.avSessionCtrl.on('validCommandChange', (cmds) => {
                this.log('validCommandChange success');
                console.info('[ttt] AVSessionController[IndexPage] AVSessionCtrl validCommandChange callback.');
                this.ValidCmd.clear();
                for (let c of this.CenterSupportCmd) {
                    if (cmds.has(c)) {
                        this.ValidCmd.add(c);
                    }
                }
            });
    
            // 获取输出设备信息
            this.avSessionCtrl.getOutputDevice((err,outputDeviceInfo)=> {
                this.log("getOutputDevice success");
                if (outputDeviceInfo && outputDeviceInfo.isRemote) {
                    this.log('getOutputDevice success  1' + JSON.stringify(outputDeviceInfo.isRemote));
                    this.log('getOutputDevice success  2' + JSON.stringify(outputDeviceInfo.audioDeviceId));
                    this.log('getOutputDevice success  2' + JSON.stringify(outputDeviceInfo.deviceName));
                    if (outputDeviceInfo.audioDeviceId && outputDeviceInfo.deviceName) {
                        for (let i = 0; i < outputDeviceInfo.audioDeviceId.length; i++) {
                            let tem = {
                                deviceId:outputDeviceInfo.audioDeviceId[i],
                                deviceName:outputDeviceInfo.deviceName[i]
                            }
                            this.deviceArr.push(tem);
                        }
                    } else {
                        this.log("getOutputDevice empty data");
                    }
                } else {
                    this.log("getOutputDevice empty data");
                }
            });
    
            // 注册输出设备变更监听
            this.avSessionCtrl.on('outputDeviceChange', () => {
                this.log('outputDeviceChange success');
                console.info('[ttt] AVSessionController[IndexPage] AVSessionCtrl outputDeviceChange callback.');
            });
        }
    },
    
    onDestroy() {
        this.avSessionCtrl.off("validCommandChange");
        this.avSessionCtrl.off("metadataChange");
        this.avSessionCtrl.off("outputDeviceChange");
    },
    
    onUpdateMusicSlider() {
        let this_ = this;
        clearInterval(this.intervalID);
    
        this.intervalID = setInterval(function() {
            this_.musicValue += (0.5 * this_.SetSpeedArray[this_.SpeedIndex] * 1000);
            let muv = this_.musicValue/1000;
            let minutes = Math.floor(muv / 60);
            let seconds = Math.floor(muv % 60);
            if(seconds.toString().length < 2) {
                seconds = '0' + seconds.toString();
            }
            this_.CurrentTimeOn = minutes.toString() + ':' + seconds.toString();
            if (this_.musicValue > this_.duration && this_.duration != 0) {
                this_.musicValue = 0;
                this_.CurrentTimeOn = '0:00';
                if(this_.loopModIndex == 0) {
                    clearInterval(this_.intervalID);
                    this_.onNextClick();
                } else if (this_.loopModIndex == 1) {
                    this_.musicValue = 0;
                    this_.CurrentTimeOn = '0:00';
                } else if (this_.loopModIndex == 2) {
                    clearInterval(this_.intervalID);
                    this_.onNextClick();
                } else if (this_.loopModIndex == 3) {
                    clearInterval(this_.intervalID);
                    this_.index = Math.floor(Math.random()*4);
                    this_.onNextClick();
                }
            }
        }, 500);
    },

    // 点击播放
    onPlayClick() {
        if (this.avSessionCtrl == undefined) {
            if (!this.isCallingDefault) {
                this.isCallingDefault = true;
                AVSessionManager.createController('default').then((controller) => {
                    this.controllerMap.set(controller.sessionId, controller);
                    this.avSessionCtrl = controller;
                    this.onShow();
                    console.info('[ttt] AVSessionController[IndexPage] sessionCreate this.avSessionCtrl session success %s, %s', this.avSessionCtrl, controller);
                }, e => {
                    console.error('[ttt] AVSessionController[IndexPage] sessionCreate this.avSessionCtrl createfaultController error');
                })
                this.isCallingDefault = false;
            }
            return;
        }
    
        // 判断会话是否激活
        this.avSessionCtrl.isActive((active) => {
            if ((active == false) || (active == undefined)) {
                return;
            }
        })
        console.info('[ttt] AVSessionController[IndexPage] onPlayClick this.avSessionCtrl %s', this.avSessionCtrl);
        if (this.isPlaying) {
            clearInterval(this.intervalID);
            this.isPlaying = false;
            this.audioUrl = 'common/images/pause.png';
            // 发送暂停控制命令
            this.avSessionCtrl.sendControlCommand({command:'pause'});
            this.log('sendcontrolcommand success');
            console.info('sendcontrolcommand success');
            console.info('[ttt] AVSessionController[IndexPage] onPlayClick is pause.');
        } else {
            this.onUpdateMusicSlider();
            this.isPlaying = true;
            this.audioUrl = 'common/images/play.png';
            // 发送播放控制命令
            this.avSessionCtrl.sendControlCommand({command:'play'});
            this.log('sendcontrolcommand success');
            console.info('sendcontrolcommand success');
            console.info('[ttt] AVSessionController[IndexPage] onPlayClick is playing.');
        }
    },

    // 点击上一首
    onPreviousClick() {
        if (this.avSessionCtrl == undefined) {
            return;
        }
    
        this.avSessionCtrl.isActive((active) => {
            if ((active == false) || (active == undefined)) {
                return;
            }
        })
    
        console.info('[ttt] AVSessionController[IndexPage] onPreviousClick');
        if (this.isPlaying == false) {
            this.audioUrl = 'common/images/play.png';
            this.isPlaying = true;
            this.avSessionCtrl.sendControlCommand({command:'play'});
            this.log('sendcontrolcommand success');
            console.info('sendcontrolcommand success');
        }
        this.avSessionCtrl.sendControlCommand({command:'playPrevious'});
        this.log('sendcontrolcommand success');
        console.info('sendcontrolcommand success');
        this.onUpdateMusicSlider();
    },
    
    // 点击下一首
    onNextClick() {
        if (this.avSessionCtrl == undefined) {
            return;
        }
    
        this.avSessionCtrl.isActive((active) => {
            if ((active == false) || (active == undefined)) {
                return;
            }
        })
        console.info('[ttt] AVSessionController[IndexPage] onNextClick');
        if (this.isPlaying == false) {
            this.audioUrl = 'common/images/play.png';
            this.isPlaying = true;
            this.avSessionCtrl.sendControlCommand({command:'play'});
            this.log('sendcontrolcommand success');
            console.info('sendcontrolcommand success');
        }
        this.avSessionCtrl.sendControlCommand({command:'playNext'});
        this.log('sendcontrolcommand success');
        console.info('sendcontrolcommand success');
        this.onUpdateMusicSlider();
    },
    
    media(e) {
        this.volume = e.value
        this.audioManager.setVolume(audio.AudioVolumeType.MEDIA, this.volume).then(() => {
            console.info('Promise returned to indicate a successful volume setting.');
        })
    },
    
    // 流转按钮
    onSelectDeviceClick() {
        console.info('[ttt] AVSessionController[IndexPage] onSelectDeviceClick button.');
        if (!this.showOrHide) {
            this.selectDevice = 'common/images/ic_hop_blue.svg';
            this.showOrHide = true;
        } else {
            this.selectDevice = 'common/images/ic_hop.svg';
            this.showOrHide = false;
            this.remoteDeviceModel.registerDeviceListCallback(() => {
                var list = [];
                list[0] = DEVICE_LIST_LOCALHOST;
                var deviceList;
                if (this.remoteDeviceModel.discoverList.length > 0) {
                    deviceList = this.remoteDeviceModel.discoverList;
                    console.info('[ttt] AVSessionController[IndexPage] discoverList length is ' + this.remoteDeviceModel.discoverList.length);
                } else {
                    deviceList = this.remoteDeviceModel.deviceList;
                    console.info('[ttt] AVSessionController[IndexPage] deviceList length is ' + this.remoteDeviceModel.deviceList.length);
                }
                for (var i = 0; i < deviceList.length; i++) {
                    console.info('[ttt] AVSessionController[IndexPage] device ' + i + '/' + deviceList.length + ' deviceId='
                    + deviceList[i].deviceId + ' deviceName=' + deviceList[i].deviceName + ' deviceType='
                    + deviceList[i].deviceType);
                    list[i + 1] = {
                        name: deviceList[i].deviceName,
                        id: deviceList[i].deviceId,
                    };
                }
                this.deviceList = list;
            });
            console.info('[ttt] AVSessionController[IndexPage] onContinueAbilityClick end');
        }
    },
    
    onDeviceChange(inputValue, e) {
        console.info('[ttt] AVSessionController[IndexPage] onDeviceChange ' + inputValue + ', ' + e.value);
        if (inputValue === e.value) {
            if (this.remoteDeviceModel.discoverList.length > 0) {
                console.info('[ttt] AVSessionController[IndexPage] continue to unauthed device');
                var name = undefined;
                for (var i = 0; i < this.remoteDeviceModel.discoverList.length; i++) {
                    if (this.remoteDeviceModel.discoverList[i].deviceId === e.value) {
                        name = this.remoteDeviceModel.discoverList[i].deviceName;
                        break;
                    }
                }
                if (name == undefined) {
                    console.error('[ttt] AVSessionController[IndexPage] onRadioChange failed, can not get name from discoverList');
                    return;
                }
                console.info('[ttt] AVSessionController[IndexPage] onRadioChange name=' + name);
    
                let self = this;
                this.remoteDeviceModel.authDevice(e.value, () => {
                    console.info('[ttt] AVSessionController[IndexPage] auth and online finished');
                    for (i = 0; i < self.remoteDeviceModel.deviceList.length; i++) {
                        if (self.remoteDeviceModel.deviceList[i].deviceName === name) {
                            self.startAbilityContinuation(self.remoteDeviceModel.deviceList[i].deviceId,                                                     self.remoteDeviceModel.deviceList[i].deviceName);
                        }
                    }
                });
            } else {
                console.info('[ttt] AVSessionController[IndexPage] continue to authed device');
                for (i = 0; i < this.remoteDeviceModel.deviceList.length; i++) {
                    if (this.remoteDeviceModel.deviceList[i].deviceId === e.value) {
                        this.startAbilityContinuation(this.remoteDeviceModel.deviceList[i].deviceId,                                                     this.remoteDeviceModel.deviceList[i].deviceName);
                    }
                }
            }
        }
        this.showOrHide = false;
        this.selectDevice = 'common/images/ic_hop.svg';
    },
    
    getDeviceList() {
        this.$element("eventDialog").show();
    },
    getDevice(e) {
        this.log("getDeviceId success :" + e.newValue);
        this.deviceIdNew = e.newValue;
    },
    changeDevice() {
        this.$element("eventDialog").close();
        this.castAudio();
    },
    
    // 远端投播
    async castAudio() {
        this.log('castAudio method');
        this.audioManager.getRoutingManager((err,audioRoutingManager) => {
            this.log('getRoutingManager success');
            audioRoutingManager.getDevices(4,(err,AudioDeviceDescriptors) => {
                this.log('getDevices success');
                if (AudioDeviceDescriptors) {
                    this.log('getDeviceIds' + JSON.stringify(AudioDeviceDescriptors));
                    for (let i = 0; i < AudioDeviceDescriptors.length; i++) {
                        this.log("id = " + AudioDeviceDescriptors[i].id);
                    }
                }
                let token = {
                    sessionId:this.avSessionCtrl.sessionId,
                    pid:process.pid,
                    uid:process.uid
                };
                AVSessionManager.castAudio(token,AudioDeviceDescriptors,(err) => {
                    if (err) {
                        this.log('castAudio err');
                        console.info(' ttt AVSessionPlayer[IndexPage] castAudio err');
                    } else {
                        this.log('castAudio success');
                        console.info(' ttt AVSessionPlayer[IndexPage] castAudio success');
                    }
                });
            });
        });
    },
    
    startAbilityContinuation(deviceId, deviceName) {
        this.showOrHide = false;
        this.selectDevice = 'common/images/ic_hop.svg';
        var params;
        console.info('[ttt] AVSessionController[IndexPage] featureAbility.startAbility deviceId=' + deviceId
        + ' deviceName=' + deviceName);
        var wantValue = {
            bundleName:'com.ohos.AVSessionController',
            abilityName:'com.ohos.AVSessionController.MainAbility',
            deviceId:deviceId,
            parameters:params
        };
        featureAbility.startAbility({
            want: wantValue
        }).then((data) => {
            console.info('[ttt] AVSessionController[IndexPage] featureAbility.startAbility finished, ' + JSON.stringify(data));
        });
        console.info('[ttt] AVSessionController[IndexPage] featureAbility.startAbility want=' + JSON.stringify(wantValue));
    },
    
    // 点击收藏按钮
    onCollectionClick() {
        if (this.avSessionCtrl == undefined) {
            return;
        }
   
        this.avSessionCtrl.isActive((active) => {
            if ((active == false) || (active == undefined)) {
                return;
            }
        })
    
        console.info('[ttt] AVSessionController[IndexPage] onCollectionClick button.');
        // 发送命令
        this.avSessionCtrl.sendControlCommand({command: 'toggleFavorite', parameter: "1234567"});
        this.avSessionCtrl.sendControlCommand({command:'stop'});
        this.avSessionCtrl.sendControlCommand({command:'fastForward'});
        this.avSessionCtrl.sendControlCommand({command:'rewind'});
        
        this.log('sendcontrolcommand success');
        console.info('sendcontrolcommand success');
        console.info('[ttt] AVSessionController[IndexPage] onCollectionClick is valid.');

        if (this.collectBtn === 'button_press') {
            this.collectBtn = 'button_release';
            console.info('[ttt] AVSessionController[IndexPage] onCollectionClick is button_release.');
        } else {
            this.collectBtn = 'button_press';
            console.info('[ttt] AVSessionController[IndexPage] onCollectionClick is button_press.');
        }
    },

    onSetLoopMode(){
        if (this.avSessionCtrl == undefined) {
            return;
        }
    
        this.avSessionCtrl.isActive((active) => {
            if ((active == false) || (active == undefined)) {
                return;
            }
        })
    
        this.loopModIndex ++;
        if (this.loopModIndex > 3) {
            this.loopModIndex = 0;
        }
        this.SetLoopMode = this.SetLoopIconArray[this.loopModIndex];
    
        let self = this;
        this.avSessionCtrl.sendControlCommand({
            command:'setLoopMode',
            parameter:this.SetLoopParam[self.loopModIndex]
        });
        this.log('sendcontrolcommand success');
        console.info('sendcontrolcommand success');
        console.info('[ttt] AVSessionController[IndexPage] onSetLoopMode button.');
    },
    
    onSetSpeed() {
        if (this.avSessionCtrl == undefined) {
            return;
        }
    
        this.avSessionCtrl.isActive((active) => {
            if ((active == false) || (active == undefined)) {
                return;
            }
        })
    
        this.SpeedIndex ++;
        if (this.SpeedIndex > 2) {
            this.SpeedIndex = 0;
        }
        this.SetSpeed = 'x' + this.SetSpeedArray[this.SpeedIndex];
    
        let self = this;
        this.avSessionCtrl.sendControlCommand({
            command:'setSpeed',
            parameter:self.SpeedIndex
        });
        this.log('sendcontrolcommand success');
        console.info('sendcontrolcommand success');
        console.info('[ttt] AVSessionController[IndexPage] onSetSpeed button.');
    },
    
    onToAbility() {
    
        if (this.avSessionCtrl == undefined) {
            return;
        }
    
        this.avSessionCtrl.isActive((active) => {
            if (active == false) {
                return;
            }
        })
    
        let TriggerInfo = {
            code:0
        }
        this.avSessionCtrl.getLaunchAbility((err,wantAgent1) => {
            this.log('getLaunchAbility success')
            this.log(err.code);
            WantAgent.getBundleName(wantAgent1).then((name) => {
                console.info('[ttt] AVSessionPlayer[IndexPage] getBundleName bundle name:' + name);
                this.log('getWantAgent success agent bundle name:' + name);
            }, e => {
                this.log(e)
                console.info('[ttt] AVSessionPlayer[IndexPage] getBundleName error' +  ' is ' + e.message);
            });
            wantAgent.trigger(wantAgent1, TriggerInfo,(completeData) => {
                this.log('completeaData : '+completeData);
                if(completeData !=undefined){
                    this.log('getWantAgent success agent completeData:' + completeData.finalCode);
                }
    
            })
        })
        console.info('[ttt] AVSessionController[IndexPage] onToAbility button.');
    },
    
    mediaMusic(e) {
    
        if (this.avSessionCtrl == undefined) {
            return;
        }
    
        this.avSessionCtrl.isActive((active) => {
            if (active == false) {
                return;
            }
        })


        this.avSessionCtrl.sendControlCommand({
            command:'seek',
            parameter:e.value
        });
        this.log('sendcontrolcommand success');
        console.info('sendcontrolcommand success');
        console.info('[ttt] AVSessionController[IndexPage] mediaMusic set.' + e.value);
    
    },
    
    ssyave(){
        let keyItem = {code:10, pressedTime:123456789, deviceId:0};
        let event = {action:2, key:keyItem, keys:[keyItem]};
        AVSessionManager.sendSystemAVKeyEvent(event, (err) => {
            if (err) {
                console.info('AVSessionFrameworkTest: Send System KeyEvent : ERROR : '+err.message);
            } else {
                this.log('sendSystemAVKeyEvent success');
                console.info('AVSessionFrameworkTest: Send System KeyEvent');
            }
        });
    },
    
    // 释放资源
    offsessioncreate(){
        AVSessionManager.off('sessionCreate');
    },
    
    offtopsessionchange(){
        AVSessionManager.off('topSessionChange');
    },
    
    offmetadataChange(){
        this.avSessionCtrl.off('metadataChange');
    },
    
    offplaybackstatechange(){
        this.avSessionCtrl.off('playbackStateChange');
    },
    
    offactivestatechange(){
        this.avSessionCtrl.off('activeStateChange');
    },
    
    offvalidcommandchange(){
        this.avSessionCtrl.off('validCommandChange');
    },
    
    destroyde(){
        this.avSessionCtrl.destroy();
    }
}
```



