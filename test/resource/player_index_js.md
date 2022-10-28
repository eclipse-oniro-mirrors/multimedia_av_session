# 播放器demo

1. 导入模块
```js
import audio from '@ohos.multimedia.audio';
import PlayerModel from '../../common/PlayerModel.js';
import AVSessionManager from '@ohos.multimedia.avsession';
import WantAgent from '@ohos.wantAgent';
import display from '@ohos.display';
import multimedia_image from '@ohos.multimedia.image';
import featureAbility from '@ohos.ability.featureAbility';
import process from '@ohos.process';
```

2.demo代码

```js

export default {
    // 定义变量，请开发者根据实际情况使用
    data: {
        container:'',
        div_image:'',
        titleCss:'',
        lyricCss:'',
        div_but:'',
        btn:'',
        image:'',
        btn_image:'',
        bell_div:'',
        slider_value:'',
        slider:'',
        btn1:'',
        btn2:'',
        deviceIdNew:null,
        btnCss:'',
        logListCss:'',
        listLog:'',
        btnS:'',
        isShowRk:false,
        isShowWgr:true,
        btnC:'',
        timeEnd:0,
        musicValue:0,
        intervalID:0,
        deviceArr:[],
        time: (new Date()).getTime(),
        assetIdArr:[],
        title: 'dynamic.wav',
        audioUrl: 'common/images/pause.png',                           
        loopModeUrl: 'common/images/ic_public_list_cycle1.png',        
        artist:'品冠',
        lyric:'dynamic.wav-品冠的歌词',
        duration:1,
        index: 0,
        audioPlayer: null,
        isSwitching: false,
        playerModel: new PlayerModel(),
        audioManager: null,
        volume: 0,
        mediaFavorite: false,
        favoriteBtn:'btn1',
        currentSession: null,
        currentProgress: 0,
        logList: ['log日志显示'],
        loopMode: 1,
        speedMode: 'x1',
        speedArr: ['x1','x2','x0.5'],
        speedArrSet: [1.0,2.0,0.5],
        speedIndex: 0,
        mediaImage:'common/images/bg-tv.jpg',                         
        durationMin:'0:00',
        loopModeArr: ['common/images/ic_public_list_cycle1.png','common/images/ic_public_single_cycle2.png',
        'common/images/ic_public_order_play3.png','common/images/ic_public_random4.png'],   
        pixelMap:undefined,
        context:undefined,
        deviceId:[],
        deviceName:[],
    },
    
    // 日志
    log(log) {
        this.logList.unshift(this.logList.length + ': ' + JSON.stringify(log));
    },
    
    async onInit() {
        this.log("onInit start");
        console.info(' ttt AVSessionPlayer[IndexPage] onInit start');
        // 横竖屏幕适配
        display.getDefaultDisplay((err, data) => {
            if ( data.width > data.height ) {
                console.info(' ttt AVSessionPlayer[IndexPage] getDefaultDisplay direction is horizontal.[width]' +
                data.width + '[height]' + data.height);
                this.container = 'W_container';
                this.div_image = 'W_div-image';
                this.image = 'W_image';
                this.titleCss = 'W_title';
                this.lyricCss = 'W_lyric';
                this.div_but = 'W_div-but';
                this.btn = 'W_btn';
                this.btn_image = 'W_btn-image';
                this.bell_div = 'W_bell-div';
                this.slider_value = 'W_slider-value';
                this.slider = 'W_slider';
                this.btnCss = 'W_';
                this.btnC = 'W_btnC';
                this.favoriteBtn = 'W_btn1';
                this.logListCss = 'W_logList';
                this.listLog = 'W_listLog';
                this.btnS = 'W_btnS';
                this.isShowWgr = true;
                this.isShowRk= false;
            } else {
                console.info(' ttt AVSessionPlayer[IndexPage] getDefaultDisplay direction is vertical.[width]' +
                data.width + '[height]' + data.height);
                this.container = 'container';
                this.div_image = 'div-image';
                this.image = 'image';
                this.titleCss = 'title';
                this.lyricCss = 'lyric';
                this.div_but = 'div-but';
                this.btn = 'btn';
                this.btn_image = 'btn-image';
                this.bell_div = 'bell-div';
                this.slider_value = 'slider-value';
                this.slider = 'slider';
                this.btnCss = '';
                this.favoriteBtn = 'btn1';
                this.logListCss = 'logList';
                this.listLog = 'listLog';
                this.btnS = 'btn';
                this.btnC = 'btn';
                this.isShowRk= true;
                this.isShowWgr = false;

            }
        });
    
        this.context = await featureAbility.getContext();
        this.audioUrl = 'common/images/pause.png';                           // 请开发者根据实际情况使用
        this.loopModeUrl = 'common/images/ic_public_list_cycle1.png';        // 请开发者根据实际情况使用
    
        this.playerModel.setOnStatusChangedListener((isPlaying) => {
            this.log("setOnStatusChangedListener success ");
            console.info(' ttt AVSessionPlayer[IndexPage] on player status changed, isPlaying=' + isPlaying + ', refresh ui');
            if (isPlaying) {
                this.audioUrl = 'common/images/play.png';
                this.currentSession.setAVPlaybackState({state:AVSessionManager.PlaybackState.PLAYBACK_STATE_PLAY,
                    position:{elapsedTime:this.musicValue, 
                        updateTime:this.onTime()}}).then(() =>{
                }).catch ((e) => {
                    this.log("error " + e.message);
                });
                this.playMusic();
            } else {
                clearInterval(this.intervalID);
                this.audioUrl = 'common/images/pause.png';
                this.playerModel.pause();
                clearInterval(this.intervalID);
                this.playerModel.seek(this.musicValue);
                this.currentSession.setAVPlaybackState({state:AVSessionManager.PlaybackState.PLAYBACK_STATE_PAUSE,
                    position:{elapsedTime:this.musicValue,
                        updateTime:this.onTime()}}).then(() => {
                }).catch ((e) => {
                    this.log("error " + e.message);
                });
            }
        });
        this.playerModel.getPlaylist(() => {
            this.log('getPlaylist ok');
            console.info(' ttt AVSessionPlayer[IndexPage] getPlaylist ok');
        });
        this.setPageData();
        this.audioManager = await audio.getAudioManager();
    
        this.log('getAudioManager ok');
        AVSessionManager.on('sessionServiceDie', (descriptor) => {
            this.log('sessionServiceDie success');
        });
    
        // 创建avSession会话并激活
        AVSessionManager.createAVSession(this.context,'AVSessionPlayer', 'audio').then(async(session) => {
            this.log('createAVSession success');
            console.info("ttt AVSessionPlayer[IndexPage] createAVSession success");
            this.currentSession = session;
            await this.currentSession.activate(() => {
                this.log('activate success');
            });
            // 获取输出设备信息
            this.currentSession.getOutputDevice((err,outputDeviceInfo)=> {
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
    
            this.currentSession.setAudioStreamId([0,10,20]);
            let metadata = this.setMetaData();
            // 设置会话元数据
            this.currentSession.setAVMetadata(metadata,() => {
                this.log('onInit setAVMetadata success');
                console.info(' ttt AVSessionPlayer[IndexPage] onInit  setAVMetadata');
            });
            // 设置会话播放状态
            this.currentSession.setAVPlaybackState({
                speed:this.speedIndex,loopMode:AVSessionManager.LoopMode.LOOP_MODE_SEQUENCE,
                position:{elapsedTime:0,updateTime:this.onTime()}
            }, () => {
                this.log('onInit setAVPlaybackState success');
                console.info(' ttt AVSessionPlayer[IndexPage] setAVPlaybackState');
            });
    
            // 设置启动ability
            let wantAgentInfo = {
                wants: [
                    {
                        bundleName: this.context.getAbilityInfo().bundleName,
                        abilityName: this.context.getAbilityInfo().name
                    }
                ],
                operationType: WantAgent.OperationType.START_ABILITIES,
                requestCode: 0,
                wantAgentFlags: [WantAgent.WantAgentFlags.UPDATE_PRESENT_FLAG]
            };
            WantAgent.getWantAgent(wantAgentInfo,(err,agent) => {
                WantAgent.getBundleName(agent).then((name) => {
                    console.info('[ttt] AVSessionPlayer[IndexPage] getBundleName bundle name:' + name);
                    this.log('getWantAgent success');
                }, e => {
                    console.error('[ttt] AVSessionPlayer[IndexPage] getBundleName error' +  ' is ' + e.message);
                });
                this.currentSession.setLaunchAbility(agent,() => {
                    this.log('setLaunchAbility success ');
                });
            });
    
            // 注册播放命令监听
            this.currentSession.on('play', () => {
                if (this.isSwitching) {
                    console.info(' ttt AVSessionPlayer[IndexPage] onPlayClick ignored, isSwitching');
                    return;
                }
                this.log('on Play success callBack');
                console.info(' ttt AVSessionPlayer[IndexPage] on Play success, isPlaying=' + this.playerModel.isPlaying + 'callBack');
                this.playerModel.preLoad(this.index, () => {
                    this.playerModel.play(-1, true);
                });
                this.currentSession.setAVPlaybackState({state:AVSessionManager.PlaybackState.PLAYBACK_STATE_PLAY,
                    position:{elapsedTime:this.musicValue,
                        updateTime:this.onTime()}}).then(() =>{
                }).catch ((e) => {
                    this.log("error " + e.message);
                });
                this.playMusic();
            });
            
            // 注册暂停命令监听
            this.currentSession.on('pause', () => {
                if (this.isSwitching) {
                    console.info(' ttt AVSessionPlayer[IndexPage] onPlayClick ignored, isSwitching');
                    return;
                }
                clearInterval(this.intervalID);
                this.log('on Pause success callBack');
                console.info(' ttt AVSessionPlayer[IndexPage] onPause success, isPlaying ' + this.playerModel.isPlaying + 'callBack');
                this.playerModel.pause();
                this.playerModel.seek(this.musicValue);
                this.currentSession.setAVPlaybackState({state:AVSessionManager.PlaybackState.PLAYBACK_STATE_PAUSE,
                    position:{elapsedTime:this.musicValue, updateTime:this.onTime()}});
            });
            
            // 注册停止命令监听
            this.currentSession.on('stop', () => {
                this.log('on Stop success callBack');
                console.info(' ttt AVSessionPlayer[IndexPage] stop success callBack');
                this.playerModel.stop();
                this.currentSession.setAVPlaybackState({state:AVSessionManager.PlaybackState.PLAYBACK_STATE_STOP,
                    position:{elapsedTime:this.musicValue,updateTime:this.onTime()}});
            });
            
            // 注册上一首命令监听
            this.currentSession.on('playPrevious', () => {
                if (this.isSwitching) {
                    console.info(' ttt AVSessionPlayer[IndexPage] onPreviousClick ignored, isSwitching');
                    return;
                }
                clearInterval(this.intervalID);
                this.log('on PlayPrevious success callBack');
                console.info(' ttt AVSessionPlayer[IndexPage] onPrevious success callBack');
                this.index--;
                this.musicValue = 0;
                this.playerModel.seek(0);
                if (this.index < 0 && this.playerModel.playlist.audioFiles.length >= 1) {
                    this.index = this.playerModel.playlist.audioFiles.length - 1;
                }
                this.currentProgress = 0;
                this.isSwitching = true;
                this.playerModel.preLoad(this.index, () => {
                    this.playerModel.play(0, true);
                    this.isSwitching = false;
                });
                this.setFavorite();
                this.setPageData();
    
                this.currentSession.setAVMetadata(this.setMetaData());
                this.currentSession.setAVPlaybackState({state:AVSessionManager.PlaybackState.PLAYBACK_STATE_PLAY,
                    position:{elapsedTime:this.musicValue,updateTime:this.onTime()},
                    bufferedTime:2000,isFavorite:this.mediaFavorite})
                this.playMusic();
                console.info(' ttt AVSessionPlayer[IndexPage] onPreviousClick callBack');
    
            });
            
            // 注册下一首命令监听
            this.currentSession.on('playNext', () => {
                if (this.isSwitching) {
                    console.info(' ttt AVSessionPlayer[IndexPage] playNext event is running.');
                    return;
                }
                clearInterval(this.intervalID);
                this.log('onPlayNext callBack success ');
                console.info(' ttt AVSessionPlayer[IndexPage] set playNext success callback.');
                this.index++;
                this.musicValue = 0;
                if (this.index >= this.playerModel.playlist.audioFiles.length) {
                    this.index = 0;
                }
                this.currentProgress = 0;
                this.playerModel.seek(0);
                this.isSwitching = true;
                this.playerModel.preLoad(this.index, () => {
                    this.playerModel.play(0, true);
                    this.isSwitching = false;
                });
                this.setFavorite();
                this.setPageData();
                this.currentSession.setAVPlaybackState({state:AVSessionManager.PlaybackState.PLAYBACK_STATE_PLAY,
                    position:{elapsedTime:0,updateTime:this.onTime()},
                    bufferedTime:2000,isFavorite:this.mediaFavorite});
                this.currentSession.setAVMetadata(this.setMetaData());
    
                console.info(' ttt AVSessionPlayer[IndexPage] playNext - setAVMetadata author:' + metadata.author +
                ', publishDate:' + metadata.publishDate);
                this.playMusic();
                console.info(' ttt AVSessionPlayer[IndexPage] set playNext callback.' + this.title + ':' + this.artist);
            });
            
            // 注册播放快进命令监听
            this.currentSession.on('fastForward', () => {
                this.log('on FastForward success callBack');
                console.info(' ttt AVSessionPlayer[IndexPage] fastForward success callBack');
            });
            
            // 注册播放快退命令监听
            this.currentSession.on('rewind', () => {
                this.log('on Rewind success callBack');
                console.info(' ttt AVSessionPlayer[IndexPage] rewind success callBack');
            });
            
            // 注册跳播命令监听
            this.currentSession.on('seek', (time) => {
                this.log('on Seek success callBack');
                console.info(' ttt AVSessionPlayer[IndexPage] seek success callBack is :' + time);
                this.musicValue = time;
                this.playerModel.seek(this.musicValue);
                this.currentSession.setAVPlaybackState({ position:{elapsedTime:this.musicValue,updateTime:this.onTime()},
                    bufferedTime:2000});
    
            });
            
            // 注册设置播放速度命令监听
            this.currentSession.on('setSpeed', (speed) => {
                this.log('on SetSpeed success callBack');
                console.info(' ttt AVSessionPlayer[IndexPage] set Speed success callBack is :' + speed);
                this.speedIndex = speed;
                this.speedMode = this.speedArr[this.speedIndex];
                this.currentSession.setAVPlaybackState({
                    speed:this.speedIndex
                }, () => {
                    console.info(' ttt AVSessionPlayer[IndexPage] onSetSpeed');
                });
            });
            
            // 注册设置播放循环模式命令监听
            this.currentSession.on('setLoopMode', (mode) => {
                this.log('on SetLoopMode success callBack');
                console.info(' ttt AVSessionPlayer[IndexPage] setLoopMode success callBack is:' + mode);
                if (mode == 0) {
                    this.loopMode = 1;
                    this.loopModeUrl = 'common/images/ic_public_list_cycle1.png';
                    this.currentSession.setAVPlaybackState({loopMode:AVSessionManager.LoopMode.LOOP_MODE_SEQUENCE});
                } else if (mode == 1) {
                    this.loopMode = 2;
                    this.loopModeUrl = 'common/images/ic_public_single_cycle2.png';
                    this.currentSession.setAVPlaybackState({loopMode:AVSessionManager.LoopMode.LOOP_MODE_SINGLE});
                } else if (mode == 2) {
                    this.loopMode = 3;
                    this.loopModeUrl = 'common/images/ic_public_order_play3.png';
                    this.currentSession.setAVPlaybackState({loopMode:AVSessionManager.LoopMode.LOOP_MODE_LIST});
                } else if (mode == 3) {
                    this.loopMode = 4;
                    this.loopModeUrl = 'common/images/ic_public_random4.png';
                    this.currentSession.setAVPlaybackState({loopMode:AVSessionManager.LoopMode.LOOP_MODE_SHUFFLE});
                }
            });
            
            // 注册设置歌曲收藏命令监听
            this.currentSession.on('toggleFavorite', (assetId) => {
                this.log('on ToggleFavorite success callBack');
                console.info(' ttt AVSessionPlayer[IndexPage] toggleFavorite success callBack, assetId: ' + assetId);
                this.mediaFavorite = this.mediaFavorite == false? true : false;
                if (this.mediaFavorite) {
                    this.favoriteBtn = this.btnCss + 'btn2';
                    this.assetIdArr.push(this.playerModel.playlist.audioFiles[this.index].assetId);
                } else {
                    this.favoriteBtn = this.btnCss + 'btn1';
                    this.deleteAssetId();
                }
                this.currentSession.setAVPlaybackState({isFavorite:this.mediaFavorite});
            });
            
            // 注册媒体按键命令监听
            this.currentSession.on('handleKeyEvent', (event) => {
                this.log('on HandleKeyEvent success callBack ');
                console.info(' ttt AVSessionPlayer[IndexPage] handleKeyEvent success callBack,event is: ' + JSON.stringify(event));
            });
            
            // 注册播放设备变化命令监听
            this.currentSession.on('outputDeviceChanged', (device) => {
                this.log('on OutputDeviceChanged success callBack ');
                console.info(' ttt AVSessionPlayer[IndexPage] outputDeviceChanged success callBack, is: ' + device.deviceName);
            });
        }, e => {
            console.info(' ttt AVSessionPlayer[IndexPage] createAVSession log code is ' + e.code + 'message is' + e.message);
        }).then(()=>{
            let state = {
                state: AVSessionManager.PlaybackState.PLAYBACK_STATE_STOP,
                speed: 1.0,
                position: {elapsedTime:0, updateTime:this.onTime()},
                bufferedTime: 2000,
                loopMode: AVSessionManager.LoopMode.LOOP_MODE_SEQUENCE,
                isFavorite: false,
            };
            this.currentSession.setAVPlaybackState(state);
            console.info(' ttt AVSessionPlayer[IndexPage] setAVPlaybackState state complete.');
        }).then(()=>{
            console.info(' ttt AVSessionPlayer[IndexPage] this.currentSession is activate.');
            //            return this.currentSession.activate();
        }), e => {
            console.info(' ttt AVSessionPlayer[IndexPage] createAVSession code is ' + e.code + 'message is' + e.message);
        }
    },
    
    // 释放资源
    onDestroy() {
        this.log('onDestroy Start');
        console.info(' ttt AVSessionPlayer[IndexPage] this.currentSession is destroy.');
        this.currentSession.off('handleKeyEvent');
        this.currentSession.off('seek');
        this.currentSession.off('play');
        this.currentSession.off('pause');
        this.currentSession.off('stop');
        this.currentSession.off('playNext');
        this.currentSession.off('playPrevious');
        this.currentSession.off('fastForward');
        this.currentSession.off('rewind');
        this.currentSession.off('setSpeed');
        this.currentSession.off('setLoopMode');
        this.currentSession.off('toggleFavorite');
        this.currentSession.off('outputDeviceChanged');
        this.currentSession.deactivate().then(() => {
            this.currentSession.destroy();
        });
        this.log('onDestroy end');
    },
    
    // 设置循环模式
    onSetLoopMode() {
        this.log('onSetLoopMode Start');
        console.info(' ttt AVSessionPlayer[IndexPage] onSetLoopMode ' + this.loopMode + this.loopModeUrl);
        this.loopMode++;
        if (this.loopMode > 4) {
            this.loopMode = 1;
        }
        if (this.loopMode == 1) {
            this.loopModeUrl = 'common/images/ic_public_list_cycle1.png';
            this.currentSession.setAVPlaybackState({loopMode:AVSessionManager.LoopMode.LOOP_MODE_SEQUENCE});
        } else if (this.loopMode == 2) {
            this.loopModeUrl = 'common/images/ic_public_single_cycle2.png';
            this.currentSession.setAVPlaybackState({loopMode:AVSessionManager.LoopMode.LOOP_MODE_SINGLE});
        } else if (this.loopMode == 3) {
            this.loopModeUrl = 'common/images/ic_public_order_play3.png';
            this.currentSession.setAVPlaybackState({loopMode:AVSessionManager.LoopMode.LOOP_MODE_LIST});
        } else if (this.loopMode == 4) {
            this.loopModeUrl = 'common/images/ic_public_random4.png';
            this.currentSession.setAVPlaybackState({loopMode:AVSessionManager.LoopMode.LOOP_MODE_SHUFFLE});
        } else {
            this.loopModeUrl = 'common/images/ic_public_list_cycle1.png';
            this.currentSession.setAVPlaybackState({loopMode:AVSessionManager.LoopMode.LOOP_MODE_SEQUENCE});
        }
        console.info(' ttt AVSessionPlayer[IndexPage] onSetLoopMode 22 ' + this.loopMode + this.loopModeUrl);
    },
    
    // 设置播放速度
    onSetSpeed() {
        this.log('onSetLoopMode start');
        this.speedIndex++;
        if (this.speedIndex > 2) {
            this.speedIndex = 0
        }
        this.speedMode = this.speedArr[this.speedIndex];
        this.currentSession.setAVPlaybackState({
            speed:this.speedIndex
        }, () => {
            console.info(' ttt AVSessionPlayer[IndexPage] onSetSpeed');
        });
    },
    
    // 点击播放
    onPlayClick() {
        this.log('onPlayClick start');
        if (this.isSwitching) {
            console.info(' ttt AVSessionPlayer[IndexPage] onPlayClick ignored, isSwitching');
            return;
        }
        console.info(' ttt AVSessionPlayer[IndexPage] onPlayClick, isPlaying=' + this.playerModel.isPlaying);
        if (this.playerModel.isPlaying) {
            this.playerModel.pause();
            this.playerModel.seek(this.musicValue);
            clearInterval(this.intervalID);
            this.currentSession.setAVPlaybackState({state:AVSessionManager.PlaybackState.PLAYBACK_STATE_PAUSE,
                position:{elapsedTime:this.musicValue,updateTime:this.onTime()}, bufferedTime:2000});
        } else {
            this.playerModel.preLoad(this.index, () => {
                this.playerModel.play(-1, true);
                this.currentSession.setAVPlaybackState({state:AVSessionManager.PlaybackState.PLAYBACK_STATE_PLAY,
                    position:{elapsedTime:this.musicValue,updateTime:this.onTime()}});
                this.playMusic();
    
            });
        }
    },
    
    // 播放音乐
    playMusic() {
        let this_ = this;
        let startT = this.musicValue;
        clearInterval(this.intervalID);
        this.intervalID = setInterval(function() {
            this_.musicValue += (0.5 * this_.speedArrSet[this_.speedIndex] * 1000);
            //            this_.playerModel.seek(this_.musicValue);
            if (this_.musicValue > this_.playerModel.playlist.audioFiles[this_.index].duration) {
                this_.musicValue = 0;
                if (this_.loopMode == 1) {
                    this_.onNextClick();
                    clearInterval(this_.intervalID);
                } else if (this_.loopMode == 2) {
                    this_.musicValue = 0;
                    this_.playerModel.preLoad(this_.index, () => {
                        this_.playerModel.play(0, true)
                        console.info(' ttt AVSessionPlayer[IndexPage] onPlayClick isPlaying :' + this_.playerModel.isPlaying);
                        this_.isSwitching = false;
                    });
    
                } else if (this_.loopMode == 3) {
                    clearInterval(this_.intervalID);
                    this_.onNextClick();
                } else if (this_.loopMode == 4) {
                    clearInterval(this_.intervalID);
                    this_.index = Math.floor(Math.random()*4);
                    this_.onNextClick();
                }
            }
        }, 500);
        this_.currentSession.setAVPlaybackState({state:AVSessionManager.PlaybackState.PLAYBACK_STATE_PLAY,
            position:{elapsedTime:startT,updateTime:this_.onTime()}, bufferedTime:2000});
    },
    
    // 点击上一首
    onPreviousClick() {
        this.log('onPreviousClick start')
        if (this.isSwitching) {
            console.info(' ttt AVSessionPlayer[IndexPage] onPreviousClick ignored, isSwitching');
            return;
        }
        clearInterval(this.intervalID);
        console.info(' ttt AVSessionPlayer[IndexPage] onPreviousClick');
        this.index--;
        this.musicValue = 0;
        this.playerModel.seek(0);
        if (this.index < 0 && this.playerModel.playlist.audioFiles.length >= 1) {
            this.index = this.playerModel.playlist.audioFiles.length - 1;
        }
        this.currentProgress = 0;
        this.isSwitching = true;
        this.playerModel.preLoad(this.index, () => {
            this.playerModel.play(0, true);
            this.isSwitching = false;
        });
        this.setFavorite();
        this.setPageData();
    
        this.currentSession.setAVMetadata(this.setMetaData());
        this.currentSession.setAVPlaybackState({state:AVSessionManager.PlaybackState.PLAYBACK_STATE_PLAY,
            position:{elapsedTime:0,updateTime:this.onTime()}, bufferedTime:2000, isFavorite:this.mediaFavorite})
        console.info(' ttt AVSessionPlayer[IndexPage] onPreviousClick 11111');
        this.playMusic();
    },
    
    // 点击下一首
    onNextClick() {
        this.log('onNextClick start');
        if (this.isSwitching) {
            console.info(' ttt AVSessionPlayer[IndexPage] onNextClick ignored, isSwitching');
            return;
        }
        clearInterval(this.intervalID);
        console.info(' ttt AVSessionPlayer[IndexPage] onNextClick');
        this.index++;
        this.musicValue = 0;
        this.playerModel.seek(0);
        if (this.index >= this.playerModel.playlist.audioFiles.length) {
            this.index = 0;
        }
        this.currentProgress = 0;
        this.isSwitching = true;
        let self = this;
        this.playerModel.preLoad(this.index, () => {
            self.playerModel.play(0, true);
            self.isSwitching = false;
        });
        this.setFavorite();
        this.setPageData();
    
        console.info(" ttt this.setMetaData()0 :  ");
        let metadata = this.setMetaData()
        console.info(" ttt this.setMetaData()1 :  " + metadata.mediaImage);
        this.currentSession.setAVMetadata(metadata);
        console.info(" ttt this.setMetaData()2 :  " + metadata.mediaImage);
        this.currentSession.setAVPlaybackState({state:AVSessionManager.PlaybackState.PLAYBACK_STATE_PLAY,
            position:{elapsedTime:0,updateTime:this.onTime()}, bufferedTime:2000, isFavorite:this.mediaFavorite})
        console.info(" ttt this.setMetaData()3 :  " + metadata.mediaImage);
        this.playMusic();
    },
    
    media(e) {
        this.log('onMedia start')
        this.volume = e.value
        this.audioManager.setVolume(audio.AudioVolumeType.MEDIA, this.volume).then(() => {
            console.info(' ttt Promise returned to indicate a successful volume setting.');
        });
    },
    
    // 设置收藏
    async setFavorite() {
        console.info(' ttt AVSessionPlayer[IndexPage] setFavorite1' + this.mediaFavorite);
        let flg = false;
        for(let i = 0; i < this.assetIdArr.length; i++) {
            if (this.assetIdArr[i] == this.playerModel.playlist.audioFiles[this.index].assetId) {
                console.info(' ttt AVSessionPlayer[IndexPage] setFavorite1 id:' + this.assetIdArr[i] + " assetId:" +
                this.playerModel.playlist.audioFiles[this.index].assetId);
                flg = true;
                break;
            }
        }
        this.mediaFavorite = flg;
        if (this.mediaFavorite) {
            this.favoriteBtn = this.btnCss + 'btn2';
        } else {
            this.favoriteBtn = this.btnCss + 'btn1';
        }
        console.info(' ttt AVSessionPlayer[IndexPage] setFavorite2' + this.mediaFavorite);
    },
    
    showPanel() {
        this.$element('showPanel').show();
    },
    
    closePanel() {
        this.$element('showPanel').close();
    },
    
    async toggleFavorite() {
        this.log('toggleFavorite start');
        console.info(' ttt AVSessionPlayer[IndexPage] toggleFavorite');
        this.mediaFavorite = this.mediaFavorite == false? true : false;
        if (this.mediaFavorite) {
            this.favoriteBtn = this.btnCss + 'btn2';
            this.assetIdArr.push(this.playerModel.playlist.audioFiles[this.index].assetId);
        } else {
            this.favoriteBtn = this.btnCss + 'btn1';
            this.deleteAssetId();
        }
        this.currentSession.setAVPlaybackState({isFavorite:this.mediaFavorite});
        console.info(' ttt AVSessionPlayer[IndexPage] toggleFavorite' + this.assetIdArr.toString());
    },
    deleteAssetId() {
        for(let i = 0; i < this.assetIdArr.length; i++) {
            if (this.assetIdArr[i] == this.playerModel.playlist.audioFiles[this.index].assetId) {
                this.assetIdArr.splice(i,1);
            }
        }
    },
    setPageData() {
        this.title = this.playerModel.playlist.audioFiles[this.index].title;
        this.artist = this.playerModel.playlist.audioFiles[this.index].artist;
        this.lyric = this.playerModel.playlist.audioFiles[this.index].lyric;
        this.duration = this.playerModel.playlist.audioFiles[this.index].duration;
        this.mediaImage  = this.playerModel.playlist.audioFiles[this.index].mediaImage;
        console.info('ttt AVSessionPlayer[IndexPage] setPageData - mediaImage' + this.mediaImage);
        let muv = this.duration/1000
        let minutes = Math.floor(muv / 60);
        let seconds = muv % 60;
        if (seconds.toString().length < 2) {
            seconds = '0' + seconds.toString();
        }
        this.durationMin = minutes.toString() + ':' + seconds.toString();
    },
    mediaMusic(e) {
        console.info('ttt AVSessionPlayer[IndexPage] mediaMusic');
        this.log('mediaMusic start');
        let startT = this.musicValue;
        this.musicValue = e.value;
        this.playerModel.seek(this.musicValue);
        if (this.playerModel.isPlaying) {
            this.currentSession.setAVPlaybackState({state:AVSessionManager.PlaybackState.PLAYBACK_STATE_PLAY,
                position:{elapsedTime:startT,updateTime:this.onTime()}, bufferedTime:2000});
        } else {
            this.currentSession.setAVPlaybackState({state:AVSessionManager.PlaybackState.PLAYBACK_STATE_PAUSE,
                position:{elapsedTime:startT,updateTime:this.onTime()}, bufferedTime:2000});
        }
    },
    setMetaData() {
        return {
            assetId:this.playerModel.playlist.audioFiles[this.index].assetId,
            title:this.playerModel.playlist.audioFiles[this.index].title,
            artist:this.playerModel.playlist.audioFiles[this.index].artist,
            lyric:this.playerModel.playlist.audioFiles[this.index].lyric,
            duration:this.playerModel.playlist.audioFiles[this.index].duration,
            mediaImage:this.playerModel.playlist.audioFiles[this.index].mediaImage,
            author: this.playerModel.playlist.audioFiles[this.index].author,
            album: this.playerModel.playlist.audioFiles[this.index].album,
            writer: this.playerModel.playlist.audioFiles[this.index].writer,
            composer: this.playerModel.playlist.audioFiles[this.index].composer,
            publishDate: this.playerModel.playlist.audioFiles[this.index].publishDate,
            subtitle: this.playerModel.playlist.audioFiles[this.index].subtitle,
            description: this.playerModel.playlist.audioFiles[this.index].description,
            previousAssetId: this.playerModel.playlist.audioFiles[this.index].previousAssetId,
            nextAssetId: this.playerModel.playlist.audioFiles[this.index].nextAssetId
        }
    },
    onTime() {
        return (new Date()).getTime();
    },
    sleep(ms) {
        return new Promise(resolve => {
            setTimeout(resolve,ms)
        })
    },
    getDeviceList() {
        this.log('getDeviceList method');
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
                    sessionId:this.currentSession.sessionId,
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
    avdestroy() {
        this.currentSession.destroy();
    },
    
    deactive() {
        this.currentSession.deactivate();
    },
    
    active() {
        this.currentSession.activate();
    },
    
    offplay() {
        this.currentSession.off('play');
    },
    
    offpause() {
        this.currentSession.off('pause');
    },
    
    offplaynext() {
        this.currentSession.off('playNext');
    },
    
    offplayprevious() {
        this.currentSession.off('playPrevious');
    },
    
    offseek() {
        this.currentSession.off('seek');
    },
    
    offsetspeed() {
        this.currentSession.off('setSpeed');
    },
    
    offsetloopmode() {
        this.currentSession.off('setLoopMode');
    },
    
    offtogglefavorite() {
        this.currentSession.off('toggleFavorite');
    },
    
    offhandlekeyhevent() {
        this.currentSession.off('handleKeyEvent');
    },
    
    offsessionservicedie() {
        AVSessionManager.off('sessionServiceDie');
    },
}

```
