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

import avSession from '@ohos.multimedia.avsession';
import featureAbility from '@ohos.ability.featureAbility';
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'


const TAG = "[AVSessionJSTest]";

describe("AVSessionJsTest", function () {
  let session = null;
  let controller = null;
  let receivedCallback = false;
  let receivedCallback2 = false;
  let receivedString = null;
  let receivedString2 = null;
  let receivedParam = null;
  let receivedParam2 = null;
  const INVALID_STRING = "invalid string";
  const UPDATE_LYRICS_EVENT = "dynamic_lyrics";
  const UPDATE_LYRICS_WANT_PARAMS = {
    lyric: "This is my lyrics"
  };
  const COMMON_COMMAND_STRING = "common_command";
  const COMMON_COMMAND_PARAMS = {
    command: "This is my command"
  };
  const CUSTOM_EXTRAS = {
    extras: "This is custom media packet"
  };

  beforeAll(async function () {
    session = await avSession.createAVSession(featureAbility.getContext(), "AVSessionDemo", 'audio').catch((err) => {
      console.error(TAG + "Create AVSession in avsessionjstest error " + JSON.stringify(err));
      expect().assertFail();
    });
    session.activate();
    controller = await avSession.createController(session.sessionId).catch((err) => {
      console.error(TAG + "Create controller in avsessionjstest error " + JSON.stringify(err));
      expect().assertFail();
    })
    console.info(TAG + "Create session finished, beforeAll called");
  })

  afterAll(function () {
    session.destroy();
    console.info(TAG + 'afterAll called')
  })

  beforeEach(function () {
    console.info(TAG + 'beforeEach called')
  })

  afterEach(function () {
    console.info(TAG + 'afterEach called')
  })

  function sleep(time) {
    return new Promise((resolve) => setTimeout(resolve, time));
  }

  function commonCommandCallback1(command, args) {
    console.log(TAG + "Callback1 received event: " + JSON.stringify(command));
    console.log(TAG + "Callback1 received args: " + JSON.stringify(args));
    if (command != COMMON_COMMAND_STRING) {
      console.error(TAG + "Callback1 common command unmatch");
      expect().assertFail();
    }
    receivedCallback = true;
    receivedString = command;
    receivedParam = args;
  }

  function commonCommandCallback2(command, args) {
    console.log(TAG + "Callback2 received event: " + JSON.stringify(command));
    console.log(TAG + "Callback2 received args: " + JSON.stringify(args));
    if (command != COMMON_COMMAND_STRING) {
      console.error(TAG + "Callback2 common command unmatch");
      expect().assertFail();
    }
    receivedCallback2 = true;
    receivedString2 = command;
    receivedParam2 = args;
  }

  /*
   * @tc.name:dispatchSessionEventTest001
   * @tc.desc:Set session event - callback
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("dispatchSessionEventTest001", 0, async function (done) {
    session.dispatchSessionEvent(UPDATE_LYRICS_EVENT, UPDATE_LYRICS_WANT_PARAMS, (err) => {
      if (err) {
        console.error(TAG + "dispatchSessionEventTest001 error " + JSON.stringify(err));
        expect().assertFail();
        done();
      }
      console.info(TAG + "dispatchSessionEventTest001 finished");
      expect(true).assertTrue();
      done();
    });
  })

  /*
   * @tc.name:dispatchSessionEventTest002
   * @tc.desc:Set session event - promise
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("dispatchSessionEventTest002", 0, async function (done) {
    await session.dispatchSessionEvent(UPDATE_LYRICS_EVENT, UPDATE_LYRICS_WANT_PARAMS).catch((err) => {
      console.error(TAG + "dispatchSessionEventTest002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    console.info(TAG + "dispatchSessionEventTest002 finished");
    done();
  })

  /*
   * @tc.name:dispatchSessionEventTest003
   * @tc.desc:Set session event - one param
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("dispatchSessionEventTest003", 0, async function (done) {
    let errCode = 0;
    await session.dispatchSessionEvent(UPDATE_LYRICS_EVENT).catch((err) => {
      console.info(TAG + "dispatchSessionEventTest003 caught error" + err.code);
      errCode = err.code;
    });
    sleep(200).then(()=>{
      expect(errCode == 401).assertTrue();
      done();
    })
  })

  /*
   * @tc.name:dispatchSessionEventTest004
   * @tc.desc:Set session event - invalid params
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("dispatchSessionEventTest004", 0, async function (done) {
    let errCode = 0;
    await session.dispatchSessionEvent(UPDATE_LYRICS_WANT_PARAMS, UPDATE_LYRICS_WANT_PARAMS).catch((err) => {
    console.info(TAG + "dispatchSessionEventTest003 caught error" + err.code);
      errCode = err.code;
    });
    sleep(200).then(()=>{
      expect(errCode == 401).assertTrue();
      done();
    })
  })

  /*
   * @tc.name:SetExtras001
   * @tc.desc:Set extras - callback
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("SetExtras001", 0, async function (done) {
    session.setExtras(CUSTOM_EXTRAS, (err) => {
      if (err) {
        console.error(TAG + "SetExtras001 error " + JSON.stringify(err));
        expect().assertFail();
        done();
      }
      console.info(TAG + "SetExtras001 finished");
      expect(true).assertTrue();
      done();
    });
  })

  /*
   * @tc.name:SetExtras002
   * @tc.desc:Set extras - promise
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("SetExtras002", 0, async function (done) {
    await session.setExtras(CUSTOM_EXTRAS).catch((err) => {
      console.error(TAG + "SetExtras002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    console.info(TAG + "SetExtras002 finished");
    done();
  })

  /*
   * @tc.name:SetExtras003
   * @tc.desc:Set extras - zero param
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("SetExtras003", 0, async function (done) {
    let errCode = 0;
    await session.setExtras().catch((err) => {
      console.info(TAG + "SetExtras003 caught error" + err.code);
      errCode = err.code;
    });
    sleep(200).then(()=>{
      expect(errCode == 401).assertTrue();
      console.info(TAG + "SetExtras003 finished");
      done();
    })
  })

  /*
   * @tc.name:SetExtras004
   * @tc.desc:Set extras - invalid params
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("SetExtras004", 0, async function (done) {
    let errCode = 0;
    await session.setExtras(INVALID_STRING).catch((err) => {
    console.info(TAG + "SetExtras004 caught error" + err.code);
      errCode = err.code;
    });
    sleep(200).then(()=>{
      expect(errCode == 401).assertTrue();
      console.info(TAG + "SetExtras004 finished");
      done();
    })
  })

  /*
   * @tc.name:onCommonCommandTest001
   * @tc.desc:One on function - common command
   * @tc.type: FUNC
   * @tc.require: I6ETY6
   */
  it("onCommonCommandTest001", 0, async function (done) {
    session.on('commonCommand', commonCommandCallback1);
    await controller.sendCommonCommand(COMMON_COMMAND_STRING, COMMON_COMMAND_PARAMS).catch((err) => {
      console.error(TAG + "onCommonCommandTest001 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    sleep(200).then(() => {
      if (receivedCallback) {
        console.log(TAG + "Received common command");
        expect(receivedString == COMMON_COMMAND_STRING).assertTrue();
        expect(receivedParam.command == COMMON_COMMAND_PARAMS.command).assertTrue();
      } else {
        console.error(TAG + "Common command not received");
        expect().assertFail();
      }
      receivedCallback = false;
      receivedString = null;
      receivedParam = null;
      done();
    })
  })

  /*
   * @tc.name:onCommonCommandTest002
   * @tc.desc:Two on functions - common command
   * @tc.type: FUNC
   * @tc.require: I6ETY6
   */
  it("onCommonCommandTest002", 0, async function (done) {
    session.on('commonCommand', commonCommandCallback1);
    session.on('commonCommand', commonCommandCallback2);
    await controller.sendCommonCommand(COMMON_COMMAND_STRING, COMMON_COMMAND_PARAMS).catch((err) => {
      console.error(TAG + "Send common command error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (receivedCallback && receivedCallback2) {
      console.log(TAG + "Received common command");
      expect(receivedString == COMMON_COMMAND_STRING).assertTrue();
      expect(receivedParam.command == COMMON_COMMAND_PARAMS.command).assertTrue();
      expect(receivedString2 == COMMON_COMMAND_STRING).assertTrue();
      expect(receivedParam2.command == COMMON_COMMAND_PARAMS.command).assertTrue();
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Common command not received");
      expect().assertFail();
    }
    receivedCallback = false;
    receivedString = null;
    receivedParam = null;
    receivedCallback2 = false;
    receivedString2 = null;
    receivedParam2 = null;
    done();
  })

  /*
   * @tc.name:onCommonCommandTest003
   * @tc.desc:One on functions - one param
   * @tc.type: FUNC
   * @tc.require: I6ETY6
   */
  it("onCommonCommandTest003", 0, async function (done) {
    try {
      session.on('commonCommand');
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:onCommonCommandTest004
   * @tc.desc:One on functions - three params
   * @tc.type: FUNC
   * @tc.require: I6ETY6
   */
  it("onCommonCommandTest004", 0, async function (done) {
    try {
      session.on('sessionEventChange', commonCommandCallback1, commonCommandCallback2);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:onCommonCommandTest005
   * @tc.desc:One on functions - invalid type
   * @tc.type: FUNC
   * @tc.require: I6ETY6
   */
  it("onCommonCommandTest005", 0, async function (done) {
    try {
      session.on('commonCommand', INVALID_STRING);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:offCommonCommandTest001
   * @tc.desc:Two on functions and one off function
   * @tc.type: FUNC
   * @tc.require: I6ETY6
   */
  it("offCommonCommandTest001", 0, async function (done) {
    session.on('commonCommand', commonCommandCallback1);
    session.on('commonCommand', commonCommandCallback2);
    session.off('commonCommand', commonCommandCallback2);
    await controller.sendCommonCommand(COMMON_COMMAND_STRING, COMMON_COMMAND_PARAMS).catch((err) => {
      console.error(TAG + "Send common command error" + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (receivedCallback && !receivedCallback2) {
      console.log(TAG + "offCommonCommandTest001 finished");
      expect(receivedString == COMMON_COMMAND_STRING).assertTrue();
      expect(receivedParam.command == COMMON_COMMAND_PARAMS.command).assertTrue();
      expect(true).assertTrue();
    } else {
      console.error(TAG + "offCommonCommandTest001 failed");
      expect().assertFail();
    }
    receivedCallback = false;
    receivedString = null;
    receivedParam = null;
    done();
  })

  /*
   * @tc.name:offCommonCommandTest002
   * @tc.desc:Two on functions and two off function
   * @tc.type: FUNC
   * @tc.require: I6ETY6
   */
  it("offCommonCommandTest002", 0, async function (done) {
    session.on('commonCommand', commonCommandCallback1);
    session.on('commonCommand', commonCommandCallback2);
    session.off('commonCommand', commonCommandCallback1);
    session.off('commonCommand', commonCommandCallback2);
    await controller.sendCommonCommand(COMMON_COMMAND_STRING, COMMON_COMMAND_PARAMS).catch((err) => {
      console.error(TAG + "Send common command error" + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (!receivedCallback && !receivedCallback2) {
      console.log(TAG + "offCommonCommandTest002 finished");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "offCommonCommandTest002 failed");
      expect().assertFail();
    }
    receivedCallback = false;
    done();
  })

  /*
   * @tc.name:offCommonCommandTest003
   * @tc.desc:Two on functions and off all function
   * @tc.type: FUNC
   * @tc.require: I6ETY6
   */
  it("offCommonCommandTest003", 0, async function (done) {
    session.on('commonCommand', commonCommandCallback1);
    session.on('commonCommand', commonCommandCallback2);
    session.off('commonCommand');

    await controller.sendCommonCommand(COMMON_COMMAND_STRING, COMMON_COMMAND_PARAMS).catch((err) => {
      console.error(TAG + "Send common command error" + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (!receivedCallback && !receivedCallback2) {
      console.log(TAG + "offSessionEventChangeTest003 finished");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "offSessionEventChangeTest003 failed");
      expect().assertFail();
    }
    receivedCallback = false;
    done();
  })

  /*
   * @tc.name:offCommonCommandTest004
   * @tc.desc:Two on functions and off function - three params
   * @tc.type: FUNC
   * @tc.require: I6ETY6
   */
  it("offSessionEventChangeTest004", 0, async function (done) {
    try {
      session.on('commonCommand', commonCommandCallback1);
      session.on('commonCommand', commonCommandCallback2);
      session.off('commonCommand', commonCommandCallback1, commonCommandCallback2);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:offCommonCommandTest005
   * @tc.desc:One on functions and off all function - invalid type
   * @tc.type: FUNC
   * @tc.require: I6ETY6
   */
  it("offCommonCommandTest005", 0, async function (done) {
    try {
      session.on('commonCommand', commonCommandCallback1);
      session.off('commonCommand', INVALID_STRING);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name: GetOutputDeviceSync001
   * @tc.desc: Get output device - sync
   * @tc.type: FUNC
   * @tc.require: I6ETY6
   */
  it("GetOutputDeviceSync001", 0, async function (done) {
    try {
      let outputDeviceInfo = session.getOutputDeviceSync();
      console.log(`Get output device info: ${outputDeviceInfo}`);
      expect(outputDeviceInfo.devices[0].deviceId).assertEqual("0");
    } catch (err) {
      expect().assertFail();
    }
    done();
  })
})
