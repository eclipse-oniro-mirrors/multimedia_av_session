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
  const INVALID_STRING = "invalid string";
  const UPDATE_LYRICS_EVENT = "dynamic_lyrics";
  const UPDATE_LYRICS_WANT_PARAMS = {
    lyric: "This is my lyrics"
  };
  const COMMON_COMMAND_STRING = "common_command";
  const COMMON_COMMAND_PARAMS = {
    command: "This is my command"
  };

  beforeAll(async function () {
    session = await avSession.createAVSession(featureAbility.getContext(), "AVSessionDemo", 'audio').catch((err) => {
      console.error(TAG + "Create AVSession error " + JSON.stringify(err));
      expect().assertFail();
    });
    controller = await avSession.createController(session.sessionId).catch((err) => {
      console.error(TAG + "Create controller error " + JSON.stringify(err));
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
  }

  function commonCommandCallback2(command, args) {
    console.log(TAG + "Callback2 received event: " + JSON.stringify(command));
    console.log(TAG + "Callback2 received args: " + JSON.stringify(args));
    if (command != COMMON_COMMAND_STRING) {
      console.error(TAG + "Callback2 common command unmatch");
      expect().assertFail();
    }
    receivedCallback2 = true;
  }

  /*
   * @tc.name:setSessionEventTest001
   * @tc.desc:Set session event - callback
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("setSessionEventTest001", 0, async function (done) {
    session.dispatchSessionEvent(UPDATE_LYRICS_EVENT, UPDATE_LYRICS_WANT_PARAMS, (err) => {
      if (err) {
        console.error(TAG + "setSessionEventTest001 error " + JSON.stringify(err));
        expect().assertFail();
        done();
      }
      console.info(TAG + "setSessionEventTest001 finished");
      expect(true).assertTrue();
      done();
    });
  })

  /*
   * @tc.name:setSessionEventTest002
   * @tc.desc:Set session event - promise
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("setSessionEventTest002", 0, async function (done) {
    await session.dispatchSessionEvent(UPDATE_LYRICS_EVENT, UPDATE_LYRICS_WANT_PARAMS).catch((err) => {
      console.error(TAG + "setSessionEventTest002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    console.info(TAG + "setSessionEventTest002 finished");
    done();
  })

  /*
   * @tc.name:setSessionEventTest003
   * @tc.desc:Set session event - one param
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("setSessionEventTest003", 0, async function (done) {
    let errCode = 0;
    await session.dispatchSessionEvent(UPDATE_LYRICS_EVENT).catch((err) => {
      console.info(TAG + "setSessionEventTest003 caught error" + err.code);
      errCode = err.code;
    });
    sleep(200).then(()=>{
      expect(errCode == 401).assertTrue();
      done();
    })
  })

  /*
   * @tc.name:setSessionEventTest004
   * @tc.desc:Set session event - invalid params
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("setSessionEventTest004", 0, async function (done) {
    let errCode = 0;
    await session.dispatchSessionEvent(UPDATE_LYRICS_WANT_PARAMS, UPDATE_LYRICS_WANT_PARAMS).catch((err) => {
    console.info(TAG + "setSessionEventTest003 caught error" + err.code);
      errCode = err.code;
    });
    sleep(200).then(()=>{
      expect(errCode == 401).assertTrue();
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
        expect(true).assertTrue();
      } else {
        console.error(TAG + "Common command not received");
        expect().assertFail();
      }
      receivedCallback = false;
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
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Common command not received");
      expect().assertFail();
    }
    receivedCallback = false;
    receivedCallback2 = false;
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
      expect(true).assertTrue();
    } else {
      console.error(TAG + "offCommonCommandTest001 failed");
      expect().assertFail();
    }
    receivedCallback = false;
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
})
