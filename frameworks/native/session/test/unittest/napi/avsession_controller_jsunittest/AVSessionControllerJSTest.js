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
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index';


const TAG = "[AVSessionControllerJSTest]";

describe("AVSessionControllerJsTest", function () {
  let session = null;
  let controller = null;
  let receivedCallback = false;
  let receivedCallback2 = false;
  let receivedString = null;
  let receivedString2 = null;
  let receivedParam = null;
  let receivedParam2 = null;
  let receivedExtras = null;
  let receivedExtras2 = null;
  const INVALID_STRING = "invalid string";
  const UPDATE_LYRICS_EVENT = "dynamic_lyrics";
  const UPDATE_LYRICS_WANT_PARAMS = {
    lyrics: "This is my lyrics"
  };
  const COMMON_COMMAND_STRING = "common_command";
  const COMMON_COMMAND_PARAMS = {
    command: "This is my command"
  };
  const CUSTOM_EXTRAS = {
    extrasKey: "This is custom media packet"
  };

  beforeAll(async function () {
    session = await avSession.createAVSession(featureAbility.getContext(), "AVSessionDemo", 'audio').catch((err) => {
      console.error(TAG + "Create AVSession error " + JSON.stringify(err));
      expect().assertFail();
    });
    session.activate();
    controller = await avSession.createController(session.sessionId).catch((err) => {
      console.error(TAG + "Create controller error " + JSON.stringify(err));
      expect().assertFail();
    })
    console.info(TAG + "Create session and controller finished, beforeAll called");
  })

  afterAll(function () {
    controller.destroy();
    session.destroy();
    console.info(TAG + 'afterAll called');
  })

  beforeEach(function () {
    console.info(TAG + 'beforeEach called');
  })

  afterEach(function () {
    console.info(TAG + 'afterEach called');
  })

  function sleep(time) {
    return new Promise((resolve) => setTimeout(resolve, time));
  }

  function dynamicLyricsCallback1(sessionEvent, args) {
    console.log(TAG + "Callback1 received event: " + JSON.stringify(sessionEvent));
    console.log(TAG + "Callback1 received args: " + JSON.stringify(args));
    if (sessionEvent != UPDATE_LYRICS_EVENT) {
      console.error(TAG + "Callback1 lyrics event unmatch");
      expect().assertFail();
    }
    receivedCallback = true;
    receivedString = sessionEvent;
    receivedParam = args;
  }

  function dynamicLyricsCallback2(sessionEvent, args) {
    console.log(TAG + "Callback2 received event: " + JSON.stringify(sessionEvent));
    console.log(TAG + "Callback2 received args: " + JSON.stringify(args));
    if (sessionEvent != UPDATE_LYRICS_EVENT) {
      console.error(TAG + "Callback2 lyrics event unmatch");
      expect().assertFail();
    }
    receivedCallback2 = true;
    receivedString2 = sessionEvent;
    receivedParam2 = args;
  }

  function extrasChangeCallback1(extras) {
    console.log(TAG + "Callback1 received args: " + JSON.stringify(extras));
    if (extras.extrasKey != CUSTOM_EXTRAS.extrasKey) {
      console.error(TAG + "Callback1 extras unmatch");
      expect().assertFail();
    }
    receivedCallback = true;
    receivedExtras = extras;
  }

  function extrasChangeCallback2(extras) {
    console.log(TAG + "Callback2 received args: " + JSON.stringify(extras));
    if (extras.extrasKey != CUSTOM_EXTRAS.extrasKey) {
      console.error(TAG + "Callback2 extras unmatch");
      expect().assertFail();
    }
    receivedCallback2 = true;
    receivedExtras2 = extras;
  }

  /*
   * @tc.name:onSessionEventTest001
   * @tc.desc:One on function - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("onSessionEventTest001", 0, async function (done) {
    controller.on('sessionEvent', dynamicLyricsCallback1);
    await session.dispatchSessionEvent(UPDATE_LYRICS_EVENT, UPDATE_LYRICS_WANT_PARAMS).catch((err) => {
      console.error(TAG + "dispatchSessionEventTest002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    sleep(200).then(() => {
      if (receivedCallback) {
        console.log(TAG + "Received session event change event");
        expect(receivedString == UPDATE_LYRICS_EVENT).assertTrue();
        expect(receivedParam.lyrics == UPDATE_LYRICS_WANT_PARAMS.lyrics).assertTrue();
      } else {
        console.error(TAG + "Session event change event not received");
        expect().assertFail();
      }
      receivedCallback = false;
      receivedString = null;
      receivedParam = null;
      done();
    })
  })

  /*
   * @tc.name:onSessionEventTest002
   * @tc.desc:Two on functions - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("onSessionEventTest002", 0, async function (done) {
    controller.on('sessionEvent', dynamicLyricsCallback1);
    controller.on('sessionEvent', dynamicLyricsCallback2);
    await session.dispatchSessionEvent(UPDATE_LYRICS_EVENT, UPDATE_LYRICS_WANT_PARAMS).catch((err) => {
      console.error(TAG + "Set session event error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (receivedCallback && receivedCallback2) {
      console.log(TAG + "Received session event change event");
      expect(receivedString == UPDATE_LYRICS_EVENT).assertTrue();
      expect(receivedParam.lyrics == UPDATE_LYRICS_WANT_PARAMS.lyrics).assertTrue();
      expect(receivedString2 == UPDATE_LYRICS_EVENT).assertTrue();
      expect(receivedParam2.lyrics == UPDATE_LYRICS_WANT_PARAMS.lyrics).assertTrue();
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Session event change event not received");
      expect().assertFail();
    }
    receivedCallback = false;
    receivedCallback2 = false;
    receivedString2 = null;
    receivedParam2 = null;
    receivedString2 = null;
    receivedParam2 = null;
    done();
  })

  /*
   * @tc.name:onSessionEventTest003
   * @tc.desc:One on functions - one param
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("onSessionEventTest003", 0, async function (done) {
    try {
      controller.on('sessionEvent');
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:onSessionEventTest004
   * @tc.desc:One on functions - three params
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("onSessionEventTest004", 0, async function (done) {
    try {
      controller.on('sessionEvent', dynamicLyricsCallback1, dynamicLyricsCallback2);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:onSessionEventTest005
   * @tc.desc:One on functions - invalid type
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("onSessionEventTest005", 0, async function (done) {
    try {
      controller.on('sessionEvent', INVALID_STRING);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:offSessionEventTest001
   * @tc.desc:Two on functions and one off function - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("offSessionEventTest001", 0, async function (done) {
    controller.on('sessionEvent', dynamicLyricsCallback1);
    controller.on('sessionEvent', dynamicLyricsCallback2);
    controller.off('sessionEvent', dynamicLyricsCallback2);
    await session.dispatchSessionEvent(UPDATE_LYRICS_EVENT, UPDATE_LYRICS_WANT_PARAMS).catch((err) => {
      console.error(TAG + "Set session event error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (receivedCallback && !receivedCallback2) {
      console.log(TAG + "Received session event change event");
      expect(receivedString == UPDATE_LYRICS_EVENT).assertTrue();
      expect(receivedParam.lyrics == UPDATE_LYRICS_WANT_PARAMS.lyrics).assertTrue();
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Session event change event not received");
      expect().assertFail();
    }
    receivedCallback = false;
    receivedString = null;
    receivedParam = null;
    done();
  })

  /*
   * @tc.name:offSessionEventTest002
   * @tc.desc:Two on functions and two off function - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("offSessionEventTest002", 0, async function (done) {
    controller.on('sessionEvent', dynamicLyricsCallback1);
    controller.on('sessionEvent', dynamicLyricsCallback2);
    controller.off('sessionEvent', dynamicLyricsCallback1);
    controller.off('sessionEvent', dynamicLyricsCallback2);

    await session.dispatchSessionEvent(UPDATE_LYRICS_EVENT, UPDATE_LYRICS_WANT_PARAMS).catch((err) => {
      console.error(TAG + "Set session event error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (!receivedCallback && !receivedCallback2) {
      console.log(TAG + "Received session event change event");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Session event change event not received");
      expect().assertFail();
    }
    receivedCallback = false;
    done();
  })

  /*
   * @tc.name:offSessionEventTest003
   * @tc.desc:Two on functions and off all function - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("offSessionEventTest003", 0, async function (done) {
    controller.on('sessionEvent', dynamicLyricsCallback1);
    controller.on('sessionEvent', dynamicLyricsCallback2);
    controller.off('sessionEvent');

    await session.dispatchSessionEvent(UPDATE_LYRICS_EVENT, UPDATE_LYRICS_WANT_PARAMS).catch((err) => {
      console.error(TAG + "Set session event error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (!receivedCallback && !receivedCallback2) {
      console.log(TAG + "Received session event change event");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Session event change event not received");
      expect().assertFail();
    }
    receivedCallback = false;
    done();
  })

  /*
   * @tc.name:offSessionEventTest004
   * @tc.desc:Two on functions and off function - three params
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("offSessionEventTest004", 0, async function (done) {
    try {
      controller.on('sessionEvent', dynamicLyricsCallback1);
      controller.on('sessionEvent', dynamicLyricsCallback2);
      controller.off('sessionEvent', dynamicLyricsCallback1, dynamicLyricsCallback2);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:offSessionEventTest005
   * @tc.desc:One on functions and off all function - invalid type
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("offSessionEventTest005", 0, async function (done) {
    try {
      controller.on('sessionEvent', dynamicLyricsCallback1);
      controller.off('sessionEvent', INVALID_STRING);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:sendCommonCommandTest001
   * @tc.desc:Send common command - callback
   * @tc.type: FUNC
   * @tc.require: I6ETY6
   */
  it("sendCommonCommandTest001", 0, async function (done) {
    controller.sendCommonCommand(COMMON_COMMAND_STRING, COMMON_COMMAND_PARAMS, (err) => {
      if (err) {
        console.error(TAG + "sendCommonCommandTest001 error " + JSON.stringify(err));
        expect().assertFail();
        done();
      }
      console.info(TAG + "sendCommonCommandTest001 finished");
      expect(true).assertTrue();
      done();
    });
  })

  /*
   * @tc.name:sendCommonCommandTest002
   * @tc.desc:Send common command - promise
   * @tc.type: FUNC
   * @tc.require: I6ETY6
   */
  it("sendCommonCommandTest002", 0, async function (done) {
    await controller.sendCommonCommand(COMMON_COMMAND_STRING, COMMON_COMMAND_PARAMS).catch((err) => {
      console.error(TAG + "sendCommonCommandTest002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    console.info(TAG + "sendCommonCommandTest002 finished");
    done();
  })

  /*
   * @tc.name:sendCommonCommandTest003
   * @tc.desc:Set common command - one param
   * @tc.type: FUNC
   * @tc.require: I6ETY6
   */
  it("sendCommonCommandTest003", 0, async function (done) {
    let errCode = 0;
    await controller.sendCommonCommand(COMMON_COMMAND_STRING).catch((err) => {
      console.info(TAG + "sendCommonCommandTest003 caught error" + err.code);
      errCode = err.code;
    });
    sleep(200).then(() => {
      expect(errCode == 401).assertTrue();
      done();
    })
  })

  /*
   * @tc.name:sendCommonCommandTest004
   * @tc.desc:Send common command - invalid params
   * @tc.type: FUNC
   * @tc.require: I6ETY6
   */
  it("sendCommonCommandTest004", 0, async function (done) {
    let errCode = 0;
    await controller.sendCommonCommand(COMMON_COMMAND_PARAMS, COMMON_COMMAND_PARAMS).catch((err) => {
      console.info(TAG + "sendCommonCommandTest004 caught error" + err.code);
      errCode = err.code;
    });
    sleep(200).then(() => {
      expect(errCode == 401).assertTrue();
      done();
    })
  })

  /*
   * @tc.name:sendCommonCommandTest005
   * @tc.desc:Send common command - deactive
   * @tc.type: FUNC
   * @tc.require: I6ETY6
   */
  it("sendCommonCommandTest005", 0, async function (done) {
    try {
      session.deactivate(async () => {
        await controller.sendCommonCommand(COMMON_COMMAND_STRING, COMMON_COMMAND_PARAMS);
      });
    } catch (err) {
      expect(err.code == 6600106).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:GetExtras001
   * @tc.desc:Get extras - callback
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("GetExtras001", 0, async function (done) {
    console.info(TAG + "GetExtras001 start");
    await session.setExtras(CUSTOM_EXTRAS).catch((err) => {
      console.error(TAG + "GetExtras001 error " + JSON.stringify(err));
      expect().assertFail();
    });

    controller.getExtras((err, extras) => {
      if (err) {
        console.error(TAG + "GetExtras001 error " + JSON.stringify(err));
        expect().assertFail();
        done();
      }
      expect(extras.extrasKey == CUSTOM_EXTRAS.extrasKey).assertTrue();
      console.info(TAG + "GetExtras001 finished");
      done();
    });
  })

  /*
   * @tc.name:GetExtras002
   * @tc.desc:Get extras - promise
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("GetExtras002", 0, async function (done) {
    console.info(TAG + "GetExtras002 start");
    await session.setExtras(CUSTOM_EXTRAS).catch((err) => {
      console.error(TAG + "GetExtras002 error " + JSON.stringify(err));
      expect().assertFail();
    });

    let extras = await controller.getExtras().catch((err) => {
      console.error(TAG + "GetExtras002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    })
    expect(extras.extrasKey == CUSTOM_EXTRAS.extrasKey).assertTrue();
    console.info(TAG + "GetExtras002 finished");
    done();
  })

  /*
   * @tc.name:OnExtrasChange001
   * @tc.desc:One on function - extras change
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("OnExtrasChange001", 0, async function (done) {
    console.info(TAG + "OnExtrasChange001 start");
    controller.on('extrasChange', extrasChangeCallback1);
    await session.setExtras(CUSTOM_EXTRAS).catch((err) => {
      console.error(TAG + "OnExtrasChange001 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    sleep(200).then(() => {
      if (receivedCallback) {
        console.log(TAG + "Received extras change event");
        expect(receivedExtras.extrasKey == CUSTOM_EXTRAS.extrasKey).assertTrue();
      } else {
        console.error(TAG + "OnExtrasChange001 extras change event not received");
        expect().assertFail();
      }
      receivedCallback = false;
      receivedExtras = null;
      console.info(TAG + "OnExtrasChange001 finished");
      done();
    })
  })

  /*
   * @tc.name:OnExtrasChange002
   * @tc.desc:Two on function - extras change
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("OnExtrasChange002", 0, async function (done) {
    console.info(TAG + "OnExtrasChange002 start");
    controller.on('extrasChange', extrasChangeCallback1);
    controller.on('extrasChange', extrasChangeCallback2);
    await session.setExtras(CUSTOM_EXTRAS).catch((err) => {
      console.error(TAG + "OnExtrasChange002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    sleep(200).then(() => {
      if (receivedCallback && receivedCallback2) {
        console.log(TAG + "Received extras change event");
        expect(receivedExtras.extrasKey == CUSTOM_EXTRAS.extrasKey).assertTrue();
        expect(receivedExtras2.extrasKey == CUSTOM_EXTRAS.extrasKey).assertTrue();
      } else {
        console.error(TAG + "OnExtrasChange002 extras change event not received");
        expect().assertFail();
      }
      receivedCallback = false;
      receivedCallback2 = false;
      receivedExtras = null;
      receivedExtras2 = null;
      console.info(TAG + "OnExtrasChange002 finished");
      done();
    })
  })

  /*
   * @tc.name:OnExtrasChange003
   * @tc.desc:One on functions - one param
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("OnExtrasChange003", 0, async function (done) {
    try {
      controller.on('extrasChange');
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    console.info(TAG + "OnExtrasChange003 finished");
    done();
  })

  /*
   * @tc.name:OnExtrasChange004
   * @tc.desc:One on functions - three params
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("OnExtrasChange004", 0, async function (done) {
    try {
      controller.on('extrasChange', extrasChangeCallback1, extrasChangeCallback2);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    console.info(TAG + "OnExtrasChange004 finished");
    done();
  })

  /*
   * @tc.name:OnExtrasChange005
   * @tc.desc:One on functions - invalid type
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("OnExtrasChange005", 0, async function (done) {
    try {
      controller.on('extrasChange', INVALID_STRING);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    console.info(TAG + "OnExtrasChange005 finished");
    done();
  })

  /*
   * @tc.name:OffExtrasChange001
   * @tc.desc:Two on functions and one off function - extras change
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("OffExtrasChange001", 0, async function (done) {
    controller.on('extrasChange', extrasChangeCallback1);
    controller.on('extrasChange', extrasChangeCallback2);
    controller.off('extrasChange', extrasChangeCallback2);
    await session.setExtras(CUSTOM_EXTRAS).catch((err) => {
      console.error(TAG + "OnExtrasChange002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (receivedCallback && !receivedCallback2) {
      console.log(TAG + "Received extras change event");
      expect(receivedExtras.extrasKey == CUSTOM_EXTRAS.extrasKey).assertTrue();
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Extras change event not received");
      expect().assertFail();
    }
    receivedCallback = false;
    receivedExtras = null;
    console.info(TAG + "OffExtrasChange001 finished");
    done();
  })

  /*
   * @tc.name:OffExtrasChange002
   * @tc.desc:Two on functions and two off function - extras change
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("OffExtrasChange002", 0, async function (done) {
    controller.on('extrasChange', extrasChangeCallback1);
    controller.on('extrasChange', extrasChangeCallback2);
    controller.off('extrasChange', extrasChangeCallback1);
    controller.off('extrasChange', extrasChangeCallback2);
    await session.setExtras(CUSTOM_EXTRAS).catch((err) => {
      console.error(TAG + "OnExtrasChange002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (!receivedCallback && !receivedCallback2) {
      console.log(TAG + "Success, not received extras change event");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Test failed, extras change event received");
      expect().assertFail();
    }
    console.info(TAG + "OffExtrasChange002 finished");
    done();
  })

  /*
   * @tc.name:OnExtrasChange003
   * @tc.desc:Two on functions and off all function - extras change
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("OnExtrasChange003", 0, async function (done) {
    controller.on('extrasChange', extrasChangeCallback1);
    controller.on('extrasChange', extrasChangeCallback2);
    controller.off('extrasChange');
    await session.setExtras(CUSTOM_EXTRAS).catch((err) => {
      console.error(TAG + "OnExtrasChange003 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (!receivedCallback && !receivedCallback2) {
      console.log(TAG + "Success, not received extras change event");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Test failed, extras change event received");
      expect().assertFail();
    }
    console.info(TAG + "OnExtrasChange003 finished");
    done();
  })

  /*
   * @tc.name:OnExtrasChange004
   * @tc.desc:Two on functions and off function - three params
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("OnExtrasChange004", 0, async function (done) {
    try {
      controller.on('extrasChange', extrasChangeCallback1);
      controller.on('extrasChange', extrasChangeCallback2);
      controller.off('extrasChange', extrasChangeCallback1, extrasChangeCallback2);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    console.info(TAG + "OnExtrasChange004 finished");
    done();
  })

  /*
   * @tc.name:OnExtrasChange005
   * @tc.desc:One on functions and off all function - invalid type
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("OnExtrasChange005", 0, async function (done) {
    try {
      controller.on('extrasChange', extrasChangeCallback1);
      controller.off('extrasChange', INVALID_STRING);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    console.info(TAG + "OnExtrasChange005 finished");
    done();
  })
})
