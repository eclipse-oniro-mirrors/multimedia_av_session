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
  const INVALID_STRING = "invalid string";
  const UPDATE_LYRICS_EVENT = "dynamic_lyrics";
  const UPDATE_LYRICS_WANT_PARAMS = {
    lyrics: "This is my lyrics"
  }

  beforeAll(async function () {
    session = await avSession.createAVSession(featureAbility.getContext(), "AVSessionDemo", 'audio').catch((err) => {
      console.error(TAG + "Create AVSession error " + JSON.stringify(err));
      expect().assertFail();
    });
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
  }

  function dynamicLyricsCallback2(sessionEvent, args) {
    console.log(TAG + "Callback2 received event: " + JSON.stringify(sessionEvent));
    console.log(TAG + "Callback2 received args: " + JSON.stringify(args));
    if (sessionEvent != UPDATE_LYRICS_EVENT) {
      console.error(TAG + "Callback2 lyrics event unmatch");
      expect().assertFail();
    }
    receivedCallback2 = true;
  }

  /*
   * @tc.name:onSessionEventChangeTest001
   * @tc.desc:One on function - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("onSessionEventChangeTest001", 0, async function (done) {
    controller.on('sessionEventChange', dynamicLyricsCallback1);
    await session.setSessionEvent(UPDATE_LYRICS_EVENT, UPDATE_LYRICS_WANT_PARAMS).catch((err) => {
      console.error(TAG + "setSessionEventTest002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    sleep(200).then(() => {
      if (receivedCallback) {
        console.log(TAG + "Received session event change event");
        expect(true).assertTrue();
      } else {
        console.error(TAG + "Session event change event not received");
        expect().assertFail();
      }
      receivedCallback = false;
      done();
    })
  })

  /*
   * @tc.name:onSessionEventChangeTest002
   * @tc.desc:Two on functions - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("onSessionEventChangeTest002", 0, async function (done) {
    controller.on('sessionEventChange', dynamicLyricsCallback1);
    controller.on('sessionEventChange', dynamicLyricsCallback2);
    await session.setSessionEvent(UPDATE_LYRICS_EVENT, UPDATE_LYRICS_WANT_PARAMS).catch((err) => {
      console.error(TAG + "Set session event error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (receivedCallback && receivedCallback2) {
      console.log(TAG + "Received session event change event");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Session event change event not received");
      expect().assertFail();
    }
    receivedCallback = false;
    receivedCallback2 = false;
    done();
  })

  /*
   * @tc.name:onSessionEventChangeTest003
   * @tc.desc:One on functions - one param
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("onSessionEventChangeTest003", 0, async function (done) {
    try {
      controller.on('sessionEventChange');
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:onSessionEventChangeTest004
   * @tc.desc:One on functions - three params
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("onSessionEventChangeTest004", 0, async function (done) {
    try {
      controller.on('sessionEventChange', dynamicLyricsCallback1, dynamicLyricsCallback2);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:onSessionEventChangeTest005
   * @tc.desc:One on functions - invalid type
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("onSessionEventChangeTest005", 0, async function (done) {
    try {
      controller.on('sessionEventChange', INVALID_STRING);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:offSessionEventChangeTest001
   * @tc.desc:Two on functions and one off function - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("offSessionEventChangeTest001", 0, async function (done) {
    controller.on('sessionEventChange', dynamicLyricsCallback1);
    controller.on('sessionEventChange', dynamicLyricsCallback2);
    controller.off('sessionEventChange', dynamicLyricsCallback2);
    await session.setSessionEvent(UPDATE_LYRICS_EVENT, UPDATE_LYRICS_WANT_PARAMS).catch((err) => {
      console.error(TAG + "Set session event error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (receivedCallback && !receivedCallback2) {
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
   * @tc.name:offSessionEventChangeTest002
   * @tc.desc:Two on functions and two off function - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("offSessionEventChangeTest002", 0, async function (done) {
    controller.on('sessionEventChange', dynamicLyricsCallback1);
    controller.on('sessionEventChange', dynamicLyricsCallback2);
    controller.off('sessionEventChange', dynamicLyricsCallback1);
    controller.off('sessionEventChange', dynamicLyricsCallback2);

    await session.setSessionEvent(UPDATE_LYRICS_EVENT, UPDATE_LYRICS_WANT_PARAMS).catch((err) => {
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
   * @tc.name:offSessionEventChangeTest003
   * @tc.desc:Two on functions and off all function - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("offSessionEventChangeTest003", 0, async function (done) {
    controller.on('sessionEventChange', dynamicLyricsCallback1);
    controller.on('sessionEventChange', dynamicLyricsCallback2);
    controller.off('sessionEventChange');

    await session.setSessionEvent(UPDATE_LYRICS_EVENT, UPDATE_LYRICS_WANT_PARAMS).catch((err) => {
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
   * @tc.name:offSessionEventChangeTest004
   * @tc.desc:Two on functions and off function - three params
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("offSessionEventChangeTest004", 0, async function (done) {
    try {
      controller.on('sessionEventChange', dynamicLyricsCallback1);
      controller.on('sessionEventChange', dynamicLyricsCallback2);
      controller.off('sessionEventChange', dynamicLyricsCallback1, dynamicLyricsCallback2);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:offSessionEventChangeTest005
   * @tc.desc:One on functions and off all function - invalid type
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("offSessionEventChangeTest005", 0, async function (done) {
    try {
      controller.on('sessionEventChange', dynamicLyricsCallback1);
      controller.off('sessionEventChange', INVALID_STRING);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })
})
