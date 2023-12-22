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
  const QUEUE_ITEM_ID = 666;
  const QUEUE_ITEM_LENGTH = 1;
  const QUEUE_ITEM_KEY_WORD = "QUEUE_ITEM_RELATE";
  const EXTRAS = { "items_author": "name" };
  const QUEUE_ITEM_DESCRIPTION = {
    mediaId: QUEUE_ITEM_KEY_WORD,
    title: QUEUE_ITEM_KEY_WORD,
    extras: EXTRAS
  };
  const QUEUE_ITEM = {
    itemId: QUEUE_ITEM_ID,
    description: QUEUE_ITEM_DESCRIPTION
  }
  const ITEMS_ARRAY = [QUEUE_ITEM];
  const QUEUE_TITLE = "title";
  const SKIP_ITEM_ID = 200;

  beforeAll(async function () {
    session = await avSession.createAVSession(featureAbility.getContext(), "AVSessionDemo", 'audio').catch((err) => {
      console.error(TAG + "Create AVSession in avsessioncontrollerjstest error " + JSON.stringify(err));
      expect().assertFail();
    });
    session.activate();
    controller = await avSession.createController(session.sessionId).catch((err) => {
      console.error(TAG + "Create controller in avsessioncontrollerjstest error " + JSON.stringify(err));
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
    console.info(TAG + 'beforeEach in avsessioncontrollerjstest called');
  })

  afterEach(function () {
    console.info(TAG + 'afterEach in avsessioncontrollerjstest called');
  })

  function sleep(time) {
    console.info(TAG + 'sleep in avsessioncontrollerjstest called');
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

  function queueTitleCallback1(title) {
    console.log(TAG + "queueTitleCallback1 received Title " + JSON.stringify(title));
    if (title != QUEUE_TITLE) {
      console.error(TAG + "queueTitleCallback1 received Title unmatch");
      expect().assertFail();
    }
    receivedCallback = true;
  }

  function queueTitleCallback2(title) {
    console.log(TAG + "queueTitleCallback2 received Title " + JSON.stringify(title));
    if (title != QUEUE_TITLE) {
      console.error(TAG + "queueTitleCallback2 received Title unmatch");
      expect().assertFail();
    }
    receivedCallback2 = true;
  }

  function queueItemsCallback1(items) {
    console.log(TAG + "queueItemsCallback1 received items length: " + items.length);
    console.log(TAG + "queueItemsCallback1 received items id: " + items[0].itemId);
    console.log(TAG + "queueItemsCallback1 received items title: " + items[0].description.title);
    if (items.length != QUEUE_ITEM_LENGTH) {
      console.error(TAG + "queueItemsCallback1 received items length unmatch");
      expect().assertFail();
      return;
    }
    if (items[0].itemId != QUEUE_ITEM_ID) {
      console.error(TAG + "queueItemsCallback1 received items id unmatch");
      expect().assertFail();
      return;
    }
    if (items[0].description.title != QUEUE_ITEM_KEY_WORD) {
      console.error(TAG + "queueItemsCallback1 received items key word unmatch");
      expect().assertFail();
      return;
    }
    receivedCallback = true;
  }

  function queueItemsCallback2(items) {
    console.log(TAG + "queueItemsCallback2 received items length: " + items.length);
    console.log(TAG + "queueItemsCallback2 received items id: " + items[0].itemId);
    console.log(TAG + "queueItemsCallback2 received items title: " + items[0].description.title);
    if (items.length != QUEUE_ITEM_LENGTH) {
      console.error(TAG + "queueItemsCallback2 received items length unmatch");
      expect().assertFail();
      return;
    }
    if (items[0].itemId != QUEUE_ITEM_ID) {
      console.error(TAG + "queueItemsCallback2 received items id unmatch");
      expect().assertFail();
      return;
    }
    if (items[0].description.title != QUEUE_ITEM_KEY_WORD) {
      console.error(TAG + "queueItemsCallback2 received items key word unmatch");
      expect().assertFail();
      return;
    }
    receivedCallback2 = true;
  }

  function skipToQueueItemCallback1(itemId) {
    console.log(TAG + "skipToQueueItemCallback1 received itemid " + itemId);
    if (itemId != SKIP_ITEM_ID) {
      console.error(TAG + "skipToQueueItemCallback1 received uid unmatch");
      expect().assertFail();
    }
    receivedCallback = true;
  }

  function skipToQueueItemCallback2(itemId) {
    console.log(TAG + "skipToQueueItemCallback2 received itemid " + itemId);
    if (itemId != SKIP_ITEM_ID) {
      console.error(TAG + "skipToQueueItemCallback2 received uid unmatch");
      expect().assertFail();
    }
    receivedCallback2 = true;
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
      console.error(TAG + "Set session event in offSessionEventTest002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (!receivedCallback && !receivedCallback2) {
      console.log(TAG + "Received session event change event in offSessionEventTest002");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Session event change event not received in offSessionEventTest002");
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
      console.error(TAG + "Set session event in offSessionEventTest003 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (!receivedCallback && !receivedCallback2) {
      console.log(TAG + "Received session event change event in offSessionEventTest003");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Session event change event not received in offSessionEventTest003");
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
      console.log(TAG + "Success in OnExtrasChange002, not received extras change event");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Test failed in OnExtrasChange002, extras change event received");
      expect().assertFail();
    }
    console.info(TAG + "OffExtrasChange002 finished in OnExtrasChange002");
    done();
  })

  /*
   * @tc.name:OffExtrasChange003
   * @tc.desc:Two on functions and off all function - extras change
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("OffExtrasChange003", 0, async function (done) {
    controller.on('extrasChange', extrasChangeCallback1);
    controller.on('extrasChange', extrasChangeCallback2);
    controller.off('extrasChange');
    await session.setExtras(CUSTOM_EXTRAS).catch((err) => {
      console.error(TAG + "OffExtrasChange003 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (!receivedCallback && !receivedCallback2) {
      console.log(TAG + "Success in OnExtrasChange003, not received extras change event");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Test failed in OnExtrasChange003, extras change event received");
      expect().assertFail();
    }
    console.info(TAG + "OffExtrasChange003 finished in OnExtrasChange003");
    done();
  })

  /*
   * @tc.name:OffExtrasChange004
   * @tc.desc:Two on functions and off function - three params
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("OffExtrasChange004", 0, async function (done) {
    try {
      controller.on('extrasChange', extrasChangeCallback1);
      controller.on('extrasChange', extrasChangeCallback2);
      controller.off('extrasChange', extrasChangeCallback1, extrasChangeCallback2);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    console.info(TAG + "OffExtrasChange004 finished");
    done();
  })

  /*
   * @tc.name:OffExtrasChange005
   * @tc.desc:One on functions and off all function - invalid type
   * @tc.type: FUNC
   * @tc.require: I6TD43
   */
  it("OffExtrasChange005", 0, async function (done) {
    try {
      controller.on('extrasChange', extrasChangeCallback1);
      controller.off('extrasChange', INVALID_STRING);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    console.info(TAG + "OffExtrasChange005 finished");
    done();
  })

  /*
   * @tc.name:onQueueItemsChangeTest001
   * @tc.desc:One on function - queue items change
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("onQueueItemsChangeTest001", 0, async function (done) {
    controller.on('queueItemsChange', queueItemsCallback1);
    await session.setAVQueueItems(ITEMS_ARRAY).catch((err) => {
      console.error(TAG + "onQueueItemsChangeTest001 setAVQueueItems error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    sleep(200).then(() => {
      if (receivedCallback) {
        console.log(TAG + "Received queue items change");
        expect(true).assertTrue();
      } else {
        console.error(TAG + "Session queue items change  not received");
        expect().assertFail();
      }
      receivedCallback = false;
      done();
    });
  })

  /*
   * @tc.name:onQueueItemsChangeTest002
   * @tc.desc:One on function - queue items change
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("onQueueItemChangeTest002", 0, async function (done) {
    controller.on('queueItemsChange', queueItemsCallback1);
    controller.on('queueItemsChange', queueItemsCallback2);
    await session.setAVQueueItems(ITEMS_ARRAY).catch((err) => {
      console.error(TAG + "setAVQueueItemsTest002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (receivedCallback && receivedCallback2) {
      console.log(TAG + "Received queue items change");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Session queue items change  not received");
      expect().assertFail();
    }
    receivedCallback = false;
    receivedCallback2 = false;
    done();
  })

  /*
   * @tc.name:onQueueItemsChangeTest003
   * @tc.desc:One on functions - one param
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("onQueueItemsChangeTest003", 0, async function (done) {
    try {
      controller.on('queueItemsChange');
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:onQueueItemsChangeTest004
   * @tc.desc:One on functions - three params
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("onQueueItemsChangeTest004", 0, async function (done) {
    try {
      controller.on('queueItemsChange', queueItemsCallback1, queueItemsCallback2);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:onQueueTitleChangeTest001
   * @tc.desc:One on function - queue title change
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("onQueueTitleChangeTest001", 0, async function (done) {
    controller.on('queueTitleChange', queueTitleCallback1);
    await session.setAVQueueTitle(QUEUE_TITLE).catch((err) => {
      console.error(TAG + "onQueueTitleChangeTest001 setAVQueueTitle error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    sleep(200).then(() => {
      if (receivedCallback) {
        console.log(TAG + "Received queue Title change");
        expect(true).assertTrue();
      } else {
        console.error(TAG + "Session queue Title change  not received");
        expect().assertFail();
      }
      receivedCallback = false;
      done();
    });
  })

  /*
   * @tc.name:onQueueTitleChangeTest002
   * @tc.desc:One on function - queue title change
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("onQueueTitleChangeTest002", 0, async function (done) {
    controller.on('queueTitleChange', queueTitleCallback1);
    controller.on('queueTitleChange', queueTitleCallback2);
    await session.setAVQueueTitle(QUEUE_TITLE).catch((err) => {
      console.error(TAG + "setAVQueueTitleTest002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (receivedCallback && receivedCallback2) {
      console.log(TAG + "Received queue Title change");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Session queue Title change  not received");
      expect().assertFail();
    }
    receivedCallback = false;
    receivedCallback2 = false;
    done();
  })

  /*
   * @tc.name:onQueueTitleChangeTest003
   * @tc.desc:One on functions - one param
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("onQueueTitleChangeTest003", 0, async function (done) {
    try {
      controller.on('queueTitleChange');
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:onQueueTitleChangeTest004
   * @tc.desc:One on functions - three params
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("onQueueTitleChangeTest004", 0, async function (done) {
    try {
      controller.on('queueTitleChange', queueTitleCallback1, queueTitleCallback2);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:offQueueItemsChangeTest001
   * @tc.desc:Two on functions and one off function - queue items change
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("offQueueItemsChangeTest001", 0, async function (done) {
    controller.on('queueItemsChange', queueItemsCallback1);
    controller.on('queueItemsChange', queueItemsCallback2);
    controller.off('queueItemsChange', queueItemsCallback2);
    await session.setAVQueueItems(ITEMS_ARRAY).catch((err) => {
      console.error(TAG + "offQueueItemsChangeTest001 setAVQueueItems error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (receivedCallback && !receivedCallback2) {
      console.log(TAG + "Received queue items change");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Session queue items change in offQueueItemsChangeTest001 not received");
      expect().assertFail();
    }
    receivedCallback = false;
    done();
  })

  /*
   * @tc.name:offQueueItemsChangeTest002
   * @tc.desc:Two on functions and two off function - queue items change
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("offQueueItemsChangeTest002", 0, async function (done) {
    controller.on('queueItemsChange', queueItemsCallback1);
    controller.on('queueItemsChange', queueItemsCallback2);
    controller.off('queueItemsChange', queueItemsCallback1);
    controller.off('queueItemsChange', queueItemsCallback2);
    await session.setAVQueueItems(ITEMS_ARRAY).catch((err) => {
      console.error(TAG + "offQueueItemsChangeTest002 setAVQueueItems error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (!receivedCallback && !receivedCallback2) {
      console.log(TAG + "Received queue items change in offQueueItemsChangeTest002");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Session queue items change in offQueueItemsChangeTest002 not received");
      expect().assertFail();
    }
    receivedCallback = false;
    done();
  })

  /*
   * @tc.name:offQueueItemsChangeTest003
   * @tc.desc:Two on functions and off all function - queue items change
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("offQueueItemsChangeTest003", 0, async function (done) {
    controller.on('queueItemsChange', queueItemsCallback1);
    controller.on('queueItemsChange', queueItemsCallback2);
    controller.off('queueItemsChange');
    await session.setAVQueueItems(ITEMS_ARRAY).catch((err) => {
      console.error(TAG + "offQueueItemsChangeTest003 setAVQueueItems error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (!receivedCallback && !receivedCallback2) {
      console.log(TAG + "Received queue items change in offQueueItemsChangeTest003");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Session queue items change in offQueueItemsChangeTest003 not received");
      expect().assertFail();
    }
    receivedCallback = false;
    done();
  })

  /*
   * @tc.name:offQueueItemsChangeTest004
   * @tc.desc:Two on functions and off function - three params
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("offQueueItemsChangeTest004", 0, async function (done) {
    try {
      controller.on('queueItemsChange', queueItemsCallback1);
      controller.on('queueItemsChange', queueItemsCallback2);
      controller.off('queueItemsChange', queueItemsCallback1, queueItemsCallback2);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:offQueueTitleChangeTest001
   * @tc.desc:Two on functions and one off function - queue title change
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("offQueueTitleChangeTest001", 0, async function (done) {
    controller.on('queueTitleChange', queueTitleCallback1);
    controller.on('queueTitleChange', queueTitleCallback2);
    controller.off('queueTitleChange', queueTitleCallback2);
    await session.setAVQueueTitle(QUEUE_TITLE).catch((err) => {
      console.error(TAG + "offQueueTitleChangeTest001 setAVQueueTitle error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (receivedCallback && !receivedCallback2) {
      console.log(TAG + "Received queue Title change");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Session queue Title change  not received");
      expect().assertFail();
    }
    receivedCallback = false;
    done();
  })

  /*
   * @tc.name:offQueueTitleChangeTest002
   * @tc.desc:Two on functions and two off function - queue title change
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("offQueueTitleChangeTest002", 0, async function (done) {
    controller.on('queueTitleChange', queueTitleCallback1);
    controller.on('queueTitleChange', queueTitleCallback2);
    controller.off('queueTitleChange', queueTitleCallback1);
    controller.off('queueTitleChange', queueTitleCallback2);

    await session.setAVQueueTitle(QUEUE_TITLE).catch((err) => {
      console.error(TAG + "offQueueTitleChangeTest002 setAVQueueTitle error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (!receivedCallback && !receivedCallback2) {
      console.log(TAG + "Received queue Title change in offQueueTitleChangeTest002");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Session queue Title change in offQueueTitleChangeTest002 not received");
      expect().assertFail();
    }
    receivedCallback = false;
    done();
  })

  /*
   * @tc.name:offQueueTitleChangeTest003
   * @tc.desc:Two on functions and off all function - queue title change
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("offQueueTitleChangeTest003", 0, async function (done) {
    controller.on('queueTitleChange', queueTitleCallback1);
    controller.on('queueTitleChange', queueTitleCallback2);
    controller.off('queueTitleChange');

    await session.setAVQueueTitle(QUEUE_TITLE).catch((err) => {
      console.error(TAG + "offQueueTitleChangeTest003 setAVQueueTitle error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (!receivedCallback && !receivedCallback2) {
      console.log(TAG + "Received queue Title change in offQueueTitleChangeTest003");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "Session queue Title change in offQueueTitleChangeTest003 not received");
      expect().assertFail();
    }
    receivedCallback = false;
    done();
  })

  /*
   * @tc.name:offQueueTitleChangeTest004
   * @tc.desc:Two on functions and off function - three params
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("offQueueTitleChangeTest004", 0, async function (done) {
    try {
      controller.on('queueTitleChange', queueTitleCallback1);
      controller.on('queueTitleChange', queueTitleCallback2);
      controller.off('queueTitleChange', queueTitleCallback1, queueTitleCallback2);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:setAVQueueItemsTest001
   * @tc.desc:setAVQueueItems - callback
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */

  it("setAVQueueItemsTest001", 0, async function (done) {
    session.setAVQueueItems(ITEMS_ARRAY, (err) => {
      if (err) {
        console.error(TAG + "setAVQueueItemsTest001 error " + JSON.stringify(err));
        expect().assertFail();
        done();
      }
      console.info(TAG + "setAVQueueItemsTest001 finished");
      expect(true).assertTrue();
      done();
    });
  })

  /*
   * @tc.name:setAVQueueItemsTest002
   * @tc.desc:setAVQueueItems - promise
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("setAVQueueItemsTest002", 0, async function (done) {
    await session.setAVQueueItems(ITEMS_ARRAY).catch((err) => {
      console.error(TAG + "setAVQueueItemsTest002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    console.info(TAG + "setAVQueueItemsTest002 finished");
    done();
  })

  /*
   * @tc.name:setAVQueueTitleTest001
   * @tc.desc:setAVQueueTitle - callback
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("setAVQueueTitleTest001", 0, async function (done) {
    session.setAVQueueTitle(QUEUE_TITLE, (err) => {
      if (err) {
        console.error(TAG + "setAVQueueTitleTest001 error " + JSON.stringify(err));
        expect().assertFail();
        done();
      }
      console.info(TAG + "setAVQueueTitleTest001 finished");
      expect(true).assertTrue();
      done();
    });
  })

  /*
   * @tc.name:setAVQueueTitleTest002
   * @tc.desc:setAVQueueTitle - promise
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("setAVQueueTitleTest002", 0, async function (done) {
    await session.setAVQueueTitle(QUEUE_TITLE).catch((err) => {
      console.error(TAG + "setAVQueueTitleTest002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    console.info(TAG + "setAVQueueTitleTest002 finished");
    done();
  })

  /*
   * @tc.name:SkipToQueueItemTest001
   * @tc.desc:SkipToQueueItem - callback
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("SkipToQueueItemTest001", 0, async function (done) {
    controller.skipToQueueItem(QUEUE_ITEM_ID, (err) => {
      if (err) {
        console.error(TAG + "SkipToQueueItemTest001 error " + JSON.stringify(err));
        expect().assertFail();
        done();
      }
      console.info(TAG + "SkipToQueueItemTest001 finished");
      expect(true).assertTrue();
      done();
    });
  })

  /*
   * @tc.name:SkipToQueueItemTest002
   * @tc.desc:SkipToQueueItem - promise
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("SkipToQueueItemTest002", 0, async function (done) {
    await controller.skipToQueueItem(QUEUE_ITEM_ID).catch((err) => {
      console.error(TAG + "SkipToQueueItemTest002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    console.info(TAG + "SkipToQueueItemTest002 finished");
    done();
  })

  /*
   * @tc.name:OnSkipToQueueItemTest001
   * @tc.desc:One on function - skip to queue items
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("OnSkipToQueueItemTest001", 0, async function (done) {
    session.on('skipToQueueItem', skipToQueueItemCallback1);
    await controller.skipToQueueItem(SKIP_ITEM_ID).catch((err) => {
      console.error(TAG + "skipToQueueItemTest001 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    sleep(200).then(() => {
      if (receivedCallback) {
        console.log(TAG + "Received skipToQueueItem ");
        expect(true).assertTrue();
      } else {
        console.error(TAG + "skipToQueueItem not received");
        expect().assertFail();
      }
      receivedCallback = false;
      done();
    })
  })

  /*
   * @tc.name:OnSkipToQueueItemTest002
   * @tc.desc:One on function - skip to queue items
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("OnSkipToQueueItemTest002", 0, async function (done) {
    session.on('skipToQueueItem', skipToQueueItemCallback1);
    session.on('skipToQueueItem', skipToQueueItemCallback2);
    await controller.skipToQueueItem(SKIP_ITEM_ID).catch((err) => {
      console.error(TAG + "skipToQueueItemTest002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    await sleep(200);
    if (receivedCallback && receivedCallback2) {
      console.log(TAG + "Received skipToQueueItem ");
      expect(true).assertTrue();
    } else {
      console.error(TAG + "skipToQueueItem not received");
      expect().assertFail();
    }
    receivedCallback = false;
    receivedCallback2 = false;
    done();
  })

  /*
   * @tc.name:OnSkipToQueueItemTest003
   * @tc.desc:One on functions - one param
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("OnSkipToQueueItemTest003", 0, async function (done) {
    try {
      session.on('skipToQueueItem');
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:OnSkipToQueueItemTest004
   * @tc.desc:One on functions - three params
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("OnSkipToQueueItemTest004", 0, async function (done) {
    try {
      session.on('skipToQueueItem', skipToQueueItemCallback1, skipToQueueItemCallback2);
    } catch (err) {
      expect(err.code == 401).assertTrue();
    }
    done();
  })

  /*
   * @tc.name:GetAVQueueItemsTest001
   * @tc.desc:GetAVQueueItems - callback
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("GetAVQueueItemsTest001", 0, async function (done) {
    session.setAVQueueItems(ITEMS_ARRAY, (err) => {
      if (err) {
        console.error(TAG + "GetAVQueueItemsTest001 error " + JSON.stringify(err));
        expect().assertFail();
        done();
      }
      console.info(TAG + "GetAVQueueItemsTest001 finished");
      expect(true).assertTrue();
      done();
    });
    await sleep(200);
    controller.getAVQueueItems((err) => {
      if (err) {
        console.error(TAG + "getAVQueueItemsTest001 error " + JSON.stringify(err));
        expect().assertFail();
        done();
      }
      console.info(TAG + "getAVQueueItemsTest001 finished");
      expect(true).assertTrue();
      done();
    });
    await sleep(200);
  })

  /*
   * @tc.name:GetAVQueueItemsTest002
   * @tc.desc:GetAVQueueItems - promise
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("GetAVQueueItemsTest002", 0, async function (done) {
    await session.setAVQueueItems(ITEMS_ARRAY).catch((err) => {
      console.error(TAG + "GetAVQueueItemsTest002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    console.info(TAG + "GetAVQueueItemsTest002 finished");
    done();
    await sleep(200);
    await controller.getAVQueueItems().catch((err) => {
      console.error(TAG + "getAVQueueItemsTest002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    console.info(TAG + "getAVQueueItemsTest002 finished");
    done();
    await sleep(200);
  })

  /*
   * @tc.name:GetAVQueueTitleTest001
   * @tc.desc:GetAVQueueTitle - callback
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("GetAVQueueTitleTest001", 0, async function (done) {
    session.setAVQueueTitle(QUEUE_TITLE, (err) => {
      if (err) {
        console.error(TAG + "GetAVQueueTitleTest001 error " + JSON.stringify(err));
        expect().assertFail();
        done();
      }
      console.info(TAG + "GetAVQueueTitleTest001 finished");
      expect(true).assertTrue();
      done();
    });
    await sleep(200);
    controller.getAVQueueTitle((err) => {
      if (err) {
        console.error(TAG + "getAVQueueTitleTest001 error " + JSON.stringify(err));
        expect().assertFail();
        done();
      }
      console.info(TAG + "getAVQueueTitleTest001 finished");
      expect(true).assertTrue();
      done();
    });
    await sleep(200);
  })

  /*
   * @tc.name:GetAVQueueTitleTest002
   * @tc.desc:GetAVQueueTitle - promise
   * @tc.type: FUNC
   * @tc.require: I6KTU4
   */
  it("GetAVQueueTitleTest002", 0, async function (done) {
    await session.setAVQueueTitle(QUEUE_TITLE).catch((err) => {
      console.error(TAG + "GetAVQueueTitleTest002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    console.info(TAG + "GetAVQueueTitleTest002 finished");
    done();
    await sleep(200);
    await controller.getAVQueueTitle().catch((err) => {
      console.error(TAG + "getAVQueueTitleTest002 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    console.info(TAG + "getAVQueueTitleTest002 finished");
    done();
    await sleep(200);
  })

  /*
   * @tc.name:GetAVPlaybackStateSync001
   * @tc.desc:Get av playback state - sync
   * @tc.type: FUNC
   * @tc.require: I7V81A
   */
  it("GetAVPlaybackStateSync001", 0, async function (done) {
    console.info(TAG + "GetAVPlaybackStateSync001 start");
    try {
      let playbackState = {
        state: 0
      }
      await session.setAVPlaybackState(playbackState);
      sleep(200);
      let currentPlaybackState = controller.getAVPlaybackStateSync();
      console.log(`Get playback state: ${playbackState}`);
      expect(currentPlaybackState.state).assertEqual(0);
    } catch (err) {
      expect().assertFail();
    }
    console.info(TAG + "GetAVPlaybackStateSync001 finished");
    done();
  })

  /*
   * @tc.name:GetAVMetadataSync001
   * @tc.desc:Get av metadata - sync
   * @tc.type: FUNC
   * @tc.require: I7V81A
   */
  it("GetAVMetadataSync001", 0, async function (done) {
    console.info(TAG + "GetAVMetadataSync001 start");
    try {
      let metaData = {
        assetId: "0"
      }
      await session.setAVMetadata(metaData);
      sleep(200);
      let currentMetaData = controller.getAVMetadataSync();
      console.log(`Get metadata: ${currentMetaData}`);
      expect(currentMetaData.assetId).assertEqual("0");
    } catch (err) {
      expect().assertFail();
    }
    console.info(TAG + "GetAVMetadataSync001 finished");
    done();
  })

  /*
   * @tc.name:GetAVQueueTitleSync001
   * @tc.desc:Get av queue title - sync
   * @tc.type: FUNC
   * @tc.require: I7V81A
   */
  it("GetAVQueueTitleSync001", 0, async function (done) {
    console.info(TAG + "GetAVQueueTitleSync001 start");
    try {
      await session.setAVQueueTitle(QUEUE_TITLE);
      sleep(200);
      let currentQueueTitle = controller.getAVQueueTitleSync();
      console.log(`Get queue title: ${currentQueueTitle}`);
      expect(currentQueueTitle).assertEqual(QUEUE_TITLE);
    } catch (err) {
      expect().assertFail();
    }
    console.info(TAG + "GetAVQueueTitleSync001 finished");
    done();
  })

  /*
   * @tc.name:GetAVQueueItemSync001
   * @tc.desc:Get av queue item - sync
   * @tc.type: FUNC
   * @tc.require: I7V81A
   */
  it("GetAVQueueItemSync001", 0, async function (done) {
    console.info(TAG + "GetAVQueueItemSync001 start");
    try {
      await session.setAVQueueItems(ITEMS_ARRAY);
      sleep(200);
      let currentQueueItem = controller.getAVQueueItemsSync();
      console.log(`Get queue item: ${currentQueueItem}`);
      expect(currentQueueItem[0].itemId).assertEqual(ITEMS_ARRAY[0].itemId);
    } catch (err) {
      expect().assertFail();
    }
    console.info(TAG + "GetAVQueueItemSync001 finished");
    done();
  })

  /*
   * @tc.name:GetOutputDeviceSync001
   * @tc.desc:Get output device - sync
   * @tc.type: FUNC
   * @tc.require: I7V81A
   */
  it("GetOutputDeviceSync001", 0, async function (done) {
    console.info(TAG + "GetOutputDeviceSync001 start");
    try {
      let outputDeviceInfo = controller.getOutputDeviceSync();
      console.log(`Get output device info: ${outputDeviceInfo}`);
      expect(outputDeviceInfo.devices[0].deviceId).assertEqual("0");
    } catch (err) {
      expect().assertFail();
    }
    console.info(TAG + "GetOutputDeviceSync001 finished");
    done();
  })

  /*
   * @tc.name:IsActiveSync001
   * @tc.desc:Is session active - sync
   * @tc.type: FUNC
   * @tc.require: I7V81A
   */
  it("IsActiveSync001", 0, async function (done) {
    console.info(TAG + "IsActiveSync001 start");
    try {
      await session.activate();
      sleep(200);
      let isActive = controller.isActiveSync();
      console.log(`Get session active state: ${isActive}`);
      expect(isActive).assertEqual(true);
    } catch (err) {
      expect().assertFail();
    }
    console.info(TAG + "IsActiveSync001 finished");
    done();
  })

  /*
   * @tc.name:GetValidCommandsSync001
   * @tc.desc:Get valid commands - sync
   * @tc.type: FUNC
   * @tc.require: I7V81A
   */
  it("GetValidCommandsSync001", 0, async function (done) {
    console.info(TAG + "GetValidCommandsSync001 start");
    try {
      session.on('play', () => {});
      sleep(200);
      let validCommands = controller.getValidCommandsSync();
      console.log(`Get valid commands: ${validCommands}`);
      expect(validCommands[0]).assertEqual('play');
    } catch (err) {
      expect().assertFail();
    }
    console.info(TAG + "GetValidCommandsSync001 finished");
    done();
  })
})
