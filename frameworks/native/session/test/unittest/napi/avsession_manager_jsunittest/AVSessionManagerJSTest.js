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

import AVSessionManager from '@ohos.multimedia.avsession';
import featureAbility from '@ohos.ability.featureAbility';
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index';


const TAG = "[AVSessionManagerJSTest]";

describe("AVSessionManagerJSTest", function () {
  let session = null;
  let controller = null;
  let receivedCallback = false;
  let receivedCallback2 = false;
  let context = featureAbility.getContext();

  const INVALID_STRING = "invalid string";
  const UPDATE_LYRICS_EVENT = "dynamic_lyrics";
  const UPDATE_LYRICS_WANT_PARAMS = {
    lyrics: "This is my lyrics"
  }

  beforeAll(async function () {
    console.info(TAG + "beforeAll called");
  })

  afterAll(function () {
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

  async function createSessionTask() {
    session = await AVSessionManager.createAVSession(context, "AVSessionDemo", 'audio').catch((err) => {
      console.error(TAG + "Create AVSession error " + JSON.stringify(err));
      expect().assertFail();
    });
    console.info(TAG + "Create session finished");
  }

  function destroySessionTask() {
    session.destroy();
    console.info(TAG + 'Destroy session finished');
  }

  async function createControllerTask() {
    controller = await AVSessionManager.createController(session.sessionId).catch((err) => {
      console.error(TAG + "Create controller error " + JSON.stringify(err));
      expect().assertFail();
    });
    console.info(TAG + "Create controller finished");
  }

  function destroyControllerTask() {
    controller.destroy();
    console.info(TAG + 'Destroy session finished');
  }

  /*
   * @tc.name:GetHistoricalSessionDescriptors
   * @tc.desc:One on function - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("GetHistoricalSessionDescriptors001", 0, async function (done) {
    await createSessionTask();
    let descriptors = await AVSessionManager.getHistoricalSessionDescriptors().catch((err) => {
      console.error(TAG + "getHistoricalSessionDescriptors001 error " + JSON.stringify(err));
      expect().assertFail();
      destroySessionTask();
      done();
    });
    if (descriptors.length >= 1) {
        expect(true).assertTrue();
    } else {
        console.error(TAG + " get history session number : " + descriptors.length + ", error ");
        expect().assertFail();
    }
    destroySessionTask();
    done();
  })

  /*
   * @tc.name:getHistoricalSessionDescriptors002
   * @tc.desc:One on function - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("getHistoricalSessionDescriptors002", 0, async function (done) {
    await createSessionTask();
    let descriptors = await AVSessionManager.getHistoricalSessionDescriptors(10).catch((err) => {
      console.error(TAG + "getHistoricalSessionDescriptors002 error " + JSON.stringify(err));
      expect().assertFail();
      destroySessionTask();
      done();
    });
    if (descriptors.length >= 1) {
        expect(true).assertTrue();
    } else {
        console.error(TAG + " 002 get history session number : " + descriptors.length + ", error ");
        expect().assertFail();
    }
    destroySessionTask();
    done();
  })

  /*
   * @tc.name:getHistoricalSessionDescriptors003
   * @tc.desc:One on function - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("getHistoricalSessionDescriptors003", 0, async function (done) {
    await createSessionTask();
    let descriptors = await AVSessionManager.getHistoricalSessionDescriptors(0).catch((err) => {
      console.error(TAG + "getHistoricalSessionDescriptors003 error " + JSON.stringify(err));
      expect().assertFail();
      destroySessionTask();
      done();
    });
    if (descriptors.length == 0) {
        expect(true).assertTrue();
    } else {
        console.error(TAG + " 003 get history session number : " + descriptors.length + ", error ");
        expect().assertFail();
    }
    destroySessionTask();
    done();
  })

  /*
   * @tc.name:getHistoricalSessionDescriptors004
   * @tc.desc:One on function - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("getHistoricalSessionDescriptors004", 0, async function (done) {
    let flag = false;
    await createSessionTask();
    let descriptors = await AVSessionManager.getHistoricalSessionDescriptors("0").catch((err) => {
      flag = true;
      console.error(TAG + "getHistoricalSessionDescriptors004 param error " + JSON.stringify(err));
      expect(true).assertTrue();
      destroySessionTask();
      done();
    });
    if (flag || (!descriptors)) {
      console.error(TAG + " error input param has callback , pass");
      expect(true).assertTrue();
      destroySessionTask();
      done();
    } else {
      console.error(TAG + " error input param should not return , error");
      expect().assertFail();
      destroySessionTask();
      done();
    }
  })

  /*
   * @tc.name:getHistoricalSessionDescriptors005
   * @tc.desc:One on function - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("getHistoricalSessionDescriptors005", 0, async function (done) {
    await createSessionTask();
    await AVSessionManager.getHistoricalSessionDescriptors((err, data) => {
      if (err) {
        console.error(TAG + "getHistoricalSessionDescriptors005 error " + JSON.stringify(err));
        expect().assertFail();
        destroySessionTask();
        done();
      }
      console.error(TAG + "getHistoricalSessionDescriptors005 return :" + data);
      if (data.length >= 1) {
        expect(true).assertTrue();
      } else {
          console.error(TAG + " get history session number : " + data.length + ", error ");
          expect().assertFail();
      }
      destroySessionTask();
      done();
    });
  })

  /*
   * @tc.name:getHistoricalSessionDescriptors006
   * @tc.desc:One on function - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("getHistoricalSessionDescriptors006", 0, async function (done) {
    await createSessionTask();
    destroySessionTask();
    let descriptors = await AVSessionManager.getHistoricalSessionDescriptors().catch((err) => {
      console.error(TAG + "getHistoricalSessionDescriptors006 error " + JSON.stringify(err));
      expect().assertFail();
      destroySessionTask();
      done();
    });
    if (descriptors.length >= 1) {
        expect(true).assertTrue();
    } else {
        console.error(TAG + " get history session number : " + descriptors.length + ", error ");
        expect().assertFail();
    }
    destroySessionTask();
    done();
  })

  /*
   * @tc.name:getHistoricalSessionDescriptors007
   * @tc.desc:One on function - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("getHistoricalSessionDescriptors007", 0, async function (done) {
    let descriptors = await AVSessionManager.getHistoricalSessionDescriptors().catch((err) => {
      console.error(TAG + "getHistoricalSessionDescriptors007 error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    let size = descriptors.length;
    await createSessionTask();
    destroySessionTask();
    let descriptorsRetry = await AVSessionManager.getHistoricalSessionDescriptors().catch((err) => {
      console.error(TAG + "getHistoricalSessionDescriptors007 retry error " + JSON.stringify(err));
      expect().assertFail();
      done();
    });
    if (descriptorsRetry.length >= size) {
        expect(true).assertTrue();
    } else {
        console.error(TAG + " get history session number : " + descriptors.length + ", error ");
        expect().assertFail();
    }
    done();
  })

  /*
   * @tc.name:getHistoricalSessionDescriptors008
   * @tc.desc:One on function - lyrics session event
   * @tc.type: FUNC
   * @tc.require: I6C6IN
   */
  it("getHistoricalSessionDescriptors008", 0, async function (done) {
    await createSessionTask();
    for (let i = 0; i < 100; i ++) {
      let descriptors = await AVSessionManager.getHistoricalSessionDescriptors().catch((err) => {
        console.error(TAG + " loop : " + i + ", getHistoricalSessionDescriptors008 error " + JSON.stringify(err));
        expect().assertFail();
        destroySessionTask();
        done();
      });
      if (descriptors.length >= 1) {
          expect(true).assertTrue();
      } else {
          console.error(TAG + " loop : " + i + ", get history session number : " + descriptors.length + ", error ");
          expect().assertFail();
          destroySessionTask();
          done();
      }
    }
    destroySessionTask();
    done();
  })
})