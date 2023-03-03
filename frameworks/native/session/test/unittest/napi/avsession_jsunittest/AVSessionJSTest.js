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
  const UPDATE_LYRICS_EVENT = "dynamic_lyrics";
  const UPDATE_LYRICS_WANT_PARAMS = {
    lyric: "This is my lyrics"
  }

  beforeAll(async function () {
    session = await avSession.createAVSession(featureAbility.getContext(), "AVSessionDemo", 'audio').catch((err) => {
      console.error(TAG + "Create AVSession error " + JSON.stringify(err));
      expect().assertFail();
    });
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
})
