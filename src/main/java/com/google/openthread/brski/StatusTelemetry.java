/*
 *    Copyright (c) 2021, The OpenThread Registrar Authors.
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 */

package com.google.openthread.brski;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;

/**
 * Represents a status telemetry message as received from a Pledge; either enrollment status
 * telemetry or voucher status telemetry.
 */
public class StatusTelemetry {

  /** status field of telemetry report, success (true) or failure (false) */
  public boolean status;

  /** in case of failure (status==false), contains the reason for failure given, if any. */
  public String reason = "";

  /** stores the CBOR object as sent by the Pledge, for reference. */
  public CBORObject cbor = null;

  protected StatusTelemetry() {
    ;
  }

  /**
   * Deserialize a status telemetry report from CBOR bytes.
   *
   * @param data CBOR bytes
   * @return new StatusTelemetry object
   * @throws CBORException if CBOR cannot be parsed from data
   * @throws IllegalArgumentException if CBOR object is missing required fields
   */
  public static StatusTelemetry deserialize(byte[] data) throws CBORException {
    CBORObject stCbor = CBORObject.DecodeFromBytes(data);
    if (stCbor == null || stCbor.size() == 0) {
      throw new IllegalArgumentException(
          "CBOR object is not in status telemetry report format; must be a map");
    }
    if (!stCbor.ContainsKey("status")
        || (!stCbor.get("status").isTrue() && !stCbor.get("status").isFalse())) {
      throw new IllegalArgumentException(
          "'status' field missing or not boolean in status telemetry report");
    }
    StatusTelemetry st = new StatusTelemetry();
    st.status = stCbor.get("status").isTrue();
    st.cbor = stCbor;
    if (stCbor.ContainsKey("reason")) {
      String r;
      try {
        r = stCbor.get("reason").AsString();
      } catch (IllegalStateException ex) {
        r = stCbor.get("reason").toString();
      }
      st.reason = r;
    }
    return st;
  }
}
