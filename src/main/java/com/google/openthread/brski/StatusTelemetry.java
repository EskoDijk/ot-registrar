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

  /** single instance representing an 'undefined' status telemetry, e.g. a not-yet-parsed one. */
  public static final StatusTelemetry UNDEFINED = new StatusTelemetry();

  /** status field of telemetry report by Pledge, success (true) or failure (false) */
  public boolean status;

  /**
   * in case of failure (status==false), contains the reason for failure given by Pledge, if any
   * given.
   */
  public String reason = "";

  /** keep track of whether the telemetry report was in 100% valid format, or not. */
  public boolean isValidFormat = false;

  /** store message on result of parsing of telemetry message by this class */
  public String parseResultStatus = "";

  /**
   * stores the CBOR object as sent by the Pledge, for reference. Null if couldn't be parsed as
   * CBOR.
   */
  public CBORObject cbor = null;

  protected StatusTelemetry() {
    ;
  }

  /**
   * Deserialize a status telemetry report from CBOR bytes. In case of invalid 'data', i.e. invalid
   * CBOR format or invalid report format, flags in the StatusTelemetry object are set to indicate
   * this.
   *
   * @param data CBOR bytes
   * @return new StatusTelemetry object
   */
  public static StatusTelemetry deserialize(byte[] data) {
    StatusTelemetry st = new StatusTelemetry();
    boolean isValidFormat = true;
    try {
      CBORObject stCbor = CBORObject.DecodeFromBytes(data);
      if (stCbor == null || stCbor.size() == 0) {
        isValidFormat = false;
        st.parseResultStatus =
            "CBOR object is not in status telemetry report format; it should be a map";
        return st;
      }

      // getting status report from the data
      if (!stCbor.ContainsKey("status")
          || (!stCbor.get("status").isTrue() && !stCbor.get("status").isFalse())) {
        isValidFormat = false;
        st.parseResultStatus = "'status' field missing or not boolean in status telemetry report";
      }
      st.status = stCbor.get("status").isTrue();
      // Note: should be boolean, but for testing/leniency purposes the Registrar will accept int
      // '1' as well.
      // this will be logged though as invalid format usage by Pledge.
      if (stCbor.get("status").equals(CBORObject.FromObject(1))) {
        isValidFormat = false;
        st.status = true;
      }

      // store the cbor object
      st.cbor = stCbor;

      // get reason from data
      if (stCbor.ContainsKey("reason")) {
        String r;
        try {
          r = stCbor.get("reason").AsString();
        } catch (IllegalStateException ex) {
          r = stCbor.get("reason").toString();
          isValidFormat = false;
        }
        st.reason = r;
      }
    } catch (CBORException ex) {
      st.parseResultStatus = "Not a valid CBOR object";
      isValidFormat = false;
    }

    // evaluate cases of valid format.
    if (isValidFormat && ((st.status == false && st.reason.length() > 0) || (st.status == true)))
      st.isValidFormat = true;

    return st;
  }
}
