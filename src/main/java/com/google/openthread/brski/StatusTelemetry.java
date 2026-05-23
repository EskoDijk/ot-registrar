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
 * Represents a status telemetry message as received from a Pledge — either
 * voucher-status (RFC 8995 §5.7) or enrollment-status (RFC 8995 §5.9). The
 * payload is a CBOR map with {@code version} (=1), {@code status} (Boolean),
 * and {@code reason} (string, required when {@code status==false}).
 */
public final class StatusTelemetry {

  // --- CBOR map keys / version literal ---------------------------------
  private static final String K_VERSION = "version";
  private static final String K_STATUS = "status";
  private static final String K_REASON = "reason";
  private static final int VERSION = 1;

  /** Sentinel for "no telemetry received yet" / "not yet parsed". */
  public static final StatusTelemetry UNDEFINED =
      new StatusTelemetry(false, null, false, "UNDEFINED", null);

  private final boolean status;
  private final String reason;
  private final boolean validFormat;
  private final String parseResultStatus;
  private final CBORObject cbor;

  private StatusTelemetry(
      boolean status, String reason, boolean validFormat, String parseResultStatus, CBORObject cbor) {
    this.status = status;
    this.reason = reason;
    this.validFormat = validFormat;
    this.parseResultStatus = parseResultStatus;
    this.cbor = cbor;
  }

  /**
   * Create a new StatusTelemetry object with given state info.
   *
   * @param isSuccess true if status should indicate success, false otherwise.
   * @param reason    required human-readable failure reason if {@code isSuccess==false},
   *                  should be null otherwise (but not necessarily).
   * @return New StatusTelemetry object.
   */
  public static StatusTelemetry create(boolean isSuccess, String reason) {
    boolean valid = isSuccess || (reason != null && !reason.isEmpty());
    return new StatusTelemetry(isSuccess, reason, valid, "", null);
  }

  /**
   * Deserialize a status telemetry report from CBOR bytes. In case of invalid
   * {@code data} (invalid CBOR or wrong report shape), the returned object's
   * {@link #isValidFormat()} is false and {@link #getParseResultStatus()}
   * carries a human-readable explanation.
   *
   * @param data CBOR bytes of an encoded status telemetry object
   * @return New StatusTelemetry object
   */
  public static StatusTelemetry deserialize(byte[] data) {
    boolean status = false;
    String reason = null;
    boolean validFormat = true;
    String parseResultStatus = "";
    CBORObject cbor = null;

    try {
      CBORObject stCbor = CBORObject.DecodeFromBytes(data);
      if (stCbor == null
          || stCbor.size() == 0
          || !stCbor.ContainsKey(K_VERSION)
          || !stCbor.get(K_VERSION).equals(CBORObject.FromObject(VERSION))) {
        return new StatusTelemetry(
            false, null, false, "CBOR object not in correct status telemetry report format", null);
      }
      cbor = stCbor;

      // status field — required Boolean. Be lenient about integer 0/1 from
      // non-conforming Pledges, but flag the message as invalid format.
      CBORObject statusVal = stCbor.get(K_STATUS);
      if (statusVal == null) {
        return new StatusTelemetry(
            false, null, false, "'status' field missing in status telemetry report", cbor);
      }
      if (statusVal.isTrue() || statusVal.isFalse()) {
        status = statusVal.isTrue();
      } else if (statusVal.equals(CBORObject.FromObject(1))
          || statusVal.equals(CBORObject.FromObject(0))) {
        status = statusVal.equals(CBORObject.FromObject(1));
        validFormat = false;
        parseResultStatus = "'status' field must use Boolean value instead of Int";
      } else {
        return new StatusTelemetry(
            false, null, false, "'status' field not boolean in status telemetry report", cbor);
      }

      // reason field — optional, string-typed.
      if (stCbor.ContainsKey(K_REASON)) {
        CBORObject reasonVal = stCbor.get(K_REASON);
        try {
          reason = reasonVal.AsString();
        } catch (IllegalStateException ex) {
          reason = reasonVal.toString();
          validFormat = false;
          parseResultStatus = "'reason' field has wrong value format, must be String";
        }
      }
    } catch (CBORException ex) {
      return new StatusTelemetry(false, null, false, "Not a valid CBOR object", null);
    }

    // post-conditions
    if (validFormat && !status && (reason == null || reason.isEmpty())) {
      validFormat = false;
      parseResultStatus = "'reason' field must be provided if status==false";
    }

    return new StatusTelemetry(status, reason, validFormat, parseResultStatus, cbor);
  }

  /**
   * Serialize the current status telemetry report into CBORObject.
   *
   * @return status telemetry report as CBORObject.
   */
  public CBORObject serialize() {
    CBORObject o = CBORObject.NewMap();
    o.Add(K_VERSION, CBORObject.FromObject(VERSION));
    o.Add(K_STATUS, CBORObject.FromObject(status));
    if (reason != null) {
      o.Add(K_REASON, CBORObject.FromObject(reason));
    }
    return o;
  }

  /**
   * Serialize the current status telemetry report into CBOR bytes.
   *
   * @return status telemetry report as bytes.
   */
  public byte[] serializeToBytes() {
    return serialize().EncodeToBytes();
  }

  public boolean isStatus() {
    return status;
  }

  public String getReason() {
    return reason;
  }

  public boolean isValidFormat() {
    return validFormat;
  }

  public String getParseResultStatus() {
    return parseResultStatus;
  }

  public CBORObject getCbor() {
    return cbor;
  }

  @Override
  public String toString() {
    if (this == UNDEFINED) {
      return "UNDEFINED";
    }
    StringBuilder s = new StringBuilder("{status=").append(status);
    if (reason != null) {
      s.append(", reason=").append(reason);
    }
    if (!validFormat) {
      s.append(" (INVALID: ").append(parseResultStatus).append(")");
    }
    return s.append("}").toString();
  }
}
