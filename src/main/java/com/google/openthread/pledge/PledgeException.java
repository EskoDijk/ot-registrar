/*
 *    Copyright (c) 2019, The OpenThread Registrar Authors.
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

package com.google.openthread.pledge;

import java.nio.charset.StandardCharsets;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;

public final class PledgeException extends Exception {

  private static final long serialVersionUID = -1980574489782019605L;

  /**
   * An optional CoAP response code, from a CoAP response, that was unexpected
   * or related to the exception. {@code null} when no CoAP context applies.
   */
  private final ResponseCode code;

  public PledgeException(String msg) {
    this(msg, (ResponseCode) null, null);
  }

  public PledgeException(String msg, Throwable cause) {
    super(msg, cause);
    this.code = null;
  }

  public PledgeException(String msg, CoapResponse resp) {
    this(msg, resp.getCode(),
        (resp.getCode() != null && resp.getPayload() != null)
            ? new String(resp.getPayload(), StandardCharsets.UTF_8)
            : null);
  }

  public PledgeException(String msg, ResponseCode coapCode, String coapDiagnosticMsg) {
    super(formatMessage(msg, coapCode, coapDiagnosticMsg));
    this.code = coapCode;
  }

  public ResponseCode getCode() {
    return code;
  }

  private static String formatMessage(String msg, ResponseCode coapCode, String coapDiagnosticMsg) {
    StringBuilder sb = new StringBuilder(msg);
    if (coapCode != null) {
      sb.append(" (").append(coapCode).append(")");
    }
    if (coapDiagnosticMsg != null) {
      sb.append(" - CoAP diagnostic: '").append(coapDiagnosticMsg).append("'");
    }
    return sb.toString();
  }
}
