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

import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;

public class PledgeException extends Exception {

  /**
   * An optional CoAP response code, from a CoAP response, that was unexpected or related to the exception.
   */
  public ResponseCode code = null;

  /**
   * An optional CoAP diagnostic message, from a CoAP response, to clarify what went wrong.
   */
  public String diagMsg = null;

  public PledgeException(String msg) {
    this(msg, null, null);
  }

  public PledgeException(String msg, CoapResponse resp) {
    super(msg + ((resp.getCode() != null) ? (" (" + resp.getCode().toString() + ")") : "")
        + ((resp.getCode() != null && resp.getPayload() != null)
        ? (" - CoAP diagnostic: '" + new String(resp.getPayload()) + "'") : ""));
    this.code = resp.getCode();
    if (!ResponseCode.isSuccess(this.code) && resp.getPayload() != null) {
      this.diagMsg = new String(resp.getPayload());
    }
  }

  public PledgeException(String msg, ResponseCode coapCode, String coapDiagnosticMsg) {
    // FIXME
  }

  private static final long serialVersionUID = -1980574489782019605L;
}
