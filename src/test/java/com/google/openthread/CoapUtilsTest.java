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

package com.google.openthread;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.junit.Assert;
import org.junit.Test;

public class CoapUtilsTest {

  @Test
  public void httpToCoap_exactMappings() {
    Assert.assertEquals(ResponseCode.CHANGED,                    CoapUtils.httpToCoap(200));
    Assert.assertEquals(ResponseCode.CREATED,                    CoapUtils.httpToCoap(201));
    Assert.assertEquals(ResponseCode.DELETED,                    CoapUtils.httpToCoap(204));
    Assert.assertEquals(ResponseCode.VALID,                      CoapUtils.httpToCoap(304));
    Assert.assertEquals(ResponseCode.BAD_REQUEST,                CoapUtils.httpToCoap(400));
    Assert.assertEquals(ResponseCode.UNAUTHORIZED,               CoapUtils.httpToCoap(401));
    Assert.assertEquals(ResponseCode.FORBIDDEN,                  CoapUtils.httpToCoap(403));
    Assert.assertEquals(ResponseCode.NOT_FOUND,                  CoapUtils.httpToCoap(404));
    Assert.assertEquals(ResponseCode.METHOD_NOT_ALLOWED,         CoapUtils.httpToCoap(405));
    Assert.assertEquals(ResponseCode.NOT_ACCEPTABLE,             CoapUtils.httpToCoap(406));
    Assert.assertEquals(ResponseCode.CONFLICT,                   CoapUtils.httpToCoap(409));
    Assert.assertEquals(ResponseCode.PRECONDITION_FAILED,        CoapUtils.httpToCoap(412));
    Assert.assertEquals(ResponseCode.REQUEST_ENTITY_TOO_LARGE,   CoapUtils.httpToCoap(413));
    Assert.assertEquals(ResponseCode.UNSUPPORTED_CONTENT_FORMAT, CoapUtils.httpToCoap(415));
    Assert.assertEquals(ResponseCode.UNPROCESSABLE_ENTITY,       CoapUtils.httpToCoap(422));
    Assert.assertEquals(ResponseCode.TOO_MANY_REQUESTS,          CoapUtils.httpToCoap(429));
    Assert.assertEquals(ResponseCode.INTERNAL_SERVER_ERROR,      CoapUtils.httpToCoap(500));
    Assert.assertEquals(ResponseCode.NOT_IMPLEMENTED,            CoapUtils.httpToCoap(501));
    Assert.assertEquals(ResponseCode.BAD_GATEWAY,                CoapUtils.httpToCoap(502));
    Assert.assertEquals(ResponseCode.SERVICE_UNAVAILABLE,        CoapUtils.httpToCoap(503));
    Assert.assertEquals(ResponseCode.GATEWAY_TIMEOUT,            CoapUtils.httpToCoap(504));
  }

  @Test
  public void httpToCoap_unknown4xxFallsBackToBadRequest() {
    Assert.assertEquals(ResponseCode.BAD_REQUEST, CoapUtils.httpToCoap(408)); // Request Timeout
    Assert.assertEquals(ResponseCode.BAD_REQUEST, CoapUtils.httpToCoap(411)); // Length Required
    Assert.assertEquals(ResponseCode.BAD_REQUEST, CoapUtils.httpToCoap(414)); // URI Too Long
  }

  @Test
  public void httpToCoap_unknown5xxFallsBackToInternalServerError() {
    Assert.assertEquals(ResponseCode.INTERNAL_SERVER_ERROR, CoapUtils.httpToCoap(505)); // Version Not Supported
  }

  @Test
  public void httpToCoap_unknown2xxFallsBackToChanged() {
    Assert.assertEquals(ResponseCode.CHANGED, CoapUtils.httpToCoap(299));
  }

  @Test
  public void httpToCoap_1xxFallsBackToInternalServerError() {
    // 1xx codes have no meaningful CoAP class for a response; surface as a server error.
    Assert.assertEquals(ResponseCode.INTERNAL_SERVER_ERROR, CoapUtils.httpToCoap(100));
  }

  @Test
  public void coapToHttp_exactMappings() {
    Assert.assertEquals(201, CoapUtils.coapToHttp(ResponseCode.CREATED));
    Assert.assertEquals(204, CoapUtils.coapToHttp(ResponseCode.DELETED));
    Assert.assertEquals(304, CoapUtils.coapToHttp(ResponseCode.VALID));
    Assert.assertEquals(200, CoapUtils.coapToHttp(ResponseCode.CHANGED));
    Assert.assertEquals(200, CoapUtils.coapToHttp(ResponseCode.CONTENT));
    Assert.assertEquals(100, CoapUtils.coapToHttp(ResponseCode.CONTINUE));
    Assert.assertEquals(400, CoapUtils.coapToHttp(ResponseCode.BAD_REQUEST));
    Assert.assertEquals(401, CoapUtils.coapToHttp(ResponseCode.UNAUTHORIZED));
    Assert.assertEquals(403, CoapUtils.coapToHttp(ResponseCode.FORBIDDEN));
    Assert.assertEquals(404, CoapUtils.coapToHttp(ResponseCode.NOT_FOUND));
    Assert.assertEquals(405, CoapUtils.coapToHttp(ResponseCode.METHOD_NOT_ALLOWED));
    Assert.assertEquals(406, CoapUtils.coapToHttp(ResponseCode.NOT_ACCEPTABLE));
    Assert.assertEquals(408, CoapUtils.coapToHttp(ResponseCode.REQUEST_ENTITY_INCOMPLETE));
    Assert.assertEquals(409, CoapUtils.coapToHttp(ResponseCode.CONFLICT));
    Assert.assertEquals(412, CoapUtils.coapToHttp(ResponseCode.PRECONDITION_FAILED));
    Assert.assertEquals(413, CoapUtils.coapToHttp(ResponseCode.REQUEST_ENTITY_TOO_LARGE));
    Assert.assertEquals(415, CoapUtils.coapToHttp(ResponseCode.UNSUPPORTED_CONTENT_FORMAT));
    Assert.assertEquals(422, CoapUtils.coapToHttp(ResponseCode.UNPROCESSABLE_ENTITY));
    Assert.assertEquals(429, CoapUtils.coapToHttp(ResponseCode.TOO_MANY_REQUESTS));
    Assert.assertEquals(500, CoapUtils.coapToHttp(ResponseCode.INTERNAL_SERVER_ERROR));
    Assert.assertEquals(501, CoapUtils.coapToHttp(ResponseCode.NOT_IMPLEMENTED));
    Assert.assertEquals(502, CoapUtils.coapToHttp(ResponseCode.BAD_GATEWAY));
    Assert.assertEquals(503, CoapUtils.coapToHttp(ResponseCode.SERVICE_UNAVAILABLE));
    Assert.assertEquals(504, CoapUtils.coapToHttp(ResponseCode.GATEWAY_TIMEOUT));
  }

  @Test
  public void coapToHttp_nullReturnsZero() {
    Assert.assertEquals(0, CoapUtils.coapToHttp(null));
  }

  @Test
  public void coapToHttp_noExactPeerFallsBackToClassDefault() {
    // 4.02 BAD_OPTION and 5.05 PROXY_NOT_SUPPORTED have no exact HTTP peer;
    // they should still produce a plausible 4xx/5xx.
    Assert.assertEquals(400, CoapUtils.coapToHttp(ResponseCode.BAD_OPTION));
    Assert.assertEquals(502, CoapUtils.coapToHttp(ResponseCode.PROXY_NOT_SUPPORTED));
  }

  @Test
  public void roundTrip_brskiCodes() {
    // The codes BRSKI actually emits should round-trip cleanly.
    int[] httpCodes = {200, 201, 304, 400, 401, 403, 404, 415, 500};
    for (int http : httpCodes) {
      int round = CoapUtils.coapToHttp(CoapUtils.httpToCoap(http));
      Assert.assertEquals("HTTP " + http + " round-trip", http, round);
    }
  }
}
