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

/**
 * CoAP utilities for BRSKI/cBRSKI/Registrar.
 * Includes bidirectional mapping between HTTP status codes and CoAP {@link ResponseCode}s,
 * following RFC 8075 §7.
 */
public final class CoapUtils {

  private CoapUtils() {}

  /**
   * Convert an HTTP status code to a CoAP {@link ResponseCode}.
   * Returns {@link ResponseCode#INTERNAL_SERVER_ERROR} for inputs without
   * a meaningful CoAP class (e.g. {@code 1xx}).
   */
  public static ResponseCode httpToCoap(int httpStatus) {
    switch (httpStatus) {
      case 200: return ResponseCode.CHANGED;                     // POST-success (BRSKI)
      case 201: return ResponseCode.CREATED;
      case 202: return ResponseCode.CHANGED;                     // no exact CoAP equivalent
      case 204: return ResponseCode.DELETED;
      case 304: return ResponseCode.VALID;
      case 400: return ResponseCode.BAD_REQUEST;
      case 401: return ResponseCode.UNAUTHORIZED;
      case 403: return ResponseCode.FORBIDDEN;
      case 404: return ResponseCode.NOT_FOUND;
      case 405: return ResponseCode.METHOD_NOT_ALLOWED;
      case 406: return ResponseCode.NOT_ACCEPTABLE;
      case 409: return ResponseCode.CONFLICT;
      case 412: return ResponseCode.PRECONDITION_FAILED;
      case 413: return ResponseCode.REQUEST_ENTITY_TOO_LARGE;
      case 415: return ResponseCode.UNSUPPORTED_CONTENT_FORMAT;
      case 422: return ResponseCode.UNPROCESSABLE_ENTITY;
      case 429: return ResponseCode.TOO_MANY_REQUESTS;
      case 500: return ResponseCode.INTERNAL_SERVER_ERROR;
      case 501: return ResponseCode.NOT_IMPLEMENTED;
      case 502: return ResponseCode.BAD_GATEWAY;
      case 503: return ResponseCode.SERVICE_UNAVAILABLE;
      case 504: return ResponseCode.GATEWAY_TIMEOUT;
      default:
        if (httpStatus >= 400 && httpStatus < 500) return ResponseCode.BAD_REQUEST;
        if (httpStatus >= 500 && httpStatus < 600) return ResponseCode.INTERNAL_SERVER_ERROR;
        if (httpStatus >= 200 && httpStatus < 300) return ResponseCode.CHANGED;
        return ResponseCode.INTERNAL_SERVER_ERROR;
    }
  }

  /**
   * Convert a CoAP {@link ResponseCode} to an HTTP status code.
   * Returns 0 if {@code code} is null. Codes without an exact HTTP peer fall back
   * to the {@code *00} of the same class (400 / 500).
   */
  public static int coapToHttp(ResponseCode code) {
    if (code == null) return 0;
    switch (code) {
      case CREATED:                     return 201;
      case DELETED:                     return 204;
      case VALID:                       return 304;
      case CHANGED:                     return 200;              // POST-success (BRSKI)
      case CONTENT:                     return 200;              // GET-success
      case CONTINUE:                    return 100;
      case BAD_REQUEST:                 return 400;
      case UNAUTHORIZED:                return 401;              // 403 is an alternative
      case BAD_OPTION:                  return 400;              // no HTTP equivalent
      case FORBIDDEN:                   return 403;
      case NOT_FOUND:                   return 404;
      case METHOD_NOT_ALLOWED:          return 405;
      case NOT_ACCEPTABLE:              return 406;
      case REQUEST_ENTITY_INCOMPLETE:   return 408;              // questionable
      case CONFLICT:                    return 409;
      case PRECONDITION_FAILED:         return 412;
      case REQUEST_ENTITY_TOO_LARGE:    return 413;
      case UNSUPPORTED_CONTENT_FORMAT:  return 415;
      case UNPROCESSABLE_ENTITY:        return 422;
      case TOO_MANY_REQUESTS:           return 429;
      case INTERNAL_SERVER_ERROR:       return 500;
      case NOT_IMPLEMENTED:             return 501;
      case BAD_GATEWAY:                 return 502;
      case SERVICE_UNAVAILABLE:         return 503;
      case GATEWAY_TIMEOUT:             return 504;
      case PROXY_NOT_SUPPORTED:         return 502;              // closest HTTP analogue (RFC 8075)
      default:
        // Fall back by CoAP class
        switch (code.codeClass) {
          case 2: return 200;
          case 4: return 400;
          case 5: return 500;
          default: return 500;
        }
    }
  }
}
