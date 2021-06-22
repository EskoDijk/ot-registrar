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

package com.google.openthread.brski;

import java.util.HashMap;
import java.util.Map;

public class ConstrainedVoucherRequest extends ConstrainedVoucher {

  public static final int VOUCHER_REQUEST_SID = 2501;

  @SuppressWarnings("serial")
  protected static final Map<String, Integer> voucherRequestSIDMap = new HashMap<String, Integer>() {
    {
      put(VOUCHER_REQUEST, VOUCHER_REQUEST_SID);
      put(ASSERTION, VOUCHER_REQUEST_SID + 1);
      put(CREATED_ON, VOUCHER_REQUEST_SID + 2);
      put(DOMAIN_CERT_REVOCATION_CHECKS, VOUCHER_REQUEST_SID + 3);
      put(EXPIRES_ON, VOUCHER_REQUEST_SID + 4);
      put(IDEVID_ISSUER, VOUCHER_REQUEST_SID + 5);
      put(LAST_RENEWAL_DATE, VOUCHER_REQUEST_SID + 6);
      put(NONCE, VOUCHER_REQUEST_SID + 7);
      put(PINNED_DOMAIN_CERT, VOUCHER_REQUEST_SID + 8);
      put(PRIOR_SIGNED_VOUCHER_REQUEST, VOUCHER_REQUEST_SID + 9);
      put(PROXIMITY_REGISTRAR_CERT, VOUCHER_REQUEST_SID + 10);
      put(SHA256_REGISTRAR_SPKI, VOUCHER_REQUEST_SID + 11);
      put(PROXIMITY_REGISTRAR_SPKI, VOUCHER_REQUEST_SID + 12);
      put(SERIAL_NUMBER, VOUCHER_REQUEST_SID + 13);
    }
  };

  public ConstrainedVoucherRequest() {
    sidMap = voucherRequestSIDMap;
    baseSid = VOUCHER_REQUEST_SID;
  }

  @Override
  public boolean validate() {
    if (serialNumber == null) {
      return false;
    }
    if (expiresOn != null && nonce != null) {
      return false;
    }
    if (lastRenewalDate != null && expiresOn == null) {
      return false;
    }
    if (assertion == Assertion.PROXIMITY && proximityRegistrarSPKI == null) {
      return false;
    }
    return true;
  }

  @Override
  public String getName() {
    return VOUCHER_REQUEST;
  }
}
