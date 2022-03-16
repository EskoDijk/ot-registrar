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

import com.google.gson.Gson;
import com.google.openthread.brski.Voucher;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public class JSONTest {

  /** * Utility class defining the structure of the Voucher. */
  @SuppressWarnings("serial")
  class GsonVoucher extends HashMap<String, HashMap<String, Object>> {
    //
  }

  @Test
  public void testSimple() {
    Gson gson = new Gson();
    GsonVoucher request = new GsonVoucher();
    HashMap<String, Object> container = new HashMap<String, Object>();
    container.put("created-on", (new Date()).toString());
    container.put("expires-on", (new Date()).toString());
    container.put("assertion", Voucher.Assertion.VERIFIED.toString());
    container.put("serial-number", "JADA123456789");
    container.put("idevid-issuer", "AQINDw==");
    container.put("pinned-domain-cert", "AQINDw==");
    container.put("domain-cert-revocation-checks", Boolean.FALSE);
    container.put("last-renewal-date", (new Date()).toString());
    container.put("proximity-registrar-subject-public-key-info", "AQINDw==");
    request.put("constrained-voucher-request", container);

    // serialize request to JSON
    String jsonStr = gson.toJson(request);
    System.out.println(jsonStr);
    System.out.println("\n");

    // unserialize from JSON to request2
    Object o =
        gson.fromJson(
            jsonStr, Object.class); // use 'Object' class, to avoid casting runtime errors.
    o.toString(); // dummy test

    // access the individual container elements again
    @SuppressWarnings("unchecked")
    Map<String, Map<String, Object>> request2 = (Map<String, Map<String, Object>>) o;
    Map<String, Object> container2 = request2.get("constrained-voucher-request");
    for (String key : container2.keySet()) {
      Object val = container2.get(key);
      System.out.println(key + "=" + val);
    }
  }

  public static void main(String args[]) {
    new JSONTest().testSimple();
  }
}
