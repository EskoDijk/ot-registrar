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
import org.junit.Assert;
import org.junit.Test;

public final class JSONTest {

  @Test
  public void testSimple() {
    Gson gson = new Gson();
    String createdOn = new Date().toString();
    String expiresOn = new Date().toString();
    String lastRenewal = new Date().toString();

    HashMap<String, Object> container = new HashMap<>();
    container.put("created-on", createdOn);
    container.put("expires-on", expiresOn);
    container.put("assertion", Voucher.Assertion.VERIFIED.toString());
    container.put("serial-number", "JADA123456789");
    container.put("idevid-issuer", "AQINDw==");
    container.put("pinned-domain-cert", "AQINDw==");
    container.put("domain-cert-revocation-checks", Boolean.FALSE);
    container.put("last-renewal-date", lastRenewal);
    container.put("proximity-registrar-subject-public-key-info", "AQINDw==");

    HashMap<String, HashMap<String, Object>> request = new HashMap<>();
    request.put("constrained-voucher-request", container);

    String jsonStr = gson.toJson(request);

    @SuppressWarnings("unchecked")
    Map<String, Map<String, Object>> request2 =
        (Map<String, Map<String, Object>>) gson.fromJson(jsonStr, Object.class);
    Map<String, Object> container2 = request2.get("constrained-voucher-request");

    // Every key/value the producer put in must round-trip back to the consumer.
    Assert.assertNotNull("missing wrapper key after round-trip", container2);
    Assert.assertEquals(container.size(), container2.size());
    Assert.assertEquals(createdOn, container2.get("created-on"));
    Assert.assertEquals(expiresOn, container2.get("expires-on"));
    Assert.assertEquals(lastRenewal, container2.get("last-renewal-date"));
    Assert.assertEquals(Voucher.Assertion.VERIFIED.toString(), container2.get("assertion"));
    Assert.assertEquals("JADA123456789", container2.get("serial-number"));
    Assert.assertEquals("AQINDw==", container2.get("idevid-issuer"));
    Assert.assertEquals("AQINDw==", container2.get("pinned-domain-cert"));
    Assert.assertEquals(Boolean.FALSE, container2.get("domain-cert-revocation-checks"));
    Assert.assertEquals(
        "AQINDw==", container2.get("proximity-registrar-subject-public-key-info"));
  }
}
