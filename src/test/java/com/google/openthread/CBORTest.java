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

import com.google.openthread.brski.Voucher;
import com.upokecenter.cbor.CBORObject;
import java.util.Date;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

public class CBORTest {

  @Test
  public void testSimple() {
    CBORObject request = CBORObject.NewMap();
    CBORObject container = CBORObject.NewMap();
    container.Add("created-on", (new Date()).toString());
    container.Add("expires-on", (new Date()).toString());
    container.Add("assertion", Voucher.Assertion.VERIFIED.toString());
    container.Add("serial-number", "JADA123456789");
    container.Add("idevid-issuer", Hex.decode("01020D0F"));
    container.Add(
        "pinned-domain-cert",
        Hex.decode(
            "308202753082021ca00302010202147056eaaa3066d8826a555b9088d462bf9cf28cfd300a06082a8648ce3d0403023073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c301e170d3230313230393130303233365a170d3231313230393130303233365a3073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c3059301306072a8648ce3d020106082a8648ce3d03010703420004507ac8491a8c69c7b5c31d0309ed35ba13f5884ce62b88cf3018154fa059b020ec6bebb94e02b8934021898da789c711cea71339f50e348edf0d923ed02dc7b7a3818d30818a301d0603551d0e0416041408c2bf36887f79412185872f16a7aca6efb3d2b3301f0603551d2304183016801408c2bf36887f79412185872f16a7aca6efb3d2b3300f0603551d130101ff040530030101ff30270603551d250420301e06082b0601050507031c06082b0601050507030106082b06010505070302300e0603551d0f0101ff0404030201f6300a06082a8648ce3d04030203470030440220744c99008513b2f1bcfdf9021a46fb174cf883a27ca1d93faeacf31e4edd12c60220114714dbf51a5e78f581b9421c6e4702ab537270c5bafb2d16c3de9aa182c35f"));
    container.Add("domain-cert-revocation-checks", false);
    container.Add("last-renewal-date", (new Date()).toString());
    container.Add("proximity-registrar-subject-public-key-info", Hex.decode("01020D0F"));
    request.Add("constrained-voucher-request", container);

    String jsonStr = request.ToJSONString();
    CBORObject.FromJSONString(jsonStr);
  }

  @Test
  public void testIntegralTypeDetection() {
    CBORObject ci = CBORObject.FromObject(42);
    Assert.assertTrue(ci.isNumber());
    // tagged CBOR is not seen as a number by the CBOR library (4.0.0/4.4.2 tried)
    Assert.assertFalse(ci.WithTag(47).isNumber());
    // untagged CBOR is detected as number.
    Assert.assertTrue(ci.WithTag(47).Untag().isNumber());
  }
}
