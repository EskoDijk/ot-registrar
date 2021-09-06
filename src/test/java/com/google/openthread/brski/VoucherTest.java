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

import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import com.upokecenter.cbor.CBORObject;

public class VoucherTest {

  @Rule public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testYoungDate() throws Exception {
    Date date = new Date();
    String young = Voucher.dateToYoungFormat(date);
    Date date2 = Voucher.dateFromYoungFormat(young);

    Assert.assertTrue(date.getTime() == date2.getTime());
  }

  @Test
  public void testSimple() {
    Voucher v1 = new Voucher();
    v1.assertion = Voucher.Assertion.PROXIMITY;
    v1.createdOn = new Date();
    v1.expiresOn = new Date();

    v1.serialNumber = "12345";
    v1.pinnedDomainCert = new byte[] {0x01, 0x02, 0x03};

    Assert.assertTrue(v1.validate());

    byte[] data = new CBORSerializer().serialize(v1);
    Voucher v2 = new CBORSerializer().deserialize(data);
    Assert.assertTrue(v2.validate());

    Assert.assertTrue(v1.assertion.equals(v2.assertion));
    Assert.assertTrue(v1.serialNumber.equals(v2.serialNumber));
    Assert.assertTrue(Arrays.equals(v1.pinnedDomainCert, v2.pinnedDomainCert));

    data = new JSONSerializer().serialize(v1);
    Voucher v3 = new JSONSerializer().deserialize(data);
    Assert.assertTrue(v3.validate());

    Assert.assertTrue(v1.assertion.equals(v3.assertion));
    Assert.assertTrue(v1.serialNumber.equals(v3.serialNumber));
    Assert.assertTrue(Arrays.equals(v1.pinnedDomainCert, v3.pinnedDomainCert));
  }

  @Test
  public void testSimpleRequest() {
    Voucher vr1 = new VoucherRequest();
    vr1.assertion = Voucher.Assertion.PROXIMITY;
    vr1.serialNumber = "12345";
    vr1.proximityRegistrarCert = new byte[] {0x01, 0x02, 0x03};

    Assert.assertTrue(vr1.validate());

    byte[] data = new CBORSerializer().serialize(vr1);
    Voucher vr2 = new CBORSerializer().deserialize(data);
    Assert.assertTrue(vr2.validate());

    Assert.assertTrue(vr1.assertion.equals(vr2.assertion));
    Assert.assertTrue(vr1.serialNumber.equals(vr2.serialNumber));
    Assert.assertTrue(Arrays.equals(vr1.proximityRegistrarCert, vr2.proximityRegistrarCert));

    data = new JSONSerializer().serialize(vr1);
    Voucher vr3 = new JSONSerializer().deserialize(data);
    Assert.assertTrue(vr3.validate());

    Assert.assertTrue(vr1.assertion.equals(vr3.assertion));
    Assert.assertTrue(vr1.serialNumber.equals(vr3.serialNumber));
    Assert.assertTrue(Arrays.equals(vr1.proximityRegistrarCert, vr3.proximityRegistrarCert));
  }

  @Test
  public void testSimpleConstrained() {
    Voucher cv1 = new Voucher();
    cv1.assertion = Voucher.Assertion.LOGGED;
    cv1.serialNumber = "12345";
    cv1.createdOn = new Date();
    cv1.expiresOn = new Date();
    cv1.pinnedDomainSPKI = new byte[] {0x01, 0x02, 0x03};

    Assert.assertTrue(cv1.validate());

    byte[] data = new CBORSerializer().serialize(cv1);
    Voucher cv2 = new CBORSerializer().deserialize(data);
    Assert.assertTrue(cv2.validate());

    Assert.assertTrue(cv1.assertion.equals(cv2.assertion));
    Assert.assertTrue(cv1.serialNumber.equals(cv2.serialNumber));
    Assert.assertTrue(Arrays.equals(cv1.pinnedDomainSPKI, cv2.pinnedDomainSPKI));
  }

  @Test
  public void testSimpleConstrainedRequest() {
    Voucher cvr1 = new VoucherRequest();
    cvr1.setConstrained(true);
    cvr1.assertion = Voucher.Assertion.PROXIMITY;
    cvr1.serialNumber = "123";

    cvr1.proximityRegistrarSPKI = new byte[] {0x01, 0x02, 0x03};

    Assert.assertTrue(cvr1.validate());

    byte[] data = new CBORSerializer().serialize(cvr1);
    Voucher cvr2 = new CBORSerializer().deserialize(data);
    Assert.assertTrue(cvr2.isConstrained());
    Assert.assertTrue(cvr2.validate());   

    Assert.assertTrue(cvr1.assertion.equals(cvr2.assertion));
    Assert.assertTrue(cvr1.serialNumber.equals(cvr2.serialNumber));
    Assert.assertTrue(Arrays.equals(cvr1.proximityRegistrarSPKI, cvr2.proximityRegistrarSPKI));
  }

  @Test
  public void testConstrainedRequestMixedDeltaEncoding() throws ParseException {
    // an example constrained Voucher Request. It uses mixed delta/Tag-47 encoding in SID values.
    // to view on site CBOR.me, use following hex input:
    // a11909c5a9d82f1909c774323031362d31302d30375431393a33313a34325ad82f1909c974323031362d31302d32315431393a33313a34325a01020d6d4a414441313233343536373839054401020d0f0a4401020d0fd82f1909c8f50674323031372d31302d30375431393a33313a34325a0c590279308202753082021ca00302010202147056eaaa3066d8826a555b9088d462bf9cf28cfd300a06082a8648ce3d0403023073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c301e170d3230313230393130303233365a170d3231313230393130303233365a3073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c3059301306072a8648ce3d020106082a8648ce3d03010703420004507ac8491a8c69c7b5c31d0309ed35ba13f5884ce62b88cf3018154fa059b020ec6bebb94e02b8934021898da789c711cea71339f50e348edf0d923ed02dc7b7a3818d30818a301d0603551d0e0416041408c2bf36887f79412185872f16a7aca6efb3d2b3301f0603551d2304183016801408c2bf36887f79412185872f16a7aca6efb3d2b3300f0603551d130101ff040530030101ff30270603551d250420301e06082b0601050507031c06082b0601050507030106082b06010505070302300e0603551d0f0101ff0404030201f6300a06082a8648ce3d04030203470030440220744c99008513b2f1bcfdf9021a46fb174cf883a27ca1d93faeacf31e4edd12c60220114714dbf51a5e78f581b9421c6e4702ab537270c5bafb2d16c3de9aa182c35f
    byte[] data =
        Base64.decode(
            "oRkJxanYLxkJx3QyMDE2LTEwLTA3VDE5OjMxOjQyWtgvGQnJdDIwMTYtMTAtMjFUMTk6MzE6NDJaAQINbUpBREExMjM0NTY3ODkFRAECDQ8KRAECDQ/YLxkJyPUGdDIwMTctMTAtMDdUMTk6MzE6NDJaDFkCeTCCAnUwggIcoAMCAQICFHBW6qowZtiCalVbkIjUYr+c8oz9MAoGCCqGSM49BAMCMHMxCzAJBgNVBAYTAk5MMQswCQYDVQQIDAJOQjEQMA4GA1UEBwwHSGVsbW9uZDETMBEGA1UECgwKdmFuZGVyc3RvazEUMBIGA1UECwwLY29uc3VsdGFuY3kxGjAYBgNVBAMMEXJlZ2lzdHJhci5zdG9rLm5sMB4XDTIwMTIwOTEwMDIzNloXDTIxMTIwOTEwMDIzNlowczELMAkGA1UEBhMCTkwxCzAJBgNVBAgMAk5CMRAwDgYDVQQHDAdIZWxtb25kMRMwEQYDVQQKDAp2YW5kZXJzdG9rMRQwEgYDVQQLDAtjb25zdWx0YW5jeTEaMBgGA1UEAwwRcmVnaXN0cmFyLnN0b2submwwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARQeshJGoxpx7XDHQMJ7TW6E/WITOYriM8wGBVPoFmwIOxr67lOAriTQCGJjaeJxxHOpxM59Q40jt8Nkj7QLce3o4GNMIGKMB0GA1UdDgQWBBQIwr82iH95QSGFhy8Wp6ym77PSszAfBgNVHSMEGDAWgBQIwr82iH95QSGFhy8Wp6ym77PSszAPBgNVHRMBAf8EBTADAQH/MCcGA1UdJQQgMB4GCCsGAQUFBwMcBggrBgEFBQcDAQYIKwYBBQUHAwIwDgYDVR0PAQH/BAQDAgH2MAoGCCqGSM49BAMCA0cAMEQCIHRMmQCFE7LxvP35AhpG+xdM+IOifKHZP66s8x5O3RLGAiARRxTb9RpeePWBuUIcbkcCq1NycMW6+y0Ww96aoYLDXw==");
    Voucher cvr = new CBORSerializer().deserialize(data);
    Assert.assertTrue(cvr.validate());

    Assert.assertTrue(cvr.assertion.equals(Voucher.Assertion.PROXIMITY));
    Assert.assertTrue(cvr.serialNumber.equals("JADA123456789"));
    Assert.assertTrue(cvr.proximityRegistrarSPKI.length == 633);
    Assert.assertTrue(cvr.createdOn.equals(Voucher.dateFromYoungFormat("2016-10-07T19:31:42Z")));
  }
  
  @Test
  public void testThirdPartyVoucherRequestValidation() {
    final String voucherHex = "A11909C5A60274323032312D30392D30365430393A32383A35355A0474323032332D30392D30365430393A32383A35355A0102075019CDED78A318FEBD1EB0BF8E4D5538AE0D6A413835443333303030310A5902223082021E308201C4A003020102020103300A06082A8648CE3D04030230533111300F06035504030C08646F6D61696E636131133011060355040B0C0A4F70656E546872656164310F300D060355040A0C06476F6F676C65310B300906035504070C025348310B300906035504061302434E301E170D3231303732303130333831305A170D3236303731393130333831305A30543112301006035504030C0972656769737472617231133011060355040B0C0A4F70656E546872656164310F300D060355040A0C06476F6F676C65310B300906035504070C025348310B300906035504061302434E3059301306072A8648CE3D020106082A8648CE3D03010703420004047C75B435FCECBB21BB0979F3F6C7FF36AD3C6CB320D0D1EA296840783E9E255D9B38279B46275547D9A5B90BF3B2D43AF0DDF7C6D67EF81A11A3D48FD31B46A38187308184301F0603551D230418301680149EDAC23395FF7228EB7DAEC87D182DF9E8576F57301D0603551D0E04160414292E7DFCBB55A67B25C7498AC83DF1A4510D1DF0300C0603551D130101FF04023000300B0603551D0F0404030204F030270603551D250420301E06082B0601050507031C06082B0601050507030106082B06010505070302300A06082A8648CE3D040302034800304502200E4578DA2F19B8FDBDC8490F9C694F6758F099A97AC388E9E8DA170A59DEEBE7022100F9B6D3CFA32FB64D890A95C5F9CCA1008FDD281EB4394C7BDF37C29E982FFE80";
    byte[] voucherCbor = Hex.decode(voucherHex);
    Voucher voucher = new CBORSerializer().deserialize(voucherCbor);
    
    // should fail due to nonce and expires-on being present at same time.
    Assert.assertFalse(voucher.validate());
  }
  
}
