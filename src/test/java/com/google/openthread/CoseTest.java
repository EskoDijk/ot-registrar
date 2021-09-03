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

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.HeaderKeys;
import COSE.Message;
import COSE.MessageTag;
import COSE.OneKey;
import COSE.Sign1Message;
import static org.junit.Assert.assertFalse;
import java.io.Reader;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.openthread.tools.HardwarePledgeTestSuite;
import com.upokecenter.cbor.CBORObject;

public class CoseTest {

  private static Logger logger = LoggerFactory.getLogger(CoseTest.class);
  
  @Test
  public void testSignAndVerify() throws Exception {
    final String certificate =
        "-----BEGIN CERTIFICATE-----\r\n"
            + "MIICATCCAaegAwIBAgIIJU8KN/Bcw4cwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwN\r\n"
            + "VGhyZWFkR3JvdXBDQTAeFw0xOTA2MTkyMTM2MTFaFw0yNDA2MTcyMTM2MTFaMBox\r\n"
            + "GDAWBgNVBAMMD1RocmVhZFJlZ2lzdHJhcjBZMBMGByqGSM49AgEGCCqGSM49AwEH\r\n"
            + "A0IABCAwhVvoRpELPssVyvhXLT61Zb3GVKFe+vbt66qLnhYIxckQyTogho/IUE03\r\n"
            + "Dxsm+pdZ9nmDu3iGPtqay+pRJPajgdgwgdUwDwYDVR0TBAgwBgEB/wIBAjALBgNV\r\n"
            + "HQ8EBAMCBeAwbAYDVR0RBGUwY6RhMF8xCzAJBgNVBAYTAlVTMRUwEwYDVQQKDAxU\r\n"
            + "aHJlYWQgR3JvdXAxFzAVBgNVBAMMDlRlc3QgUmVnaXN0cmFyMSAwHgYJKoZIhvcN\r\n"
            + "AQkBFhFtYXJ0aW5Ac3Rva29lLm5ldDBHBgNVHSMEQDA+gBSS6nZAQEqPq08nC/O8\r\n"
            + "N52GzXKA+KEcpBowGDEWMBQGA1UEAwwNVGhyZWFkR3JvdXBDQYIIc5C+m8ijatIw\r\n"
            + "CgYIKoZIzj0EAwIDSAAwRQIgbI7Vrg348jGCENRtT3GbV5FaEqeBaVTeHlkCA99z\r\n"
            + "RVACIQDGDdZSWXAR+AlfmrDecYnmp5Vgz8eTyjm9ZziIFXPUwA==\r\n"
            + "-----END CERTIFICATE-----\r\n";

    final String privateKey =
        "-----BEGIN PRIVATE KEY-----\r\n"
            + "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYJ/MP0dWA9BkYd4W\r\n"
            + "s6oRY62hDddaEmrAVm5dtAXE/UGhRANCAAQgMIVb6EaRCz7LFcr4Vy0+tWW9xlSh\r\n"
            + "Xvr27euqi54WCMXJEMk6IIaPyFBNNw8bJvqXWfZ5g7t4hj7amsvqUST2\r\n"
            + "-----END PRIVATE KEY-----\r\n";

    X509Certificate cert;
    PrivateKey key;

    try (Reader reader = new StringReader(certificate)) {
      cert = SecurityUtils.parseCertFromPem(reader);
    }
    try (Reader reader = new StringReader(privateKey)) {
      key = SecurityUtils.parsePrivateKeyFromPem(reader);
    }

    byte[] content = {1, 2, 3, 4, 5, 6};

    OneKey signingKey = new OneKey(null, key);

    Sign1Message msg = new Sign1Message();
    msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_256.AsCBOR(), Attribute.PROTECTED);
    msg.SetContent(content);
    msg.sign(signingKey);

    byte[] signature = msg.EncodeToBytes();
    logger.info("Encoded COSE message: " + Hex.toHexString(signature));

    msg = (Sign1Message) Message.DecodeFromBytes(signature, MessageTag.Sign1);

    assert (msg.validate(new OneKey(cert.getPublicKey(), null)));
  }
  
  @Test
  public void testVerifyThirdPartyCose() throws Exception {
    final String coseHex = "d28443a10126a20458201e8190148b54c6f691db9d6f4379086b455b1b15d8ceb2f0be3386c6f4f8d81718205902423082023e308201e4a003020102020139300a06082a8648ce3d040302304f310d300b06035504030c046d61736131133011060355040b0c0a4f70656e546872656164310f300d060355040a0c06476f6f676c65310b300906035504070c025348310b300906035504061302434e301e170d3231303731333039333630345a170d3236303731323039333630345a3078311e301c06035504030c155465737456656e646f7220496f5420646576696365311330110603550405130a4138354433333030303131133011060355040a0c0a5465737456656e646f723112301006035504070c0953616e2052616d6f6e310b300906035504080c024341310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d0301070342000422a1d9b2d6f6ee31e7f6611351720d8af8a905ba8098bacb62a77fa328c8cd5059075c6a8a517c9832759fff4906282a9eccc2266c67d6e85b3314b715b0976ea38187308184300c0603551d130101ff04023000300b0603551d0f0404030204f0301f0603551d230418301680146f07b5ce1fa1aaff43051b1a7e4d4b257d750d1a301b0603551d1104143012a01006092b0601040182df2a02a003020103302906082b06010505070120041d161b6d6173612e696f74636f6e73756c74616e63792e6e6c3a39343433300a06082a8648ce3d04030203480030450221009702cbaa3b97b9825ba338241cb212108289cbb7428135d841e9c73e52e4b998022072a0b50f57bea4a28c8da773f2973d269aef5b02a652bb09e6e8208f5f5ba9c95902a6a11909c5a60274323032312d30392d30335430373a31363a32365a0474323032332d30392d30335430373a31363a32365a0102075030b3146fa19b0cb2ce7ce67040a8661b0d6a413835443333303030310a5902513082024d308201f3a003020102020711223344556600300a06082a8648ce3d0403023073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c301e170d3231303930323037303133305a170d3232303930323037303133305a305a310b3009060355040613024e4c310b300906035504080c024e4231133011060355040a0c0a76616e64657273746f6b31123010060355040b0c096f7065726174696f6e3115301306035504030c0c5245474953207365727665723059301306072a8648ce3d020106082a8648ce3d03010703420004582b23d35a34b793590492f0f5b32b5d11c3ff495e76033cbccd730c59e71306d6e9abd0672227d31e8231febdda84a0ccf8aa57dccb21fc1e42ddbab3e46076a3818a308187301d0603551d0e04160414ae167cd8221e7e4c1dc79a10aca6ad3b16afd025301f0603551d23041830168014d5039fc78a4dc0468760191fd71b1534c2d88428300c0603551d130101ff0402300030270603551d250420301e06082b0601050507031c06082b0601050507030106082b06010505070302300e0603551d0f0101ff040403020186300a06082a8648ce3d0403020348003045022005402bdd4b7c5f388a2b9b428b93c040846562887c98070738b4f4b53c0882e0022100b7211801096417605b294d78e14714a9b26d05c3d6c97e07bf9f7b67afec069458483046022100cbdff5e6270a4f94639cd12fb4d1be312f5e3e88a44758135082d311a3155ff7022100da8fd7bc42f1178bd1ce816d8c0fd6f819dd9cf52cf50baa82252e1de23fad6d";
    final String publicKeyAsnHex = "3059301306072a8648ce3d020106082a8648ce3d0301070342000422a1d9b2d6f6ee31e7f6611351720d8af8a905ba8098bacb62a77fa328c8cd5059075c6a8a517c9832759fff4906282a9eccc2266c67d6e85b3314b715b0976e";
    byte[] coseData = Hex.decode(coseHex);
    byte[] publicKeyAsn = Hex.decode(publicKeyAsnHex);
        
    // decode Cose-Sign1 message
    Sign1Message msg = (Sign1Message) Message.DecodeFromBytes(coseData, MessageTag.Sign1);
     
    // verify against public key:
    // should not pass, as wrong signature format is used (DER-encoded, instead of raw 2*32 bytes) in COSE
    KeyFactory kf = KeyFactory.getInstance("EC");
    PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyAsn));
    assertFalse (msg.validate(new OneKey(pubKey,null)));
  }
}
