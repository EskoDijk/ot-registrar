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

import COSE.OneKey;
import COSE.Sign1Message;
import com.google.openthread.tools.CredentialGenerator;
import com.upokecenter.cbor.CBORObject;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class SecurityUtilsTest {

  @Rule public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testSignatureVerification() throws Exception {
    final String SIG_ALG = "SHA256withECDSA";
    final String KEY_ALG = "EC";

    PrivateKey privKey;
    PublicKey pubKey;

    KeyPairGenerator gen = KeyPairGenerator.getInstance(KEY_ALG);
    gen.initialize(256);

    KeyPair pair = gen.generateKeyPair();
    privKey = pair.getPrivate();
    pubKey = pair.getPublic();

    PKCS10CertificationRequest req =
        new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=XXX"), pubKey)
            .build(new JcaContentSignerBuilder(SIG_ALG).build(privKey));
    Assert.assertTrue(req.isSignatureValid(new JcaContentVerifierProviderBuilder().build(pubKey)));

    pair = gen.generateKeyPair();
    privKey = pair.getPrivate();
    req =
        new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=XXX"), pubKey)
            .build(new JcaContentSignerBuilder(SIG_ALG).build(privKey));

    // Signed by different private key, should fail
    Assert.assertFalse(req.isSignatureValid(new JcaContentVerifierProviderBuilder().build(pubKey)));
  }

  @Test
  public void testHWModuleName() throws Exception {
    HardwareModuleName name0 =
        new HardwareModuleName(Constants.PRIVATE_HARDWARE_TYPE_OID, new byte[] {0x01, 0x02, 0x03});
    HardwareModuleName name1 = HardwareModuleName.getInstance(name0.getEncoded());
    Assert.assertTrue(name0.equals(name1));
  }

  @Test
  public void testSubjectPublicKeyInfo() throws Exception {
    KeyPair kp = SecurityUtils.genKeyPair();
    PublicKey pk = kp.getPublic();
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pk.getEncoded());
    System.out.println("public key algorithm: " + pk.getAlgorithm());
    System.out.println("public key: ");
    System.out.println(Hex.toHexString(pk.getEncoded()));

    System.out.println("spki key algorithm: " + spki.getAlgorithm().getAlgorithm().getId());
    System.out.println("spki: ");
    System.out.println(Hex.toHexString(spki.getEncoded()));
  }

  @Test
  public void testX5BagEncoding() throws Exception {
    KeyPair kp = SecurityUtils.genKeyPair();
    X509Certificate cert = SecurityUtils.genCertificate(kp, "CN=Root", kp, "CN=Root", true, null);
    CBORObject bagSingle = SecurityUtils.createX5BagCertificates(new X509Certificate[] {cert});

    KeyPair kp2 = SecurityUtils.genKeyPair();
    X509Certificate cert2 =
        SecurityUtils.genCertificate(
            kp, "CN=AnotherRoot/L=InSpace", kp2, "CN=AnotherRoot/L=InSpace", true, null);
    CBORObject bagMultiple =
        SecurityUtils.createX5BagCertificates(new X509Certificate[] {cert, cert2});
    byte[] payload = new byte[] {1, 2, 3, 4, 5};

    // try single bag
    byte[] cose =
        SecurityUtils.genCoseSign1Message(
            kp.getPrivate(),
            SecurityUtils.COSE_SIGNATURE_ALGORITHM,
            payload,
            new X509Certificate[] {cert});
    Sign1Message sign1 = (Sign1Message) Sign1Message.DecodeFromBytes(cose);
    Assert.assertTrue(sign1.validate(new OneKey(kp.getPublic(), kp.getPrivate())));
    List<X509Certificate> certList = SecurityUtils.getX5BagCertificates(sign1);
    Assert.assertTrue(certList.size() == 1);
    Assert.assertEquals(certList.get(0), cert);

    // try multi bag
    cose =
        SecurityUtils.genCoseSign1Message(
            kp2.getPrivate(),
            SecurityUtils.COSE_SIGNATURE_ALGORITHM,
            payload,
            new X509Certificate[] {cert, cert2});
    sign1 = (Sign1Message) Sign1Message.DecodeFromBytes(cose);
    Assert.assertTrue(sign1.validate(new OneKey(kp2.getPublic(), kp2.getPrivate())));
    certList = SecurityUtils.getX5BagCertificates(sign1);
    Assert.assertTrue(certList.size() == 2);
    Assert.assertEquals(certList.get(0), cert);
    Assert.assertEquals(certList.get(1), cert2);
  }
  
  @Test
  public void testAuthorityKeyIdentifier() throws Exception {
    CredentialGenerator cg = new CredentialGenerator();
    cg.make(null, null, null, null);    
    Assert.assertTrue(SecurityUtils.getAuthorityKeyIdentifier(cg.pledgeCert).length == 24);
    Assert.assertTrue(SecurityUtils.getAuthorityKeyIdentifierKeyId(cg.pledgeCert).length == 20);
  }
}
