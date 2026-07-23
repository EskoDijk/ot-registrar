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
import com.google.openthread.brski.ConstantsBrski;
import com.google.openthread.brski.HardwareModuleName;
import com.google.openthread.tools.CredentialGenerator;
import com.upokecenter.cbor.CBORObject;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Assert;
import org.junit.Test;

public final class SecurityUtilsTest {

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
    HardwareModuleName name0 = new HardwareModuleName(ConstantsBrski.PRIVATE_HARDWARE_TYPE_OID, new byte[]{0x01, 0x02, 0x03});
    HardwareModuleName name1 = HardwareModuleName.getInstance(name0.getEncoded());
    Assert.assertEquals(name0, name1);
  }

  @Test
  public void testSubjectPublicKeyInfo() throws Exception {
    // PublicKey.getEncoded() is documented to return the X.509 SubjectPublicKeyInfo
    // DER encoding. Verify the round-trip through SubjectPublicKeyInfo.getInstance
    // is byte-stable -- several other tests and callers rely on it (e.g. building
    // proximity-registrar-SPKI directly from PublicKey.getEncoded()).
    KeyPair kp = SecurityUtils.genKeyPair();
    PublicKey pk = kp.getPublic();
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pk.getEncoded());
    Assert.assertArrayEquals(pk.getEncoded(), spki.getEncoded());
  }

  @Test
  public void testX5BagEncoding() throws Exception {
    KeyPair kp = SecurityUtils.genKeyPair();
    X509Certificate cert =
        SecurityUtils.genCertificate(kp, "CN=Root", kp, new X500Name("CN=Root"), true, null);
    CBORObject bagSingle = SecurityUtils.createX5BagCertificates(new X509Certificate[]{cert});
    Assert.assertNotNull(bagSingle);

    KeyPair kp2 = SecurityUtils.genKeyPair();
    X509Certificate cert2 =
        SecurityUtils.genCertificate(
            kp,
            "CN=AnotherRoot,L=InSpace",
            kp2,
            new X500Name("CN=AnotherRoot,L=InSpace"),
            true,
            null);
    CBORObject bagMultiple = SecurityUtils.createX5BagCertificates(new X509Certificate[]{cert, cert2});
    Assert.assertNotNull(bagMultiple);

    byte[] payload = new byte[]{1, 2, 3, 4, 5};

    // try single bag
    byte[] cose = SecurityUtils.genCoseSign1Message(kp.getPrivate(), SecurityUtils.COSE_SIGNATURE_ALGORITHM, payload, new X509Certificate[]{cert});
    Sign1Message sign1 = (Sign1Message) Sign1Message.DecodeFromBytes(cose);
    Assert.assertTrue(sign1.validate(new OneKey(kp.getPublic(), kp.getPrivate())));
    List<X509Certificate> certList = SecurityUtils.getX5BagCertificates(sign1);
    Assert.assertNotNull(certList);
    Assert.assertEquals(1, certList.size());
    Assert.assertEquals(cert, certList.get(0));

    // try multi bag
    cose = SecurityUtils.genCoseSign1Message(
        kp2.getPrivate(),
        SecurityUtils.COSE_SIGNATURE_ALGORITHM,
        payload,
        new X509Certificate[]{cert, cert2});
    sign1 = (Sign1Message) Sign1Message.DecodeFromBytes(cose);
    Assert.assertTrue(sign1.validate(new OneKey(kp2.getPublic(), kp2.getPrivate())));
    certList = SecurityUtils.getX5BagCertificates(sign1);
    Assert.assertNotNull(certList);
    Assert.assertEquals(2, certList.size());
    Assert.assertEquals(cert, certList.get(0));
    Assert.assertEquals(cert2, certList.get(1));
  }

  @Test
  public void testAuthorityKeyIdentifier() throws Exception {
    CredentialGenerator cg = new CredentialGenerator();
    cg.make(null, null, null, null, null);
    X509Certificate pledgeCert =
        cg.getCredentials(CredentialsSet.PLEDGE_ALIAS).getCertificate();
    byte[] akiOctetString = SecurityUtils.getAuthorityKeyIdentifier(pledgeCert);
    byte[] keyId = SecurityUtils.getAuthorityKeyIdentifierKeyId(pledgeCert);
    Assert.assertNotNull(keyId);
    Assert.assertEquals(26, akiOctetString.length);
    Assert.assertEquals(20, keyId.length);

    // verify that the last part of akiOctetString in fact contains the keyId.
    byte[] akiOctetStringLastPart = new byte[20];
    System.arraycopy(akiOctetString, 6, akiOctetStringLastPart, 0, 20);
    Assert.assertArrayEquals(keyId, akiOctetStringLastPart);
  }

  // --- Certificate hierarchy checks: isRootCaCertificate, isSignedBy and chainsTo.

  /**
   * A two-level PKI: root CA -> sub-CA -> end entity. This is the shape for which the optimized
   * enrollment shortcut of cBRSKI 6.7.1 step 3 does not apply, so that a Pledge must obtain the
   * trust anchors with a CA certificates request and chain to them (step 4).
   */
  private static final class TwoLevelPki {

    final X509Certificate rootCa;
    final X509Certificate subCa;
    final X509Certificate endEntity;

    TwoLevelPki() throws Exception {
      KeyPair rootKey = SecurityUtils.genKeyPair();
      KeyPair subKey = SecurityUtils.genKeyPair();
      KeyPair eeKey = SecurityUtils.genKeyPair();

      String rootName = "CN=test root CA";
      String subName = "CN=test sub CA";
      rootCa =
          SecurityUtils.genCertificate(
              rootKey, rootName, rootKey, new X500Name(rootName), true, caExtensions());
      subCa =
          SecurityUtils.genCertificate(
              subKey, subName, rootKey, new X500Name(rootName), true, caExtensions());
      endEntity =
          SecurityUtils.genCertificate(
              eeKey, "CN=test LDevID", subKey, new X500Name(subName), false, null);
    }

    /** The key usage a CA certificate needs to be usable as a certification path element. */
    private static List<Extension> caExtensions() throws IOException {
      return Collections.singletonList(
          new Extension(
              Extension.keyUsage,
              true,
              new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign)
                  .getEncoded()));
    }
  }

  @Test
  public void testIsRootCaCertificate() throws Exception {
    TwoLevelPki pki = new TwoLevelPki();
    CredentialGenerator cg = new CredentialGenerator();
    cg.make(null, null, null, null, null);

    Assert.assertTrue(
        "self-signed domain CA is a root CA",
        SecurityUtils.isRootCaCertificate(
            cg.getCredentials(CredentialsSet.DOMAIN_CA_ALIAS).getCertificate()));
    Assert.assertTrue(SecurityUtils.isRootCaCertificate(pki.rootCa));

    Assert.assertFalse("a sub-CA is not a root CA", SecurityUtils.isRootCaCertificate(pki.subCa));
    Assert.assertFalse(
        "an end-entity certificate is not a root CA",
        SecurityUtils.isRootCaCertificate(
            cg.getCredentials(CredentialsSet.REGISTRAR_ALIAS).getCertificate()));
  }

  @Test
  public void testIsSignedBy() throws Exception {
    TwoLevelPki pki = new TwoLevelPki();

    Assert.assertTrue(SecurityUtils.isSignedBy(pki.subCa, pki.rootCa));
    Assert.assertTrue(SecurityUtils.isSignedBy(pki.endEntity, pki.subCa));
    Assert.assertTrue("a root CA signs itself", SecurityUtils.isSignedBy(pki.rootCa, pki.rootCa));

    // signed by the sub-CA, not directly by the root
    Assert.assertFalse(SecurityUtils.isSignedBy(pki.endEntity, pki.rootCa));
    Assert.assertFalse(SecurityUtils.isSignedBy(pki.rootCa, pki.subCa));
  }

  @Test
  public void testChainsToThroughSubCa() throws Exception {
    TwoLevelPki pki = new TwoLevelPki();

    Assert.assertTrue(
        "should chain end entity -> sub-CA -> root CA",
        SecurityUtils.chainsTo(pki.endEntity, Arrays.asList(pki.subCa, pki.rootCa)));

    Assert.assertTrue(
        "the issuing sub-CA alone is enough of an anchor",
        SecurityUtils.chainsTo(pki.endEntity, Collections.singletonList(pki.subCa)));
  }

  @Test
  public void testChainsToFailsWithoutPath() throws Exception {
    TwoLevelPki pki = new TwoLevelPki();
    CredentialGenerator cg = new CredentialGenerator();
    cg.make(null, null, null, null, null);

    Assert.assertFalse(
        "a certificate of a different PKI must not chain",
        SecurityUtils.chainsTo(
            pki.endEntity,
            Collections.singletonList(
                cg.getCredentials(CredentialsSet.DOMAIN_CA_ALIAS).getCertificate())));

    Assert.assertFalse(
        "missing the intermediate sub-CA, no path exists to the root",
        SecurityUtils.chainsTo(pki.endEntity, Collections.singletonList(pki.rootCa)));

    Assert.assertFalse(
        "an empty CA set never chains",
        SecurityUtils.chainsTo(pki.endEntity, Collections.emptyList()));
  }

  /**
   * The three-argument {@code chainsTo} separates trust anchors from intermediates: a path is
   * accepted only when it actually reaches an anchor, with intermediates merely bridging the gap.
   */
  @Test
  public void testChainsToWithSeparateAnchorsAndIntermediates() throws Exception {
    TwoLevelPki pki = new TwoLevelPki();

    Assert.assertTrue(
        "reaches the root anchor via the sub-CA intermediate",
        SecurityUtils.chainsTo(
            pki.endEntity,
            Collections.singletonList(pki.rootCa),
            Collections.singletonList(pki.subCa)));

    Assert.assertFalse(
        "the sub-CA is only an intermediate here, not an anchor, so nothing to reach",
        SecurityUtils.chainsTo(
            pki.endEntity,
            Collections.emptyList(),
            Collections.singletonList(pki.subCa)));

    Assert.assertFalse(
        "without the sub-CA intermediate the root anchor is unreachable",
        SecurityUtils.chainsTo(
            pki.endEntity,
            Collections.singletonList(pki.rootCa),
            Collections.emptyList()));

    Assert.assertTrue(
        "the sub-CA on its own is a sufficient anchor",
        SecurityUtils.chainsTo(
            pki.endEntity,
            Collections.singletonList(pki.subCa),
            Collections.emptyList()));
  }

  @Test
  public void testFindPledgeIdevid() throws Exception {
    CredentialGenerator cg = new CredentialGenerator();
    cg.make(null, null, null, null, null);
    X509Certificate idevid = cg.getCredentials(CredentialsSet.PLEDGE_ALIAS).getCertificate();
    X509Certificate registrar = cg.getCredentials(CredentialsSet.REGISTRAR_ALIAS).getCertificate();
    X509Certificate domainCa = cg.getCredentials(CredentialsSet.DOMAIN_CA_ALIAS).getCertificate();

    // The IDevID (end-entity carrying a MASA URI) is picked out from among the other certs.
    Assert.assertEquals(
        idevid, SecurityUtils.findPledgeIdevid(Arrays.asList(registrar, domainCa, idevid)));

    // No IDevID present -> null: the Registrar end-entity has no MASA URI, the Domain CA is a CA.
    Assert.assertNull(SecurityUtils.findPledgeIdevid(Arrays.asList(registrar, domainCa)));
  }

  @Test
  public void testFindCmcRaCert() throws Exception {
    CredentialGenerator cg = new CredentialGenerator();
    cg.make(null, null, null, null, null);
    X509Certificate idevid = cg.getCredentials(CredentialsSet.PLEDGE_ALIAS).getCertificate();
    X509Certificate registrar = cg.getCredentials(CredentialsSet.REGISTRAR_ALIAS).getCertificate();
    X509Certificate domainCa = cg.getCredentials(CredentialsSet.DOMAIN_CA_ALIAS).getCertificate();

    // The Registrar cert (id-kp-cmcRA) is found; the IDevID and Domain CA do not carry that EKU.
    Assert.assertEquals(
        registrar, SecurityUtils.findCmcRaCert(Arrays.asList(idevid, domainCa, registrar)));
    Assert.assertNull(SecurityUtils.findCmcRaCert(Arrays.asList(idevid, domainCa)));
  }

  @Test
  public void testTopOfChain() throws Exception {
    TwoLevelPki pki = new TwoLevelPki();

    // The self-signed root is the top of its chain, regardless of list order.
    Assert.assertEquals(
        pki.rootCa,
        SecurityUtils.topOfChain(Arrays.asList(pki.endEntity, pki.subCa, pki.rootCa)));
    Assert.assertEquals(
        pki.rootCa,
        SecurityUtils.topOfChain(Arrays.asList(pki.rootCa, pki.endEntity, pki.subCa)));

    // With the root absent, the highest available cert (the sub-CA) is returned.
    Assert.assertEquals(
        pki.subCa, SecurityUtils.topOfChain(Arrays.asList(pki.endEntity, pki.subCa)));

    // A single certificate is its own top; an empty list has none.
    Assert.assertEquals(
        pki.endEntity, SecurityUtils.topOfChain(Collections.singletonList(pki.endEntity)));
    Assert.assertNull(SecurityUtils.topOfChain(Collections.emptyList()));
  }
}
