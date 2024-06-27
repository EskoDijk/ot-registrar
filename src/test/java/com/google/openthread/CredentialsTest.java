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

import com.google.openthread.brski.ConstantsBrski;
import com.google.openthread.brski.HardwareModuleName;
import com.google.openthread.tools.CredentialGenerator;
import java.io.File;
import java.io.Reader;
import java.io.StringReader;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.util.encoders.Hex;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class CredentialsTest {

  public static final String KEY_STORE_FILE = "test-credentials.temp.p12";
  private static String pledgeSn;

  @BeforeClass
  public static void createCredentialFile() throws Exception {
    CredentialGenerator cg = new CredentialGenerator();
    cg.make(null, null, null, null, null);
    cg.store(KEY_STORE_FILE);
    pledgeSn = cg.getPledgeSerialNumber();
  }

  @AfterClass
  public static void cleanCredentialFile() {
    File f = new File(KEY_STORE_FILE);
    Assert.assertTrue(f.delete());
  }

  @Test
  public void testASN1() throws Exception {
    byte[] hardwareModuleName = "OT-9527".getBytes();
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new ASN1ObjectIdentifier(ConstantsBrski.HARDWARE_MODULE_NAME_OID));
    v.add(new DEROctetString(hardwareModuleName));
    byte[] encoded =
        new GeneralNames(new GeneralName(GeneralName.otherName, new DERSequence(v)))
            .getEncoded(ASN1Encoding.DER);
    GeneralNames names = GeneralNames.getInstance(encoded);
    for (GeneralName name : names.getNames()) {
      Assert.assertEquals(GeneralName.otherName, name.getTagNo());
      ASN1Sequence seq = DERSequence.getInstance(name.getName());
      Assert.assertEquals(ConstantsBrski.HARDWARE_MODULE_NAME_OID, ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0)).getId());
      ASN1OctetString sn = DEROctetString.getInstance(seq.getObjectAt(1));
      Assert.assertArrayEquals(sn.getOctets(), hardwareModuleName);
    }
  }

  @Test
  public void testDomainCredentials() throws Exception {
    Credentials domainCred = new Credentials(KEY_STORE_FILE, CredentialGenerator.DOMAINCA_ALIAS, CredentialGenerator.PASSWORD);
    Credentials registrarCred = new Credentials(KEY_STORE_FILE, CredentialGenerator.REGISTRAR_ALIAS, CredentialGenerator.PASSWORD);

    Assert.assertEquals(3, domainCred.getCertificate().getVersion());
    Assert.assertEquals(3, registrarCred.getCertificate().getVersion());
    Assert.assertTrue(registrarCred.getCertificate().getEncoded().length < 1024);
    Assert.assertTrue(registrarCred.getCertificate().getPublicKey().getEncoded().length < 1024);
    Assert.assertEquals(2, registrarCred.getCertificateChain().length);

    Assert.assertEquals(registrarCred.getCertificate().getIssuerX500Principal(), domainCred.getCertificate().getSubjectX500Principal());

    registrarCred.getCertificate().verify(domainCred.getCertificate().getPublicKey());
  }

  @Test
  public void testMASACredentials() throws Exception {
    Credentials masaCred = new Credentials(KEY_STORE_FILE, CredentialGenerator.MASACA_ALIAS, CredentialGenerator.PASSWORD);
    Credentials pledgeCred = new Credentials(KEY_STORE_FILE, CredentialGenerator.PLEDGE_ALIAS, CredentialGenerator.PASSWORD);

    Assert.assertEquals(SecurityUtils.getMasaUri(pledgeCred.getCertificate()), Constants.DEFAULT_MASA_URI);
    Assert.assertEquals(2, pledgeCred.getCertificateChain().length);

    pledgeCred.getCertificate().verify(masaCred.getCertificate().getPublicKey());

    String pledgeSN = SecurityUtils.getSerialNumber(pledgeCred.getCertificate());
    Assert.assertNotNull(pledgeSN);
    Assert.assertEquals(pledgeSN, pledgeSn);
    HardwareModuleName hwsn = SecurityUtils.getHWModuleName(pledgeCred.getCertificate());

    Assert.assertNotNull(hwsn);
    Assert.assertEquals(new String(hwsn.getSerialNumber().getOctets()), pledgeSn);
  }

  @Test
  public void testHWSerialNumber() throws Exception {
    final String CERT_PEM =
        "-----BEGIN CERTIFICATE-----\n"
            + "MIICDzCCAbSgAwIBAgIJAKIfmfE87I/hMAoGCCqGSM49BAMCMBMxETAPBgNVBAMM\n"
            + "CE1BU0EyLUNBMB4XDTE4MDUxNjIwMzAzM1oXDTE5MDUyNjIwMzAzM1owdDELMAkG\n"
            + "A1UEBhMCVVMxCzAJBgNVBAgMAk1BMRAwDgYDVQQHDAdCZXZlcmx5MRMwEQYDVQQK\n"
            + "DApPU1JBTSBHbWJIMRMwEQYDVQQLDApJbm5vdmF0aW9uMRwwGgYDVQQDDBNMaWdo\n"
            + "dGlmeSBQcm8gTW9kdWxlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2BlkB8o4\n"
            + "AWL9fucHjSFQC58AcSaqVSpEm+j9+w6NQQHyey575E81AAsfvIZXoWkySc/XLwv6\n"
            + "IkQLb/S1vQ8gq6OBjzCBjDAJBgNVHRMEAjAAMEMGA1UdIwQ8MDqAFFCd5c6TwJh+\n"
            + "Iltu9InbQ6yFkgg0oRekFTATMREwDwYDVQQDDAhNQVNBMi1DQYIJAOS7oRcRWr1u\n"
            + "MA4GA1UdDwEB/wQEAwIFoDAqBgNVHREEIzAhoB8GCCsGAQUFBwgEoBMwEQYIKwYB\n"
            + "BAGBplcEBcE8RAD/MAoGCCqGSM49BAMCA0kAMEYCIQDiHvIYb8CiXkXhRNpQg90u\n"
            + "tGaZwH4teHjpmL7ENrBmFgIhAMLawr7FOJMQPfYhzWIlVvKKym0AS42JhETpooWH\n"
            + "7WR5\n"
            + "-----END CERTIFICATE-----";

    final byte[] SERIAL_NUMBER = Hex.decode("C13C4400FF");

    X509Certificate cert;
    try (Reader reader = new StringReader(CERT_PEM)) {
      cert = SecurityUtils.parseCertFromPem(reader);
    }

    HardwareModuleName hwmn = SecurityUtils.getHWModuleName(cert);
    Assert.assertNotNull(hwmn);

    Assert.assertArrayEquals(SERIAL_NUMBER, hwmn.getSerialNumber().getOctets());
  }

  @Test(expected = CertPathValidatorException.class)
  public void testRegistrarCertChainValidationWithSelfFails() throws Exception {
    Credentials registrarCred = new Credentials(KEY_STORE_FILE, CredentialGenerator.REGISTRAR_ALIAS, CredentialGenerator.PASSWORD);
    X509Certificate cert = registrarCred.getCertificate();

    Set<TrustAnchor> trustAnchors = new HashSet<>();
    trustAnchors.add(new TrustAnchor(cert, null));
    PKIXParameters params = new PKIXParameters(trustAnchors);
    params.setRevocationEnabled(false);
    CertPathValidator validator = CertPathValidator.getInstance("PKIX");

    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    List<Certificate> certs = new ArrayList<>();
    certs.add(cert);
    CertPath path = cf.generateCertPath(certs);
    validator.validate(path, params);
  }
}
