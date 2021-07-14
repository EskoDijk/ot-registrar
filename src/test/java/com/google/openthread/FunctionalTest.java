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

import static org.junit.Assert.assertSame;

import com.google.openthread.brski.ConstrainedVoucher;
import com.google.openthread.commissioner.Commissioner;
import com.google.openthread.domainca.DomainCA;
import com.google.openthread.masa.MASA;
import com.google.openthread.pledge.Pledge;
import com.google.openthread.pledge.PledgeException;
import com.google.openthread.registrar.Registrar;
import com.google.openthread.registrar.RegistrarBuilder;
import com.google.openthread.tools.CredentialGenerator;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.sics.ace.cwt.CWT;

public class FunctionalTest {

  public static final String REGISTRAR_URI =
      "coaps://[::1]:" + Constants.DEFAULT_REGISTRAR_COAPS_PORT;

  public static final String DEFAULT_DOMAIN_NAME = "Thread-Test";

  private DomainCA domainCA;
  private Registrar registrar, registrar2;
  private Commissioner commissioner;
  private Pledge pledge;
  private MASA masa;

  private static CredentialGenerator cg;

  private static Logger logger = LoggerFactory.getLogger(FunctionalTest.class);

  @Rule public ExpectedException thrown = ExpectedException.none();

  @BeforeClass
  public static void setup() throws Exception {
    cg = new CredentialGenerator();
    cg.make(null, null, null, null);
  }

  @AfterClass
  public static void tearDown() {}

  @Before
  public void init() throws Exception {
    masa =
        new MASA(
            cg.masaKeyPair.getPrivate(),
            cg.masaCert,
            cg.getCredentials(CredentialGenerator.MASA_ALIAS),
            Constants.DEFAULT_MASA_HTTPS_PORT,
            false);
    pledge =
        new Pledge(
            cg.pledgeKeyPair.getPrivate(),
            new X509Certificate[] {cg.pledgeCert, cg.masaCert},
            REGISTRAR_URI);

    domainCA = new DomainCA(DEFAULT_DOMAIN_NAME, cg.domaincaKeyPair.getPrivate(), cg.domaincaCert);

    RegistrarBuilder registrarBuilder = new RegistrarBuilder();
    registrar =
        registrarBuilder
            .setPrivateKey(cg.registrarKeyPair.getPrivate())
            .setCertificateChain(new X509Certificate[] {cg.registrarCert, cg.domaincaCert})
            .addMasaCertificate(cg.masaCert)
            .setMasaClientCredentials(cg.getCredentials(CredentialGenerator.REGISTRAR_ALIAS))
            .build();
    registrar.setDomainCA(domainCA);

    commissioner =
        new Commissioner(
            cg.commissionerKeyPair.getPrivate(),
            new X509Certificate[] {cg.commissionerCert, cg.domaincaCert});

    masa.start();
    registrar.start();
  }

  @After
  public void finalize() {
    pledge.shutdown();
    commissioner.shutdown();
    registrar.stop();
    if (registrar2 != null) registrar2.stop();
    masa.stop();
  }

  private void VerifyEnroll(Pledge pledge) throws Exception {
    X509Certificate cert = pledge.getOperationalCert();
    Assert.assertTrue(cert != null);

    String domainName = pledge.getDomainName();
    Assert.assertTrue(domainName.equals(registrar.getDomainName()));

    // we expect the LDevID to NOT contain subject key id, per 802.1AR-2018 spec section 8.10.2 for
    // LDevID.
    byte[] subjKeyId = cert.getExtensionValue("2.5.29.14");
    Assert.assertNull(subjKeyId);
  }

  @Test
  public void testCertificateChainValidationWithSelf() throws Exception {
    thrown.expect(Exception.class);

    X509Certificate cert = cg.registrarCert;

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

  @Test
  public void testPledgeCertificate() {
    Assert.assertTrue(SecurityUtils.getMasaUri(cg.pledgeCert).equals(Constants.DEFAULT_MASA_URI));
  }

  @Test
  public void testConnection() throws Exception {
    CoapResponse response = pledge.sayHello();
    assertSame(CoAP.ResponseCode.CONTENT, response.getCode());
  }

  @Test
  public void testVoucherRequest() throws Exception {
    ConstrainedVoucher voucher = pledge.requestVoucher();

    // TODO(wgtdkp): verify pledge state
  }

  @Test
  public void testCsrAttrsRequest() throws Exception {
    pledge.requestVoucher();
    pledge.requestCSRAttributes();

    // TODO(wgtdkp): verify pledge state
  }

  @Test
  public void testEnroll() throws Exception {
    pledge.requestVoucher();
    pledge.requestCSRAttributes();
    pledge.enroll();

    VerifyEnroll(pledge);

    // TODO(wgtdkp): verify pledge state
  }

  @Test
  public void testReenroll() throws Exception {
    pledge.requestVoucher();
    pledge.requestCSRAttributes();
    pledge.enroll();
    VerifyEnroll(pledge);

    pledge.reenroll();
    VerifyEnroll(pledge);

    // TODO(wgtdkp): verify pledge state
  }

  @Test
  public void testReset() throws Exception {
    pledge.requestVoucher();
    pledge.requestCSRAttributes();
    pledge.enroll();
    VerifyEnroll(pledge);

    pledge.reenroll();
    VerifyEnroll(pledge);

    pledge.reset();

    pledge.requestVoucher();
    pledge.requestCSRAttributes();
    pledge.enroll();
    VerifyEnroll(pledge);

    pledge.reenroll();
    VerifyEnroll(pledge);
  }

  @Test
  public void testSimpleCommissioning() throws Exception {
    CWT comTok = commissioner.requestToken("TestDomainTCE", REGISTRAR_URI);
    // TODO check result
  }

  @Test
  public void testMultiPledges() throws Exception {
    PledgeThread[] threads = new PledgeThread[12];

    for (int i = 0; i < threads.length; ++i) {
      threads[i] = new PledgeThread();
    }
    for (PledgeThread thread : threads) {
      thread.start();
      Thread.sleep(20);
    }
    for (PledgeThread thread : threads) {
      try {
        thread.join();
        if (thread.errorState != null) {
          String msg =
              "Pledge [" + thread.getId() + "] had an exception/error: " + thread.errorState;
          logger.error(msg, thread.errorState);
          Assert.fail();
        }
      } catch (InterruptedException e) {
        Assert.fail("join failed: " + e.getMessage());
      }
    }
  }

  /**
   * In a thread, create a new Pledge and let it do voucher request and enrollment operations. Any
   * error state is logged internally.
   */
  private class PledgeThread extends Thread {

    public Throwable errorState = null;

    @Override
    public void run() {
      Pledge p = null;
      try {
        p =
            new Pledge(
                cg.pledgeKeyPair.getPrivate(),
                new X509Certificate[] {cg.pledgeCert, cg.masaCert},
                REGISTRAR_URI);
        p.requestVoucher();
        p.requestCSRAttributes();
        p.enroll();
        VerifyEnroll(p);

        p.reenroll();
        VerifyEnroll(p);
      } catch (Throwable e) {
        errorState = e;
      } finally {
        if (p != null) p.shutdown();
      }
    }
  }

  @Test
  public void testRegistrarWithoutCmcRa() throws Exception {

    registrar.stop();

    // create new Registrar without EKU extension in Registrar cert
    cg.setRegistrarExtendedKeyUsage(false);
    X509Certificate registrarCert =
        cg.genRegistrarCertificate(
            cg.registrarKeyPair,
            CredentialGenerator.REGISTRAR_DNAME,
            cg.domaincaKeyPair,
            cg.domaincaCert.getSubjectX500Principal().getName());

    // build a new Registrar
    X509Certificate[] certChain = new X509Certificate[] {registrarCert, cg.domaincaCert};
    RegistrarBuilder registrarBuilder = new RegistrarBuilder();
    registrar2 =
        registrarBuilder
            .setPrivateKey(cg.registrarKeyPair.getPrivate())
            .setCertificateChain(certChain)
            .addMasaCertificate(cg.masaCert)
            .setMasaClientCredentials(
                new Credentials(
                    cg.registrarKeyPair.getPrivate(),
                    certChain,
                    CredentialGenerator.REGISTRAR_ALIAS,
                    CredentialGenerator.PASSWORD))
            .build();
    registrar2.setDomainCA(domainCA);
    registrar2.start();

    // test connection works - our Pledge won't check for cmcRA in certificate (other
    // implementations may do this)
    CoapResponse response = pledge.sayHello();
    assertSame(CoAP.ResponseCode.CONTENT, response.getCode());

    // test that the voucher request now fails
    try {
      pledge.requestVoucher();
      Assert.fail("MASA mistakenly accepted voucher request");
    } catch (PledgeException ex) {
      Assert.assertEquals(ResponseCode.FORBIDDEN, ex.code);
    }
  }

  @Test
  public void testRegistrarUsingCoseVoucherRequest() throws Exception {

    registrar.stop();

    // create new Registrar that uses COSE-signed requests towards MASA
    RegistrarBuilder registrarBuilder = new RegistrarBuilder();
    registrar2 =
        registrarBuilder
            .setPrivateKey(cg.registrarKeyPair.getPrivate())
            .setCertificateChain(new X509Certificate[] {cg.registrarCert, cg.domaincaCert})
            .addMasaCertificate(cg.masaCert)
            .setMasaClientCredentials(cg.getCredentials(CredentialGenerator.REGISTRAR_ALIAS))
            .setRequestFormat(Constants.HTTP_APPLICATION_VOUCHER_COSE_CBOR)
            .build();
    registrar2.setDomainCA(domainCA);
    registrar2.start();

    ConstrainedVoucher voucher = pledge.requestVoucher();
    pledge.enroll();
    VerifyEnroll(pledge);
    // TODO verify voucher
  }
}
