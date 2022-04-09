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

package com.google.openthread.registrar;

import static org.junit.Assert.assertSame;

import com.google.openthread.*;
import com.google.openthread.brski.*;
import com.google.openthread.commissioner.*;
import com.google.openthread.domainca.*;
import com.google.openthread.masa.*;
import com.google.openthread.pledge.*;
import com.google.openthread.pledge.Pledge.CertState;
import com.google.openthread.tools.*;
import java.io.IOException;
import java.security.cert.*;
import org.bouncycastle.util.encoders.Hex;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.junit.*;
import org.junit.rules.ExpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.sics.ace.cwt.CWT;

public class FunctionalTest {

  public static final String REGISTRAR_URI =
      "coaps://[::1]:" + Constants.DEFAULT_REGISTRAR_COAPS_PORT;

  public static final String DEFAULT_DOMAIN_NAME = "Thread-Test";

  // the acting entities
  private DomainCA domainCA;
  private Registrar registrar;
  private Commissioner commissioner;
  private Pledge pledge;
  private MASA masa;

  // credentials used
  private static CredentialGenerator cg;

  private static Logger logger = LoggerFactory.getLogger(FunctionalTest.class);

  @Rule public ExpectedException thrown = ExpectedException.none();

  @BeforeClass
  public static void setup() throws Exception {
    // generated credentials set
    cg = new CredentialGenerator();
    cg.make(null, null, null, null, null);
  }

  @AfterClass
  public static void tearDown() {}

  @Before
  public void init() throws Exception {
    initEntities(cg);
  }

  protected void initEntities(CredentialGenerator credGen) throws Exception {
    masa =
        new MASA(
            credGen.getCredentials(CredentialGenerator.MASA_ALIAS),
            credGen.getCredentials(CredentialGenerator.MASACA_ALIAS),
            Constants.DEFAULT_MASA_HTTPS_PORT);
    pledge = new Pledge(credGen.getCredentials(CredentialGenerator.PLEDGE_ALIAS), REGISTRAR_URI);
    pledge.setLightweightClientCertificates(true);

    domainCA =
        new DomainCA(
            DEFAULT_DOMAIN_NAME, credGen.getCredentials(CredentialGenerator.DOMAINCA_ALIAS));

    RegistrarBuilder registrarBuilder = new RegistrarBuilder();
    registrar =
        registrarBuilder
            .setCredentials(credGen.getCredentials(CredentialGenerator.REGISTRAR_ALIAS))
            // .addMasaCertificate(cg.masaCaCert)   // enable this, to trust a single MASA CA only
            .setTrustAllMasas(true) // or enable this, to trust all MASAs.
            .build();
    registrar.setDomainCA(domainCA);

    commissioner = new Commissioner(credGen.getCredentials(CredentialGenerator.COMMISSIONER_ALIAS));

    masa.start();
    registrar.start();
  }

  @After
  public void finalize() {
    stopEntities();
  }

  protected void stopEntities() {
    pledge.shutdown();
    commissioner.shutdown();
    registrar.stop();
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

  private void VerifyPledge(Pledge pledge) {
    Assert.assertNotEquals(pledge.getState(), CertState.NO_CONTACT);
    Assert.assertNotEquals(pledge.getState(), CertState.PROVISIONALLY_ACCEPT);
    // TODO - implement state verification of Pledge after voucher request, while enroll may or may
    // not have happened at this point.
  }

  @Test
  public void testConnectionToRegistrar() throws Exception {
    CoapResponse response = pledge.sayHello();
    assertSame(CoAP.ResponseCode.CONTENT, response.getCode());
    response = pledge.discoverResources();
    assertSame(CoAP.ResponseCode.CONTENT, response.getCode());
    assertSame(MediaTypeRegistry.APPLICATION_LINK_FORMAT, response.getOptions().getContentFormat());
  }

  @Test
  public void testConnectionToRegistrarWithFullCertChain() throws Exception {

    pledge.setLightweightClientCertificates(false);

    CoapResponse response = pledge.sayHello();
    assertSame(CoAP.ResponseCode.CONTENT, response.getCode());
    response = pledge.discoverResources();
    assertSame(CoAP.ResponseCode.CONTENT, response.getCode());
    assertSame(MediaTypeRegistry.APPLICATION_LINK_FORMAT, response.getOptions().getContentFormat());
  }

  @Test
  public void testVoucherRequest() throws Exception {
    Voucher voucher = pledge.requestVoucher();
    Assert.assertTrue(voucher.validate());
    VerifyPledge(pledge);
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));
  }

  /**
   * Test BRSKI voucher request while first requesting CSR attributes. The returned attributes
   * aren't used. Requesting this is not recommended anymore for constrained Pledges, but tested
   * here nevertheless.
   *
   * @throws Exception
   */
  @Test
  public void testCsrAttrsRequest() throws Exception {
    Voucher voucher = pledge.requestVoucher();
    pledge.requestCSRAttributes();
    Assert.assertTrue(voucher.validate());
    VerifyPledge(pledge);
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));
  }

  @Test
  public void testEnroll() throws Exception {
    Voucher voucher = pledge.requestVoucher();
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));
    Assert.assertTrue(voucher.validate());

    pledge.enroll();
    VerifyPledge(pledge);
    VerifyEnroll(pledge);
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendEnrollStatusTelemetry(true, null));
  }

  @Test
  public void testEnrollWithUnsupportedFormat() throws Exception {
    Voucher voucher = pledge.requestVoucher();
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));
    Assert.assertTrue(voucher.validate());

    // modify the CSR's Content Format to something not supported.
    pledge.csrContentFormat = ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT;
    try {
      pledge.enroll();
      Assert.fail("CSR with unsupported Content Format should fail.");
    } catch (PledgeException ex) {
      // ok, as expected it fails.
    }
  }

  @Test
  public void testEnrollWithLoadedCredentials() throws Exception {
    // start a new set of entities, using loaded credentials.
    CredentialGenerator cred = new CredentialGenerator();
    cred.load(CredentialGenerator.CREDENTIALS_FILE_IOTCONSULTANCY);
    this.stopEntities();
    this.initEntities(cred);
    registrar.setForcedMasaUri(Constants.DEFAULT_MASA_URI); // force to local.

    Voucher voucher = pledge.requestVoucher();
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));
    Assert.assertTrue(voucher.validate());

    pledge.enroll();
    VerifyPledge(pledge);
    VerifyEnroll(pledge);
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendEnrollStatusTelemetry(true, null));
  }

  @Test
  public void testReenroll() throws Exception {
    Voucher voucher = pledge.requestVoucher();
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));

    pledge.enroll();
    Assert.assertTrue(voucher.validate());
    VerifyPledge(pledge);
    VerifyEnroll(pledge);
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendEnrollStatusTelemetry(true, null));

    pledge.reenroll();
    VerifyEnroll(pledge);
  }

  /**
   * Test various status telemetry messages, stand-alone (not associated to enrollment/voucher
   * request). Current Registrar is implemented to just accept/log these.
   *
   * @throws Exception
   */
  @Test
  public void testStatusTelemetry() throws Exception {
    Assert.assertEquals(
        ResponseCode.CHANGED,
        pledge.sendEnrollStatusTelemetry(
            true,
            "this message should not be here, but may be accepted by Registrar nevertheless."));
    Assert.assertEquals(
        ResponseCode.CHANGED,
        pledge.sendVoucherStatusTelemetry(
            true,
            "this message should not be here, but may be accepted by Registrar nevertheless."));
    byte[] wrongFormatTelemetry =
        Hex.decode(
            "a46776657273696f6e6131665374617475730166526561736f6e7822496e666f726d61746976652068756d616e207265616461626c65206d6573736167656e726561736f6e2d636f6e74657874764164646974696f6e616c20696e666f726d6174696f6e");
    Assert.assertEquals(
        ResponseCode.BAD_REQUEST,
        pledge.sendStatusTelemetry(
            Constants.ENROLL_STATUS,
            wrongFormatTelemetry,
            ExtendedMediaTypeRegistry.APPLICATION_CBOR));
    Assert.assertEquals(
        ResponseCode.UNSUPPORTED_CONTENT_FORMAT,
        pledge.sendStatusTelemetry(
            Constants.ENROLL_STATUS,
            StatusTelemetry.create(true, null).serializeToBytes(),
            ExtendedMediaTypeRegistry.APPLICATION_COSE_SIGN1));
    Assert.assertEquals(
        ResponseCode.UNSUPPORTED_CONTENT_FORMAT,
        pledge.sendStatusTelemetry(
            Constants.VOUCHER_STATUS,
            wrongFormatTelemetry,
            ExtendedMediaTypeRegistry.APPLICATION_COSE_SIGN1));
    wrongFormatTelemetry =
        Hex.decode(
            "a36776657273696f6e0166737461747573f467726561736f6e787174686973206b65792069732077726f6e67");
    Assert.assertEquals(
        ResponseCode.BAD_REQUEST,
        pledge.sendStatusTelemetry(
            Constants.VOUCHER_STATUS,
            wrongFormatTelemetry,
            ExtendedMediaTypeRegistry.APPLICATION_CBOR));
    Assert.assertEquals(
        ResponseCode.CHANGED,
        pledge.sendStatusTelemetry(
            Constants.ENROLL_STATUS,
            StatusTelemetry.create(true, "this msg is not needed").serializeToBytes(),
            ExtendedMediaTypeRegistry.APPLICATION_CBOR));
  }

  @Test
  public void testReset() throws Exception {
    pledge.requestVoucher();
    pledge.enroll();
    VerifyEnroll(pledge);
    pledge.reenroll();
    VerifyEnroll(pledge);

    pledge.reset();

    pledge.requestVoucher();
    pledge.enroll();
    VerifyEnroll(pledge);
    pledge.reenroll();
    VerifyEnroll(pledge);
  }

  @Test
  public void testCommissionerTokenRequest() throws Exception {
    CWT comTok = commissioner.requestToken("TestDomainTCE", REGISTRAR_URI);
    // TODO check result more; try 'bad commissioner' cases.
    Assert.assertTrue(comTok.getClaims().size() > 0);
    Assert.assertTrue(comTok.isValid(System.currentTimeMillis() + 500000));
  }

  @Test
  public void testMultiPledges() throws Exception {
    PledgeThread[] threads = new PledgeThread[12];

    // create multiple PledgeThreads, each with own Pledge and own credentials.
    for (int i = 0; i < threads.length; ++i) {
      threads[i] = new PledgeThread();
    }

    // run the Pledges
    for (PledgeThread thread : threads) {
      thread.start();
      Thread.sleep(20);
    }

    // wait for each Pledge to finish
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
    public Pledge pledge = null;

    public PledgeThread() throws Exception {
      cg.makePledge(null); // create a new Pledge identity and serial number
      pledge = new Pledge(cg.getCredentials(CredentialGenerator.PLEDGE_ALIAS), REGISTRAR_URI);
    }

    @Override
    public void run() {
      try {
        pledge.requestVoucher();
        Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));
        pledge.enroll();
        VerifyEnroll(pledge);
        Assert.assertEquals(ResponseCode.CHANGED, pledge.sendEnrollStatusTelemetry(true, null));

        pledge.reenroll();
        VerifyEnroll(pledge);

      } catch (Throwable e) {
        errorState = e;
      } finally {
        if (pledge != null) pledge.shutdown();
      }
    }
  }

  @Test
  public void testRegistrarWithoutCmcRa() throws Exception {

    registrar.stop();

    // create new Registrar without EKU extension in Registrar cert
    cg.setRegistrarExtendedKeyUsage(false);
    X509Certificate cert = cg.genRegistrarCredentials();
    X509Certificate domainCaCert =
        cg.getCredentials(CredentialGenerator.DOMAINCA_ALIAS).getCertificate();
    RegistrarBuilder registrarBuilder = new RegistrarBuilder();
    registrar =
        registrarBuilder
            .setCredentials(cg.getCredentials(CredentialGenerator.REGISTRAR_ALIAS))
            .setCertificateChain(new X509Certificate[] {cert, domainCaCert})
            .setTrustAllMasas(true)
            .build();
    registrar.setDomainCA(domainCA);
    registrar.start();

    // test connection does not work - our Pledge checks for cmcRA in certificate
    CoapResponse response = null;
    try {
      response = pledge.sayHello();
      Assert.fail("Pledge mistakenly accepted Registrar without cmcRA");
    } catch (IOException ex) {;
    }

    // try again without checking strictly for cmcRA
    pledge.setCmcRaCheck(false);
    response = pledge.sayHello();
    assertSame(CoAP.ResponseCode.CONTENT, response.getCode());

    // test that the voucher request now fails
    try {
      pledge.requestVoucher();
      Assert.fail("MASA mistakenly accepted voucher request");
    } catch (PledgeException ex) {
      Assert.assertEquals(
          ResponseCode.CHANGED,
          pledge.sendVoucherStatusTelemetry(
              false, "MASA didn't accept voucher request: " + ex.getMessage()));
      Assert.assertEquals(ResponseCode.FORBIDDEN, ex.code);
    }
  }

  @Test
  public void testRegistrarUsingCmsJsonVoucherRequest() throws Exception {

    registrar.stop();

    // create new Registrar that uses only CMS-signed JSON voucher requests towards MASA
    RegistrarBuilder registrarBuilder = new RegistrarBuilder();
    registrar =
        registrarBuilder
            .setCredentials(cg.getCredentials(CredentialGenerator.REGISTRAR_ALIAS))
            .setTrustAllMasas(true)
            .build();
    registrar.setDomainCA(domainCA);
    registrar.setForcedRequestFormat(Constants.HTTP_APPLICATION_VOUCHER_CMS_JSON);
    registrar.start();

    Voucher voucher = pledge.requestVoucher();
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));
    pledge.enroll();
    VerifyEnroll(pledge);
    voucher.validate();
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendEnrollStatusTelemetry(true, null));
  }
}
