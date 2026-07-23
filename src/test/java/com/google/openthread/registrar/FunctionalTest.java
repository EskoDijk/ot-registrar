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

import com.google.openthread.Constants;
import com.google.openthread.Credentials;
import com.google.openthread.CredentialsSet;
import com.google.openthread.Role;
import com.google.openthread.brski.ConstantsBrski;
import com.google.openthread.brski.ExtendedMediaTypeRegistry;
import com.google.openthread.brski.StatusTelemetry;
import com.google.openthread.brski.Voucher;
import com.google.openthread.domainca.DomainCA;
import com.google.openthread.masa.MASA;
import com.google.openthread.pledge.Pledge;
import com.google.openthread.pledge.Pledge.CertState;
import com.google.openthread.pledge.PledgeException;
import com.google.openthread.tools.CredentialGenerator;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.util.encoders.Hex;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class FunctionalTest {

  private static final String REGISTRAR_URI = "coaps://[::1]:" + ConstantsBrski.DEFAULT_REGISTRAR_COAPS_PORT;
  private static final String DEFAULT_DOMAIN_NAME = "Thread-Test";
  private static final String TEST_VENDOR_ID = "TestVendor";

  private static final Logger logger = LoggerFactory.getLogger(FunctionalTest.class);

  // the acting entities
  private DomainCA domainCA;
  private Registrar registrar;
  private Pledge pledge;
  private MASA masa;

  // generated credentials used
  private static CredentialGenerator cg;

  @BeforeClass
  public static void setup() throws Exception {
    // fully generated credentials set
    cg = new CredentialGenerator();
    cg.make(null, null, null, null, null);
  }

  @Before
  public void init() throws Exception {
    initEntities(cg);
  }

  // TODO: support pinning a single MASA CA here instead of trusting all. Replace
  //   setTrustAllMasas(true) with .addMasaCertificate(
  //     cg.getCredentials(CredentialsSet.MASA_CA_ALIAS).getCertificate())
  //   once the test scenarios distinguish trust modes.
  protected void initEntities(CredentialsSet... credentialSets) throws Exception {
    masa =
        new MASA(
            findCredentials(CredentialsSet.MASA_ALIAS, credentialSets),
            findCredentials(CredentialsSet.MASA_CA_ALIAS, credentialSets),
            ConstantsBrski.DEFAULT_MASA_HTTPS_PORT);
    pledge =
        new Pledge(findCredentials(CredentialsSet.PLEDGE_ALIAS, credentialSets), REGISTRAR_URI);
    pledge.setLightweightClientCertificates(true);

    domainCA =
        new DomainCA(
            DEFAULT_DOMAIN_NAME, findCredentials(CredentialsSet.DOMAIN_CA_ALIAS, credentialSets));

    RegistrarBuilder registrarBuilder = new RegistrarBuilder();
    registrar =
        registrarBuilder
            .setCredentials(findCredentials(CredentialsSet.REGISTRAR_ALIAS, credentialSets))
            .setTrustAllMasas(true)
            .build();
    registrar.setDomainCA(domainCA);

    masa.start();
    registrar.start();
  }

  /**
   * Find the credentials stored under {@code alias} as a key entry, in the first of the given
   * credential sets that provides it. Trusted-certificate-only entries (no private key) are
   * skipped, so e.g. a Pledge keystore's trust-anchor MASA CA is not mistaken for the MASA's own
   * key entry. This lets the entities be sourced either from one combined keystore or from several
   * per-role keystores.
   */
  private static Credentials findCredentials(String alias, CredentialsSet... credentialSets)
      throws IllegalStateException, GeneralSecurityException, IOException {
    for (CredentialsSet creds : credentialSets) {
      if (creds.getKeyStore().isKeyEntry(alias)) {
        return creds.getCredentials(alias);
      }
    }
    throw new IllegalStateException(
        "no key entry for alias '" + alias + "' found in the given credential set(s)");
  }

  @After
  public void shutdown() {
    pledge.shutdown();
    registrar.stop();
    masa.stop();
  }

  private void verifyEnroll(Pledge pledge) {
    X509Certificate cert = pledge.getOperationalCert();
    Assert.assertNotNull(cert);

    Assert.assertEquals(registrar.getDomainName(), pledge.getDomainName());

    // we expect the LDevID to NOT contain subject key id, per 802.1AR-2018 spec section 8.10.2 for LDevID.
    byte[] subjKeyId = cert.getExtensionValue("2.5.29.14");
    Assert.assertNull(subjKeyId);
  }

  private void verifyPledge(Pledge pledge) {
    Assert.assertNotEquals(CertState.NO_CONTACT, pledge.getState());
    Assert.assertNotEquals(CertState.PROVISIONALLY_ACCEPT, pledge.getState());
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
    verifyPledge(pledge);
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));
  }

  @Test
  public void testEnroll() throws Exception {
    Voucher voucher = pledge.requestVoucher();
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));
    Assert.assertTrue(voucher.validate());

    pledge.enroll();
    verifyPledge(pledge);
    verifyEnroll(pledge);
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendEnrollStatusTelemetry(true, null));
  }

  /**
   * A CA certificates request (/crts) against the Registrar, in the Pledge's default Content-Format
   * (multipart-core, 62).
   */
  @Test
  public void testRequestCaCertificates() throws Exception {
    Voucher voucher = pledge.requestVoucher();
    Assert.assertTrue(voucher.validate());
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));

    List<X509Certificate> caCerts = pledge.requestCACertificates();
    Assert.assertEquals(1, caCerts.size());
    Assert.assertEquals(
        cg.getCredentials(CredentialsSet.DOMAIN_CA_ALIAS).getCertificate(), caCerts.get(0));
  }

  /**
   * The Registrar must answer a /crts request in the Content-Format asked for in the CoAP Accept
   * Option. All three formats of cBRSKI Appendix E carry the same domain CA certificate here, since
   * the test domain has a single, self-signed CA.
   */
  @Test
  public void testRequestCaCertificatesContentFormats() throws Exception {
    Voucher voucher = pledge.requestVoucher();
    Assert.assertTrue(voucher.validate());
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));

    X509Certificate domainCaCert =
        cg.getCredentials(CredentialsSet.DOMAIN_CA_ALIAS).getCertificate();

    int[] formats = {
        ExtendedMediaTypeRegistry.APPLICATION_MULTIPART_CORE,
        ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT,
        ExtendedMediaTypeRegistry.APPLICATION_PKCS7_MIME_CERTS_ONLY,
    };
    for (int format : formats) {
      pledge.setCaCertsAcceptContentFormat(format);
      List<X509Certificate> caCerts = pledge.requestCACertificates();
      Assert.assertEquals(
          "unexpected number of CA certificates for format " + format, 1, caCerts.size());
      Assert.assertEquals(
          "unexpected CA certificate for format " + format, domainCaCert, caCerts.get(0));
    }
  }

  /** A /crts request for a Content-Format the Registrar cannot produce must give a 4.06. */
  @Test
  public void testRequestCaCertificatesNotAcceptable() throws Exception {
    Voucher voucher = pledge.requestVoucher();
    Assert.assertTrue(voucher.validate());
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));

    pledge.setCaCertsAcceptContentFormat(ExtendedMediaTypeRegistry.APPLICATION_JSON);
    try {
      pledge.requestCACertificates();
      Assert.fail("/crts in an unsupported Content-Format should fail");
    } catch (PledgeException ex) {
      Assert.assertEquals(ResponseCode.NOT_ACCEPTABLE, ex.getCode());
    }
  }

  /**
   * After a normal enrollment the optimized shortcut of cBRSKI section 6.7.1 step 3 applies, since
   * the test PKI's pinned domain CA is a root CA that directly signs the LDevID. The pinned domain
   * CA is then the Pledge's sole trust anchor and no /crts request was needed.
   */
  @Test
  public void testEnrollUsesOptimizedShortcut() throws Exception {
    Voucher voucher = pledge.requestVoucher();
    Assert.assertTrue(voucher.validate());
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));

    pledge.enroll();
    verifyEnroll(pledge);

    List<X509Certificate> trustAnchors = pledge.getCaCertificates();
    Assert.assertEquals(1, trustAnchors.size());
    Assert.assertEquals(
        cg.getCredentials(CredentialsSet.DOMAIN_CA_ALIAS).getCertificate(), trustAnchors.get(0));
  }

  @Test
  public void testEnrollWithUnsupportedFormat() throws Exception {
    Voucher voucher = pledge.requestVoucher();
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));
    Assert.assertTrue(voucher.validate());

    // modify the CSR's Content Format to something not supported.
    pledge.setCsrContentFormat(ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT);
    try {
      pledge.enroll();
      Assert.fail("CSR with unsupported Content Format should fail.");
    } catch (PledgeException ex) {
      // ok, as expected it fails.
    }
  }

  @Test
  public void testEnrollWithLoadedCredentials() throws Exception {
    // start a new set of entities, using per-role credentials loaded from file.
    CredentialsSet credMasa = new CredentialsSet(TEST_VENDOR_ID, Role.Masa);
    CredentialsSet credPledge = new CredentialsSet(TEST_VENDOR_ID, Role.Pledge);
    CredentialsSet credRegistrar = new CredentialsSet(TEST_VENDOR_ID, Role.Registrar);

    this.shutdown();
    this.initEntities(credMasa, credPledge, credRegistrar);
    registrar.setForcedMasaUri(Constants.DEFAULT_MASA_URI); // force to local.

    Voucher voucher = pledge.requestVoucher();
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));
    Assert.assertTrue(voucher.validate());

    pledge.enroll();
    verifyPledge(pledge);
    verifyEnroll(pledge);
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendEnrollStatusTelemetry(true, null));
  }

  @Test
  public void testReenroll() throws Exception {
    Voucher voucher = pledge.requestVoucher();
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));

    pledge.enroll();
    Assert.assertTrue(voucher.validate());
    verifyPledge(pledge);
    verifyEnroll(pledge);
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendEnrollStatusTelemetry(true, null));

    pledge.reenroll();
    verifyEnroll(pledge);
  }

  /**
   * Test various status telemetry messages, stand-alone (not associated to enrollment/voucher request). Current Registrar is implemented to just accept/log these.
   */
  @Test
  public void testStatusTelemetry() throws Exception {
    Assert.assertEquals(
        ResponseCode.CHANGED,
        pledge.sendEnrollStatusTelemetry(true, "this message should not be here, but may be accepted by Registrar nevertheless."));
    Assert.assertEquals(
        ResponseCode.CHANGED,
        pledge.sendVoucherStatusTelemetry(
            true,
            "this message should not be here, but may be accepted by Registrar nevertheless."));
    byte[] wrongFormatTelemetry = Hex.decode(
        "a46776657273696f6e6131665374617475730166526561736f6e7822496e666f726d61746976652068756d616e207265616461626c65206d6573736167656e726561736f6e2d636f6e74657874764164646974696f6e616c20696e666f726d6174696f6e");
    Assert.assertEquals(
        ResponseCode.BAD_REQUEST,
        pledge.sendStatusTelemetry(
            ConstantsBrski.ENROLL_STATUS,
            wrongFormatTelemetry,
            ExtendedMediaTypeRegistry.APPLICATION_CBOR));
    Assert.assertEquals(
        ResponseCode.UNSUPPORTED_CONTENT_FORMAT,
        pledge.sendStatusTelemetry(
            ConstantsBrski.ENROLL_STATUS,
            StatusTelemetry.create(true, null).serializeToBytes(),
            ExtendedMediaTypeRegistry.APPLICATION_COSE_SIGN1));
    Assert.assertEquals(
        ResponseCode.UNSUPPORTED_CONTENT_FORMAT,
        pledge.sendStatusTelemetry(
            ConstantsBrski.VOUCHER_STATUS,
            wrongFormatTelemetry,
            ExtendedMediaTypeRegistry.APPLICATION_COSE_SIGN1));
    wrongFormatTelemetry = Hex.decode("a36776657273696f6e0166737461747573f467726561736f6e787174686973206b65792069732077726f6e67");
    Assert.assertEquals(
        ResponseCode.BAD_REQUEST,
        pledge.sendStatusTelemetry(
            ConstantsBrski.VOUCHER_STATUS,
            wrongFormatTelemetry,
            ExtendedMediaTypeRegistry.APPLICATION_CBOR));
    Assert.assertEquals(
        ResponseCode.CHANGED,
        pledge.sendStatusTelemetry(
            ConstantsBrski.ENROLL_STATUS,
            StatusTelemetry.create(true, "this msg is not needed").serializeToBytes(),
            ExtendedMediaTypeRegistry.APPLICATION_CBOR));
  }

  @Test
  public void testReset() throws Exception {
    pledge.requestVoucher();
    pledge.enroll();
    verifyEnroll(pledge);
    pledge.reenroll();
    verifyEnroll(pledge);

    pledge.reset();

    pledge.requestVoucher();
    pledge.enroll();
    verifyEnroll(pledge);
    pledge.reenroll();
    verifyEnroll(pledge);
  }

  @Test
  public void testMultiPledges() throws Exception {
    PledgeThread[] threads = new PledgeThread[12];

    // create multiple PledgeThreads, each with own Pledge and own credentials.
    for (int i = 0; i < threads.length; ++i) {
      threads[i] = new PledgeThread();
    }

    // run the Pledges -- staggered slightly to simulate Pledges arriving non-simultaneously,
    // rather than a synchronized thundering herd at the Registrar.
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
          Assert.fail(msg);
        }
      } catch (InterruptedException e) {
        Assert.fail("join failed: " + e.getMessage());
      }
    }
  }

  /**
   * In a thread, create a new Pledge and let it do voucher request and enrollment operations. Any error state is logged internally.
   */
  private class PledgeThread extends Thread {

    public Throwable errorState = null;
    public Pledge pledge;

    public PledgeThread() throws Exception {
      cg.makePledge(null); // create a new Pledge identity and serial number
      pledge = new Pledge(cg.getCredentials(CredentialsSet.PLEDGE_ALIAS), REGISTRAR_URI);
    }

    @Override
    public void run() {
      try {
        pledge.requestVoucher();
        Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));
        pledge.enroll();
        verifyEnroll(pledge);
        Assert.assertEquals(ResponseCode.CHANGED, pledge.sendEnrollStatusTelemetry(true, null));

        pledge.reenroll();
        verifyEnroll(pledge);

      } catch (Throwable e) {
        errorState = e;
      } finally {
        if (pledge != null) {
          pledge.shutdown();
        }
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
        cg.getCredentials(CredentialsSet.DOMAIN_CA_ALIAS).getCertificate();

    // Re-pack as fresh Credentials with the new chain, reusing the original
    // alias/password/private-key.
    Credentials baseRegCred = cg.getCredentials(CredentialsSet.REGISTRAR_ALIAS);
    Credentials regCredWithNewChain =
        new Credentials(
            baseRegCred.getPrivateKey(),
            new X509Certificate[]{cert, domainCaCert},
            baseRegCred.getAlias(),
            baseRegCred.getPassword());

    RegistrarBuilder registrarBuilder = new RegistrarBuilder();
    registrar =
        registrarBuilder
            .setCredentials(regCredWithNewChain)
            .setTrustAllMasas(true)
            .build();
    registrar.setDomainCA(domainCA);
    registrar.start();

    // test connection does not work - our Pledge checks for cmcRA in certificate
    CoapResponse response;
    try {
      pledge.sayHello();
      Assert.fail("Pledge mistakenly accepted Registrar without cmcRA");
    } catch (IOException ex) {
      // expected IOException here.
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
      Assert.assertEquals(ResponseCode.FORBIDDEN, ex.getCode());
    }
  }

  @Test
  public void testRegistrarUsingCmsJsonVoucherRequest() throws Exception {

    registrar.stop();

    // create new Registrar that uses only CMS-signed JSON voucher requests towards MASA
    RegistrarBuilder registrarBuilder = new RegistrarBuilder();
    registrar = registrarBuilder.setCredentials(cg.getCredentials(CredentialsSet.REGISTRAR_ALIAS))
        .setTrustAllMasas(true)
        .build();
    registrar.setDomainCA(domainCA);
    registrar.setForcedRequestFormat(ConstantsBrski.MEDIA_TYPE_VOUCHER_CMS_JSON);
    registrar.start();

    Voucher voucher = pledge.requestVoucher();
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));
    pledge.enroll();
    verifyEnroll(pledge);
    Assert.assertTrue(voucher.validate());
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendEnrollStatusTelemetry(true, null));
  }
}
