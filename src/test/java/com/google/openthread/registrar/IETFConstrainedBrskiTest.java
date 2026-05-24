/*
 *    Copyright (c) 2022, The OpenThread Registrar Authors.
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

import com.google.openthread.brski.ConstantsBrski;
import com.google.openthread.brski.Voucher;
import com.google.openthread.domainca.DomainCA;
import com.google.openthread.masa.MASA;
import com.google.openthread.pledge.Pledge;
import com.google.openthread.pledge.Pledge.CertState;
import com.google.openthread.tools.CredentialGenerator;
import org.bouncycastle.util.encoders.Hex;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This test code is to specifically produce the COSE examples in the Appendix of IETF draft
 * "Constrained BRSKI" - see https://datatracker.ietf.org/doc/html/draft-ietf-anima-constrained-voucher
 */
public final class IETFConstrainedBrskiTest {

  private static final Logger logger = LoggerFactory.getLogger(IETFConstrainedBrskiTest.class);

  public static final String REGISTRAR_URI = "coaps://[::1]:" + ConstantsBrski.DEFAULT_REGISTRAR_COAPS_PORT;
  public static final String THREAD_DOMAIN_NAME = "Thread-Test";
  public static final String CREDENTIALS_KEYSTORE_FILE = "credentials/ietf-draft-constrained-brski/credentials.p12";

  // the acting entities
  private DomainCA domainCA;
  private Registrar registrar;
  private Pledge pledge;
  private MASA masa;

  // credentials used (loaded once in @BeforeClass)
  private static CredentialGenerator cg;

  @BeforeClass
  public static void setup() throws Exception {
    cg = new CredentialGenerator();
    cg.load(CREDENTIALS_KEYSTORE_FILE);
  }

  @Before
  public void init() throws Exception {
    // disable debug logging.
    ch.qos.logback.classic.Logger rootLogger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME);
    rootLogger.setLevel(ch.qos.logback.classic.Level.INFO);
    initEntities(cg);
  }

  // TODO: support pinning a single MASA CA here instead of trusting all. Replace
  //   setTrustAllMasas(true) with .addMasaCertificate(
  //     cg.getCredentials(CredentialGenerator.MASACA_ALIAS).getCertificate())
  //   once the test scenarios distinguish trust modes.
  protected void initEntities(CredentialGenerator credGen) throws Exception {
    masa =
        new MASA(
            credGen.getCredentials(CredentialGenerator.MASA_ALIAS),
            credGen.getCredentials(CredentialGenerator.MASACA_ALIAS),
            ConstantsBrski.DEFAULT_MASA_HTTPS_PORT);
    pledge = new Pledge(credGen.getCredentials(CredentialGenerator.PLEDGE_ALIAS), REGISTRAR_URI);
    pledge.setLightweightClientCertificates(true);

    domainCA = new DomainCA(THREAD_DOMAIN_NAME, credGen.getCredentials(CredentialGenerator.DOMAINCA_ALIAS));

    RegistrarBuilder registrarBuilder = new RegistrarBuilder();
    registrar =
        registrarBuilder
            .setCredentials(credGen.getCredentials(CredentialGenerator.REGISTRAR_ALIAS))
            .setTrustAllMasas(true)
            .build();
    registrar.setDomainCA(domainCA);
    registrar.setForcedMasaUri("localhost:" + ConstantsBrski.DEFAULT_MASA_HTTPS_PORT); // force localhost, don't use MASA URI in Pledge IDevID

    masa.start();
    registrar.start();
  }

  @After
  public void shutdown() {
    pledge.shutdown();
    registrar.stop();
    masa.stop();
  }

  private void verifyPledge(Pledge pledge) {
    Assert.assertNotEquals(CertState.NO_CONTACT, pledge.getState());
    Assert.assertNotEquals(CertState.PROVISIONALLY_ACCEPT, pledge.getState());
  }

  @Test
  public void testVoucherRequestAndDisplayArtifacts() throws Exception {
    // let Pledge create a PVR and get Voucher.
    Voucher voucher = pledge.requestVoucher();
    Assert.assertTrue(voucher.validate());
    verifyPledge(pledge);
    Assert.assertEquals(ResponseCode.CHANGED, pledge.sendVoucherStatusTelemetry(true, null));

    // display the artifacts.
    logger.info("Pledge Voucher Request (PVR) sent by Pledge:\n{}", pledge.getLastPvr());
    logger.info("Pledge Voucher Request (PVR) sent by Pledge as Hex string:\n{}",
        Hex.toHexString(pledge.getLastPvrCoseSigned()));

    logger.info("Registrar Voucher Request (RVR) sent by Registrar:\n{}", registrar.getLastRvr());
    logger.info("Registrar Voucher Request (RVR) sent by Registrar as Hex string:\n{}",
        Hex.toHexString(registrar.getLastRvrCoseSigned()));

    logger.info("Voucher created by MASA:\n{}", voucher);
    logger.info("Voucher created by MASA as Hex string:\n{}",
        Hex.toHexString(pledge.getLastVoucherCoseSigned()));
  }
}
