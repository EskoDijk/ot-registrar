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

import com.google.openthread.Credentials;
import com.google.openthread.CredentialsSet;
import com.google.openthread.Role;
import com.google.openthread.brski.ConstantsBrski;
import com.google.openthread.brski.Voucher;
import com.google.openthread.domainca.DomainCA;
import com.google.openthread.masa.MASA;
import com.google.openthread.pledge.Pledge;
import com.google.openthread.pledge.Pledge.CertState;
import com.google.openthread.tools.CredentialGenerator;
import java.io.IOException;
import java.security.GeneralSecurityException;
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

  private static final String REGISTRAR_URI = "coaps://[::1]:" + ConstantsBrski.DEFAULT_REGISTRAR_COAPS_PORT;
  private static final String THREAD_DOMAIN_NAME = "Thread-Test";

  // the acting entities
  private DomainCA domainCA;
  private Registrar registrar;
  private Pledge pledge;
  private MASA masa;

  // credentials used (loaded once in @BeforeClass)
  private static CredentialsSet credsMasa, credsPledge, credsRegistrar;

  @BeforeClass
  public static void setup() throws Exception {
    credsMasa = new CredentialsSet("default", Role.Masa);
    credsPledge = new CredentialsSet("default", Role.Pledge);
    credsRegistrar = new CredentialsSet("default", Role.Registrar);
  }

  @Before
  public void init() throws Exception {
    // disable debug logging.
    ch.qos.logback.classic.Logger rootLogger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME);
    rootLogger.setLevel(ch.qos.logback.classic.Level.INFO);
    initEntities(credsMasa, credsPledge, credsRegistrar);
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
            THREAD_DOMAIN_NAME, findCredentials(CredentialsSet.DOMAIN_CA_ALIAS, credentialSets));

    RegistrarBuilder registrarBuilder = new RegistrarBuilder();
    registrar =
        registrarBuilder
            .setCredentials(findCredentials(CredentialsSet.REGISTRAR_ALIAS, credentialSets))
            .setTrustAllMasas(true)
            .build();
    registrar.setDomainCA(domainCA);
    registrar.setForcedMasaUri("localhost:" + ConstantsBrski.DEFAULT_MASA_HTTPS_PORT); // force localhost, don't use MASA URI in Pledge IDevID

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
