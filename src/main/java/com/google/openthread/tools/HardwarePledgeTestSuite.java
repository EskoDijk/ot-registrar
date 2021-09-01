/*
 *    Copyright (c) 2021, The OpenThread Registrar Authors.
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

package com.google.openthread.tools;

import com.google.openthread.*;
import com.google.openthread.brski.*;
import com.google.openthread.commissioner.*;
import com.google.openthread.domainca.*;
import com.google.openthread.masa.*;
import com.google.openthread.pledge.Pledge.*;
import com.google.openthread.pledge.PledgeHardware;
import com.google.openthread.registrar.*;
import java.security.Principal;
import java.security.cert.X509Certificate;
import org.junit.*;
import org.slf4j.*;

/**
 * A tool to test a Hardware Pledge (OpenThread CLI device) against the Registrar/MASA. The specific
 * setup of Thread Network so that the Pledge can reach the Registrar, is up to the user and out of
 * scope of this tool.
 */
// @Ignore("The PledgeHw* tests can only be run with hardware Pledge and network setup, skipping.")
public class HardwarePledgeTestSuite {

  public static final String DEFAULT_DOMAIN_NAME = "Thread-Test";
  public static final int IEEE_802154_CHANNEL = 19;

  private DomainCA domainCA;
  private Registrar registrar;
  private Commissioner commissioner;
  private MASA masa;
  private static PledgeHardware pledge;

  private static CredentialGenerator cg;

  private static Logger logger = LoggerFactory.getLogger(HardwarePledgeTestSuite.class);

  @BeforeClass
  public static void setup() throws Exception {
    cg = new CredentialGenerator();
    cg.make(null, null, null, null);
    pledge = new PledgeHardware();
    Assert.assertTrue(pledge.factoryReset());
    Assert.assertTrue(pledge.execCommandDone("channel " + IEEE_802154_CHANNEL));
  }

  @AfterClass
  public static void tearDown() {
    if (pledge != null) {
      logger.info(pledge.getLog());
      pledge.shutdown();
    }
  }

  @Before
  public void init() throws Exception {
    masa =
        new MASA(
            cg.masaKeyPair.getPrivate(),
            cg.masaCert,
            cg.getCredentials(CredentialGenerator.MASA_ALIAS),
            Constants.DEFAULT_MASA_HTTPS_PORT,
            false);

    domainCA = new DomainCA(DEFAULT_DOMAIN_NAME, cg.domaincaKeyPair.getPrivate(), cg.domaincaCert);

    RegistrarBuilder registrarBuilder = new RegistrarBuilder();
    registrar =
        registrarBuilder
            .setPrivateKey(cg.registrarKeyPair.getPrivate())
            .setCertificateChain(new X509Certificate[] {cg.registrarCert, cg.domaincaCert})
            .addMasaCertificate(cg.masaCert)
            .setMasaClientCredentials(cg.getCredentials(CredentialGenerator.REGISTRAR_ALIAS))
            .setForcedMasaUri(Constants.DEFAULT_MASA_URI)
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
    commissioner.shutdown();
    registrar.stop();
    masa.stop();
  }

  private void VerifyEnroll(PledgeHardware pledge) throws Exception {}

  private void VerifyPledge(PledgeHardware pledge) {}

  @Test
  public void testBasicResponses() throws Exception {
    Assert.assertEquals("1.2", pledge.execCommand("thread version"));
    Assert.assertTrue(pledge.execCommandDone("ifconfig up"));
    Assert.assertTrue(pledge.execCommandDone("ifconfig down"));
    String nkey = pledge.execCommand("masterkey");
    Assert.assertTrue(nkey.length() == 32);
    Assert.assertFalse(pledge.isEnrolled());
  }

  /**
   * Regular BRSKI + EST enrollment
   *
   * @throws Exception
   */
  @Test
  public void testEnrollment() throws Exception {

    Assert.assertTrue(pledge.execCommandDone("ifconfig up"));
    Assert.assertFalse(pledge.isEnrolled());
    Assert.assertTrue(pledge.execCommandDone("joiner startae"));
    pledge.waitForMessage(20000);

    // verify on registrar side that enrollment completed.
    Principal[] lClients = registrar.getKnownClients();
    Assert.assertEquals(1, lClients.length);
    StatusTelemetry voucherStatus = registrar.getVoucherStatusLogEntry(lClients[0]);
    StatusTelemetry enrollStatus = registrar.getEnrollStatusLogEntry(lClients[0]);
    Assert.assertNotNull(voucherStatus);
    Assert.assertNotNull(enrollStatus);
    Assert.assertTrue(voucherStatus.status);
    Assert.assertTrue(enrollStatus.status);

    // verify same on pledge side.
    Assert.assertTrue(pledge.isEnrolled());
  }
}
