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

import static org.junit.Assert.*;

import com.google.openthread.*;
import com.google.openthread.brski.*;
import com.google.openthread.domainca.*;
import com.google.openthread.masa.*;
import com.google.openthread.pledge.*;
import com.google.openthread.registrar.*;
import java.security.Principal;
import org.junit.*;
import org.junit.runners.*;
import org.slf4j.*;

/**
 * A tool to test a Hardware Pledge DUT (OpenThread CLI device) against the Registrar/MASA. The
 * specific network setup so that the Pledge can reach the Registrar, is to be done by the user and
 * out of scope of this tool. It uses JUnit framework for easy GUI usage e.g. in Eclipse; consider
 * these as integration tests of the hardware Pledge.
 *
 * <p>Using Maven, this test suite is NOT executed during Maven test phase unit testing. So, it
 * needs to be explicitly invoked.
 */
// One can enable this line to let Eclipse JUnit ignore this test when running all unit tests from
// the GUI.
// @Ignore("The PledgeHw* tests can only be run with hardware Pledge and network setup, skipping.")
// Below test order is not mandatory, but saves time if executed in order.
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class HardwarePledgeTestSuite {

  public static final String THREAD_DOMAIN_NAME = "TestDomainTCE";
  public static final int IEEE_802154_CHANNEL = 19;
  public static final String[] MASA_CREDENTIAL_FILES =
      new String[] {
        "./credentials/local-masa/masa_cert.pem", "./credentials/local-masa/masa_private.pem"
      };
  public static final String[] MASACA_CREDENTIAL_FILES =
      new String[] {
        "./credentials/local-masa/masaca_cert.pem", "./credentials/local-masa/masaca_private.pem"
      };
  public static final String[] DOMAIN_CREDENTIAL_FILES =
      new String[] {
        "./credentials/local-masa/domainca_cert.pem",
        "./credentials/local-masa/domainca_private.pem"
      };
  public static final String BORDER_ROUTER_AUTHORITY = "[fd00:910b::3285:1958:d0c9:d06]:49191";

  private static final String REGISTRAR_URI = "[::1]:" + Constants.DEFAULT_REGISTRAR_COAPS_PORT;
  private DomainCA domainCA;
  private Registrar registrar;
  private MASA masa;
  private static PledgeHardware pledge;
  private static CredentialGenerator credGen;
  private static Logger logger = LoggerFactory.getLogger(HardwarePledgeTestSuite.class);

  @BeforeClass
  public static void setup() throws Exception {
    credGen = new CredentialGenerator();
    credGen.make(
        DOMAIN_CREDENTIAL_FILES, MASACA_CREDENTIAL_FILES, MASA_CREDENTIAL_FILES, null, null);
    pledge = new PledgeHardware();
    assertTrue(pledge.factoryReset());
    assertTrue(pledge.execCommandDone("channel " + IEEE_802154_CHANNEL));
  }

  @AfterClass
  public static void tearDown() {
    if (pledge != null) {
      pledge.shutdown();
      logger.info(pledge.getLog()); // dump the Pledge's log, to aid troubleshooting.
    }
  }

  @Before
  public void init() throws Exception {
    masa =
        new MASA(
            credGen.getCredentials(CredentialGenerator.MASA_ALIAS),
            credGen.getCredentials(CredentialGenerator.MASACA_ALIAS),
            Constants.DEFAULT_MASA_HTTPS_PORT);

    domainCA =
        new DomainCA(
            THREAD_DOMAIN_NAME, credGen.getCredentials(CredentialGenerator.DOMAINCA_ALIAS));

    RegistrarBuilder registrarBuilder = new RegistrarBuilder();
    registrar =
        registrarBuilder
            .setCredentials(credGen.getCredentials(CredentialGenerator.REGISTRAR_ALIAS))
            .setTrustAllMasas(true)
            .build();
    registrar.setDomainCA(domainCA);
    // for local testing we force the MASA URI to localhost.
    registrar.setForcedMasaUri(Constants.DEFAULT_MASA_URI);

    masa.start();
    registrar.start();
  }

  @After
  public void finalize() throws Exception {
    assertTrue(pledge.execCommandDone("thread stop"));
    registrar.stop();
    masa.stop();
  }

  /** Basic test for DUT Pledge response */
  @Test
  public void testDUT_responds() throws Exception {
    assertEquals(PledgeHardware.THREAD_VERSION_PLEDGE, pledge.execCommand("thread version"));
    assertTrue(pledge.execCommandDone("ifconfig down"));
    assertTrue(pledge.execCommandDone("ifconfig up"));
    String nkey = pledge.execCommand("masterkey");
    assertTrue(nkey.length() == 32);
  }

  /** DISC-TC-01: */
  @Test
  public void test_5_02_DISC_TC_01() throws Exception {
    if (pledge.isEnrolled()) pledge.factoryReset();
    assertFalse(pledge.isEnrolled());
    assertTrue(pledge.execCommandDone("joiner startae"));
    String res = pledge.waitForMessage(20000);
    assertNotNull(res);
    // only check that handshake went well.
    assertFalse(OpenThreadUtils.detectEnrollFailure(res));
  }

  /** DISC-TC-02: */
  @Test
  public void test_5_02_DISC_TC_02() throws Exception {
    if (!pledge.isEnrolled()) pledge.enroll();
    assertTrue(pledge.isEnrolled());
    assertTrue(pledge.execCommandDone("joiner startae"));
    String res = pledge.waitForMessage(20000);
    assertNotNull(res);
    assertFalse(OpenThreadUtils.detectNkpFailure(res));
    // assertTrue(OpenThreadUtils.detectNkpSuccess(res));
  }

  /** AE-TC-01: Regular BRSKI + EST enrollment */
  @Test
  public void test_5_05_AE_TC_01() throws Exception {

    if (pledge.isEnrolled()) pledge.factoryReset();

    assertFalse(pledge.isEnrolled());
    assertTrue(pledge.execCommandDone("joiner startae"));
    pledge.waitForMessage(20000);

    // verify on registrar side that enrollment completed.
    Principal[] lClients = registrar.getKnownClients();
    assertEquals(1, lClients.length);
    StatusTelemetry voucherStatus = registrar.getVoucherStatusLogEntry(lClients[0]);
    StatusTelemetry enrollStatus = registrar.getEnrollStatusLogEntry(lClients[0]);

    // verify voucherStatus aspects
    assertNotNull(voucherStatus);
    assertNotEquals(StatusTelemetry.UNDEFINED, voucherStatus);
    assertEquals(true, voucherStatus.status);
    assertEquals(true, voucherStatus.isValidFormat);

    // verify enrollStatus aspects
    assertNotNull(enrollStatus);
    assertNotEquals(StatusTelemetry.UNDEFINED, enrollStatus);
    assertEquals(true, enrollStatus.status);
    assertEquals(true, enrollStatus.isValidFormat);

    // verify same on pledge side.
    assertTrue(pledge.isEnrolled());
  }

  /** NKP-TC-01: */
  @Test
  public void test_5_06_NKP_TC_01() throws Exception {
    assertTrue(false);
  }

  /** NKP-TC-01a: */
  @Test
  public void test_5_06_NKP_TC_01a() throws Exception {
    // Need to be enrolled to do NKP.
    if (!pledge.isEnrolled()) pledge.enroll();
    assertTrue(pledge.isEnrolled());
    assertTrue(pledge.execCommandDone("joiner startnmkp"));
    String resp = pledge.waitForMessage(15000);
    assertTrue(false); // TODO
  }

  /** NKP-TC-02: Network Key Provisioning (NKP) after enrollment. */
  @Test
  public void test_5_06_NKP_TC_02() throws Exception {

    // Need to be enrolled to do NKP.
    if (!pledge.isEnrolled()) pledge.enroll();

    assertTrue(pledge.execCommandDone("masterkey 33112233445566118899aabbccddeeff"));
    String oldkey = pledge.execCommand("masterkey");
    assertTrue(pledge.isEnrolled());
    assertTrue(pledge.execCommandDone("joiner startnmkp"));
    pledge.waitForMessage(15000);
    String newkey = pledge.execCommand("masterkey");
    assertNotEquals(oldkey, newkey);

    // join Thread network
    assertEquals("disabled", pledge.execCommand("state"));
    assertTrue(pledge.execCommandDone("thread start"));
    Thread.sleep(3000);
    assertNotEquals("disabled", pledge.execCommand("state")); // verify thread is started
    assertEquals("false", pledge.execCommand("singleton")); // verify I joined with BR.
  }
}
