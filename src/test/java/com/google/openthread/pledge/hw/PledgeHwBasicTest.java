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

package com.google.openthread.pledge.hw;

import com.google.openthread.*;
import com.google.openthread.brski.*;
import com.google.openthread.commissioner.*;
import com.google.openthread.domainca.*;
import com.google.openthread.masa.*;
import com.google.openthread.pledge.Pledge.*;
import com.google.openthread.pledge.PledgeHardware;
import com.google.openthread.registrar.*;
import com.google.openthread.tools.*;
import java.security.cert.X509Certificate;
import org.junit.*;
import org.slf4j.*;

/** Perform basic integration tests using a hardware Pledge vs Registrar/MASA. */
@Ignore("The PledgeHw* tests can only be run with hardware Pledge and network setup, skipping.")
public class PledgeHwBasicTest {

  public static final String DEFAULT_DOMAIN_NAME = "Thread-Test";

  private DomainCA domainCA;
  private Registrar registrar;
  private Commissioner commissioner;
  private PledgeHardware pledge;
  private MASA masa;

  private static CredentialGenerator cg;

  private static Logger logger = LoggerFactory.getLogger(FunctionalTest.class);

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
    pledge = new PledgeHardware();

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
    masa.stop();
  }

  private void VerifyEnroll(PledgeHardware pledge) throws Exception {}

  private void VerifyPledge(PledgeHardware pledge) {}

  @Test
  public void testBasicResponses() throws Exception {
    Assert.assertEquals("1.2", pledge.execCommand("thread version"));
  }
}
