/*
 *    Copyright (c) 2026, The OpenThread Registrar Authors.
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

package com.google.openthread.pledge;

import com.google.openthread.CredentialsSet;
import com.google.openthread.brski.ExtendedMediaTypeRegistry;
import com.google.openthread.tools.CredentialGenerator;
import com.upokecenter.cbor.CBORObject;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the parsing of EST-coaps CA certificates responses, in the response formats defined
 * by cBRSKI and RFC 9148.
 */
public class PledgeCaCertificatesTest {

  private static X509Certificate domainCaCert;
  private static X509Certificate registrarCert;

  @BeforeClass
  public static void setup() throws Exception {
    CredentialGenerator cg = new CredentialGenerator();
    cg.make(null, null, null, null, null);
    domainCaCert = cg.getCredentials(CredentialsSet.DOMAIN_CA_ALIAS).getCertificate();
    registrarCert = cg.getCredentials(CredentialsSet.REGISTRAR_ALIAS).getCertificate();
  }

  /** A single certificate in application/pkix-cert (287) format. */
  @Test
  public void parsesSinglePkixCert() throws Exception {
    List<X509Certificate> certs =
        Pledge.parseCACertificates(
            domainCaCert.getEncoded(), ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT);

    Assert.assertEquals(1, certs.size());
    Assert.assertEquals(domainCaCert, certs.get(0));
  }

  /**
   * A multipart-core (62) container holding two certificates, per the example in cBRSKI-31 section
   * 6.7.5: {@code [ 287, h'3082...', 287, h'3082...' ]}. Order must be preserved, since the spec
   * requires CA hierarchy order starting at the issuer of the client's LDevID.
   */
  @Test
  public void parsesMultipartCoreContainer() throws Exception {
    CBORObject container = CBORObject.NewArray();
    container.Add(ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT);
    container.Add(registrarCert.getEncoded());
    container.Add(ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT);
    container.Add(domainCaCert.getEncoded());

    List<X509Certificate> certs =
        Pledge.parseCACertificates(
            container.EncodeToBytes(), ExtendedMediaTypeRegistry.APPLICATION_MULTIPART_CORE);

    Assert.assertEquals(2, certs.size());
    Assert.assertEquals(registrarCert, certs.get(0));
    Assert.assertEquals(domainCaCert, certs.get(1));
  }

  /** Elements in a format other than pkix-cert are skipped, not fatal: future formats may appear. */
  @Test
  public void skipsUnsupportedMultipartElements() throws Exception {
    CBORObject container = CBORObject.NewArray();
    container.Add(65000 /* some future certificate format */);
    container.Add(new byte[]{0x01, 0x02, 0x03});
    container.Add(ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT);
    container.Add(domainCaCert.getEncoded());

    List<X509Certificate> certs =
        Pledge.parseCACertificates(
            container.EncodeToBytes(), ExtendedMediaTypeRegistry.APPLICATION_MULTIPART_CORE);

    Assert.assertEquals(1, certs.size());
    Assert.assertEquals(domainCaCert, certs.get(0));
  }

  /** A multipart-core container must be an array of (content-format, bytes) pairs. */
  @Test(expected = PledgeException.class)
  public void rejectsOddLengthMultipartContainer() throws Exception {
    CBORObject container = CBORObject.NewArray();
    container.Add(ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT);
    container.Add(domainCaCert.getEncoded());
    container.Add(ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT);

    Pledge.parseCACertificates(
        container.EncodeToBytes(), ExtendedMediaTypeRegistry.APPLICATION_MULTIPART_CORE);
  }

  @Test(expected = PledgeException.class)
  public void rejectsNonArrayMultipartContainer() throws Exception {
    Pledge.parseCACertificates(
        CBORObject.FromObject("not an array").EncodeToBytes(),
        ExtendedMediaTypeRegistry.APPLICATION_MULTIPART_CORE);
  }

  @Test(expected = PledgeException.class)
  public void rejectsUnsupportedContentFormat() throws Exception {
    Pledge.parseCACertificates(domainCaCert.getEncoded(), ExtendedMediaTypeRegistry.APPLICATION_CBOR);
  }
}
