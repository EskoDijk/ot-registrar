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

import java.security.GeneralSecurityException;
import java.security.cert.CertPathValidator;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class RegistrarCertificateVerifier implements CertificateVerifier {

  private static final Logger logger =
      LoggerFactory.getLogger(RegistrarCertificateVerifier.class);

  private final Set<TrustAnchor> trustAnchors;

  /**
   * Create a new RegistrarCertificateVerifier that only trusts the given rootCertificates. Use null
   * parameter to trust everyone.
   *
   * @param rootCertificates trusted root certificates, or empty array to trust none, or null to
   *     trust ALL.
   */
  public RegistrarCertificateVerifier(X509Certificate[] rootCertificates) {
    if (rootCertificates == null) {
      this.trustAnchors = null;
    } else {
      Set<TrustAnchor> set = new HashSet<>();
      for (X509Certificate cert : rootCertificates) {
        set.add(new TrustAnchor(cert, null));
      }
      this.trustAnchors = set;
    }
  }

  @Override
  public void verifyCertificate(CertificateMessage message, DTLSSession session)
      throws HandshakeException {
    if (trustAnchors == null) {
      // Trust everyone
      return;
    }
    if (trustAnchors.isEmpty()) {
      // Trust no-one
      AlertMessage alert =
          new AlertMessage(
              AlertMessage.AlertLevel.FATAL,
              AlertMessage.AlertDescription.BAD_CERTIFICATE,
              session.getPeer());
      throw new HandshakeException("no client is trusted", alert);
    }

    try {
      PKIXParameters params = new PKIXParameters(trustAnchors);
      params.setRevocationEnabled(false);

      CertPathValidator validator = CertPathValidator.getInstance("PKIX");
      validator.validate(message.getCertificateChain(), params);

    } catch (GeneralSecurityException e) {
      logger.error("handshake - certificate validation failed: " + e.getMessage(), e);
      AlertMessage alert =
          new AlertMessage(
              AlertMessage.AlertLevel.FATAL,
              AlertMessage.AlertDescription.BAD_CERTIFICATE,
              session.getPeer());
      throw new HandshakeException("Certificate chain could not be validated", alert, e);
    }
    logger.info("handshake - certificate validation succeeded");
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    // This is used in the CertificateRequest message; we set it to an empty array to include
    // no trusted anchor issuers in that message. Because we could have many MASA trust
    // anchors, there is risk of IP fragmentation. So we leave this empty as we don't
    // really need it.
    return new X509Certificate[0];
  }
}
