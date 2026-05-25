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

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.CertificateVerificationResult;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class RegistrarCertificateVerifier implements NewAdvancedCertificateVerifier {

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
  public List<CertificateType> getSupportedCertificateTypes() {
    return Collections.singletonList(CertificateType.X_509);
  }

  @Override
  public CertificateVerificationResult verifyCertificate(
      ConnectionId cid,
      ServerNames serverName,
      InetSocketAddress remotePeer,
      boolean clientUsage,
      boolean verifySubject,
      boolean truncateCertificatePath,
      CertificateMessage message) {
    CertPath certChain = message.getCertificateChain();

    if (trustAnchors == null) {
      // Trust everyone
      return new CertificateVerificationResult(cid, certChain, null);
    }
    if (trustAnchors.isEmpty()) {
      // Trust no-one
      AlertMessage alert =
          new AlertMessage(
              AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.BAD_CERTIFICATE);
      return new CertificateVerificationResult(
          cid, new HandshakeException("no client is trusted", alert), null);
    }

    try {
      PKIXParameters params = new PKIXParameters(trustAnchors);
      params.setRevocationEnabled(false);

      CertPathValidator validator = CertPathValidator.getInstance("PKIX");
      validator.validate(certChain, params);

    } catch (GeneralSecurityException e) {
      logger.error("handshake - certificate validation failed: " + e.getMessage(), e);
      AlertMessage alert =
          new AlertMessage(
              AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.BAD_CERTIFICATE);
      return new CertificateVerificationResult(
          cid, new HandshakeException("Certificate chain could not be validated", alert, e), null);
    }
    logger.info("handshake - certificate validation succeeded");
    return new CertificateVerificationResult(cid, certChain, null);
  }

  @Override
  public List<X500Principal> getAcceptedIssuers() {
    // This is used in the CertificateRequest message; we set it to an empty list to include
    // no trusted anchor issuers in that message. Because we could have many MASA trust
    // anchors, there is risk of IP fragmentation. So we leave this empty as we don't
    // really need it.
    return Collections.emptyList();
  }

  @Override
  public void setResultHandler(HandshakeResultHandler resultHandler) {
    // Verification is performed synchronously, so no asynchronous result handler is needed.
  }
}
