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

package com.google.openthread.pledge;

import com.google.openthread.brski.ConstantsBrski;
import java.net.InetSocketAddress;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
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

/**
 * CertificateVerifier for the Pledge, to perform all actions with a Registrar such as BRSKI voucher
 * request, enrollment, re-enrollment, etc. Only valid for scope of contact with a Registrar.
 */
public final class PledgeCertificateVerifier implements NewAdvancedCertificateVerifier {

  private static final Logger logger = LoggerFactory.getLogger(PledgeCertificateVerifier.class);

  private final Set<TrustAnchor> trustAnchors;
  private CertPath peerCertPath;
  private boolean peerAccepted = false;
  private boolean doVerification = false;
  private boolean isCmcRaCheck = true;

  public PledgeCertificateVerifier(Set<TrustAnchor> trustAnchors) {
    this.trustAnchors = new HashSet<>();
    if (trustAnchors != null) {
      this.trustAnchors.addAll(trustAnchors);
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

    // We save the provisionally accepted registrar certificate chain, it will be verified
    // later, after we get a pinned domain/Registrar certificate in the voucher.
    peerCertPath = message.getCertificateChain();

    // Check that it contains at least something to verify later.
    if (peerCertPath.getCertificates().isEmpty()) {
      peerAccepted = false;
      AlertMessage alert =
          new AlertMessage(
              AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.BAD_CERTIFICATE);
      return new CertificateVerificationResult(
          cid, new HandshakeException("No server certificates", alert), null);
    }

    try {

      X509Certificate peerCert = (X509Certificate) peerCertPath.getCertificates().get(0);
      X509CertificateHolder peerCertBC =
          new X509CertificateHolder(peerCert.getEncoded()); // BouncyCastle equivalent

      // Check that it is at least an RA cert
      Extension ext = peerCertBC.getExtension(ConstantsBrski.EKU_OID);
      if (ext == null) throw new CertificateException("EKU not present in Registrar cert");
      ASN1Sequence ekus;
      try (ASN1InputStream is = new ASN1InputStream(ext.getExtnValue().getOctets())) {
        ASN1Primitive p = is.readObject();
        if (p == null) {
          throw new CertificateException("empty EKU extension in Registrar cert");
        }
        ekus = ASN1Sequence.getInstance(p);
      }
      boolean isServerAuth = false;
      boolean isCmcRa = false;
      for (ASN1Encodable eku : ekus) {
        if (eku.equals(KeyPurposeId.id_kp_serverAuth.toOID())) isServerAuth = true;
        if (eku.equals(ConstantsBrski.ID_KP_CMC_RA.toOID())) isCmcRa = true;
      }
      if (!isServerAuth) throw new CertificateException("EKU tlsServerAuth not present");
      if (!isCmcRa && isCmcRaCheck) throw new CertificateException("EKU id_kp_cmcRA not present");

      // Check that it is valid in terms of time/date.
      peerCert.checkValidity();

      // In case of non-empty TA store and verification enabled, validate it.
      if (isDoVerification() && !trustAnchors.isEmpty()) {
        PKIXParameters params = new PKIXParameters(trustAnchors);
        params.setRevocationEnabled(false);

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        validator.validate(peerCertPath, params);
        logger.info("handshake - certificate validation succeeded");
      } else {
        // We do no verification here to provisionally accept registrar certificate.
        // This is typically for the bootstrap first contact only.
        logger.info("registrar provisionally accepted without verification");
      }

      peerAccepted = true;
    } catch (Exception e) {
      logger.error("handshake - certificate validation failed: " + e.getMessage(), e);
      peerAccepted = false;
      AlertMessage alert =
          new AlertMessage(
              AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.BAD_CERTIFICATE);
      return new CertificateVerificationResult(
          cid, new HandshakeException("Certificate chain could not be validated", alert, e), null);
    }

    return new CertificateVerificationResult(cid, peerCertPath, null);
  }

  @Override
  public List<X500Principal> getAcceptedIssuers() {
    List<X500Principal> res = new ArrayList<>();
    for (TrustAnchor ta : trustAnchors) {
      if (ta.getTrustedCert() != null) {
        res.add(ta.getTrustedCert().getSubjectX500Principal());
      }
    }
    return res;
  }

  @Override
  public void setResultHandler(HandshakeResultHandler resultHandler) {
    // Verification is performed synchronously, so no asynchronous result handler is needed.
  }

  public void addTrustAnchor(TrustAnchor ta) {
    trustAnchors.add(ta);
  }

  public CertPath getPeerCertPath() {
    return peerCertPath;
  }

  public boolean isPeerAccepted() {
    return peerAccepted;
  }

  public void setDoVerification(boolean doVerification) {
    this.doVerification = doVerification;
  }

  public boolean isDoVerification() {
    return this.doVerification;
  }

  public void setCmcRaCheck(boolean cmcRaCheck) {
    this.isCmcRaCheck = cmcRaCheck;
  }
}
