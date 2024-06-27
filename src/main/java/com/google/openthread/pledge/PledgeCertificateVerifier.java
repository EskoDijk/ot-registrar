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
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CertificateVerifier for the Pledge, to perform all actions with a Registrar such as BRSKI voucher
 * request, enrollment, re-enrollment, etc. Only valid for scope of contact with a Registrar.
 */
public class PledgeCertificateVerifier implements CertificateVerifier {

  public PledgeCertificateVerifier(Set<TrustAnchor> trustAnchors) {
    this.trustAnchors = new HashSet<>();
    if (trustAnchors != null) {
      this.trustAnchors.addAll(trustAnchors);
    }

    logger = LoggerFactory.getLogger(PledgeCertificateVerifier.class);
  }

  @Override
  public void verifyCertificate(CertificateMessage message, DTLSSession session)
      throws HandshakeException {

    // We save the provisionally accepted registrar certificate chain, it will be verified
    // later, after we get a pinned domain/Registrar certificate in the voucher.
    peerCertPath = message.getCertificateChain();

    // Check that it contains at least something to verify later.
    if (peerCertPath.getCertificates().size() == 0) {
      AlertMessage alert =
          new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE, session.getPeer());
      peerAccepted = false;
      throw new HandshakeException("No server certificates", alert);
    }

    try {

      X509Certificate peerCert = (X509Certificate) peerCertPath.getCertificates().get(0);
      X509CertificateHolder peerCertBC =
          new X509CertificateHolder(peerCert.getEncoded()); // BouncyCastle equivalent

      // Check that it is at least an RA cert
      Extension ext = peerCertBC.getExtension(ConstantsBrski.eku);
      // byte[] ekuBytes = peerCert.getExtensionValue(Constants.EXTENDED_KEY_USAGE_OID);
      if (ext == null) throw new CertificateException("EKU not present in Registrar cert");
      ASN1InputStream is = new ASN1InputStream(ext.getExtnValue().getOctets());
      ASN1Primitive p;
      ASN1Sequence ekus = null;
      boolean isServerAuth = false;
      boolean isCmcRa = false;
      if ((p = is.readObject()) != null) {
        ekus = ASN1Sequence.getInstance(p);
      }
      for (ASN1Encodable eku : ekus) {
        if (eku.equals(KeyPurposeId.id_kp_serverAuth.toOID())) isServerAuth = true;
        if (eku.equals(ConstantsBrski.id_kp_cmcRA.toOID())) isCmcRa = true;
      }
      is.close();
      if (!isServerAuth) throw new CertificateException("EKU tlsServerAuth not present");
      if (!isCmcRa && isCmcRaCheck) throw new CertificateException("EKU id_kp_cmcRA not present");

      // eku.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth);
      // eku.hasKeyPurposeId(Constants.id_kp_cmcRA);
      // Check that it is valid in terms of time/date.
      peerCert.checkValidity();

      // In case of non-empty TA store and verification enabled, validate it.
      if (isDoVerification() && !trustAnchors.isEmpty()) {
        PKIXParameters params = new PKIXParameters(trustAnchors);
        params.setRevocationEnabled(false);

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        validator.validate(message.getCertificateChain(), params);
        logger.info("handshake - certificate validation succeed!");
      } else {
        // We do no verification here to provisionally accept registrar certificate.
        // This is typically for the bootstrap first contact only.
        logger.info("registrar provisionally accepted without verification!");
      }

      peerAccepted = true;
    } catch (Exception e) {
      logger.error("handshake - certificate validation failed: " + e.getMessage(), e);
      AlertMessage alert =
          new AlertMessage(
              AlertMessage.AlertLevel.FATAL,
              AlertMessage.AlertDescription.BAD_CERTIFICATE,
              session.getPeer());
      peerAccepted = false;
      throw new HandshakeException("Certificate chain could not be validated", alert, e);
    }
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    List<X509Certificate> res = new ArrayList<>();
    for (TrustAnchor ta : trustAnchors) {
      if (ta.getTrustedCert() != null) {
        res.add(ta.getTrustedCert());
      }
    }
    return res.toArray(new X509Certificate[res.size()]);
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

  protected Set<TrustAnchor> trustAnchors;

  protected CertPath peerCertPath;

  protected boolean peerAccepted = false;

  protected boolean doVerification = false;

  protected boolean isCmcRaCheck = true;

  protected Logger logger;

  public void setCmcRaCheck(boolean b) {
    this.isCmcRaCheck = b;
  }
}
