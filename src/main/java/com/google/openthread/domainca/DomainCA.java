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

package com.google.openthread.domainca;

import com.google.openthread.BouncyCastleInitializer;
import com.google.openthread.Constants;
import com.google.openthread.Credentials;
import com.google.openthread.SecurityUtils;
import com.google.openthread.thread.ConstantsThread;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class DomainCA {

  private static final Logger logger = LoggerFactory.getLogger(DomainCA.class);

  protected static final ASN1ObjectIdentifier THREAD_DOMAIN_NAME_OID_ASN1 =
      new ASN1ObjectIdentifier(ConstantsThread.THREAD_DOMAIN_NAME_OID); // per Thread 1.2 spec

  private static final X509ExtensionUtils EXT_UTILS = new BcX509ExtensionUtils();

  static {
    BouncyCastleInitializer.init();
  }

  private final String domainName;
  private final PrivateKey privateKey;
  private final X509Certificate certificate;

  public DomainCA(String domainName, Credentials creds) throws GeneralSecurityException {
    this.domainName = domainName;
    this.privateKey = creds.getPrivateKey();
    this.certificate = creds.getCertificateChain()[0];
  }

  public PublicKey getPublicKey() {
    return getCertificate().getPublicKey();
  }

  public X509Certificate getCertificate() {
    return certificate;
  }

  /**
   * Get the Thread Domain Name currently used by this Domain CA. Note that a Domain CA may use any number of Thread Domains within its own Enterprise Domain, with arbitrary string identifiers. In the
   * present implementation only one Thread Domain is used.
   *
   * @return the currently used Thread Domain Name used when creating new LDevID certificates.
   */
  public String getDomainName() {
    return domainName;
  }

  public X509Certificate signCertificate(PKCS10CertificationRequest csr) throws DomainCAException {
    try {
      // 0. POP (proof-of-possession) verification
      // Ref: RFC-7030 [3.4]
      if (!csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(csr.getSubjectPublicKeyInfo()))) {
        throw new DomainCAException("POP verification failed");
      }

      // TODO(wgtdkp): validate CSR request

      // 1. Build certificate
      X500Name issuer = getSubjectName();
      BigInteger serial = SecurityUtils.allocateSerialNumber();
      logger.info("allocate serial number: {}", serial);
      Instant now = Instant.now();
      Date notBefore = Date.from(now);
      Date notAfter = Date.from(
          now.atZone(ZoneId.systemDefault()).plus(Constants.CERT_VALIDITY).toInstant());
      X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer, serial, notBefore, notAfter, csr.getSubject(), csr.getSubjectPublicKeyInfo());

      logger.info("operational certificate not-before: {}", notBefore);
      logger.info("operational certificate not-after: {}", notAfter);

      builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

      // per 802.1AR-2018 section 8.10.2, don't include subject key identifier on
      // operational certs (asserted by FunctionalTest). Authority Key Identifier is
      // computed by SHA-1 hash of the CA's SubjectPublicKeyInfo per RFC 5280 §4.2.1.2.
      // TODO: prefer copying the CA's own SubjectKeyIdentifier if it was generated by a
      //   non-standard method — needs a BouncyCastle helper that doesn't exist yet.
      AuthorityKeyIdentifier authorityKeyId =
          EXT_UTILS.createAuthorityKeyIdentifier(
              SubjectPublicKeyInfo.getInstance(getPublicKey().getEncoded()));
      builder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyId);

      // Includes Thread Domain name in X.509v3 extensions section, with value IA5String.
      DERIA5String domainNameStr = new DERIA5String(domainName);
      builder.addExtension(THREAD_DOMAIN_NAME_OID_ASN1, false, domainNameStr);

      // 2. Sign and verify certificate
      ContentSigner signer =
          new JcaContentSignerBuilder(SecurityUtils.SIGNATURE_ALGORITHM).build(this.privateKey);
      X509CertificateHolder holder = builder.build(signer);
      X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
      cert.verify(this.certificate.getPublicKey());

      // 3. Make sure the signed certificate is valid
      {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certs = new ArrayList<>();
        certs.add(cert);
        CertPath path = cf.generateCertPath(certs);

        Set<TrustAnchor> trustAnchors = new HashSet<>();
        trustAnchors.add(new TrustAnchor(this.certificate, null));
        PKIXParameters params = new PKIXParameters(trustAnchors);
        params.setRevocationEnabled(false);

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        validator.validate(path, params);
      }

      return cert;
    } catch (DomainCAException e) {
      throw e;
    } catch (Exception e) {
      throw new DomainCAException("LDevID issuance failed: " + e.getMessage(), e);
    }
  }

  public X500Name getSubjectName() {
    try {
      return new JcaX509CertificateHolder(getCertificate()).getSubject();
    } catch (CertificateEncodingException e) {
      throw new IllegalStateException("CA certificate encoding error", e);
    }
  }
}
