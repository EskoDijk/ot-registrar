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
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class DomainCA {

  protected static final ASN1ObjectIdentifier THREAD_DOMAIN_NAME_OID_ASN1 =
      new ASN1ObjectIdentifier(ConstantsThread.THREAD_DOMAIN_NAME_OID); // per Thread 1.2 spec

  static {
    BouncyCastleInitializer.init();
  }

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
   * @return the currently used Thread Domain Name for signing LDevID certificates.
   */
  public String getDomainName() {
    return domainName;
  }

  public X509Certificate signCertificate(PKCS10CertificationRequest csr) throws Exception {

    // 0. POP (proof-of-possession) verification
    // Ref: RFC-7030 [3.4]
    if (!csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(csr.getSubjectPublicKeyInfo()))) {
      throw new GeneralSecurityException("POP verification failed");
    }

    // TODO(wgtdkp): validate CSR request

    // 1. Build certificate
    X500Name issuer = getSubjectName();
    BigInteger serial = allocateSerialNumber();
    Date notBefore = new Date();
    Date notAfter = new Date(System.currentTimeMillis() + Constants.CERT_VALIDITY_MILLISECONDS);
    X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer, serial, notBefore, notAfter, csr.getSubject(), csr.getSubjectPublicKeyInfo());

    logger.info("operational certificate not-before: " + notBefore.toString());
    logger.info("operational certificate not-after: " + notAfter.toString());

    // As defined in 4.2.1.2 of RFC 5280, authority key identifier (subject key
    // identifier of CA)
    // must be calculated by SHA1.
    X509ExtensionUtils extUtils = new BcX509ExtensionUtils();
    builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

    // per 802.1AR-2018 section 8.10.2, don't include subject key identifier. This
    // is tested in
    // FunctionalTest.
    // SubjectKeyIdentifier subjectKeyId =
    // extUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo());
    // builder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyId);

    // TODO: Or we should directly copy this from subject-key-identifier of domain CA ? That would
    // be better in case
    //  the Domain CA cert's Subject Key Identifier was generated by another/non-standard method.
    // Requires some (new)
    //  utility method to do this in bouncycastle.
    AuthorityKeyIdentifier authorityKeyId =
        extUtils.createAuthorityKeyIdentifier(
            SubjectPublicKeyInfo.getInstance(getPublicKey().getEncoded()));
    builder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyId);

    // Includes Thread Domain name in SubjectAltName extension field, otherName subfield,
    // otherName type-id 1.3.6.1.4.1.44970.1 with value IA5String. This is tweaked
    // to look the same as OpenSSL commandline output.
    DERSequence otherName =
        new DERSequence(
            new ASN1Encodable[]{
                THREAD_DOMAIN_NAME_OID_ASN1, new DERTaggedObject(0, new DERIA5String(domainName))
            });
    GeneralNames subjectAltNames =
        new GeneralNames(new GeneralName(GeneralName.otherName, otherName));
    builder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);

    // 2. Sign and verify certificate
    ContentSigner signer =
        new JcaContentSignerBuilder(SecurityUtils.SIGNATURE_ALGORITHM).build(this.privateKey);
    X509CertificateHolder holder = builder.build(signer);
    X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
    cert.verify(this.certificate.getPublicKey());

    // 3. Make sure the signed certificate is validate
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

    // 4. Output to PKCS#7 format
    // return SecurityUtils.genCMSCertOnlyMessage(cert);
    return cert;
  }

  public X500Name getSubjectName() {
    return new X500Name(getCertificate().getIssuerX500Principal().getName());
  }

  private static BigInteger serialNumber = new BigInteger("1");

  private static synchronized BigInteger allocateSerialNumber() {
    serialNumber = serialNumber.add(BigInteger.ONE);
    logger.info("allocate serial number: " + serialNumber);
    return serialNumber;
  }

  private String domainName;

  private PrivateKey privateKey;

  private X509Certificate certificate;

  private final static Logger logger = Logger.getLogger(DomainCA.class.getCanonicalName());
}
