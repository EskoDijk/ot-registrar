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

package com.google.openthread.tools;

import com.google.openthread.Constants;
import com.google.openthread.brski.ConstantsBrski;
import com.google.openthread.Credentials;
import com.google.openthread.CredentialsSet;
import com.google.openthread.brski.HardwareModuleName;
import com.google.openthread.Role;
import com.google.openthread.SecurityUtils;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class CredentialGenerator extends CredentialsSet {

  private static final String PASSWORD = Constants.KEY_STORE_PASSWORD;
  /** Default vendor ID for generated certificate DNs (overridable via {@link #setVendorId}). */
  public static final String DEFAULT_VENDOR_ID = "TestVendor";
  public static final String PLEDGE_SN = "OT-";

  private static final String HELP_FORMAT = "\nCredentialGenerator [...<see options below>...]\n";
  private String masaUri = Constants.DEFAULT_MASA_URI;
  private String vendorId = DEFAULT_VENDOR_ID;
  private KeyPair dummyKeyPair; // lazily allocated by getDummyKeyPair()
  private boolean isIncludeExtKeyUsage = true;
  private int pledgeSerialNumber = 9528;
  private static final Logger logger = LoggerFactory.getLogger(CredentialGenerator.class);

  /**
   * Lazily-allocated EC key pair used as a stand-in when {@link #make} loads a
   * certificate file without an accompanying private key file. Only created on
   * first use so that the common case (everything generated, or everything
   * supplied with keys) doesn't pay for an unused keygen.
   */
  private KeyPair getDummyKeyPair() {
    if (dummyKeyPair == null) {
      try {
        dummyKeyPair = SecurityUtils.genKeyPair();
      } catch (Exception e) {
        throw new IllegalStateException("dummy key pair generation failed", e);
      }
    }
    return dummyKeyPair;
  }

  /**
   * Create an empty CredentialGenerator. Use {@link #make} to generate or load a full set of
   * credentials, or {@link #makeRole} to package a single role, then {@link #store} to a keystore.
   *
   * @throws GeneralSecurityException on keystore/algorithm errors
   * @throws IOException              on keystore initialization error
   */
  public CredentialGenerator() throws GeneralSecurityException, IOException {
    super(CredentialGenerator.PASSWORD);
  }

  /**
   * Set the MASA URI that will be included in a generated Pledge certificate, in the MASA URI
   * extension (RFC 8995 2.3.2).
   *
   * @param masaUri string that is typically only the 'authority' part of a URI. See RFC 8995 for
   *     exception cases where more elements can be added.
   */
  public void setMasaUri(String masaUri) {
    this.masaUri = masaUri;
  }

  /**
   * Set the vendor ID used in the organization (O) and common name (CN) fields of generated
   * certificate distinguished names. The location (C, L) is unaffected.
   *
   * @param vendorId the vendor identifier, e.g. {@code "testvendor"} or {@code "honeydukes"}
   */
  public void setVendorId(String vendorId) {
    this.vendorId = vendorId;
  }

  /**
   * Distinguished-name prefix for generated certificates: a fixed location with the organization
   * and common name taken from the current vendor ID (e.g. {@code C=NL,L=Utrecht,O=acme,CN=acme }).
   */
  private String dnamePrefix() {
    return "C=NL,L=Utrecht,O=" + vendorId + ",CN=" + vendorId + " ";
  }

  /**
   * Sets whether the Extended Key Usage (EKU) extension is included in any generated Registrar
   * cert. By default it is included, and must be included to comply with specifications. For
   * testing situations it can be excluded.
   *
   * @param isIncluded true if EKU is included (should be used by default), false if not.
   */
  public void setRegistrarExtendedKeyUsage(boolean isIncluded) {
    this.isIncludeExtKeyUsage = isIncluded;
  }

  /**
   * Generate a self-signed CA certificate (with key-cert-sign and CRL-sign key usage) for the given
   * key pair and distinguished name.
   *
   * @param keyPair the CA key pair, used as both subject and issuer
   * @param dname   the subject/issuer distinguished name
   * @return the generated self-signed certificate
   * @throws Exception on key, certificate, or signing errors
   */
  public X509Certificate genSelfSignedCert(KeyPair keyPair, String dname) throws Exception {
    Extension keyUsage =
        new Extension(
            Extension.keyUsage,
            true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign)
                .getEncoded());
    List<Extension> extensions = new ArrayList<>();
    extensions.add(keyUsage);
    return SecurityUtils.genCertificate(
        keyPair, dname, keyPair, new X500Name(dname), true, extensions);
  }

  /**
   * Generate a Pledge (IDevID) certificate, embedding the hardware module name and MASA URI
   * extensions, signed by the given issuer.
   *
   * @param subKeyPair    the Pledge (subject) key pair
   * @param subName       the Pledge (subject) distinguished name
   * @param issuerKeyPair the issuing MASA CA key pair
   * @param issuerName    the issuing MASA CA distinguished name
   * @param moduleName    the hardware module name to embed (RFC 8995 IDevID)
   * @param masaUri       the MASA URI to embed (RFC 8995 2.3.2)
   * @return the generated Pledge certificate
   * @throws Exception on key, certificate, or signing errors
   */
  public X509Certificate genPledgeCertificate(
      KeyPair subKeyPair,
      String subName,
      KeyPair issuerKeyPair,
      X500Name issuerName,
      HardwareModuleName moduleName,
      String masaUri)
      throws Exception {

    Extension keyUsage =
        new Extension(
            Extension.keyUsage,
            true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
                .getEncoded(ASN1Encoding.DER));

    OtherName otherName =
        new OtherName(new ASN1ObjectIdentifier(ConstantsBrski.HARDWARE_MODULE_NAME_OID), moduleName);
    Extension subjectAltName =
        new Extension(
            Extension.subjectAlternativeName,
            false,
            new GeneralNames(new GeneralName(GeneralName.otherName, otherName))
                .getEncoded(ASN1Encoding.DER));

    Extension masaUriExt =
        new Extension(
            new ASN1ObjectIdentifier(ConstantsBrski.MASA_URI_OID).intern(),
            false,
            new DERIA5String(masaUri).getEncoded());

    List<Extension> extensions = new ArrayList<>();
    extensions.add(keyUsage);
    extensions.add(subjectAltName);
    extensions.add(masaUriExt);
    return SecurityUtils.genCertificate(
        subKeyPair, subName, issuerKeyPair, issuerName, false, extensions);
  }

  /**
   * Generate a Registrar certificate, which has the cmcRA extended key usage (EKU) set by default.
   * Per RFC 5280  4.2.1.12, if that EKU is present the 'server' EKU must also be present, or the
   * identity is not allowed to operate as a server. Similarly for the 'client' EKU, as the
   * Registrar must also operate as a client towards the MASA, potentially with the same identity.
   *
   * @param subKeyPair    the Registrar (subject) key pair
   * @param subName       the Registrar (subject) distinguished name
   * @param issuerKeyPair the issuing domain CA key pair
   * @param issuerName    the issuing domain CA distinguished name
   * @return the generated Registrar certificate
   * @throws Exception on key, certificate, or signing errors
   */
  public X509Certificate genRegistrarCertificate(
      KeyPair subKeyPair, String subName, KeyPair issuerKeyPair, X500Name issuerName)
      throws Exception {

    Extension keyUsage =
        new Extension(
            Extension.keyUsage,
            true,
            new KeyUsage(
                KeyUsage.digitalSignature
                    | KeyUsage.keyEncipherment
                    | KeyUsage.dataEncipherment
                    | KeyUsage.keyAgreement)
                .getEncoded(ASN1Encoding.DER));

    Extension extKeyUsage =
        new Extension(
            Extension.extendedKeyUsage,
            false,
            new ExtendedKeyUsage(
                new KeyPurposeId[]{
                    KeyPurposeId.id_kp_serverAuth,
                    KeyPurposeId.id_kp_clientAuth,
                    isIncludeExtKeyUsage ? ConstantsBrski.ID_KP_CMC_RA : KeyPurposeId.id_kp_codeSigning
                })
                .getEncoded(ASN1Encoding.DER));

    List<Extension> extensions = new ArrayList<>();
    extensions.add(keyUsage);
    extensions.add(extKeyUsage);
    return SecurityUtils.genCertificate(
        subKeyPair, subName, issuerKeyPair, issuerName, false, extensions);
  }

  /**
   * Generate a new Registrar certificate using the default Registrar/DomainCA credentials stored in
   * this object.
   *
   * @return the generated Registrar certificate
   */
  public X509Certificate genRegistrarCredentials() throws Exception {
    Credentials regCreds = getCredentials(REGISTRAR_ALIAS);
    Credentials domainCa = getCredentials(DOMAIN_CA_ALIAS);
    X509Certificate cert =
        genRegistrarCertificate(
            regCreds.getKeyPair(),
            dnamePrefix() + REGISTRAR_ALIAS,
            domainCa.getKeyPair(),
            new JcaX509CertificateHolder(domainCa.getCertificate()).getSubject());
    return cert;
  }

  /**
   * Generate a MASA server (TLS) certificate, with the serverAuth EKU and a {@code localhost} DNS
   * subject alternative name, signed by the given issuer.
   *
   * @param subKeyPair    the MASA server (subject) key pair
   * @param subName       the MASA server (subject) distinguished name
   * @param issuerKeyPair the issuing MASA CA key pair
   * @param issuerName    the issuing MASA CA distinguished name
   * @return the generated MASA server certificate
   * @throws Exception on key, certificate, or signing errors
   */
  public X509Certificate genMasaServerCertificate(
      KeyPair subKeyPair, String subName, KeyPair issuerKeyPair, X500Name issuerName)
      throws Exception {

    Extension keyUsage =
        new Extension(
            Extension.keyUsage,
            true,
            new KeyUsage(
                KeyUsage.digitalSignature
                    | KeyUsage.keyEncipherment
                    | KeyUsage.dataEncipherment
                    | KeyUsage.keyAgreement)
                .getEncoded(ASN1Encoding.DER));

    Extension extKeyUsage =
        new Extension(
            Extension.extendedKeyUsage,
            false,
            new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth})
                .getEncoded(ASN1Encoding.DER));

    // for MASA certs, include dns name so that Registrar HTTP client can accept it.
    GeneralName altName = new GeneralName(GeneralName.dNSName, "localhost");
    GeneralNames subjectAltName = new GeneralNames(altName);
    Extension san =
        new Extension(Extension.subjectAlternativeName, false, subjectAltName.getEncoded());

    List<Extension> extensions = new ArrayList<>();
    extensions.add(keyUsage);
    extensions.add(extKeyUsage);
    extensions.add(san);

    return SecurityUtils.genCertificate(
        subKeyPair, subName, issuerKeyPair, issuerName, false, extensions);
  }

  /**
   * Make/generate a complete set of certificates and store locally within this CredentialsSet.
   *
   * @param domaincaCertKeyFiles  {cert, key} filenames for the domain CA, or null to generate it
   * @param masaCaCertKeyFiles    {cert, key} filenames for the MASA CA, or null to generate it, or
   *     a single {cert} filename for a MASA CA certificate without private key
   * @param masaCertKeyFiles      {cert, key} filenames for the MASA server, or null to generate it,
   *     or a single {cert} filename for a MASA server certificate without private key
   * @param registrarCertKeyFiles {cert, key} filenames for the Registrar, or null to generate it
   * @param pledgeCertKeyFiles    {cert, key} filenames for the Pledge, or null to generate it
   * @throws Exception on key, certificate, or signing errors
   */
  public void make(
      String[] domaincaCertKeyFiles,
      String[] masaCaCertKeyFiles,
      String[] masaCertKeyFiles,
      String[] registrarCertKeyFiles,
      String[] pledgeCertKeyFiles)
      throws Exception {

    X509Certificate masaCaCert;
    KeyPair masaCaKeyPair;

    // MASA CA
    if (masaCaCertKeyFiles != null) {
      masaCaCert = loadCertFromPemFile(masaCaCertKeyFiles[0]);
      if (masaCaCertKeyFiles.length > 1) {
        masaCaKeyPair = loadPrivateKeyFromPemFile(masaCaCert, masaCaCertKeyFiles[1]);
      } else {
        masaCaKeyPair = getDummyKeyPair();
      }
    } else {
      masaCaKeyPair = SecurityUtils.genKeyPair();
      masaCaCert = genSelfSignedCert(masaCaKeyPair, dnamePrefix() + MASA_CA_ALIAS);
    }
    this.setCredentials(
        MASA_CA_ALIAS, new X509Certificate[]{masaCaCert}, masaCaKeyPair.getPrivate());

    // MASA server
    X509Certificate cert;
    KeyPair keyPair;
    if (masaCertKeyFiles != null) {
      cert = loadCertFromPemFile(masaCertKeyFiles[0]);
      if (masaCertKeyFiles.length > 1) {
        keyPair = loadPrivateKeyFromPemFile(cert, masaCertKeyFiles[1]);
      } else {
        keyPair = getDummyKeyPair();
      }
    } else {
      keyPair = SecurityUtils.genKeyPair();
      cert =
          genMasaServerCertificate(
              keyPair,
              dnamePrefix() + MASA_ALIAS,
              masaCaKeyPair,
              new JcaX509CertificateHolder(masaCaCert).getSubject());
    }
    this.setCredentials(MASA_ALIAS, new X509Certificate[]{cert, masaCaCert}, keyPair.getPrivate());

    // Pledge
    makePledge(pledgeCertKeyFiles);

    // Domain CA
    X509Certificate domaincaCert;
    KeyPair domaincaKeyPair;
    if (domaincaCertKeyFiles != null) {
      domaincaCert = loadCertFromPemFile(domaincaCertKeyFiles[0]);
      domaincaKeyPair = loadPrivateKeyFromPemFile(domaincaCert, domaincaCertKeyFiles[1]);
    } else {
      domaincaKeyPair = SecurityUtils.genKeyPair();
      domaincaCert = genSelfSignedCert(domaincaKeyPair, dnamePrefix() + DOMAIN_CA_ALIAS);
    }
    this.setCredentials(
        DOMAIN_CA_ALIAS, new X509Certificate[]{domaincaCert}, domaincaKeyPair.getPrivate());

    // Registrar
    if (registrarCertKeyFiles != null) {
      cert = loadCertFromPemFile(registrarCertKeyFiles[0]);
      keyPair = loadPrivateKeyFromPemFile(cert, registrarCertKeyFiles[1]);
    } else {
      keyPair = SecurityUtils.genKeyPair();
      cert =
          genRegistrarCertificate(
              keyPair,
              dnamePrefix() + REGISTRAR_ALIAS,
              domaincaKeyPair,
              new JcaX509CertificateHolder(domaincaCert).getSubject());
    }
    this.setCredentials(
        REGISTRAR_ALIAS, new X509Certificate[]{cert, domaincaCert}, keyPair.getPrivate());

    // Commissioner - not yet loading from a file. TODO
    keyPair = SecurityUtils.genKeyPair();
    cert =
        SecurityUtils.genCertificate(
            keyPair,
            dnamePrefix() + COMMISSIONER_ALIAS,
            domaincaKeyPair,
            new JcaX509CertificateHolder(domaincaCert).getSubject(),
            false,
            null);
    this.setCredentials(
        COMMISSIONER_ALIAS, new X509Certificate[]{cert, domaincaCert}, keyPair.getPrivate());
  }

  /**
   * Package the credentials needed by a single role into this CredentialsSet, from previously
   * generated cert/key PEM files. Unlike {@link #make}, this does not generate any missing
   * material and only stores the aliases that the given role actually loads at runtime:
   *
   * <ul>
   *   <li>{@code PLEDGE}: {@code pledge} (key + chain to MASA CA) and {@code masaca} (trusted
   *       certificate only - the MASA CA private key is not required by a Pledge).
   *   <li>{@code REGISTRAR}: {@code registrar} (key + chain to domain CA) and {@code domainca}
   *       (key).
   *   <li>{@code MASA}: {@code masa} (key + chain to MASA CA) and {@code masaca} (key).
   * </ul>
   *
   * @param role                  the role to package credentials for
   * @param domaincaCertKeyFiles  {cert, key} PEM files for the domain CA (REGISTRAR role)
   * @param masaCaCertKeyFiles    {cert[, key]} PEM files for the MASA CA (PLEDGE: cert only;
   *     MASA: cert + key)
   * @param masaCertKeyFiles      {cert, key} PEM files for the MASA server (MASA role)
   * @param registrarCertKeyFiles {cert, key} PEM files for the Registrar (REGISTRAR role)
   * @param pledgeCertKeyFiles    {cert, key} PEM files for the Pledge (PLEDGE role)
   * @throws GeneralSecurityException on keystore errors or a bad certificate
   * @throws IOException              if an input PEM file cannot be read
   */
  public void makeRole(
      Role role,
      String[] domaincaCertKeyFiles,
      String[] masaCaCertKeyFiles,
      String[] masaCertKeyFiles,
      String[] registrarCertKeyFiles,
      String[] pledgeCertKeyFiles)
      throws GeneralSecurityException, IOException {
    switch (role) {
      case Pledge: {
        require(pledgeCertKeyFiles, 2, "-p <pledge-cert> <pledge-key>");
        require(masaCaCertKeyFiles, 1, "-m <masaca-cert>");
        X509Certificate masaCaCert = loadCertFromPemFile(masaCaCertKeyFiles[0]);
        X509Certificate pledgeCert = loadCertFromPemFile(pledgeCertKeyFiles[0]);
        KeyPair pledgeKey = loadPrivateKeyFromPemFile(pledgeCert, pledgeCertKeyFiles[1]);
        setCredentials(
            PLEDGE_ALIAS, new X509Certificate[]{pledgeCert, masaCaCert}, pledgeKey.getPrivate());
        // A Pledge only needs the MASA CA as a trust anchor, not its private key.
        setTrustedCertificate(MASA_CA_ALIAS, masaCaCert);
        break;
      }
      case Registrar: {
        require(registrarCertKeyFiles, 2, "-r <registrar-cert> <registrar-key>");
        require(domaincaCertKeyFiles, 2, "-c <domainca-cert> <domainca-key>");
        X509Certificate domaincaCert = loadCertFromPemFile(domaincaCertKeyFiles[0]);
        KeyPair domaincaKey = loadPrivateKeyFromPemFile(domaincaCert, domaincaCertKeyFiles[1]);
        X509Certificate registrarCert = loadCertFromPemFile(registrarCertKeyFiles[0]);
        KeyPair registrarKey = loadPrivateKeyFromPemFile(registrarCert, registrarCertKeyFiles[1]);
        setCredentials(
            REGISTRAR_ALIAS,
            new X509Certificate[]{registrarCert, domaincaCert},
            registrarKey.getPrivate());
        setCredentials(
            DOMAIN_CA_ALIAS, new X509Certificate[]{domaincaCert}, domaincaKey.getPrivate());
        break;
      }
      case Masa: {
        require(masaCertKeyFiles, 2, "-ms <masa-cert> <masa-key>");
        require(masaCaCertKeyFiles, 2, "-m <masaca-cert> <masaca-key>");
        X509Certificate masaCaCert = loadCertFromPemFile(masaCaCertKeyFiles[0]);
        KeyPair masaCaKey = loadPrivateKeyFromPemFile(masaCaCert, masaCaCertKeyFiles[1]);
        X509Certificate masaCert = loadCertFromPemFile(masaCertKeyFiles[0]);
        KeyPair masaKey = loadPrivateKeyFromPemFile(masaCert, masaCertKeyFiles[1]);
        setCredentials(
            MASA_ALIAS, new X509Certificate[]{masaCert, masaCaCert}, masaKey.getPrivate());
        setCredentials(
            MASA_CA_ALIAS, new X509Certificate[]{masaCaCert}, masaCaKey.getPrivate());
        break;
      }
      default:
        throw new IllegalArgumentException("unsupported role for credential packaging: " + role);
    }
  }

  private static void require(String[] files, int minLen, String optionHint) {
    if (files == null || files.length < minLen) {
      throw new IllegalArgumentException("missing required input file(s): " + optionHint);
    }
  }

  private static Role parseRole(String s) {
    switch (s.toLowerCase()) {
      case "pledge":
        return Role.Pledge;
      case "registrar":
        return Role.Registrar;
      case "masa":
        return Role.Masa;
      default:
        throw new IllegalArgumentException(
            "unknown role: " + s + " (expected pledge|registrar|masa)");
    }
  }

  /**
   * Make a new Pledge certificate.
   *
   * @param pledgeCertKeyFiles {cert, key} filenames for the Pledge, or null to generate it
   */
  public void makePledge(String[] pledgeCertKeyFiles) throws Exception {
    X509Certificate pledgeCert;
    KeyPair pledgeKeyPair;
    Credentials masaCaCreds = getCredentials(MASA_CA_ALIAS);
    String sn = createNewPledgeSerialNumber();
    HardwareModuleName hwModuleName =
        new HardwareModuleName(ConstantsBrski.PRIVATE_HARDWARE_TYPE_OID, sn.getBytes());

    if (pledgeCertKeyFiles != null) {
      pledgeCert = loadCertFromPemFile(pledgeCertKeyFiles[0]);
      pledgeKeyPair = loadPrivateKeyFromPemFile(pledgeCert, pledgeCertKeyFiles[1]);
    } else {
      pledgeKeyPair = SecurityUtils.genKeyPair();
      pledgeCert =
          genPledgeCertificate(
              pledgeKeyPair,
              dnamePrefix() + PLEDGE_ALIAS + ",SERIALNUMBER=" + sn,
              masaCaCreds.getKeyPair(),
              new JcaX509CertificateHolder(masaCaCreds.getCertificate()).getSubject(),
              hwModuleName,
              masaUri);
    }
    this.setCredentials(
        PLEDGE_ALIAS,
        new X509Certificate[]{pledgeCert, masaCaCreds.getCertificate()},
        pledgeKeyPair.getPrivate());
  }

  /**
   * Returns the Pledge serial number of current Pledge identity in the generator.
   *
   * @return serial number string
   */
  public String getPledgeSerialNumber() {
    return PLEDGE_SN + pledgeSerialNumber;
  }

  /**
   * Load a certificate PEM from file.
   *
   * @param fn the PEM file path
   */
  protected X509Certificate loadCertFromPemFile(String fn)
      throws IOException, CertificateException {
    try (Reader reader = new FileReader(fn, StandardCharsets.UTF_8)) {
      return SecurityUtils.parseCertFromPem(reader);
    }
  }

  /**
   * Load a private-key PEM file and combine it with the public key in {@code cert} to return the
   * resulting {@link KeyPair}.
   */
  protected KeyPair loadPrivateKeyFromPemFile(X509Certificate cert, String fn) throws IOException {
    try (Reader reader = new FileReader(fn, StandardCharsets.UTF_8)) {
      return new KeyPair(cert.getPublicKey(), SecurityUtils.parsePrivateKeyFromPem(reader));
    }
  }

  protected String createNewPledgeSerialNumber() {
    pledgeSerialNumber++;
    return getPledgeSerialNumber();
  }

  /**
   * Load a set of previously generated credentials from a file.
   *
   * @param filename the keystore (PKCS#12) file to load
   * @throws GeneralSecurityException on keystore/algorithm errors
   * @throws IOException              if the file cannot be read
   */
  public void load(String filename) throws GeneralSecurityException, IOException {
    char[] password = PASSWORD.toCharArray();
    KeyStore ksAll = KeyStore.getInstance(Constants.KEY_STORE_FORMAT);
    File file = new File(filename);

    try (InputStream in = new FileInputStream(file)) {
      ksAll.load(in, password);
    }
    this.setKeyStore(ksAll);
  }

  /**
   * Store the current set of (generated) credentials in a file.
   *
   * @param filename the keystore (PKCS#12) file to write
   * @throws GeneralSecurityException on keystore/algorithm errors
   * @throws IOException              if the file cannot be written
   */
  public void store(String filename) throws GeneralSecurityException, IOException {
    char[] password = PASSWORD.toCharArray();

    KeyStore ks = this.getKeyStore();

    try (OutputStream os = new FileOutputStream(filename, false)) {
      ks.store(os, password);
    }
  }

  /**
   * Write each credential in this set out as PEM files into a new vendor directory
   * {@code <credentials-dir>/<name>}, using the project's standard naming: {@code <role>.pem} for
   * each certificate and {@code privkey_<role>.pem} for each private key (e.g. {@code pledge.pem}
   * and {@code privkey_pledge.pem}). The result can then be packaged into per-role keystores with
   * {@code script/create-credentials-p12.sh <name>}.
   *
   * <p>The directory must not already exist: if it does, a warning is logged and nothing is
   * written. Each written PEM is verified by round-tripping it and comparing the encoding.
   *
   * @param vendorName the vendor directory name to create under the credentials directory
   * @throws GeneralSecurityException on keystore/algorithm errors or a failed round-trip check
   * @throws IOException              if the output directory or a PEM file cannot be written/read
   */
  public void dumpSeparateFiles(String vendorName) throws GeneralSecurityException, IOException {
    File dir = new File(Constants.CREDENTIALS_DIR, vendorName);
    if (dir.exists()) {
      logger.warn("output directory already exists, not writing credentials: {}", dir.getPath());
      return;
    }
    if (!dir.mkdirs()) {
      throw new IOException("could not create output directory: " + dir.getPath());
    }

    // The keystore aliases are also the standard PEM file role-names (see
    // script/create-credentials-p12.sh), so each alias maps directly to <alias>.pem.
    String[] aliases = {
        MASA_CA_ALIAS, MASA_ALIAS, PLEDGE_ALIAS, DOMAIN_CA_ALIAS, REGISTRAR_ALIAS, COMMISSIONER_ALIAS
    };

    for (String alias : aliases) {
      Credentials creds = getCredentials(alias);
      KeyPair kp = creds.getKeyPair();
      X509Certificate cert = creds.getCertificate();

      File kf = new File(dir, "privkey_" + alias + ".pem");
      try (OutputStream os = new FileOutputStream(kf, false);
          JcaPEMWriter writer = new JcaPEMWriter(new PrintWriter(os))) {
        writer.writeObject(kp.getPrivate());
      }
      // Round-trip the just-written private-key PEM and confirm the encoding matches.
      try (Reader reader = new FileReader(kf, StandardCharsets.UTF_8)) {
        PrivateKey roundTripped = SecurityUtils.parsePrivateKeyFromPem(reader);
        if (!Arrays.equals(roundTripped.getEncoded(), kp.getPrivate().getEncoded())) {
          throw new UnrecoverableKeyException("bad private key in PEM file: " + kf.getName());
        }
      }

      File cf = new File(dir, alias + ".pem");
      try (OutputStream os = new FileOutputStream(cf, false);
          JcaPEMWriter writer = new JcaPEMWriter(new PrintWriter(os))) {
        writer.writeObject(cert);
      }
      try (Reader reader = new FileReader(cf, StandardCharsets.UTF_8)) {
        X509Certificate roundTripped = SecurityUtils.parseCertFromPem(reader);
        if (!Arrays.equals(roundTripped.getEncoded(), cert.getEncoded())) {
          throw new CertificateEncodingException("bad certificate in PEM file: " + cf.getName());
        }
      }
    }
    logger.info("wrote credentials as PEM files to directory: {}", dir.getPath());
  }

  /**
   * Command-line entry point. Generates or packages credentials and writes them to a PKCS#12
   * keystore; see the {@code -h} help output for the available options.
   *
   * @param args command-line arguments
   */
  public static void main(String[] args) {
    HelpFormatter helper = new HelpFormatter();
    Options options = new Options();

    Option fileOpt =
        Option.builder("o")
            .longOpt("out")
            .hasArg()
            .argName("output-file")
            .desc("the keystore file write to")
            .build();

    Option dumpOpt =
        Option.builder("d")
            .longOpt("dump")
            .hasArg()
            .argName("vendor-dir-name")
            .desc(
                "dump the credentials as PEM files into a new credentials/<vendor-dir-name> "
                    + "directory (which must not already exist)")
            .build();

    Option caOpt =
        Option.builder("c")
            .longOpt("ca")
            .hasArg()
            .desc("domain CA certificate & root key files")
            .build();
    caOpt.setArgs(2);

    Option masaOpt =
        Option.builder("m")
            .longOpt("masa")
            .hasArg()
            .desc("MASA CA certificate file & OPTIONAL private key file")
            .build();
    masaOpt.setArgs(2);

    Option masaServerOpt =
        Option.builder("ms")
            .longOpt("masaserver")
            .hasArg()
            .desc("MASA server certificate file & private key file")
            .build();
    masaServerOpt.setArgs(2);

    Option regOpt =
        Option.builder("r")
            .longOpt("reg")
            .hasArg()
            .desc("Registrar certificate & private key files")
            .build();
    regOpt.setArgs(2);

    Option pledgeOpt =
        Option.builder("p")
            .longOpt("pledge")
            .hasArg()
            .desc("Pledge certificate & private key files")
            .build();
    pledgeOpt.setArgs(2);

    Option masaUriOpt =
        Option.builder("u")
            .longOpt("masauri")
            .hasArg()
            .desc("MASA URI to be embedded in the Pledge certificate")
            .build();

    Option roleOpt =
        Option.builder("role")
            .longOpt("role")
            .hasArg()
            .argName("pledge|registrar|masa")
            .desc(
                "package only the aliases needed by this single role, instead of a full keystore")
            .build();

    Option helpOpt =
        Option.builder("h").longOpt("help").hasArg(false).desc("print this message").build();

    options
        .addOption(fileOpt)
        .addOption(helpOpt)
        .addOption(dumpOpt)
        .addOption(caOpt)
        .addOption(masaOpt)
        .addOption(masaServerOpt)
        .addOption(regOpt)
        .addOption(pledgeOpt)
        .addOption(masaUriOpt)
        .addOption(roleOpt);

    try {
      CommandLineParser parser = new DefaultParser();
      CommandLine cmd = parser.parse(options, args);

      if (cmd.hasOption('h')) {
        helper.printHelp(HELP_FORMAT, options);
        return;
      }

      String keyStoreFile = cmd.getOptionValue('o');
      // Output is either a PKCS#12 keystore (-o) and/or a PEM dump directory (-d); at least one
      // must be specified.
      if (keyStoreFile == null && !cmd.hasOption('d')) {
        throw new IllegalArgumentException("need to specify -o <keystore-file> or -d <dump-dir>");
      }

      CredentialGenerator cg = new CredentialGenerator();
      String masaUri = cmd.getOptionValue('u');
      if (masaUri != null) {
        cg.setMasaUri(masaUri);
      }
      // Brand generated certificates with the vendor ID (the dump directory name), when given.
      if (cmd.hasOption('d')) {
        cg.setVendorId(cmd.getOptionValue('d'));
      }
      String roleStr = cmd.getOptionValue("role");
      if (roleStr != null) {
        cg.makeRole(
            parseRole(roleStr),
            cmd.getOptionValues("c"),
            cmd.getOptionValues("m"),
            cmd.getOptionValues("ms"),
            cmd.getOptionValues("r"),
            cmd.getOptionValues("p"));
      } else {
        cg.make(
            cmd.getOptionValues("c"),
            cmd.getOptionValues("m"),
            cmd.getOptionValues("ms"),
            cmd.getOptionValues("r"),
            cmd.getOptionValues("p"));
      }
      if (keyStoreFile != null) {
        cg.store(keyStoreFile);
      }
      if (cmd.hasOption('d')) {
        cg.dumpSeparateFiles(cmd.getOptionValue('d'));
      }
    } catch (Exception e) {
      System.err.println("error: " + e.getMessage());
      e.printStackTrace();
      helper.printHelp(HELP_FORMAT, options);
      System.exit(1);
    }
  }
}
