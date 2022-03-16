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
import com.google.openthread.Credentials;
import com.google.openthread.HardwareModuleName;
import com.google.openthread.SecurityUtils;
import com.google.openthread.registrar.Registrar;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
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
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CredentialGenerator {
  public static final String PASSWORD = "OpenThread";

  public static final String DNAME_PREFIX = "C=CN,L=SH,O=Google,OU=OpenThread,CN=";

  public static final String DOMAINCA_ALIAS = "domainca";
  public static final String DOMAINCA_DNAME = DNAME_PREFIX + DOMAINCA_ALIAS;

  public static final String REGISTRAR_ALIAS = "registrar";
  public static final String REGISTRAR_DNAME = DNAME_PREFIX + REGISTRAR_ALIAS;

  public static final String COMMISSIONER_ALIAS = "commissioner";
  public static final String COMMISSIONER_DNAME = DNAME_PREFIX + COMMISSIONER_ALIAS;

  public static final String MASA_ALIAS = "masa";
  public static final String MASA_DNAME = DNAME_PREFIX + MASA_ALIAS;

  public static final String PLEDGE_ALIAS = "pledge";
  public static final String PLEDGE_SN = "OT-9527";
  public static final String PLEDGE_DNAME =
      DNAME_PREFIX + PLEDGE_ALIAS + ",SERIALNUMBER=" + PLEDGE_SN;

  // Fields provided for testing, shouldn't reference outside of tests.
  public KeyPair masaKeyPair;
  public X509Certificate masaCert;
  public KeyPair pledgeKeyPair;
  public X509Certificate pledgeCert;

  public KeyPair domaincaKeyPair;
  public X509Certificate domaincaCert;
  public KeyPair registrarKeyPair;
  public X509Certificate registrarCert;
  public KeyPair commissionerKeyPair;
  public X509Certificate commissionerCert;

  private String masaUri = Constants.DEFAULT_MASA_URI;
  private boolean isIncludeExtKeyUsage = true;
  private static Logger logger = LoggerFactory.getLogger(CredentialGenerator.class);
  
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
   * Sets whether the Extended Key Usage (EKU) extensions is included in a generated Registrar cert.
   * By default, it is included and must be included to comply to specifications. For testing
   * situations it can be excluded.
   *
   * @param isIncluded true if EKU is included (should be used by default), false if not.
   */
  public void setRegistrarExtendedKeyUsage(boolean isIncluded) {
    this.isIncludeExtKeyUsage = isIncluded;
  }

  public Credentials getCredentials(String alias) throws Exception {
    return new Credentials(getKeyStore(), alias, PASSWORD);
  }

  /**
   * Return all the credentials in form of a Java KeyStore object, password protected with
   * CredentialGenerator.PASSWORD.
   *
   * @return
   * @throws KeyStoreException
   * @throws CertificateException
   * @throws NoSuchAlgorithmException
   * @throws IOException
   */
  public KeyStore getKeyStore()
      throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {

    char[] password = PASSWORD.toCharArray();

    KeyStore ks = KeyStore.getInstance(Constants.KEY_STORE_FORMAT);
    ks.load(null, password); // create empty keystore

    ks.setKeyEntry(
        MASA_ALIAS, masaKeyPair.getPrivate(), password, new X509Certificate[] {masaCert});
    ks.setKeyEntry(
        PLEDGE_ALIAS,
        pledgeKeyPair.getPrivate(),
        password,
        new X509Certificate[] {pledgeCert, masaCert});
    ks.setKeyEntry(
        DOMAINCA_ALIAS,
        domaincaKeyPair.getPrivate(),
        password,
        new X509Certificate[] {domaincaCert});
    ks.setKeyEntry(
        REGISTRAR_ALIAS,
        registrarKeyPair.getPrivate(),
        password,
        new X509Certificate[] {registrarCert, domaincaCert});
    ks.setKeyEntry(
        COMMISSIONER_ALIAS,
        commissionerKeyPair.getPrivate(),
        password,
        new X509Certificate[] {commissionerCert, domaincaCert});
    return ks;
  }

  public X509Certificate genSelfSignedCert(KeyPair keyPair, String dname) throws Exception {
    Extension keyUsage =
        new Extension(
            Extension.keyUsage,
            true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign)
                .getEncoded());
    // for MASA certs, include dns name so that Registrar HTTP client can accept it.
    GeneralName altName = new GeneralName(GeneralName.dNSName, "localhost");
    GeneralNames subjectAltName = new GeneralNames(altName);
    Extension san =
        new Extension(Extension.subjectAlternativeName, false, subjectAltName.getEncoded());
    List<Extension> extensions = new ArrayList<Extension>();
    extensions.add(keyUsage);
    extensions.add(san);
    return SecurityUtils.genCertificate(keyPair, dname, keyPair, dname, true, extensions);
  }

  public X509Certificate genPledgeCertificate(
      KeyPair subKeyPair,
      String subName,
      KeyPair issuerKeyPair,
      String issuerName,
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
        new OtherName(new ASN1ObjectIdentifier(Constants.HARDWARE_MODULE_NAME_OID), moduleName);
    Extension subjectAltName =
        new Extension(
            Extension.subjectAlternativeName,
            false,
            new GeneralNames(new GeneralName(GeneralName.otherName, otherName))
                .getEncoded(ASN1Encoding.DER));

    Extension masaUriExt =
        new Extension(
            new ASN1ObjectIdentifier(Constants.MASA_URI_OID).intern(),
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
   * generate a Registrar's certificate which has the cmcRA extended key usage (EKU) set. Due to RFC
   * 5280 4.2.1.12 rules, if the EKU is present also the 'server' EKU must be present or else the
   * identity is not allowed to operate as server. Similar for 'client' EKU; as the Registrar also
   * must operate as a client towards MASA potentially with same identity (or potentially with
   * another.)
   *
   * @param subKeyPair
   * @param subName
   * @param issuerKeyPair
   * @param issuerName
   * @param isIncludeExtKeyUsage if true (default), include Extended Key Usage (EKU) extension in
   *     cert with the cmcRA flag set. Use only 'false' for test purposes.
   * @return
   * @throws Exception
   */
  public X509Certificate genRegistrarCertificate(
      KeyPair subKeyPair, String subName, KeyPair issuerKeyPair, String issuerName)
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
                    new KeyPurposeId[] {
                      KeyPurposeId.id_kp_serverAuth,
                      KeyPurposeId.id_kp_clientAuth,
                      isIncludeExtKeyUsage ? Constants.id_kp_cmcRA : KeyPurposeId.id_kp_codeSigning
                    })
                .getEncoded(ASN1Encoding.DER));

    List<Extension> extensions = new ArrayList<>();
    extensions.add(keyUsage);
    extensions.add(extKeyUsage);
    return SecurityUtils.genCertificate(
        subKeyPair, subName, issuerKeyPair, issuerName, false, extensions);
  }

  /**
   * Make/generate a complete set of certificates and store locally in this object.
   *
   * @param caCertKeyFiles filenames for CA cert file and private key file, respectively, or null to generate this
   *     key/cert
   * @param masaCertKeyFiles filenames for MASA cert file and private key file, respectively, or null to generate
   *     this key/cert, or a single filename to a MASA cert file only (without private key)
   * @param registrarCertKeyFiles filenames for Registrar cert file and private key file, respectively, or null to
   *     generate this key/cert
   * @param pledgeCertKeyFiles filenames for Pledge cert file and private key file, respectively, or null to generate
   *     this key/cert
   * @throws Exception various error cases
   */
  public void make(
      String[] caCertKeyFiles,
      String[] masaCertKeyFiles,
      String[] registrarCertKeyFiles,
      String[] pledgeCertKeyFiles)
      throws Exception {

    HardwareModuleName hwModuleName = new HardwareModuleName(Constants.PRIVATE_HARDWARE_TYPE_OID, PLEDGE_SN.getBytes());

    if (masaCertKeyFiles != null) {
      masaCert = loadCertAndLogErrors(masaCertKeyFiles[0]);
      if (masaCertKeyFiles.length > 1) {
        masaKeyPair = loadPrivateKeyAndLogErrors(masaCert, masaCertKeyFiles[1]);
      }else {
        masaKeyPair = SecurityUtils.genKeyPair(); // dummy random key - MUST NOT be used in resulting credentials file.
      }
    } else {
      masaKeyPair = SecurityUtils.genKeyPair();
      masaCert = genSelfSignedCert(masaKeyPair, MASA_DNAME);
    }

    if (pledgeCertKeyFiles != null) {
        pledgeCert = loadCertAndLogErrors(pledgeCertKeyFiles[0]);
        pledgeKeyPair = loadPrivateKeyAndLogErrors(pledgeCert, pledgeCertKeyFiles[1]);
    } else {
      pledgeKeyPair = SecurityUtils.genKeyPair();
      pledgeCert =
          genPledgeCertificate(
              pledgeKeyPair,
              PLEDGE_DNAME,
              masaKeyPair,
              masaCert.getSubjectX500Principal().getName(),
              hwModuleName,
              masaUri);
    }

    if (caCertKeyFiles != null) {
      domaincaCert = loadCertAndLogErrors(caCertKeyFiles[0]);
      domaincaKeyPair = loadPrivateKeyAndLogErrors(domaincaCert, caCertKeyFiles[1]);
    } else {
      domaincaKeyPair = SecurityUtils.genKeyPair();
      domaincaCert = genSelfSignedCert(domaincaKeyPair, DOMAINCA_DNAME);
    }

    if (registrarCertKeyFiles != null) {
      registrarCert = loadCertAndLogErrors(registrarCertKeyFiles[0]);
      registrarKeyPair = loadPrivateKeyAndLogErrors(registrarCert, registrarCertKeyFiles[1]);
    } else {
      registrarKeyPair = SecurityUtils.genKeyPair();
      registrarCert =
          genRegistrarCertificate(
              registrarKeyPair,
              REGISTRAR_DNAME,
              domaincaKeyPair,
              domaincaCert.getSubjectX500Principal().getName());
    }
    commissionerKeyPair = SecurityUtils.genKeyPair();
    commissionerCert =
        SecurityUtils.genCertificate(
            commissionerKeyPair,
            COMMISSIONER_DNAME,
            domaincaKeyPair,
            domaincaCert.getSubjectX500Principal().getName(),
            false,
            null);
  }

  /**
   * load a certificate PEM from file and log any load/parse errors to the log. Any exception is thrown to caller.
   * 
   * @param fn
   * @return
   * @throws IOException
   * @throws CertificateException
   */
  protected X509Certificate loadCertAndLogErrors(String fn) throws IOException, CertificateException {
    try {
      Reader reader = new FileReader(fn);
      X509Certificate cert = SecurityUtils.parseCertFromPem(reader);
      return cert;
    }
    catch(IOException ex) {
      logger.error("Could not read PEM cert file: " + fn, ex);
      throw (ex);
    }
    catch(CertificateException ex) {
      logger.error("Certificate parsing error in cert file: " + fn, ex);
      throw (ex);
    }
  }
  
  /**
   * load the private key PEM file in 'fn' and combine this with the public key in 'cert', to return
   * the combined KeyPair. Any errors in load/parse are logged and any exceptions are thrown up.
   * 
   * @param cert
   * @param fn
   * @return
   */
  protected KeyPair loadPrivateKeyAndLogErrors(X509Certificate cert, String fn) throws IOException {
    try {
      Reader reader = new FileReader(fn);
      KeyPair keypair = new KeyPair(masaCert.getPublicKey(), SecurityUtils.parsePrivateKeyFromPem(reader));
      return keypair;
    } catch(IOException ex) {
      logger.error("Could not read PEM cert file: " + fn, ex);
      throw (ex);
    }
  }
  
  public void store(String filename) throws Exception {
    char[] password = PASSWORD.toCharArray();

    KeyStore ks = this.getKeyStore();

    File file = new File(filename);
    file.createNewFile();
    try (OutputStream os = new FileOutputStream(file, false)) {
      ks.store(os, password);
    }
  }

  public void dumpSeparateFiles() throws Exception {
    String[] files = {
      MASA_ALIAS, PLEDGE_ALIAS, DOMAINCA_ALIAS, REGISTRAR_ALIAS, COMMISSIONER_ALIAS
    };
    KeyPair[] keys = {
      masaKeyPair, pledgeKeyPair, domaincaKeyPair, registrarKeyPair, commissionerKeyPair
    };
    X509Certificate[] certs = {masaCert, pledgeCert, domaincaCert, registrarCert, commissionerCert};
    for (int i = 0; i < files.length; ++i) {
      File kf = new File(files[i] + "_private.pem");
      kf.createNewFile();
      try (OutputStream os = new FileOutputStream(kf, false)) {
        JcaPEMWriter writer = new JcaPEMWriter(new PrintWriter(os));
        writer.writeObject(keys[i].getPrivate());
        writer.close();

        // Verify the key in PEM file
        // PrivateKey pk = parsePrivateKey(kf.getName());
        // if (!Arrays.equals(pk.getEncoded(), keys[i].getPrivate().getEncoded())) {
        //    throw new UnrecoverableKeyException("bad private key in PEM file");
        // }
      }

      File cf = new File(files[i] + "_cert.pem");
      cf.createNewFile();
      try (OutputStream os = new FileOutputStream(cf, false)) {
        JcaPEMWriter writer = new JcaPEMWriter(new PrintWriter(os));
        writer.writeObject(certs[i]);
        writer.close();

        // Verify the cert in PEM file
        // X509Certificate cert = parseCertificate(cf.getName());
      }
    }
  }

  public static void main(String[] args) {
    final String HELP_FORMAT =
        "CredentialGenerator [-c <domain-ca-cert> <domain-ca-key>] [-m <masa-ca-cert> <masa-ca-key>] [-u <masa-uri>] [-d] -o <output-file>\nOR: " +
        "CredentialGenerator [-c <domain-ca-cert> <domain-ca-key>] [-m <masa-ca-cert>] [-u <masa-uri>] [-d] -o <output-file>\n";

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
            .hasArg(false)
            .desc("dump the certificates as separate PEM files")
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
    masaOpt.setArgs(1);

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

    Option helpOpt =
        Option.builder("h").longOpt("help").hasArg(false).desc("print this message").build();

    options
        .addOption(fileOpt)
        .addOption(helpOpt)
        .addOption(dumpOpt)
        .addOption(caOpt)
        .addOption(masaOpt)
        .addOption(regOpt)
        .addOption(pledgeOpt)
        .addOption(masaUriOpt);

    try {
      CommandLineParser parser = new DefaultParser();
      CommandLine cmd = parser.parse(options, args);

      if (cmd.hasOption('h')) {
        helper.printHelp(HELP_FORMAT, options);
        return;
      }

      String keyStoreFile = cmd.getOptionValue('o');
      if (keyStoreFile == null) {
        throw new IllegalArgumentException("need to specify keystore file!");
      }

      String masaUri = cmd.getOptionValue('u');
      if (masaUri != null) {
        throw new Exception("MASA URI option not yet implemented.");
      }

      CredentialGenerator cg = new CredentialGenerator();
      cg.make(
          cmd.getOptionValues("c"),
          cmd.getOptionValues("m"),
          cmd.getOptionValues("r"),
          cmd.getOptionValues("p"));
      cg.store(keyStoreFile);

      if (cmd.hasOption('d')) {
        cg.dumpSeparateFiles();
      }
    } catch (Exception e) {
      System.err.println("error: " + e.getMessage());
      e.printStackTrace();
      helper.printHelp(HELP_FORMAT, options);
      return;
    }
  }
}
