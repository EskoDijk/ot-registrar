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

package com.google.openthread;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * A set of multiple credentials (each having certificate and optional private key) for named entities
 * ("aliases") protected by a password.
 */
public class CredentialsSet {

  public static final String DOMAIN_CA_ALIAS = "domain_ca";
  public static final String REGISTRAR_ALIAS = "registrar";
  public static final String COMMISSIONER_ALIAS = "commissioner";
  public static final String MASA_ALIAS = "masa";
  public static final String MASA_CA_ALIAS = "masa_ca";
  public static final String PLEDGE_ALIAS = "pledge";

  public static final String DEFAULT_PASSWORD = Constants.KEY_STORE_PASSWORD;

  /**
   * Create a new CredentialsSet by loading the conventional keystore for a vendor and role,
   * {@code <credentials-dir>/<vendor>_<role>.p12} (see {@link #keystorePath}). Uses the standard
   * keystore password ({@link Constants#KEY_STORE_PASSWORD}).
   *
   * @param vendorName the vendor name, e.g. {@code "testvendor"} or {@code "honeydukes"}
   * @param role       the role; must be a concrete role (Pledge, Registrar or Masa)
   * @throws IllegalArgumentException if {@code role} is null or {@link Role#None}
   * @throws IllegalStateException    if the keystore file cannot be loaded
   */
  public CredentialsSet(String vendorName, Role role) {
    if (role == null || role == Role.None) {
      throw new IllegalArgumentException(
          "a concrete role (Pledge, Registrar or Masa) is required, got: " + role);
    }
    this.password = Constants.KEY_STORE_PASSWORD;
    String file = keystorePath(vendorName, role);
    try {
      keyStore = KeyStore.getInstance(Constants.KEY_STORE_FORMAT);
      try (InputStream in = new FileInputStream(file)) {
        keyStore.load(in, password.toCharArray());
      }
    } catch (Exception e) {
      throw new IllegalStateException("failed to load keystore file: " + file, e);
    }
  }

  /**
   * Build the conventional keystore path for a vendor and role:
   * {@code <credentials-dir>/<vendor>_<role>.p12} (e.g. {@code ./credentials/default_pledge.p12}).
   *
   * @param vendorName the vendor name
   * @param role       the role
   * @return the keystore file path
   */
  public static String keystorePath(String vendorName, Role role) {
    return Constants.CREDENTIALS_DIR
        + "/"
        + vendorName
        + "_"
        + role.name().toLowerCase(Locale.ROOT)
        + ".p12";
  }

  /**
   * Create new CredentialsSet from keystore (PKCS12) file
   *
   * @param file
   * @param password
   * @throws GeneralSecurityException on keystore/algorithm errors
   * @throws IOException              if the file cannot be read or the password is wrong
   */
  public CredentialsSet(String file, String password)
      throws GeneralSecurityException, IOException {
    this.password = password;
    keyStore = KeyStore.getInstance(Constants.KEY_STORE_FORMAT);
    try (InputStream in = new FileInputStream(file)) {
      keyStore.load(in, password.toCharArray());
    }
  }

  /**
   * Create new CredentialsSet from given KeyStore
   *
   * @param ksAll
   * @param password
   */
  public CredentialsSet(KeyStore ksAll, String password) {
    this.password = password;
    keyStore = ksAll;
  }

  /**
   * Create new empty CredentialsSet to which new credentials can be added.
   *
   * @param password
   * @throws GeneralSecurityException on keystore/algorithm errors
   * @throws IOException              on keystore initialization error
   */
  public CredentialsSet(String password) throws GeneralSecurityException, IOException {
    this.password = password;
    keyStore = KeyStore.getInstance(Constants.KEY_STORE_FORMAT);
    keyStore.load(null, password.toCharArray()); // load from null to init an empty KeyStore.
  }

  /**
   * return Credentials for a single entity (identified by alias)
   *
   * @param alias
   * @return
   * @throws GeneralSecurityException on keystore/algorithm errors
   * @throws IOException              if the keystore cannot be re-packed
   */
  public Credentials getCredentials(String alias) throws GeneralSecurityException, IOException {
    return new Credentials(keyStore, alias, password);
  }

  public void setCredentials(String alias, X509Certificate[] certChain, PrivateKey privKey)
      throws KeyStoreException {
    keyStore.setKeyEntry(alias, privKey, password.toCharArray(), certChain);
  }

  /**
   * Store a certificate as a trusted-certificate entry (no private key) under the given alias. Used
   * for CA / trust-anchor certificates whose private key is not available (e.g. a third-party MASA
   * CA), so they cannot be stored as a key entry.
   *
   * @param alias the alias to store the certificate under
   * @param cert  the trusted certificate
   * @throws KeyStoreException if the certificate cannot be stored
   */
  public void setTrustedCertificate(String alias, X509Certificate cert) throws KeyStoreException {
    keyStore.setCertificateEntry(alias, cert);
  }

  /**
   * returns the list of aliases present in the underlying KeyStore.
   *
   * @return aliases known to this CredentialsSet, in no particular order
   * @throws KeyStoreException
   */
  public List<String> aliases() throws KeyStoreException {
    return Collections.list(keyStore.aliases());
  }

  /**
   * returns the KeyStore that is used to fetch the credentials.
   *
   * @return
   */
  public KeyStore getKeyStore() {
    return keyStore;
  }

  /**
   * replace the internal KeyStore by a new one (e.g. may be used when loading a CredentialsSet from
   * file)
   *
   * @param ks
   */
  protected void setKeyStore(KeyStore ks) {
    this.keyStore = ks;
  }

  /**
   * returns the password of the KeyStore used to fetch the credentials.
   *
   * @return
   */
  public String getPassword() {
    return password;
  }

  private final String password;
  private KeyStore keyStore;
}
