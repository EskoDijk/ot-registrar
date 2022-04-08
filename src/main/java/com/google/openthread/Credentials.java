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
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import org.eclipse.californium.elements.util.SslContextUtil;

/** Credentials (certificate and private key) for a single named entity ("alias"). */
public class Credentials {

  public Credentials(String file, String alias, String password) throws Exception {
    this.alias = alias;
    this.password = password;
    KeyStore ksAll = KeyStore.getInstance(Constants.KEY_STORE_FORMAT);

    try (InputStream in = new FileInputStream(file)) {
      ksAll.load(in, password.toCharArray());
    }
    if (!ksAll.containsAlias(alias))
      throw new KeyStoreException("Alias " + alias + " not found in keystore: " + file);

    // set the single right entry in a new keystore
    keyStore = KeyStore.getInstance(Constants.KEY_STORE_FORMAT);
    keyStore.load(null, password.toCharArray());
    Key privKey = ksAll.getKey(alias, password.toCharArray());
    Certificate[] certChain = ksAll.getCertificateChain(alias);
    keyStore.setKeyEntry(alias, privKey, password.toCharArray(), certChain);
  }

  public Credentials(KeyStore ksAll, String alias, String password) throws Exception {
    this.alias = alias;
    this.password = password;

    // set the single right entry in a new keystore
    keyStore = KeyStore.getInstance(Constants.KEY_STORE_FORMAT);
    keyStore.load(null, password.toCharArray());
    Key privKey = ksAll.getKey(alias, password.toCharArray());
    Certificate[] certChain = ksAll.getCertificateChain(alias);
    keyStore.setKeyEntry(alias, privKey, password.toCharArray(), certChain);
  }

  public Credentials(PrivateKey privKey, X509Certificate[] certChain, String alias, String password)
      throws GeneralSecurityException, IOException {
    this.alias = alias;
    this.password = password;
    this.keyStore = KeyStore.getInstance(Constants.KEY_STORE_FORMAT);
    keyStore.load(null, password.toCharArray());
    keyStore.setKeyEntry(alias, privKey, password.toCharArray(), certChain);
  }

  public KeyPair getKeyPair() throws GeneralSecurityException {
    PublicKey pubk = keyStore.getCertificate(alias).getPublicKey();
    PrivateKey privk = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
    KeyPair kp = new KeyPair(pubk, privk);
    return kp;
  }

  // Returns null if alias not included i.e. key for alias was not found.
  public PrivateKey getPrivateKey() throws GeneralSecurityException {
    return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
  }

  // Returns null if alias not included i.e. key for alias was not found.
  public X509Certificate getCertificate() throws KeyStoreException {
    return (X509Certificate) keyStore.getCertificate(alias);
  }

  // Returns null if alias not included i.e. key for alias was not found.
  public X509Certificate[] getCertificateChain() throws KeyStoreException {
    return SslContextUtil.asX509Certificates(keyStore.getCertificateChain(alias));
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
   * returns the password of the KeyStore used to fetch the credentials.
   *
   * @return
   */
  public String getPassword() {
    return password;
  }

  /**
   * returns the alias for the credentials indicated by this Credentials object.
   *
   * @return alias String associated to the current credentials
   */
  public String getAlias() {
    return alias;
  }

  private String alias;
  private String password;
  private KeyStore keyStore;
}
