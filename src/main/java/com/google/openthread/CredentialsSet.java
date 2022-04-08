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
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * A set of multiple credentials (each having certificate and private key) for named entities
 * ("aliases").
 */
public class CredentialsSet {

  /**
   * Create new CredentialsSet from keystore (PKCS12) file
   *
   * @param file
   * @param password
   * @throws Exception
   */
  public CredentialsSet(String file, String password) throws Exception {
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
   * @throws Exception
   */
  public CredentialsSet(KeyStore ksAll, String password) throws Exception {
    this.password = password;
    keyStore = ksAll;
  }

  /**
   * Create new empty CredentialsSet to which new credentials can be added.
   *
   * @param password
   * @throws Exception
   */
  public CredentialsSet(String password) throws Exception {
    this.password = password;
    keyStore = KeyStore.getInstance(Constants.KEY_STORE_FORMAT);
    keyStore.load(null, password.toCharArray()); // load from null to init an empty KeyStore.
  }

  /**
   * return Credentials for a single entity (identified by alias)
   *
   * @param alias
   * @return
   * @throws Exception
   */
  public Credentials getCredentials(String alias) throws Exception {
    return new Credentials(keyStore, alias, password);
  }

  public void setCredentials(String alias, X509Certificate[] certChain, PrivateKey privKey)
      throws Exception {
    keyStore.setKeyEntry(alias, privKey, password.toCharArray(), certChain);
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

  private String password;
  private KeyStore keyStore;
}
