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

import com.google.openthread.Credentials;
import com.google.openthread.brski.ConstantsBrski;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** The builder for creating Registrar instance. */
public final class RegistrarBuilder {

  private final List<X509Certificate> masaCertificates = new ArrayList<>();
  private PrivateKey privateKey;
  private X509Certificate[] certificateChain;
  private Credentials credentials;
  private Credentials masaClientCredentials;
  private int port = ConstantsBrski.DEFAULT_REGISTRAR_COAPS_PORT;
  private boolean isHttpToMasa = true;
  private boolean isTrustAllMasas = false;

  /**
   * Supply the credentials to be used for Registrar in its role as MASA-client. By default, no
   * separate credentials are used and rather the 'setCredentials()' credentials are used for
   * authentication to MASA server as a client.
   *
   * @param cred Credentials to use in client role towards MASA server, or null to re-use the
   *             'setCredentials()' credentials for this.
   */
  public RegistrarBuilder setMasaClientCredentials(Credentials cred)
      throws GeneralSecurityException {
    if (cred != null) {
      if (cred.getPrivateKey() == null) {
        throw new IllegalArgumentException("MASA-client credentials have no private key");
      }
      X509Certificate[] chain = cred.getCertificateChain();
      if (chain == null || chain.length == 0) {
        throw new IllegalArgumentException("MASA-client credentials have no certificate chain");
      }
    }
    this.masaClientCredentials = cred;
    return this;
  }

  /** Supply the credentials for the Registrar for DTLS connections from Pledge, in DTLS server role. */
  public RegistrarBuilder setCredentials(Credentials cred) throws GeneralSecurityException {
    Objects.requireNonNull(cred, "cred");
    PrivateKey pk = Objects.requireNonNull(
        cred.getPrivateKey(), "credentials have no private key");
    X509Certificate[] chain = cred.getCertificateChain();
    if (chain == null || chain.length == 0) {
      throw new IllegalArgumentException("credentials have no certificate chain");
    }
    this.privateKey = pk;
    this.certificateChain = chain;
    this.credentials = cred;
    return this;
  }

  /**
   * Supply the private key used for DTLS connections from Pledge, in DTLS server role. Requires
   * {@link #setCredentials} to have been called first (the alias/password come from there).
   */
  public RegistrarBuilder setPrivateKey(PrivateKey privateKey)
      throws GeneralSecurityException, IOException {
    Objects.requireNonNull(privateKey, "privateKey");
    if (this.credentials == null) {
      throw new IllegalStateException(
          "setCredentials(...) must be called before setPrivateKey(...)");
    }
    this.privateKey = privateKey;
    this.credentials =
        new Credentials(
            privateKey,
            this.certificateChain,
            this.credentials.getAlias(),
            this.credentials.getPassword());
    return this;
  }

  /**
   * Supply the X.509 certificate chain used for DTLS connections from Pledge, in DTLS server role.
   * Requires {@link #setCredentials} to have been called first (the alias/password come from
   * there).
   */
  public RegistrarBuilder setCertificateChain(X509Certificate[] certificateChain)
      throws GeneralSecurityException, IOException {
    Objects.requireNonNull(certificateChain, "certificateChain");
    if (certificateChain.length == 0) {
      throw new IllegalArgumentException("certificateChain is empty");
    }
    if (this.credentials == null) {
      throw new IllegalStateException(
          "setCredentials(...) must be called before setCertificateChain(...)");
    }
    this.certificateChain = certificateChain;
    this.credentials =
        new Credentials(
            this.privateKey,
            certificateChain,
            this.credentials.getAlias(),
            this.credentials.getPassword());
    return this;
  }

  /**
   * Add a MASA certificate of a trusted MASA server. Only needed if 'setTrustAllMasas(true)' is
   * not enabled.
   */
  public RegistrarBuilder addMasaCertificate(X509Certificate masaCertificate) {
    masaCertificates.add(masaCertificate);
    return this;
  }

  /**
   * Sets whether to trust ALL MASAs (true) or only MASAs for which certificates were added
   * (false). By default, this is 'false'.
   */
  public RegistrarBuilder setTrustAllMasas(boolean status) {
    this.isTrustAllMasas = status;
    return this;
  }

  public RegistrarBuilder setPort(int port) {
    this.port = port;
    return this;
  }

  /**
   * Sets whether HTTPS is used to communicate with the MASA. This is usually the case (true). Only
   * for testing situations HTTPS is set to 'false', in which case CoAP will be used.
   *
   * @param isHttp true if HTTPS is to be used, false if COAPS is to be used.
   */
  public RegistrarBuilder setHttpToMasa(boolean isHttp) {
    this.isHttpToMasa = isHttp;
    return this;
  }

  /**
   * Return the number of supported/trusted MASA servers. Use addMasaCertificate() to add more
   * trusted MASA servers.
   *
   * @return the number of MASA certificates that are considered trusted.
   */
  public int getNumberOfMasaServers() {
    return masaCertificates.size();
  }

  public Registrar build() throws RegistrarException, GeneralSecurityException {
    if (credentials == null) {
      throw new RegistrarException("Registrar credentials not set; call setCredentials() first");
    }
    X509Certificate[] masaCerts = getMasaCertificates();
    if (masaCerts.length == 0 && !isTrustAllMasas) {
      throw new RegistrarException(
          "no MASA trust anchors set and setTrustAllMasas(true) not configured");
    }
    if (masaCerts.length > 0 && isTrustAllMasas) {
      throw new RegistrarException(
          "MASA trust anchors set and setTrustAllMasas(true); these are mutually exclusive");
    }
    return new Registrar(
        credentials,
        masaCerts,
        masaClientCredentials == null ? credentials : masaClientCredentials,
        port,
        isHttpToMasa);
  }

  private X509Certificate[] getMasaCertificates() {
    return masaCertificates.toArray(new X509Certificate[0]);
  }
}
