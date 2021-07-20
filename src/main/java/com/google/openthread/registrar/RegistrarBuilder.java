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

import com.google.openthread.*;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * The builder for creating Registrar instance
 *
 * @author wgtdkp
 */
public class RegistrarBuilder {

  public RegistrarBuilder() {
    masaCertificates = new ArrayList<>();
  }

  /**
   * Supply the credentials to be used for Registrar in its role as MASA client.
   *
   * @param cred
   * @return
   * @throws GeneralSecurityException
   */
  public RegistrarBuilder setMasaClientCredentials(Credentials cred)
      throws GeneralSecurityException {
    this.credentials = cred;
    return this;
  }

  /**
   * Supply the private key used for DTLS connections from Pledge, in DTLS server role.
   *
   * @param privateKey
   * @return
   */
  public RegistrarBuilder setPrivateKey(PrivateKey privateKey) {
    this.privateKey = privateKey;
    return this;
  }

  /**
   * Supply the X.509 certificate chain used for DTLS connections from Pledge, in DTLS server role.
   *
   * @param certificateChain
   * @return
   */
  public RegistrarBuilder setCertificateChain(X509Certificate[] certificateChain) {
    this.certificateChain = certificateChain;
    return this;
  }

  /**
   * Add a MASA certificate
   *
   * @param masaCertificate
   * @return
   */
  public RegistrarBuilder addMasaCertificate(X509Certificate masaCertificate) {
    masaCertificates.add(masaCertificate);
    return this;
  }

  /**
   * Sets whether to trust ALL MASAs (true) or only MASAs for which certificates were added (false).
   *
   * @param status
   */
  public RegistrarBuilder setTrustAllMasas(boolean status) {
    this.isTrustAllMasas = status;
    return this;
  }

  public RegistrarBuilder setPort(int port) {
    this.port = port;
    return this;
  }

  public RegistrarBuilder setHttpToMasa(boolean isHttp) {
    this.isHttpToMasa = isHttp;
    return this;
  }

  /**
   * By default the Registrar mimics the Pledge's Voucher Request format, when requesting to MASA.
   * This method changes that to force the Registrar to use one format only.
   *
   * @param mediaType one of Constants.HTTP_APPLICATION_VOUCHER_CMS_JSON or
   *     Constants.HTTP_APPLICATION_VOUCHER_COSE_CBOR, or "" to force nothing.
   * @return
   */
  public RegistrarBuilder setForcedRequestFormat(String mediaType) {
    switch (mediaType) {
      case "":
        this.forcedVoucherRequestFormat = -1;
      case Constants.HTTP_APPLICATION_VOUCHER_CMS_JSON:
        this.forcedVoucherRequestFormat = ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_CMS_JSON;
        break;
      case Constants.HTTP_APPLICATION_VOUCHER_COSE_CBOR:
        this.forcedVoucherRequestFormat = ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_COSE_CBOR;
        break;
      default:
        throw new IllegalArgumentException(
            "Unsupported mediaType for setForcedRequestFormat in RegistrarBuilder: " + mediaType);
    }
    return this;
  }

  /**
   * return the number of supported/trusted MASA servers. Use addMasaCertificate() to add more
   * trusted MASA servers.
   *
   * @return the number of MASA certificates that are considered trusted.
   */
  public int getNumberOfMasaServers() {
    return masaCertificates.size();
  }

  public Registrar build() throws RegistrarException {
    X509Certificate[] masaCerts = getMasaCertificates();
    if (privateKey == null
        || (masaCerts.length == 0 && !isTrustAllMasas)
        || (masaCerts.length > 0 && isTrustAllMasas)
        || certificateChain == null
        || credentials == null) {
      throw new RegistrarException(
          "bad or missing registrar credentials, or misconfiguration of builder");
    }
    return new Registrar(
        privateKey,
        certificateChain,
        masaCerts,
        credentials,
        port,
        forcedVoucherRequestFormat,
        isHttpToMasa);
  }

  private X509Certificate[] getMasaCertificates() {
    return masaCertificates.toArray(new X509Certificate[masaCertificates.size()]);
  }

  private PrivateKey privateKey;
  private X509Certificate[] certificateChain;
  private List<X509Certificate> masaCertificates;
  private Credentials credentials;
  private int port = Constants.DEFAULT_REGISTRAR_COAPS_PORT;
  private int forcedVoucherRequestFormat = -1;
  private boolean isHttpToMasa = true;
  private boolean isTrustAllMasas = false;
}
