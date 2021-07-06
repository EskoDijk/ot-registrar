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

import com.google.openthread.Constants;
import com.google.openthread.Credentials;
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

  public RegistrarBuilder(PrivateKey privateKey, X509Certificate[] certificateChain) {
    this();

    this.privateKey = privateKey;
    this.certificateChain = certificateChain;
  }

  public RegistrarBuilder() {
    masaCertificates = new ArrayList<>();
  }

  public RegistrarBuilder setCredentials(Credentials cred) {
    this.credentials = cred;
    return this;
  }

  public RegistrarBuilder setPrivateKey(PrivateKey privateKey) {
    this.privateKey = privateKey;
    return this;
  }

  public RegistrarBuilder setCertificateChain(X509Certificate[] certificateChain) {
    this.certificateChain = certificateChain;
    return this;
  }

  public RegistrarBuilder addMasaCertificate(X509Certificate masaCertificate) {
    masaCertificates.add(masaCertificate);
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

  public RegistrarBuilder setRequestFormat(String mediaType) {
    switch (mediaType) {
      case Constants.HTTP_APPLICATION_VOUCHER_CMS_JSON:
        this.isCmsJsonRequests = true;
        break;
      case Constants.HTTP_APPLICATION_VOUCHER_COSE_CBOR:
        this.isCmsJsonRequests = false;
        break;
      default:
        throw new IllegalArgumentException(
            "Unsupported mediaType for RegistrarBuilder: " + mediaType);
    }
    return this;
  }

  public int getMasaNumber() {
    return masaCertificates.size();
  }

  public Registrar build() throws RegistrarException {
    if (privateKey == null
        || certificateChain == null
        || getMasaCertificates().length == 0
        || credentials == null) {
      throw new RegistrarException("bad registrar credentials");
    }
    return new Registrar(
        privateKey,
        certificateChain,
        getMasaCertificates(),
        credentials,
        port,
        isCmsJsonRequests,
        isCmsJsonRequests,
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
  private boolean isCmsJsonRequests = true;
  private boolean isHttpToMasa = true;
}
