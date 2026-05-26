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
import com.google.openthread.CredentialsSet;
import com.google.openthread.domainca.DomainCA;
import com.google.openthread.main.OtRegistrarConfig;
import com.google.openthread.tools.CredentialGenerator;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class RegistrarMain {

  private static final Logger logger = LoggerFactory.getLogger(RegistrarMain.class);

  private RegistrarMain() {}

  public static int startRegistrar(OtRegistrarConfig config) {
    Objects.requireNonNull(config, "config");
    Registrar registrar;

    try {
      RegistrarBuilder builder = new RegistrarBuilder();
      Credentials cred = new Credentials(config.keyStoreFile, CredentialsSet.REGISTRAR_ALIAS, CredentialsSet.DEFAULT_PASSWORD);
      Credentials domainCred = new Credentials(config.keyStoreFile, CredentialsSet.DOMAIN_CA_ALIAS, CredentialsSet.DEFAULT_PASSWORD);

      // re-use the same creds for Pledge-facing identity and MASA-facing identity of Registrar.
      builder.setCredentials(cred);
      builder.setPort(config.serverPort);

      // TODO: support configurable MASA trust anchors. When a MASA identity is supplied
      //   in the credentials file (or via a CLI flag), pin only that one via
      //   builder.addMasaCertificate(...) instead of trusting all.
      builder.setTrustAllMasas(true);

      registrar = builder.build();

      if (config.masaUri != null) {
        registrar.setForcedMasaUri(config.masaUri);
      }

      DomainCA ca = new DomainCA(config.domainName, domainCred);
      registrar.setDomainCA(ca);
    } catch (Exception e) {
      logger.error(e.getMessage(), e);
      return 1;
    }

    registrar.start();
    logger.info("Registrar listening (CoAPS) at port: {}", registrar.getListenPort());
    return 0;
  }
}
