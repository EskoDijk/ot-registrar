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

package com.google.openthread.masa;

import com.google.openthread.Credentials;
import com.google.openthread.main.OtRegistrarConfig;
import com.google.openthread.tools.CredentialGenerator;
import java.security.KeyStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MASAMain {

  private MASAMain() {
  }

  private static final Logger logger = LoggerFactory.getLogger(MASAMain.class);

  public static void startMasa(OtRegistrarConfig config) {
    MASA masa;

    try {
      Credentials cred = new Credentials(config.keyStoreFile, CredentialGenerator.MASA_ALIAS, CredentialGenerator.PASSWORD);
      Credentials credCa = new Credentials(config.keyStoreFile, CredentialGenerator.MASACA_ALIAS, CredentialGenerator.PASSWORD);

      if (cred.getPrivateKey() == null || cred.getCertificate() == null) {
        throw new KeyStoreException("can't find MASA server key or certificate in key store");
      }
      if (credCa.getPrivateKey() == null || credCa.getCertificate() == null) {
        throw new KeyStoreException("can't find MASA CA key or CA certificate in key store");
      }

      masa = new MASA(cred, credCa, config.serverPort);
    } catch (Exception e) {
      logger.error(e.getMessage());
      logger.debug("details:", e);
      return;
    }

    masa.start();
    logger.info("MASA server listening (HTTPS) at port {}", masa.getListenPort());
  }
}
