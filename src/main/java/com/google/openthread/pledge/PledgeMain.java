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

package com.google.openthread.pledge;

import com.google.openthread.Credentials;
import com.google.openthread.main.OtRegistrarConfig;
import com.google.openthread.tools.CredentialGenerator;
import java.security.KeyStoreException;
import java.util.Scanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PledgeMain {

  private PledgeMain() {
  }

  private static final Logger logger = LoggerFactory.getLogger(PledgeMain.class);

  public static void main(OtRegistrarConfig config) {
    try {
      String password = CredentialGenerator.PASSWORD;
      Credentials cred = new Credentials(config.keyStoreFile, CredentialGenerator.PLEDGE_ALIAS, password);

      if (cred == null || cred.getPrivateKey() == null || cred.getCertificateChain() == null) {
        throw new KeyStoreException(String.format("can't find pledge key or certificate: %s", CredentialGenerator.PLEDGE_ALIAS));
      }
      Pledge pledge = new Pledge(cred, config.registrarUri);
      run(pledge);
      pledge.shutdown();
    } catch (Exception e) {
      logger.error("error: {}", e.getMessage(), e);
      return;
    }
  }

  private static void run(Pledge pledge) {
    final String help =
        "rv       -  request voucher to Registrar (cBRSKI)\n"
            + "enroll   -  simple enrollment with Registrar (EST)\n"
            + "reenroll -  simple reenrollment with Registrar (EST)\n"
            + "reset    -  reset Pledge to initial state\n"
            + "exit     -  exit pledge CLI\n"
            + "help     -  print this help message\n";
    System.out.println("Pledge CLI commands:\n" + help);

    try (Scanner scanner = new Scanner(System.in)) {
      while (true) {
        try {
          System.out.print("> ");
          String cmd = scanner.nextLine().trim();
          switch (cmd) {
            case "rv":
              pledge.requestVoucher();
              break;
            case "enroll":
              pledge.enroll();
              break;
            case "reenroll":
              pledge.reenroll();
              break;
            case "reset":
              pledge.reset();
              break;
            case "exit":
              return;
            case "help":
              System.out.println(help);
              break;
            default:
              logger.error("unknown CLI command: {}", cmd);
              System.out.println(help);
          }

          System.out.println("Done");
        } catch (Exception e) {
          logger.error("error: {}", e.getMessage(), e);
        }
      }
    }
  }
}
