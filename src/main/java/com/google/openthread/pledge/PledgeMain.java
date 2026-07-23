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
import com.google.openthread.CredentialsSet;
import com.google.openthread.SecurityUtils;
import com.google.openthread.main.OtRegistrarConfig;
import com.google.openthread.tools.CredentialGenerator;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PledgeMain {

  private PledgeMain() {
  }

  private static final Logger logger = LoggerFactory.getLogger(PledgeMain.class);

  public static int startPledge(OtRegistrarConfig config) {
    Objects.requireNonNull(config, "config");
    try {
      String password = CredentialsSet.DEFAULT_PASSWORD;
      Credentials cred = new Credentials(config.keyStoreFile, CredentialsSet.PLEDGE_ALIAS, password);

      Pledge pledge = new Pledge(cred, config.registrarUri);
      runCli(pledge);
      pledge.shutdown();
    } catch (Exception e) {
      logger.error(e.getMessage(), e);
      return 1;
    }
    return 0;
  }

  private static void runCli(Pledge pledge) {
    final String help =
        "rv       -  request voucher to Registrar (cBRSKI)\n"
            + "enroll   -  simple enrollment with Registrar (EST-coaps)\n"
            + "reenroll -  simple reenrollment with Registrar (EST-coaps)\n"
            + "cacerts  -  request CA certificates from Registrar (EST-coaps)\n"
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
            case "cacerts":
              printCaCertificates(pledge.requestCACertificates());
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
              logger.error("unknown CLI command: '{}'", cmd);
              System.out.println(help);
          }

          System.out.println("Done");
        } catch (Exception e) {
          logger.error("error: {}", e.getMessage());
          logger.debug("details:", e);
        }
      }
    }
  }

  /**
   * Print the CA certificates from a /crts response, in the order received: per cBRSKI section
   * 6.7.5 this is the CA hierarchy order, starting at the issuer of the client's LDevID.
   */
  private static void printCaCertificates(List<X509Certificate> caCerts) throws IOException {
    System.out.println("Received " + caCerts.size() + " CA certificate(s):");
    for (int i = 0; i < caCerts.size(); i++) {
      X509Certificate cert = caCerts.get(i);
      System.out.println(
          "["
              + (i + 1)
              + "] subject: "
              + cert.getSubjectX500Principal()
              + "\n    issuer : "
              + cert.getIssuerX500Principal());
      System.out.println(SecurityUtils.toPEMFormat(cert));
    }
  }
}
