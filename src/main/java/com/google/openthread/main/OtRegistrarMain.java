/*
 *    Copyright (c) 2024, The OpenThread Registrar Authors.
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

package com.google.openthread.main;

import com.google.openthread.Credentials;
import com.google.openthread.LoggerInitializer;
import com.google.openthread.domainca.DomainCA;
import com.google.openthread.registrar.Registrar;
import com.google.openthread.registrar.RegistrarBuilder;
import com.google.openthread.registrar.RegistrarMain;
import com.google.openthread.tools.CredentialGenerator;
import java.security.KeyStoreException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class OtRegistrarMain {

  private static Logger logger = LoggerFactory.getLogger(OtRegistrarMain.class);

  public static void main(String args[]) {

    final String HELP_FORMAT = "[-registrar | -masa | -pledge] [-h] [-v] [-d <domain-name>] [-f <keystore-file>] [-p <udp-port>]";

    HelpFormatter helper = new HelpFormatter();
    Options options = new Options();

    Option registrarOpt =
        Option.builder("registrar")
            .desc("start as cBRSKI Registrar")
            .build();

    Option masaOpt =
        Option.builder("masa")
            .desc("start as cBRSKI/BRSKI MASA")
            .build();

    Option pledgeOpt =
        Option.builder("pledge")
            .desc("start as cBRSKI Pledge")
            .build();

    Option domainNameOpt =
        Option.builder("d")
            .longOpt("domainname")
            .hasArg()
            .argName("domain-name")
            .desc("the domain name")
            .build();

    Option fileOpt =
        Option.builder("f")
            .longOpt("file")
            .hasArg()
            .argName("keystore-file")
            .desc("the keystore file in PKCS#12 format")
            .build();

    Option optPort =
        Option.builder("p")
            .longOpt("port")
            .hasArg()
            .argName("udp-port")
            .desc("the port to listen on")
            .build();

    Option optVerbose =
        Option.builder("v")
            .longOpt("verbose")
            .desc("verbose mode with many logs")
            .build();

    Option optForceMasaUri =
        Option.builder("m")
            .longOpt("masa")
            .hasArg()
            .argName("force-masa-uri")
            .desc("force the given MASA URI instead of the default one")
            .build();

    Option helpOpt =
        Option.builder("h").longOpt("help").hasArg(false).desc("print this message").build();

    options
        .addOption(registrarOpt)
        .addOption(masaOpt)
        .addOption(pledgeOpt)
        .addOption(domainNameOpt)
        .addOption(fileOpt)
        .addOption(optPort)
        .addOption(optVerbose)
        .addOption(optForceMasaUri)
        .addOption(helpOpt);

    try {
      String forcedMasaUri = null;
      CommandLineParser parser = new DefaultParser();
      CommandLine cmd = parser.parse(options, args);

      LoggerInitializer.Init(cmd.hasOption('v'));

      if (cmd.hasOption('h')) {
        helper.printHelp(HELP_FORMAT, options);
        return;
      }

      String keyStoreFile = cmd.getOptionValue('f');
      if (keyStoreFile == null) {
        keyStoreFile = "credentials/default.p12";
      }

      String port = cmd.getOptionValue('p');
      if (port == null) {
        port = "5683";
      }

      String domainName = cmd.getOptionValue('d');
      if (domainName == null) {
        domainName = "DefaultDomain";
      }

      if (cmd.hasOption('m')) {
        forcedMasaUri = cmd.getOptionValue('m');
      }

      logger.info("using keystore: {}", keyStoreFile);

      if (cmd.hasOption("registrar")) {
        RegistrarMain.main(keyStoreFile, Integer.parseInt(port), domainName, forcedMasaUri);
      }else{
        throw new Exception("not yet impl");
      }

    } catch (Exception e) {
      logger.error(e.getMessage(), e);
      helper.printHelp(HELP_FORMAT, options);
      return;
    }

  }
}
