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

import com.google.openthread.brski.ConstantsBrski;

public class OtRegistrarConfig {

  public Role role;
  public int serverPort;
  public String domainName;
  public String keyStoreFile;
  public String masaUri;
  public String registrarUri;
  public boolean logVerbose;

  static OtRegistrarConfig DefaultPledge() {
    OtRegistrarConfig config = new OtRegistrarConfig();
    config.role = Role.Pledge;
    config.serverPort = 0;
    config.domainName = null;
    config.keyStoreFile = "./credentials/default_pledge.p12";
    config.masaUri = null;
    config.registrarUri = "coaps://localhost:5684";
    config.logVerbose = false;
    return config;
  }

  static OtRegistrarConfig DefaultRegistrar() {
    OtRegistrarConfig config = new OtRegistrarConfig();
    config.role = Role.Registrar;
    config.serverPort = 5684;
    config.domainName = "DefaultDomain";
    config.keyStoreFile = "./credentials/default_registrar.p12";
    config.masaUri = null;
    config.registrarUri = null;
    config.logVerbose = false;
    return config;
  }

  static OtRegistrarConfig DefaultMasa() {
    OtRegistrarConfig config = new OtRegistrarConfig();
    config.role = Role.Masa;
    config.serverPort = ConstantsBrski.DEFAULT_MASA_HTTPS_PORT; // re-using corporate TLS/HTTPS port
    config.domainName = null;
    config.keyStoreFile = "./credentials/default_masa.p12";
    config.masaUri = null;
    config.registrarUri = null;
    config.logVerbose = false;
    return config;
  }

  public String ToString() {
    String s;
    s = "Role          : " + role.toString() + "\n";
    if (this.serverPort > 0) {
      s += "Server port   : " + this.serverPort + "\n";
    }
    if (this.domainName != null) {
      s += "Domain Name   : " + this.domainName + "\n";
    }
    if (this.keyStoreFile != null) {
      s += "Keystore file : " + this.keyStoreFile + "\n";
    }
    if (this.masaUri != null) {
      s += "MASA URI      : " + this.masaUri + " (forced)\n";
    }
    if (this.registrarUri != null) {
      s += "Registrar URI : " + this.registrarUri + "\n";
    }
    s += "Log verbose   : " + (this.logVerbose ? "yes" : "no") + "\n";
    return s;
  }
}
