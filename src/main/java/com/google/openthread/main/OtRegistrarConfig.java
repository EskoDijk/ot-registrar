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

import com.google.openthread.CredentialsSet;
import com.google.openthread.Role;
import com.google.openthread.brski.ConstantsBrski;

public final class OtRegistrarConfig {

  public Role role;
  public int serverPort;
  public String domainName;
  public String keyStoreFile;
  public String masaUri;
  public String registrarUri;
  public int logVerbosity;

  static OtRegistrarConfig defaultPledge() {
    OtRegistrarConfig config = new OtRegistrarConfig();
    config.role = Role.Pledge;
    config.keyStoreFile = CredentialsSet.keystorePath("default", Role.Pledge);
    config.registrarUri = "coaps://localhost:5684";
    return config;
  }

  static OtRegistrarConfig defaultRegistrar() {
    OtRegistrarConfig config = new OtRegistrarConfig();
    config.role = Role.Registrar;
    config.serverPort = 5684;
    config.domainName = "DefaultDomain";
    config.keyStoreFile = CredentialsSet.keystorePath("default", Role.Registrar);
    return config;
  }

  static OtRegistrarConfig defaultMasa() {
    OtRegistrarConfig config = new OtRegistrarConfig();
    config.role = Role.Masa;
    config.serverPort = ConstantsBrski.DEFAULT_MASA_HTTPS_PORT;
    config.keyStoreFile = CredentialsSet.keystorePath("default", Role.Masa);
    return config;
  }

  @Override
  public String toString() {
    String s;
    s = "Role          : " + role + "\n";
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
    s += "Log verbosity : " + this.logVerbosity + "\n";
    return s;
  }

  public String toStringSingleLine() {
    String s;
    s = "role=" + role;
    if (this.serverPort > 0) {
      s += " port=" + this.serverPort;
    }
    if (this.domainName != null) {
      s += " domain=" + this.domainName;
    }
    if (this.keyStoreFile != null) {
      s += " keyfile=" + this.keyStoreFile;
    }
    if (this.masaUri != null) {
      s += " masaUri=" + this.masaUri;
    }
    if (this.registrarUri != null) {
      s += " registrarUri=" + this.registrarUri;
    }
    s += " verbosity=" + this.logVerbosity;
    return s;
  }
}
