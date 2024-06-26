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

public class OtRegistrarConfig {

  public Role role;
  public int serverPortCoaps;
  public String domainName;
  public String keyStoreFile;
  public String masaUri;
  public String registrarUri;
  public boolean logVerbose;

  static OtRegistrarConfig Default() {
    OtRegistrarConfig config = new OtRegistrarConfig();
    config.role = Role.None;
    config.serverPortCoaps = 5684;
    config.domainName = "DefaultDomain";
    config.keyStoreFile = "./credentials/default.p12";
    config.masaUri = null;
    config.registrarUri = "localhost:5684";
    config.logVerbose = false;
    return config;
  }

  public String ToString() {
    return
        "Role                : " + role.toString() + "\n" +
        "Server port (CoapS) : " + this.serverPortCoaps + "\n" +
        "Domain Name         : " + this.domainName + "\n" +
        "Keystore file       : " + this.keyStoreFile + "\n" +
        "MASA URI            : " + (this.masaUri == null ? "(read from IDevID cert)" : this.masaUri + " (forced)") + "\n" +
        "Registrar URI       : " + this.registrarUri + "\n" +
        "Log verbose         : " + (this.logVerbose ? "yes" : "no" ) + "\n";
  }
}
