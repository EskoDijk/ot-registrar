/*
 * Copyright (c) 2022, The OpenThread Registrar Authors. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: 1. Redistributions of source code must retain the
 * above copyright notice, this list of conditions and the following disclaimer. 2. Redistributions
 * in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 * WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.google.openthread.tools;

import COSE.MessageTag;
import COSE.OneKey;
import COSE.Sign1Message;
import com.upokecenter.cbor.CBORObject;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tool (CLI) to validate COSE_Sign1 signature, loading the COSE from binary .cbor file; and loading
 * the signer's certificate from either binary DER .crt / .der or PEM file.
 */
public class CoseValidator {

  private static Logger logger = LoggerFactory.getLogger(CredentialGenerator.class);

  public CoseValidator() {}

  public static void main(String[] args) throws Exception {

    if (args.length != 2) {
      System.out.println("CoseValidator");
      System.out.println("Usage: CoseValidator <cose-file.cbor> <signer-x509-cert.der/pem>");
      return;
    }

    try {
      CoseValidator app = new CoseValidator();
      CBORObject c = app.loadCborFile(args[0]);
      X509Certificate cert = app.loadX509Certificate(args[1]);
      if (app.validateCose(c, cert)) {
        System.out.println("COSE object validated ok against signer identity.");
      } else {
        System.out.println("COSE object VALIDATION FAILED against signer identity.");
      }
    } catch (Exception ex) {
      logger.error("Internal error", ex);
    }
  }

  public X509Certificate loadX509Certificate(String fn) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    InputStream in = null;
    try {
      in = new FileInputStream(fn);
      X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
      return cert;
    } finally {
      if (in != null) in.close();
    }
  }

  public CBORObject loadCborFile(String fn) throws Exception {
    byte[] b;
    b = Files.readAllBytes((new File(fn)).toPath());
    CBORObject c = CBORObject.DecodeFromBytes(b);
    // logger.debug("Loaded CBOR object file "+fn+": " + b.length + " bytes.");
    return c;
  }

  public boolean validateCose(CBORObject cose, X509Certificate cert) {
    try {
      OneKey pubKey = new OneKey(cert.getPublicKey(), null);
      logger.info("Validating COSE_Sign1 object against public key: " + pubKey.AsCBOR().toString());
      Sign1Message msg =
          (Sign1Message) Sign1Message.DecodeFromBytes(cose.EncodeToBytes(), MessageTag.Sign1);
      boolean isOk = msg.validate(pubKey);
      return isOk;
    } catch (Exception ex) {
      logger.error("Validation failed", ex);
    }
    return false;
  }
}
