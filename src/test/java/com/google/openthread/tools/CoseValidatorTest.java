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

package com.google.openthread.tools;

import com.google.openthread.SecurityUtils;
import com.upokecenter.cbor.CBORObject;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Assert;
import org.junit.Test;

public class CoseValidatorTest {

  @Test
  public void validateCose_acceptsMatchingSignerCertificate() throws Exception {
    KeyPair kp = SecurityUtils.genKeyPair();
    X509Certificate cert =
        SecurityUtils.genCertificate(
            kp, "CN=signer", kp, new X500Name("CN=signer"), true, null);
    byte[] payload = {1, 2, 3, 4, 5};
    byte[] signed =
        SecurityUtils.genCoseSign1Message(
            kp.getPrivate(), SecurityUtils.COSE_SIGNATURE_ALGORITHM, payload);

    CoseValidator app = new CoseValidator();
    Assert.assertTrue(app.validateCose(CBORObject.DecodeFromBytes(signed), cert));
  }

  @Test
  public void validateCose_rejectsUnrelatedCertificate() throws Exception {
    KeyPair signer = SecurityUtils.genKeyPair();
    KeyPair other = SecurityUtils.genKeyPair();
    X509Certificate otherCert =
        SecurityUtils.genCertificate(
            other, "CN=other", other, new X500Name("CN=other"), true, null);
    byte[] payload = {1, 2, 3};
    byte[] signed =
        SecurityUtils.genCoseSign1Message(
            signer.getPrivate(), SecurityUtils.COSE_SIGNATURE_ALGORITHM, payload);

    CoseValidator app = new CoseValidator();
    Assert.assertFalse(app.validateCose(CBORObject.DecodeFromBytes(signed), otherCert));
  }

  @Test
  public void validateCose_returnsFalseOnNonCoseInput() throws Exception {
    KeyPair kp = SecurityUtils.genKeyPair();
    X509Certificate cert =
        SecurityUtils.genCertificate(
            kp, "CN=signer", kp, new X500Name("CN=signer"), true, null);
    // A plain CBOR string is not a COSE_Sign1 message.
    CBORObject notCose = CBORObject.FromObject("not a COSE_Sign1 message");

    CoseValidator app = new CoseValidator();
    Assert.assertFalse(app.validateCose(notCose, cert));
  }

  @Test
  public void loadCborFile_roundTripsArbitraryCbor() throws Exception {
    CBORObject original = CBORObject.FromObject(new int[] {1, 2, 3, 4, 5});
    File tmp = File.createTempFile("cose-validator-test", ".cbor");
    tmp.deleteOnExit();
    Files.write(tmp.toPath(), original.EncodeToBytes());

    CoseValidator app = new CoseValidator();
    CBORObject loaded = app.loadCborFile(tmp.getAbsolutePath());
    Assert.assertEquals(original, loaded);
  }
}
