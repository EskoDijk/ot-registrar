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

package com.google.openthread.brski;

import com.google.openthread.SecurityUtils;
import com.google.openthread.pledge.Pledge;
import java.security.KeyPair;
import java.util.Date;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class ExamplePayloadsTest {

  private static final Logger logger = LoggerFactory.getLogger(ExamplePayloadsTest.class);

  @Test
  public void voucherExamplePayload() throws Exception {
    VoucherRequest cvr = new VoucherRequest();
    cvr.setConstrained(true);
    cvr.setAssertion(Voucher.Assertion.PROXIMITY);
    cvr.setSerialNumber("123");
    cvr.setNonce(Pledge.generateNonce());

    KeyPair kp = SecurityUtils.genKeyPair();
    // PublicKey.getEncoded() already returns the X.509 SubjectPublicKeyInfo DER bytes,
    // so no wrap/unwrap round-trip via SubjectPublicKeyInfo is needed.
    cvr.setProximityRegistrarSPKI(kp.getPublic().getEncoded());
    Assert.assertTrue(cvr.validate());

    logger.info("example constrained voucher request payload:");
    logger.info(new CBORSerializer().toCBOR(cvr).toString());

    Voucher cv = new Voucher();
    cv.setConstrained(true);
    cv.setAssertion(Voucher.Assertion.PROXIMITY);
    cv.setCreatedOn(new Date());
    cv.setSerialNumber("123");
    cv.setNonce(cvr.getNonce());

    kp = SecurityUtils.genKeyPair();
    cv.setPinnedDomainSPKI(kp.getPublic().getEncoded());
    Assert.assertTrue(cv.validate());

    logger.info("example constrained voucher payload:");
    logger.info(new CBORSerializer().toCBOR(cv).toString());
  }
}
