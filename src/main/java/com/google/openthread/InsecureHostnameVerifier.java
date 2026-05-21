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

package com.google.openthread;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

/**
 * A {@link HostnameVerifier} that <strong>accepts any hostname without
 * verification</strong>: {@link #verify} always returns {@code true}.
 *
 * <p>Used together with {@link InsecureTrustManager} on the Registrar's
 * outbound HTTPS connection to the MASA. Authentication of that hop today
 * rests entirely on the BRSKI application-layer signature checks
 * (CMS/COSE-Sign1 on the voucher request and response), not on TLS.
 *
 * <p>This is <strong>not</strong> a property of the BRSKI protocol. RFC 8995
 * permits standard WebPKI hostname/peer checks, or a custom TLS
 * authentication scheme, on the Registrar↔MASA hop. Neither has been
 * implemented in this codebase yet, so this class plugs the gap together
 * with {@link InsecureTrustManager}. A future change should wire up real
 * hostname verification and reduce or remove the use of this class.
 *
 * <p><strong>Do not use this class in any other TLS context.</strong>
 * Disabling hostname verification is its entire purpose. Anywhere else,
 * hostname checks are part of the security model and must be performed.
 */
public final class InsecureHostnameVerifier implements HostnameVerifier {

  @Override
  public boolean verify(String hostname, SSLSession session) {
    return true;
  }
}
