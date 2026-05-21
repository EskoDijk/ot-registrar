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

import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

/**
 * An {@link X509TrustManager} that <strong>accepts every peer certificate
 * without any verification</strong>. Both {@link #checkClientTrusted} and
 * {@link #checkServerTrusted} are no-ops, and {@link #getAcceptedIssuers}
 * returns an empty array.
 *
 * <p>Used on the Registrar↔MASA HTTPS hop (Registrar's outbound HTTPS client
 * and MASA's inbound HTTPS server). On that hop, peer authentication today
 * rests entirely on the BRSKI application-layer signature checks: voucher
 * requests and responses are signed objects (CMS or COSE-Sign1) whose
 * signatures are verified independently of the TLS handshake.
 *
 * <p>This is <strong>not</strong> a property of the BRSKI protocol. RFC 8995
 * permits standard WebPKI checks, or a custom TLS authentication scheme
 * (e.g. pinned certificates), on the Registrar↔MASA hop. Neither has been
 * implemented in this codebase yet, so this class plugs the gap. A future
 * change should wire up real TLS peer authentication and reduce or remove
 * the use of this class.
 *
 * <p><strong>Do not use this class in any other TLS context.</strong>
 * Disabling validation is its entire purpose. Anywhere else, peer
 * authentication is part of the security model and must be performed.
 */
public final class InsecureTrustManager implements X509TrustManager {

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return new X509Certificate[]{};
  }

  @Override
  public void checkClientTrusted(X509Certificate[] certs, String authType) {}

  @Override
  public void checkServerTrusted(X509Certificate[] certs, String authType) {}
}
