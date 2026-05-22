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

import java.util.HashMap;
import java.util.Map;
import org.eclipse.californium.core.coap.MediaTypeRegistry;

/**
 * Extends Californium's {@link MediaTypeRegistry} with BRSKI-specific content
 * formats. Only {@link #parse(String)} and {@link #toString(int)} are overridden
 * here; they consult the local table first and fall back to the parent.
 *
 * <p>Other parent-class static methods (e.g. {@code getAllMediaTypes},
 * {@code isPrintable}, {@code toFileExtension}, {@code parseWildcard}) are
 * accessible directly via {@code ExtendedMediaTypeRegistry.X(...)} through
 * Java's static-member inheritance; we deliberately do not shadow them.
 */
public final class ExtendedMediaTypeRegistry extends MediaTypeRegistry {

  private ExtendedMediaTypeRegistry() {}

  // application/cose;cose-type="cose-sign1"
  public static final int APPLICATION_COSE_SIGN1 = 18;

  // application/voucher-cose+cbor (IANA allocated 2022-04-12)
  public static final int APPLICATION_VOUCHER_COSE_CBOR = 836;

  // The three below use CoAP content-format numbers in the 65000+ experimental
  // range; replace with IANA-allocated values once available. TODO.
  public static final int APPLICATION_VOUCHER_COSE_JSON = 65503;
  public static final int APPLICATION_VOUCHER_CMS_CBOR = 65331;
  public static final int APPLICATION_VOUCHER_CMS_JSON = 65332;

  // application/cwt
  public static final int APPLICATION_CWT = 61;

  // application/pkcs7-mime;smime-type=certs-only
  public static final int APPLICATION_PKCS7_MIME_CERTS_ONLY = 281;

  // application/csrattrs
  public static final int APPLICATION_CSRATTRS = 285;

  // application/pkcs10
  public static final int APPLICATION_PKCS10 = 286;

  // application/pkix-cert
  public static final int APPLICATION_PKIX_CERT = 287;

  private static final Map<Integer, String> extRegistry = new HashMap<>();

  static {
    add(APPLICATION_COSE_SIGN1, ConstantsBrski.MEDIA_TYPE_COSE_SIGN1);
    add(APPLICATION_VOUCHER_COSE_CBOR, ConstantsBrski.MEDIA_TYPE_VOUCHER_COSE_CBOR);
    add(APPLICATION_VOUCHER_COSE_JSON, ConstantsBrski.MEDIA_TYPE_VOUCHER_COSE_JSON);
    add(APPLICATION_VOUCHER_CMS_CBOR, ConstantsBrski.MEDIA_TYPE_VOUCHER_CMS_CBOR);
    add(APPLICATION_VOUCHER_CMS_JSON, ConstantsBrski.MEDIA_TYPE_VOUCHER_CMS_JSON);
    add(APPLICATION_CWT, "application/cwt");
    add(APPLICATION_PKCS7_MIME_CERTS_ONLY, "application/pkcs7-mime;smime-type=certs-only");
    add(APPLICATION_CSRATTRS, "application/csrattrs");
    add(APPLICATION_PKCS10, "application/pkcs10");
    add(APPLICATION_PKIX_CERT, "application/pkix-cert");
  }

  public static int parse(String type) {
    for (Map.Entry<Integer, String> e : extRegistry.entrySet()) {
      if (e.getValue().equalsIgnoreCase(type)) {
        return e.getKey();
      }
    }
    // if not found locally here, defer to parent class registry.
    return MediaTypeRegistry.parse(type);
  }

  public static String toString(int mediaType) {
    String text = extRegistry.get(mediaType);
    if (text != null) {
      return text;
    }
    return MediaTypeRegistry.toString(mediaType);
  }

  private static void add(int mediaType, String text) {
    extRegistry.put(mediaType, text);
  }
}
