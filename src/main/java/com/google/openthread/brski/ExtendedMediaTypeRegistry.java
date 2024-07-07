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
import java.util.Set;
import org.eclipse.californium.core.coap.MediaTypeRegistry;

public final class ExtendedMediaTypeRegistry extends MediaTypeRegistry {

  // application/cose;cose-type="cose-sign1"
  public static final int APPLICATION_COSE_SIGN1 = 18;

  // application/voucher-cose+cbor (IANA allocated on 2022-04-12)
  public static final int APPLICATION_VOUCHER_COSE_CBOR = 836;

  // application/voucher-cose+cbor (not yet allocated TODO)
  public static final int APPLICATION_VOUCHER_COSE_JSON = 65503;

  // application/voucher-cms+cbor (not yet allocated TODO)
  public static final int APPLICATION_VOUCHER_CMS_CBOR = 65331;

  // application/voucher-cms+cbor (not yet allocated TODO)
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

  // initializer
  private static final HashMap<Integer, String[]> extRegistry = new HashMap<Integer, String[]>();

  static {
    add(APPLICATION_COSE_SIGN1, "application/cose; cose-type=\"cose-sign1\"", "cose");
    add(APPLICATION_VOUCHER_COSE_CBOR, "application/voucher-cose+cbor", "cose");
    add(APPLICATION_VOUCHER_CMS_CBOR, "application/voucher-cms+cbor", "cms");
    add(APPLICATION_VOUCHER_CMS_JSON, "application/voucher-cms+json", "cms");
    add(APPLICATION_CWT, "application/cwt", "cwt");
    add(
        APPLICATION_PKCS7_MIME_CERTS_ONLY,
        "application/pkcs7-mime; smime-type=certs-only",
        "pkcs7");
    add(APPLICATION_CSRATTRS, "application/csrattrs", "csrattrs");
    add(APPLICATION_PKCS10, "application/pkcs10", "pkcs10");
    add(APPLICATION_PKIX_CERT, "application/pkix-cert", "crt");
  }

  public static Set<Integer> getAllMediaTypes() {
    throw new RuntimeException("not implemented");
  }

  public static boolean isPrintable(int mediaType) {
    throw new RuntimeException("not implemented");
  }

  public static int parse(String type) {
    for (Integer key : extRegistry.keySet()) {
      if (extRegistry.get(key)[0].equalsIgnoreCase(type)) {
        return key;
      }
    }

    // if not found locally here, defer to parent class registry.
    return MediaTypeRegistry.parse(type);
  }

  public static Integer[] parseWildcard(String regex) {
    throw new RuntimeException("not implemented");
  }

  public static String toFileExtension(int mediaType) {
    throw new RuntimeException("not implemented");
  }

  public static String toString(int mediaType) {
    String texts[] = extRegistry.get(mediaType);
    if (texts != null) {
      return texts[0];
    } else {
      return MediaTypeRegistry.toString(mediaType);
    }
  }

  private static void add(int mediaType, String string, String extension) {
    extRegistry.put(mediaType, new String[] {string, extension});
  }
}
