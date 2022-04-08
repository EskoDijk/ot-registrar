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

import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;

public class Constants {

  // --- BRSKI - EST resources and paths
  public static final String WELL_KNOWN = ".well-known";
  public static final String EST = "est";
  public static final String BRSKI = "brski";
  public static final String CORE = "core";
  public static final String EST_PATH = "/" + String.join("/", WELL_KNOWN, EST);
  public static final String BRSKI_PATH = "/" + String.join("/", WELL_KNOWN, BRSKI);
  public static final String CORE_PATH = "/" + String.join("/", WELL_KNOWN, CORE);
  public static final String REQUEST_VOUCHER = "rv";
  public static final String REQUEST_VOUCHER_HTTP = "requestvoucher";
  public static final String VOUCHER_STATUS = "vs";
  public static final String ENROLL_STATUS = "es";
  public static final String CSR_ATTRIBUTES = "att";
  public static final String CA_CERTIFICATES = "crts";
  public static final String SIMPLE_ENROLL = "sen";
  public static final String SIMPLE_REENROLL = "sren";

  // --- Other resources and paths
  public static final String HELLO = "hello";
  public static final String COMM_PET_REQ_PATH = "/c/cp";

  // --- HTTP Media Types
  public static final String HTTP_APPLICATION_VOUCHER_CMS_JSON = "application/voucher-cms+json";
  public static final String HTTP_APPLICATION_VOUCHER_CMS_CBOR = "application/voucher-cms+cbor";
  public static final String HTTP_APPLICATION_COSE_SIGN1 =
      "application/cose; cose-type=\"cose-sign1\"";
  public static final String HTTP_APPLICATION_COSE = "application/cose";
  public static final String HTTP_APPLICATION_VOUCHER_COSE_CBOR = "application/voucher-cose+cbor";
  public static final String HTTP_APPLICATION_VOUCHER_COSE_JSON = "application/voucher-cose+json";

  // --- COSE items
  // see https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
  public static final CBORObject COSE_X5BAG_HEADER_KEY = CBORObject.FromObject(32);

  // --- COM_TOK items
  // This is not defined in Thread specs and we currently use "/.well-known/ccm".
  // FIXME should use Thread Group's namespace for this: "/.well-known/thread/ccm".
  public static final String COM_TOK = "ccm";
  public static final String CCM_PATH = "/" + String.join("/", WELL_KNOWN, COM_TOK);
  // Commissioner token validity in days
  public static final int COM_TOK_VALIDITY = 365;

  // --- OID items
  public static final String MASA_URI_OID = "1.3.6.1.5.5.7.1.32"; // RFC 8995
  public static final String HARDWARE_MODULE_NAME_OID = "1.3.6.1.5.5.7.8.4";
  public static final String PRIVATE_HARDWARE_TYPE_OID = "1.3.6.1.4.1.21335";
  public static final String THREAD_DOMAIN_NAME_OID = "1.3.6.1.4.1.44970.1"; // per Thread 1.2 spec
  public static final String CMC_RA_PKIX_KEY_PURPOSE_OID = "1.3.6.1.5.5.7.3.28"; // RFC 6402 2.10
  public static final String EXTENDED_KEY_USAGE_OID = "2.5.29.37";
  public static final KeyPurposeId id_kp_cmcRA =
      KeyPurposeId.getInstance(new ASN1ObjectIdentifier(CMC_RA_PKIX_KEY_PURPOSE_OID));
  public static final ASN1ObjectIdentifier eku = new ASN1ObjectIdentifier(EXTENDED_KEY_USAGE_OID);
  public static final Integer ASN1_TAG_GENERALNAME_OTHERNAME =
      Integer.valueOf(0); // RFC 5280 Section 4.2.1.6

  // --- URIs, ports and hostnames
  public static final int DEFAULT_REGISTRAR_COAPS_PORT = 5684;
  public static final int DEFAULT_MASA_HTTPS_PORT = 9443;
  public static final String DEFAULT_MASA_URI_HOST = "localhost";

  // In case the MASA URI is not specified, this default value will be used.
  public static final String DEFAULT_MASA_URI =
      DEFAULT_MASA_URI_HOST + ":" + DEFAULT_MASA_HTTPS_PORT;

  // -- Other items
  // Default Thread Domain Name per Thread 1.2 spec. Must not be changed, unless spec changes.
  public static final String THREAD_DOMAIN_NAME_DEFAULT = "DefaultDomain";
  public static final String KEY_STORE_FORMAT = "PKCS12";
  public static final long CERT_VALIDITY = 5 * 365; // LDevID validity in Days.
}
