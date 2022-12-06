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

import com.strategicgains.util.date.DateAdapter;
import com.strategicgains.util.date.TimestampAdapter;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class Voucher {

  public static final int VOUCHER_SID = 2451;

  @SuppressWarnings("serial")
  protected static final Map<String, Integer> voucherSIDMap =
      new HashMap<String, Integer>() {
        {
          put(VOUCHER_CONSTRAINED, VOUCHER_SID);
          put(ASSERTION, VOUCHER_SID + 1);
          put(CREATED_ON, VOUCHER_SID + 2);
          put(DOMAIN_CERT_REVOCATION_CHECKS, VOUCHER_SID + 3);
          put(EXPIRES_ON, VOUCHER_SID + 4);
          put(IDEVID_ISSUER, VOUCHER_SID + 5);
          put(LAST_RENEWAL_DATE, VOUCHER_SID + 6);
          put(NONCE, VOUCHER_SID + 7);
          put(PINNED_DOMAIN_CERT, VOUCHER_SID + 8);
          put(PINNED_DOMAIN_SPKI, VOUCHER_SID + 9);
          put(PINNED_SHA256_DOMAIN_SPKI, VOUCHER_SID + 10);
          put(SERIAL_NUMBER, VOUCHER_SID + 11);
        }
      };

  /** single Voucher object representing an 'undefined' Voucher */
  public static final Voucher UNDEFINED = new Voucher();

  public static final class Assertion {

    public static Assertion VERIFIED = new Assertion(0);
    public static Assertion LOGGED = new Assertion(1);
    public static Assertion PROXIMITY = new Assertion(2);

    private final int value;

    private Assertion(final int val) {
      value = val;
    }

    public static Assertion newAssertion(int val) {
      switch (val) {
        case 0:
          return VERIFIED;
        case 1:
          return LOGGED;
        case 2:
          return PROXIMITY;
        default:
          throw new IllegalArgumentException("unexpect assertion value: " + val);
      }
    }

    public static Assertion newAssertion(String val) {
      switch (val) {
        case "verified":
          return VERIFIED;
        case "logged":
          return LOGGED;
        case "proximity":
          return PROXIMITY;
        default:
          throw new IllegalArgumentException("unexpect assertion value: " + val);
      }
    }

    public boolean equals(Assertion other) {
      return value == other.value;
    }

    public int getValue() {
      return value;
    }

    public String toString() {
      switch (value) {
        case 0:
          return "verified";
        case 1:
          return "logged";
        case 2:
          return "proximity";
        default:
          return null;
      }
    }
  }

  public Assertion assertion;

  public Date createdOn;

  public Boolean domainCertRevocationChecks;

  public Date expiresOn;

  public byte[] idevidIssuer;

  public Date lastRenewalDate;

  public byte[] nonce;

  /*
   * An X.509 v3 certificate structure, as specified by RFC 5280,
   * using Distinguished Encoding Rules (DER) encoding, as defined
   * in ITU-T X.690.
   * This certificate is used by a pledge to trust a Public Key
   * Infrastructure in order to verify a domain certificate
   * supplied to the pledge separately by the bootstrapping
   * protocol. The domain certificate MUST have this certificate
   * somewhere in its chain of certificates. This certificate
   * MAY be an end-entity certificate, including a self-signed
   * entity.
   */
  public byte[] pinnedDomainCert;

  /*
   * The pinned-domain-subject replaces the
   * pinned-domain-certificate in constrained uses of
   * the voucher. The pinned-domain-subject-public-key-info
   * is the Raw Public Key of the Registrar.
   * This field is encoded as specified in RFC7250, section 3.
   * The ECDSA algorithm MUST be supported.
   * The EdDSA algorithm as specified in
   * draft-ietf-tls-rfc4492bis-17 SHOULD be supported.
   * Support for the DSA algorithm is not recommended.
   * Support for the RSA algorithm is a MAY.
   */
  public byte[] pinnedDomainSPKI;

  /*
   * If it is necessary to change a voucher, or re-sign and
   * forward a voucher that was previously provided along a
   * protocol path, then the previously signed voucher SHOULD be
   * included in this field.
   * For example, a pledge might sign a proximity voucher, which
   * an intermediate registrar then re-signs to make its own
   * proximity assertion. This is a simple mechanism for a
   * chain of trusted parties to change a voucher, while
   * maintaining the prior signature information.
   * The pledge MUST ignore all prior voucher information when
   * accepting a voucher for imprinting. Other parties MAY
   * examine the prior signed voucher information for the
   * purposes of policy decisions. For example this information
   * could be useful to a MASA to determine that both pledge and
   * registrar agree on proximity assertions. The MASA SHOULD
   * remove all prior-signed-voucher-request information when
   * signing a voucher for imprinting so as to minimize the
   * final voucher size.
   */
  public byte[] priorSignedVoucherRequest;

  /*
   * An X.509 v3 certificate structure as specified by RFC 5280,
   * Section 4 encoded using the ASN.1 distinguished encoding
   * rules (DER), as specified in ITU-T X.690.
   * The first certificate in the Registrar TLS server
   * certificate_list sequence (see [RFC5246]) presented by
   * the Registrar to the Pledge. This MUST be populated in a
   * Pledge’s voucher request if the proximity assertion is
   * populated.
   */
  public byte[] proximityRegistrarCert;

  /*
   * The proximity-registrar-subject-public-key-info replaces
   * the proximity-registrar-cert in constrained uses of
   * the voucher-request.
   * The proximity-registrar-subject-public-key-info is the
   * Raw Public Key of the Registrar. This field is encoded
   * as specified in RFC7250, section 3.
   * The ECDSA algorithm MUST be supported.
   * The EdDSA algorithm as specified in
   * draft-ietf-tls-rfc4492bis-17 SHOULD be supported.
   * Support for the DSA algorithm is not recommended.
   * Support for the RSA algorithm is a MAY.
   */
  public byte[] proximityRegistrarSPKI;

  public String serialNumber;

  public static final String VOUCHER = "ietf-voucher:voucher";

  public static final String VOUCHER_CONSTRAINED = "ietf-voucher-constrained:voucher";
  
  public static final String VOUCHER_REQUEST = "ietf-voucher-request:voucher";

  public static final String VOUCHER_REQUEST_CONSTRAINED = "ietf-voucher-request-constrained:voucher";

  public static final String ASSERTION = "assertion";

  public static final String CREATED_ON = "created-on";

  public static final String DOMAIN_CERT_REVOCATION_CHECKS = "domain-cert-revocation-checks";

  public static final String EXPIRES_ON = "expires-on";

  public static final String IDEVID_ISSUER = "idevid-issuer";

  public static final String LAST_RENEWAL_DATE = "last-renewal-date";

  public static final String NONCE = "nonce";

  public static final String PINNED_DOMAIN_CERT = "pinned-domain-cert";

  public static final String PINNED_SHA256_DOMAIN_SPKI = "pinned-domain-pubk-sha256";

  public static final String PINNED_DOMAIN_SPKI = "pinned-domain-pubk";

  public static final String PRIOR_SIGNED_VOUCHER_REQUEST = "prior-signed-voucher-request";

  public static final String PROXIMITY_REGISTRAR_CERT = "proximity-registrar-cert";

  public static final String SHA256_REGISTRAR_SPKI = "proximity-registrar-pubk-sha256";

  public static final String PROXIMITY_REGISTRAR_SPKI = "proximity-registrar-pubk";

  public static final String SERIAL_NUMBER = "serial-number";

  protected Map<String, Integer> sidMap;

  protected int baseSid;

  protected boolean isConstr = false;

  public Voucher() {
    baseSid = VOUCHER_SID;
    sidMap = voucherSIDMap;
  }

  /**
   * Validates this Voucher, if the right fields are present/absent.
   *
   * @return true if successfully validated.
   */
  public boolean validate() {
    if (assertion == null
        || createdOn == null
        || serialNumber == null
        || (pinnedDomainSPKI == null && pinnedDomainCert == null)) {
      return false;
    }
    if (expiresOn != null && nonce != null) {
      return false;
    }
    if (lastRenewalDate != null && expiresOn == null) {
      return false;
    }
    if (proximityRegistrarCert != null || proximityRegistrarSPKI != null) return false;

    return true;
  }

  /**
   * Get the key-object from the specific named field, that is valid for the current voucher
   * (request) type. Subclasses of Voucher may implement other compression on key names.
   *
   * @param item
   * @return corresponding key-object for 'item' ; or null if 'item' is not valid/existing in
   *     context of current voucher type.
   */
  public Object getKey(String item) {
    if (!isConstrained()) return item;
    Integer sid = sidMap.get(item);
    // if no SID found return the item key in full.
    if (sid == null) return item;
    return sid;
  }

  /** The Internet Date/Time Format (ref: ISO8601, section 5.6 RFC 3339) */
  public static String dateToYoungFormat(Date date) {
    DateAdapter adapter = new TimestampAdapter();
    return adapter.format(date);
  }

  public static Date dateFromYoungFormat(String young) throws ParseException {
    DateAdapter adapter = new TimestampAdapter();
    return adapter.parse(young);
  }

  public boolean isConstrained() {
    return isConstr;
  }

  public void setConstrained(boolean isConstrained) {
    isConstr = isConstrained;
  }

  public String getName() {
    if (isConstrained())
      return VOUCHER_CONSTRAINED;
    else
      return VOUCHER;
  }
  
  public String toString() {
    JSONSerializer jsonSerializer = new JSONSerializer();
    return jsonSerializer.toJSON(this);
  }
}
