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
import java.util.Map;

public class Voucher {

  // --- Field name constants used by both the JSON and CBOR serializers.
  public static final String VOUCHER = "ietf-voucher:voucher";
  public static final String VOUCHER_CONSTRAINED = "ietf-voucher-constrained:voucher";
  public static final String VOUCHER_REQUEST = "ietf-voucher-request:voucher";
  public static final String VOUCHER_REQUEST_CONSTRAINED =
      "ietf-voucher-request-constrained:voucher";
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

  public static final int VOUCHER_SID = 2451;

  protected static final Map<String, Integer> voucherSIDMap = Map.ofEntries(
      Map.entry(VOUCHER_CONSTRAINED, VOUCHER_SID),
      Map.entry(ASSERTION, VOUCHER_SID + 1),
      Map.entry(CREATED_ON, VOUCHER_SID + 2),
      Map.entry(DOMAIN_CERT_REVOCATION_CHECKS, VOUCHER_SID + 3),
      Map.entry(EXPIRES_ON, VOUCHER_SID + 4),
      Map.entry(IDEVID_ISSUER, VOUCHER_SID + 5),
      Map.entry(LAST_RENEWAL_DATE, VOUCHER_SID + 6),
      Map.entry(NONCE, VOUCHER_SID + 7),
      Map.entry(PINNED_DOMAIN_CERT, VOUCHER_SID + 8),
      Map.entry(PINNED_DOMAIN_SPKI, VOUCHER_SID + 9),
      Map.entry(PINNED_SHA256_DOMAIN_SPKI, VOUCHER_SID + 10),
      Map.entry(SERIAL_NUMBER, VOUCHER_SID + 11));

  /** single Voucher object representing an 'undefined' Voucher */
  public static final Voucher UNDEFINED = new Voucher();

  public enum Assertion {
    VERIFIED(0, "verified"),
    LOGGED(1, "logged"),
    PROXIMITY(2, "proximity");

    private final int value;
    private final String name;

    Assertion(int value, String name) {
      this.value = value;
      this.name = name;
    }

    public int getValue() {
      return value;
    }

    @Override
    public String toString() {
      return name;
    }

    public static Assertion newAssertion(int val) {
      for (Assertion a : values()) {
        if (a.value == val) return a;
      }
      throw new IllegalArgumentException("unexpected assertion value: " + val);
    }

    public static Assertion newAssertion(String val) {
      for (Assertion a : values()) {
        if (a.name.equals(val)) return a;
      }
      throw new IllegalArgumentException("unexpected assertion value: " + val);
    }
  }

  private Assertion assertion;
  private Date createdOn;
  private Boolean domainCertRevocationChecks;
  private Date expiresOn;
  private byte[] idevidIssuer;
  private Date lastRenewalDate;
  private byte[] nonce;

  /*
   * pinnedDomainCert: an X.509 v3 certificate (RFC 5280, DER per ITU-T X.690)
   * used by a pledge to trust a PKI in order to verify a domain certificate
   * supplied separately by the bootstrapping protocol. May be an end-entity
   * certificate, including self-signed.
   */
  private byte[] pinnedDomainCert;

  /*
   * pinnedDomainSPKI: replaces pinnedDomainCert in constrained uses. The Raw
   * Public Key of the Registrar, encoded per RFC 7250 §3. ECDSA MUST be
   * supported; EdDSA SHOULD; DSA not recommended; RSA MAY.
   */
  private byte[] pinnedDomainSPKI;

  /*
   * priorSignedVoucherRequest: if a voucher needs to be re-signed and
   * forwarded along a protocol path, the previously signed voucher SHOULD be
   * included here. Pledges MUST ignore prior voucher info when imprinting;
   * other parties MAY examine it for policy decisions. The MASA SHOULD remove
   * prior-signed-voucher-request data when signing a voucher for imprinting.
   */
  private byte[] priorSignedVoucherRequest;

  /*
   * proximityRegistrarCert: the first certificate in the Registrar TLS
   * server certificate_list (RFC 5246) presented to the Pledge. MUST be
   * populated in a Pledge voucher request if the proximity assertion is
   * populated.
   */
  private byte[] proximityRegistrarCert;

  /*
   * proximityRegistrarSPKI: replaces proximityRegistrarCert in constrained
   * uses. Raw Public Key of the Registrar (RFC 7250 §3). Same algorithm
   * support requirements as pinnedDomainSPKI.
   */
  private byte[] proximityRegistrarSPKI;

  private String serialNumber;

  protected Map<String, Integer> sidMap;

  protected boolean isConstr = false;

  public Voucher() {
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
    if (isConstrained()) return VOUCHER_CONSTRAINED;
    else return VOUCHER;
  }

  @Override
  public String toString() {
    if (this == UNDEFINED) {
      return "UNDEFINED";
    }
    return new JSONSerializer().toJSON(this);
  }

  // --- field accessors ------------------------------------------------
  // Setters block writes to the UNDEFINED sentinel, which would otherwise
  // mutate a JVM-wide shared instance.

  private void checkMutable() {
    if (this == UNDEFINED) {
      throw new UnsupportedOperationException("UNDEFINED Voucher is immutable");
    }
  }

  public Assertion getAssertion() { return assertion; }
  public void setAssertion(Assertion v) { checkMutable(); this.assertion = v; }

  public Date getCreatedOn() { return createdOn; }
  public void setCreatedOn(Date v) { checkMutable(); this.createdOn = v; }

  public Boolean getDomainCertRevocationChecks() { return domainCertRevocationChecks; }
  public void setDomainCertRevocationChecks(Boolean v) { checkMutable(); this.domainCertRevocationChecks = v; }

  public Date getExpiresOn() { return expiresOn; }
  public void setExpiresOn(Date v) { checkMutable(); this.expiresOn = v; }

  public byte[] getIdevidIssuer() { return idevidIssuer; }
  public void setIdevidIssuer(byte[] v) { checkMutable(); this.idevidIssuer = v; }

  public Date getLastRenewalDate() { return lastRenewalDate; }
  public void setLastRenewalDate(Date v) { checkMutable(); this.lastRenewalDate = v; }

  public byte[] getNonce() { return nonce; }
  public void setNonce(byte[] v) { checkMutable(); this.nonce = v; }

  public byte[] getPinnedDomainCert() { return pinnedDomainCert; }
  public void setPinnedDomainCert(byte[] v) { checkMutable(); this.pinnedDomainCert = v; }

  public byte[] getPinnedDomainSPKI() { return pinnedDomainSPKI; }
  public void setPinnedDomainSPKI(byte[] v) { checkMutable(); this.pinnedDomainSPKI = v; }

  public byte[] getPriorSignedVoucherRequest() { return priorSignedVoucherRequest; }
  public void setPriorSignedVoucherRequest(byte[] v) { checkMutable(); this.priorSignedVoucherRequest = v; }

  public byte[] getProximityRegistrarCert() { return proximityRegistrarCert; }
  public void setProximityRegistrarCert(byte[] v) { checkMutable(); this.proximityRegistrarCert = v; }

  public byte[] getProximityRegistrarSPKI() { return proximityRegistrarSPKI; }
  public void setProximityRegistrarSPKI(byte[] v) { checkMutable(); this.proximityRegistrarSPKI = v; }

  public String getSerialNumber() { return serialNumber; }
  public void setSerialNumber(String v) { checkMutable(); this.serialNumber = v; }
}
