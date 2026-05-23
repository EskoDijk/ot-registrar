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

import com.upokecenter.cbor.CBORObject;

/**
 * Utility class to serialize/deserialize Vouchers to or from CBOR, either as byte array or
 * CBORObject. Create a new instance for each serialization/deserialization job.
 */
public class CBORSerializer implements VoucherSerializer {

  protected CBORObject container;
  protected int parentSid = 0;
  Voucher voucher;

  @Override
  public byte[] serialize(Voucher v) throws VoucherSerializationException {
    try {
      return toCBOR(v).EncodeToBytes();
    } catch (RuntimeException e) {
      throw new VoucherSerializationException("CBOR voucher serialize failed: " + e.getMessage(), e);
    }
  }

  @Override
  public Voucher deserialize(byte[] data) throws VoucherSerializationException {
    try {
      return fromCBOR(CBORObject.DecodeFromBytes(data));
    } catch (RuntimeException e) {
      throw new VoucherSerializationException("CBOR voucher decode failed: " + e.getMessage(), e);
    }
  }

  public CBORObject toCBOR(Voucher voucher) {
    this.voucher = voucher;
    Object keyObj = voucher.getKey(voucher.getName());
    if (keyObj instanceof Integer) {
      parentSid = (Integer) keyObj;
    } else {
      parentSid = 0;
    }
    CBORObject cbor = CBORObject.NewMap();
    container = CBORObject.NewMap();

    if (voucher.getAssertion() != null) add(Voucher.ASSERTION, voucher.getAssertion().getValue());

    if (voucher.getCreatedOn() != null)
      add(Voucher.CREATED_ON, Voucher.dateToYoungFormat(voucher.getCreatedOn()));

    add(Voucher.DOMAIN_CERT_REVOCATION_CHECKS, voucher.getDomainCertRevocationChecks());

    if (voucher.getExpiresOn() != null)
      add(Voucher.EXPIRES_ON, Voucher.dateToYoungFormat(voucher.getExpiresOn()));

    add(Voucher.IDEVID_ISSUER, voucher.getIdevidIssuer());

    if (voucher.getLastRenewalDate() != null)
      add(Voucher.LAST_RENEWAL_DATE, Voucher.dateToYoungFormat(voucher.getLastRenewalDate()));

    add(Voucher.NONCE, voucher.getNonce());

    add(Voucher.PINNED_DOMAIN_CERT, voucher.getPinnedDomainCert());

    add(Voucher.PINNED_DOMAIN_SPKI, voucher.getPinnedDomainSPKI());

    add(Voucher.PRIOR_SIGNED_VOUCHER_REQUEST, voucher.getPriorSignedVoucherRequest());

    add(Voucher.PROXIMITY_REGISTRAR_CERT, voucher.getProximityRegistrarCert());

    add(Voucher.PROXIMITY_REGISTRAR_SPKI, voucher.getProximityRegistrarSPKI());

    add(Voucher.SERIAL_NUMBER, voucher.getSerialNumber());

    cbor.Add(keyObj, container);

    return cbor;
  }

  public Voucher fromCBOR(CBORObject cbor) throws VoucherSerializationException {
    try {
      for (CBORObject key : cbor.getKeys()) {
        CBORObject ku = key.Untag();
        if (ku.isNumber()) {
          if (ku.AsInt32() == Voucher.VOUCHER_SID) {
            voucher = new Voucher();
            voucher.setConstrained(true);
            parentSid = Voucher.VOUCHER_SID;
          } else if (ku.AsInt32() == VoucherRequest.VOUCHER_REQUEST_SID) {
            voucher = new VoucherRequest();
            voucher.setConstrained(true);
            parentSid = VoucherRequest.VOUCHER_REQUEST_SID;
          } else {
            String msg =
                String.format(
                    "wrong voucher sid: %d, expecting %d for voucher or %d for voucher request",
                    ku.AsInt32(), Voucher.VOUCHER_SID, VoucherRequest.VOUCHER_REQUEST_SID);
            throw new IllegalArgumentException(msg);
          }
        } else if (key.AsString().equals(Voucher.VOUCHER)) {
          voucher = new Voucher();
          voucher.setConstrained(false);
        } else if (key.AsString().equals(Voucher.VOUCHER_REQUEST)) {
          voucher = new VoucherRequest();
          voucher.setConstrained(false);
        } else {
          String msg =
              String.format(
                  "wrong voucher : %s, expecting %s for voucher or %s for voucher request",
                  key.AsString(), Voucher.VOUCHER, Voucher.VOUCHER_REQUEST);
          throw new IllegalArgumentException(msg);
        }

        container = cbor.get(key);
        CBORObject leaf;

        if ((leaf = get(Voucher.ASSERTION)) != null) {
          voucher.setAssertion(Voucher.Assertion.newAssertion(leaf.AsInt32()));
        }

        if ((leaf = get(Voucher.CREATED_ON)) != null) {
          voucher.setCreatedOn(Voucher.dateFromYoungFormat(leaf.AsString()));
        }

        if ((leaf = get(Voucher.DOMAIN_CERT_REVOCATION_CHECKS)) != null) {
          voucher.setDomainCertRevocationChecks(leaf.AsBoolean());
        }

        if ((leaf = get(Voucher.EXPIRES_ON)) != null) {
          voucher.setExpiresOn(Voucher.dateFromYoungFormat(leaf.AsString()));
        }

        if ((leaf = get(Voucher.IDEVID_ISSUER)) != null) {
          voucher.setIdevidIssuer(leaf.GetByteString());
        }

        if ((leaf = get(Voucher.LAST_RENEWAL_DATE)) != null) {
          voucher.setLastRenewalDate(Voucher.dateFromYoungFormat(leaf.AsString()));
        }

        if ((leaf = get(Voucher.NONCE)) != null) {
          voucher.setNonce(leaf.GetByteString());
        }

        if ((leaf = get(Voucher.PINNED_DOMAIN_CERT)) != null) {
          voucher.setPinnedDomainCert(leaf.GetByteString());
        }

        if ((leaf = get(Voucher.PINNED_DOMAIN_SPKI)) != null) {
          voucher.setPinnedDomainSPKI(leaf.GetByteString());
        }

        if ((leaf = get(Voucher.PRIOR_SIGNED_VOUCHER_REQUEST)) != null) {
          voucher.setPriorSignedVoucherRequest(leaf.GetByteString());
        }

        if ((leaf = get(Voucher.PROXIMITY_REGISTRAR_CERT)) != null) {
          voucher.setProximityRegistrarCert(leaf.GetByteString());
        }

        if ((leaf = get(Voucher.PROXIMITY_REGISTRAR_SPKI)) != null) {
          voucher.setProximityRegistrarSPKI(leaf.GetByteString());
        }

        if ((leaf = get(Voucher.SERIAL_NUMBER)) != null) {
          voucher.setSerialNumber(leaf.AsString());
        }

        // We process only one voucher
        break;
      }
    } catch (Exception e) {
      throw new VoucherSerializationException("bad voucher: " + e.getMessage(), e);
    }

    return voucher;
  }

  protected void add(String keyName, Object val) {
    Object key = voucher.getKey(keyName);
    if (val != null) {
      if (parentSid > 0 && key instanceof Integer) { // if SID number key
        key = ((Integer) key - parentSid);
      }
      container.Add(key, val);
    }
  }

  protected CBORObject get(String keyName) {
    Object key = voucher.getKey(keyName);
    if (key instanceof Integer) {
      // it's a SID
      int keyInt = (Integer) key;
      // delta compression MAY be used now. Tag 47 indicates 'not delta' and absence
      // of Tag 47
      // indicates 'delta' value
      // https://datatracker.ietf.org/doc/html/draft-ietf-core-yang-cbor-15#section-3.2
      int deltaKey = keyInt - parentSid;
      // look for either the uncompressed full number Tagged 47, or the delta number.
      for (CBORObject k : container.getKeys()) {
        CBORObject ku = k.Untag();
        if (ku.isNumber() // Untag needed due to particularity in isNumber()
            && ((ku.AsInt32() == keyInt && k.HasTag(47))
                || (ku.AsInt32() == deltaKey && !k.HasTag(47)))) {
          return container.get(k);
        }
      }
    }

    // if SID numbers not found for this item, try if full name is there. SIDs
    // allowed to be mixed with full names.
    CBORObject keyNameObj = CBORObject.FromObject(keyName);
    if (container.ContainsKey(keyNameObj)) {
      return container.get(keyNameObj);
    }

    return null;
  }
}
