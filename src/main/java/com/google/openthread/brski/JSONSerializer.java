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

import com.google.gson.Gson;
import java.util.HashMap;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * * Utility class defineing the structure of the Voucher / Voucher-request. This is needed for Gson
 * JSON serialization.
 */
@SuppressWarnings("serial")
class GsonVoucher extends HashMap<String, HashMap<String, Object>> {
  //
}

public class JSONSerializer implements VoucherSerializer {

  protected Gson gson = new Gson();
  private static Logger logger = LoggerFactory.getLogger(JSONSerializer.class);

  @Override
  public byte[] serialize(Voucher voucher) {
    return toJSON(voucher).toString().getBytes();
  }

  @Override
  public Voucher deserialize(byte[] data) {
    String s = new String(data);
    return fromJSON(s);
  }

  public String toJSON(Voucher voucher) {

    GsonVoucher jsonRoot = new GsonVoucher();
    HashMap<String, Object> container = new HashMap<String, Object>();

    add(container, voucher.getKey(Voucher.ASSERTION), voucher.assertion.toString());

    if (voucher.createdOn != null) {
      add(
          container,
          voucher.getKey(Voucher.CREATED_ON),
          Voucher.dateToYoungFormat(voucher.createdOn));
    }

    add(
        container,
        voucher.getKey(Voucher.DOMAIN_CERT_REVOCATION_CHECKS),
        voucher.domainCertRevocationChecks);

    if (voucher.expiresOn != null) {
      add(
          container,
          voucher.getKey(Voucher.EXPIRES_ON),
          Voucher.dateToYoungFormat(voucher.expiresOn));
    }

    add(container, voucher.getKey(Voucher.IDEVID_ISSUER), voucher.idevidIssuer);

    if (voucher.lastRenewalDate != null) {
      add(
          container,
          voucher.getKey(Voucher.LAST_RENEWAL_DATE),
          Voucher.dateToYoungFormat(voucher.lastRenewalDate));
    }

    add(container, voucher.getKey(Voucher.NONCE), voucher.nonce);

    add(container, voucher.getKey(Voucher.PINNED_DOMAIN_CERT), voucher.pinnedDomainCert);

    add(container, voucher.getKey(Voucher.PINNED_DOMAIN_SPKI), voucher.pinnedDomainSPKI);

    add(
        container,
        voucher.getKey(Voucher.PRIOR_SIGNED_VOUCHER_REQUEST),
        voucher.priorSignedVoucherRequest);

    add(
        container,
        voucher.getKey(Voucher.PROXIMITY_REGISTRAR_CERT),
        voucher.proximityRegistrarCert);

    add(
        container,
        voucher.getKey(Voucher.PROXIMITY_REGISTRAR_SPKI),
        voucher.proximityRegistrarSPKI);

    add(container, voucher.getKey(Voucher.SERIAL_NUMBER), voucher.serialNumber);

    jsonRoot.put(voucher.getKey(voucher.getName()).toString(), container);

    return gson.toJson(jsonRoot);
  }

  public Voucher fromJSON(String json) {
    Voucher voucher = null;
    GsonVoucher gv = gson.fromJson(json, GsonVoucher.class);
    try {
      for (String key : gv.keySet()) {
        if (key.equals(Voucher.VOUCHER)) {
          voucher = new Voucher();
        } else if (key.equals(Voucher.VOUCHER_REQUEST)) {
          voucher = new VoucherRequest();
        } else {
          String msg =
              String.format(
                  "wrong voucher : %s, expecting %s for voucher or %s for voucher request",
                  key, Voucher.VOUCHER, Voucher.VOUCHER_REQUEST);
          throw new IllegalArgumentException(msg);
        }

        HashMap<String, Object> container = gv.get(key);
        Object leaf;

        if ((leaf = get(container, voucher.getKey(Voucher.ASSERTION))) != null) {
          voucher.assertion = Voucher.Assertion.newAssertion(leaf.toString());
        }

        if ((leaf = get(container, voucher.getKey(Voucher.CREATED_ON))) != null) {
          voucher.createdOn = Voucher.dateFromYoungFormat(leaf.toString());
        }

        if ((leaf = get(container, voucher.getKey(Voucher.DOMAIN_CERT_REVOCATION_CHECKS)))
            != null) {
          voucher.domainCertRevocationChecks = leaf.equals(Boolean.TRUE);
        }

        if ((leaf = get(container, voucher.getKey(Voucher.EXPIRES_ON))) != null) {
          voucher.expiresOn = Voucher.dateFromYoungFormat(leaf.toString());
        }

        if ((leaf = getBytes(container, voucher.getKey(Voucher.IDEVID_ISSUER))) != null) {
          voucher.idevidIssuer = (byte[]) leaf;
        }

        if ((leaf = get(container, voucher.getKey(Voucher.LAST_RENEWAL_DATE))) != null) {
          voucher.lastRenewalDate = Voucher.dateFromYoungFormat(leaf.toString());
        }

        if ((leaf = getBytes(container, voucher.getKey(Voucher.NONCE))) != null) {
          voucher.nonce = (byte[]) leaf;
        }

        if ((leaf = getBytes(container, voucher.getKey(Voucher.PINNED_DOMAIN_CERT))) != null) {
          voucher.pinnedDomainCert = (byte[]) leaf;
        }

        if ((leaf = getBytes(container, voucher.getKey(Voucher.PINNED_DOMAIN_SPKI))) != null) {
          voucher.pinnedDomainSPKI = (byte[]) leaf;
        }

        if ((leaf = getBytes(container, voucher.getKey(Voucher.PRIOR_SIGNED_VOUCHER_REQUEST)))
            != null) {
          voucher.priorSignedVoucherRequest = (byte[]) leaf;
        }

        if ((leaf = getBytes(container, voucher.getKey(Voucher.PROXIMITY_REGISTRAR_CERT)))
            != null) {
          voucher.proximityRegistrarCert = (byte[]) leaf;
        }

        if ((leaf = getBytes(container, voucher.getKey(Voucher.PROXIMITY_REGISTRAR_SPKI)))
            != null) {
          voucher.proximityRegistrarSPKI = (byte[]) leaf;
        }

        if ((leaf = get(container, voucher.getKey(Voucher.SERIAL_NUMBER))) != null) {
          voucher.serialNumber = leaf.toString();
        }

        // We process only one voucher
        break;
      }
    } catch (Exception e) {
      logger.error("bad voucher: " + e.getMessage());
      e.printStackTrace();
      return null;
    }

    return voucher;
  }

  protected void add(HashMap<String, Object> c, Object key, Object val) {
    if (val != null) {
      if (val instanceof byte[]) {
        // apply Base64 encoding
        val = Base64.toBase64String((byte[]) val);
      }
      c.put(key.toString(), val.toString());
    }
  }

  protected Object get(HashMap<String, Object> c, Object key) {
    return c.get(key);
  }

  /**
   * Get a Base64 encoded value from the HashMap, decoded into byte[].
   *
   * @param c
   * @param key
   * @return
   */
  protected byte[] getBytes(HashMap<String, Object> c, Object key) {
    Object val = c.get(key);
    if (val == null) return null;
    return Base64.decode(val.toString());
  }
}
