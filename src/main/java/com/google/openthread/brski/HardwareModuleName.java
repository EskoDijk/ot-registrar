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

import java.util.Objects;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.encoders.Hex;

/**
 * The {@code id-on-hardwareModuleName} OtherName form from RFC 4108 §5:
 * <pre>
 *   HardwareModuleName ::= SEQUENCE {
 *       hwType       OBJECT IDENTIFIER,
 *       hwSerialNum  OCTET STRING
 *   }
 * </pre>
 */
public final class HardwareModuleName extends ASN1Object {

  private final ASN1ObjectIdentifier type;
  private final ASN1OctetString serialNumber;

  public HardwareModuleName(ASN1ObjectIdentifier type, ASN1OctetString serialNumber) {
    this.type = Objects.requireNonNull(type, "type");
    this.serialNumber = Objects.requireNonNull(serialNumber, "serialNumber");
  }

  public HardwareModuleName(String typeOid, byte[] rawSerialNumber) {
    this(new ASN1ObjectIdentifier(Objects.requireNonNull(typeOid, "typeOid")),
        new DEROctetString(Objects.requireNonNull(rawSerialNumber, "rawSerialNumber")));
  }

  private HardwareModuleName(ASN1Sequence seq) {
    if (seq.size() != 2) {
      throw new IllegalArgumentException("wrong number of elements in sequence");
    }
    this.type = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
    this.serialNumber = ASN1OctetString.getInstance(seq.getObjectAt(1));
  }

  public static HardwareModuleName getInstance(Object obj) {
    if (obj == null) {
      return null;
    }
    if (obj instanceof HardwareModuleName) {
      return (HardwareModuleName) obj;
    }
    return new HardwareModuleName(ASN1Sequence.getInstance(obj));
  }

  public ASN1ObjectIdentifier getType() {
    return type;
  }

  public ASN1OctetString getSerialNumber() {
    return serialNumber;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector moduleName = new ASN1EncodableVector();
    moduleName.add(type);
    moduleName.add(serialNumber);
    return new DERSequence(moduleName);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof HardwareModuleName)) {
      return false;
    }
    HardwareModuleName hwModuleName = (HardwareModuleName) obj;
    return type.equals(hwModuleName.type) && serialNumber.equals(hwModuleName.serialNumber);
  }

  @Override
  public int hashCode() {
    return Objects.hash(type, serialNumber);
  }

  @Override
  public String toString() {
    return String.format(
        "%s: {type: %s, serialNumber: %s}",
        getClass().getSimpleName(), type.getId(), Hex.toHexString(serialNumber.getOctets()));
  }
}
