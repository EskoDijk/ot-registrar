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

/**
 * Strategy for converting a {@link Voucher} (or {@link VoucherRequest}) to and from a wire
 * representation. Implementations include {@link CBORSerializer} (constrained / Thread) and
 * {@link JSONSerializer} (classic BRSKI per RFC 8995).
 */
public interface VoucherSerializer {

  /**
   * Encode the given voucher to its wire representation.
   *
   * @param voucher the voucher to encode; must not be {@code null}.
   * @return the encoded bytes; never {@code null}.
   * @throws VoucherSerializationException if the voucher cannot be encoded (e.g. a required field
   *     is missing or contains a value the wire format cannot represent).
   */
  byte[] serialize(Voucher voucher) throws VoucherSerializationException;

  /**
   * Decode a voucher from its wire representation.
   *
   * @param data the encoded bytes; must not be {@code null}.
   * @return the decoded voucher; never {@code null}.
   * @throws VoucherSerializationException if the input is malformed or fails any format-specific
   *     consistency check.
   */
  Voucher deserialize(byte[] data) throws VoucherSerializationException;
}
