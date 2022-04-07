package com.google.openthread.commissioner.tlv;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashMap;
import org.bouncycastle.util.encoders.Hex;

/** Class to parse a byte[] into a generic set of TLVs and store them as HashMap<Type,Value> */
public class TLVset extends HashMap<Integer, byte[]> {

  private static final long serialVersionUID = 3955356716921778844L;

  /** whether this TLVset is valid; becomes false after failed parsing */
  public boolean isValid = true;

  /** error message in case isValid==false */
  public String err = null;

  private static final Charset UTF8_CHARSET = Charset.forName("UTF-8");

  /** create a new, empty TLVset with no TLVs in */
  public TLVset() {
    //
  }

  /** copy constructor */
  public TLVset(TLVset t) {
    super(t);
  }

  /** put convenience-wrapper with String value */
  public byte[] put(Integer key, String valueStr) {
    return this.put(key, valueStr.getBytes(UTF8_CHARSET));
  }

  /** put convenience-wrapper with uint32 value */
  public byte[] put(Integer key, int value) {
    byte[] b = ByteBuffer.allocate(4).putInt(value).array();
    return this.put(key, b);
  }

  /** put convenience-wrapper with zero or more IPv6 addresses */
  public byte[] put(Integer key, InetAddress[] addrs) {
    byte[] b = new byte[addrs.length * 16];
    for (int i = 0; i < addrs.length; i++) {
      System.arraycopy(addrs[i].getAddress(), 0, b, i * 16, 16);
    }
    return this.put(key, b);
  }

  public byte[] put(TLV tlv) {
    return this.put(tlv.T, tlv.V());
  }

  public String getAsString(Integer key) {
    return new String(this.get(key));
  }

  /**
   * serialize TLVset into byte array
   *
   * @return byte array serialized form
   */
  public byte[] serialize() {
    byte[] buf = new byte[8192 * 2]; // allocate some 'more than enough' space
    int i = 0; // pointer into buffer
    Integer[] keys = this.keySet().toArray(new Integer[0]);
    Arrays.sort(keys);
    for (Integer t : keys) {
      buf[i] = (byte) (t & 0xFF);
      i++;
      int L = this.get(t).length;
      if (L > 254) {
        buf[i] = (byte) 0xFF;
        buf[i + 1] = (byte) (L >> 8);
        buf[i + 2] = (byte) (L & 0xFF);
        i += 3;
      } else {
        buf[i] = (byte) L;
        i++;
      }
      System.arraycopy(this.get(t), 0, buf, i, L);
      i += L;
    }
    if (i == 0) return new byte[] {};
    byte[] s = new byte[i]; // create end result of length 'i'
    System.arraycopy(buf, 0, s, 0, i); // from buffer
    return s;
  }

  public String toString() {
    return this.toString("");
  }

  public String toString(String indentSpace) {
    StringBuilder sb = new StringBuilder();
    sb.append(indentSpace + "{\n");
    for (Integer key : this.keySet()) {
      sb.append(
          indentSpace
              + "  "
              + key
              + ": "
              + Hex.toHexString(this.get(key))
              + " ("
              + this.get(key).length
              + " bytes)\n");
    }
    sb.append(indentSpace + "}");
    return sb.toString();
  }

  /**
   * parse a byte array set of TLVs into a TLVset structure
   *
   * @param b byte array to parse
   * @return new TLVset with all the TLVs in it
   */
  public static TLVset parse(byte[] b) {
    TLVset tlvs = new TLVset();
    int i = 0;
    try {
      while (i < b.length) {
        byte[] v = null;
        int t = (0xFF & b[i]);
        int L = (0xFF & b[i + 1]);
        if (L == 255) {
          L = ((0xFF & b[i + 2]) << 8) + (0xFF & b[i + 3]);
          v = Arrays.copyOfRange(b, i + 4, i + 4 + L);
          i += (L + 4);
        } else {
          v = Arrays.copyOfRange(b, i + 2, i + 2 + L);
          i += (L + 2);
        }

        // store found tlv
        tlvs.put(t, v);
      }
    } catch (Exception e) {
      tlvs.isValid = false;
      tlvs.err = e.getMessage();
    }
    return tlvs;
  }
}
