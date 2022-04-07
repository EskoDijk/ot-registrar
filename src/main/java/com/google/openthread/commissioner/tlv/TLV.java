package com.google.openthread.commissioner.tlv;

import org.bouncycastle.util.encoders.Hex;

/** Single TLV element base class */
public abstract class TLV {

  // "C" TLV namespace
  public static final int C_COMMISSIONER_ID = 10;
  public static final int C_COMMISSIONER_SESSION_ID = 11;
  public static final int C_JOINER_DTLS_ENCAPSULATION = 17;
  public static final int C_JOINER_UDP_PORT = 18;
  public static final int C_JOINER_IID = 19;
  public static final int C_JOINER_ROUTER_LOCATOR = 20;
  public static final int C_UDP_ENCAPSULATION = 48;
  public static final int C_IPV6_ADDRESS = 49;
  public static final int C_COMMISSIONER_TOKEN = 63;
  public static final int C_COMMISSIONER_SIGNATURE = 64;

  // "A" TLV namespace
  public static final int A_TIMEOUT = 11;
  public static final int A_IPV6_ADDRESSES = 14;
  public static final int A_COMMISSIONER_TOKEN = C_COMMISSIONER_TOKEN;
  public static final int A_COMMISSIONER_SIGNATURE = C_COMMISSIONER_SIGNATURE;

  public int T;

  public TLV(int type) {
    this.T = type;
  }

  public int L() {
    return V().length;
  }

  public abstract byte[] V();

  /** whether this TLV is valid currently, or not */
  public boolean isValid = true;

  /**
   * Returns the value as a hexadecimal string.
   *
   * @return the hexadecimal code string
   */
  public String toHexString() {
    return Hex.toHexString(V());
  }

  /**
   * util method to fit int number n into the byte array of given length
   *
   * @param n
   * @param b
   */
  protected void toB(int n, byte[] b) {
    for (int i = b.length - 1; i >= 0; i--) {
      b[i] = (byte) (n & 255);
      n >>>= 8;
    }
  }

  /**
   * util method to fit int number n into the byte array of given length sz
   *
   * @param n
   * @param sz size to fit it in (bytes)
   */
  protected byte[] toB(int n, int sz) {
    byte[] b = new byte[sz];
    for (int i = b.length - 1; i >= 0; i--) {
      b[i] = (byte) (n & 255);
      n >>>= 8;
    }
    return b;
  }

  /**
   * util method to convert byte array of given length into int
   *
   * @param b
   * @param mustBeLen the length that b MUST be, else error.
   * @return parsed b into an uint, or -1 in case of error or len(b) != mustBeLen.
   */
  protected int toI(byte[] b, int mustBeLen) {
    if (b.length != mustBeLen) {
      isValid = false;
      return -1;
    }
    int n = 0;
    for (int i = 0; i < b.length; i++) {
      n <<= 8;
      n += ((int) (b[i] & 0xFF));
    }
    return n;
  }
}
