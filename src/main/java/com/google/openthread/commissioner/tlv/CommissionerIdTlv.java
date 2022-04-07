package com.google.openthread.commissioner.tlv;

/** Commissioner ID TLV */
public class CommissionerIdTlv extends TLV {

  public String id;

  public CommissionerIdTlv(String commissionerId) {
    super(TLV.C_COMMISSIONER_SESSION_ID);
    this.id = commissionerId;
  }

  public byte[] V() {
    return id.getBytes();
  }
}
