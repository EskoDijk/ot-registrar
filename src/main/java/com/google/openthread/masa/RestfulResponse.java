package com.google.openthread.masa;

import com.google.openthread.brski.*;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;

/**
 * A MASA's generic RESTful response to a Voucher Request; including status code and either a
 * diagnostic message (in case of error) or a Voucher object.
 */
public class RestfulResponse {

  public ResponseCode code;
  public String msg;
  public Voucher voucher;

  public RestfulResponse(ResponseCode code) {
    this.code = code;
    this.msg = "";
  }

  public RestfulResponse(ResponseCode code, String msg) {
    this.code = code;
    this.msg = msg;
  }

  public RestfulResponse(Voucher voucher) {
    this.code = ResponseCode.CHANGED;
    this.voucher = voucher;
  }

  public boolean isSuccess() {
    return (code != null && code.equals(ResponseCode.CHANGED));
  }
}
