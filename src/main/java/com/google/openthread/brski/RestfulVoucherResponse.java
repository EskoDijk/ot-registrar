package com.google.openthread.brski;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import com.google.openthread.ExtendedMediaTypeRegistry;

/**
 * A MASA's or Registrar's generic RESTful response to a Voucher Request; including status code and
 * either a diagnostic message (in case of error) or a Voucher object. It abstracts from HTTP or
 * CoAP specific semantics.
 */
public class RestfulVoucherResponse {

  protected ResponseCode code;
  protected String msg;
  protected Voucher voucher;
  protected byte[] payload;
  protected int contentFormat = -1;

  public RestfulVoucherResponse(ResponseCode errorStatus) {
    this.code = errorStatus;
    this.msg = "";
  }

  public RestfulVoucherResponse(ResponseCode errorStatus, String msg) {
    this.code = errorStatus;
    this.msg = msg;
  }

  public RestfulVoucherResponse(ResponseCode status, byte[] payload, int contentFormat) {
    this.code = status;
    this.payload = payload;
    this.contentFormat = contentFormat;
  }

  public RestfulVoucherResponse(int httpStatus, byte[] payload, String contentType) {
    this.code = codeFromHttpStatus(httpStatus);
    this.payload = payload;
    if(!contentType.toLowerCase().equals("application/voucher-cms+json"))
        throw new IllegalArgumentException("Unsupported Content-Type " + contentType);
    this.contentFormat = -2; // TODO
  }

  private ResponseCode codeFromHttpStatus(int httpStatus) {
    int nClass = httpStatus / 100;
    int nDetail = httpStatus - nClass*100;
    ResponseCode c = ResponseCode.valueOf( nClass << 5 + nDetail );
    return c;
  }

  public RestfulVoucherResponse(Voucher voucher) {
    this.code = ResponseCode.CHANGED;
    this.voucher = voucher;
  }

  public boolean isSuccess() {
    return (code != null
        && (voucher != null || payload != null)
        && code.equals(ResponseCode.CHANGED));
  }

  public int getHttpCode() {
    if (code == null) return 0;
    return code.codeClass * 100 + code.codeDetail;
  }

  public ResponseCode getCode() {
    return code;
  }

  public byte[] getPayload() {
    return payload;
  }

  public int getContentFormat() {
    return contentFormat;
  }

  public Voucher getVoucher() {
    return voucher;
  }

  public String getMessage() {
    return msg;
  }
}
