package com.google.openthread.brski;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;

/**
 * A MASA's or Registrar's generic RESTful response to a Voucher Request; including status code and
 * either a diagnostic message (in case of error) or a constrained Voucher which may be encoded as
 * Voucher object (if response created locally) or a byte[] payload (if response received over a
 * network). It abstracts from HTTP or CoAP specific semantics.
 */
public class RestfulVoucherResponse {

  public static final int MAX_DIAGNOSTIC_MESSAGE_LENGTH = 80;

  protected ResponseCode code;
  protected String msg;
  protected Voucher voucher;
  protected byte[] payload;
  protected int contentFormat = -1;

  /**
   * Constructor for generic RESTful error response without status message.
   *
   * @param errorStatus
   */
  public RestfulVoucherResponse(ResponseCode errorStatus) {
    this.code = errorStatus;
    this.msg = "";
  }

  /**
   * Constructor for generic RESTful error response with status/diagnostic message.
   *
   * @param errorStatus
   * @param msg
   */
  public RestfulVoucherResponse(ResponseCode errorStatus, String msg) {
    // keep message short for constrained systems
    if (msg.length() > MAX_DIAGNOSTIC_MESSAGE_LENGTH)
      msg = msg.substring(0, MAX_DIAGNOSTIC_MESSAGE_LENGTH);
    this.code = errorStatus;
    this.msg = msg;
  }

  /**
   * Constructor to create response object, from given CoAP voucher response information.
   *
   * @param status
   * @param payload
   * @param contentFormat
   */
  public RestfulVoucherResponse(ResponseCode status, byte[] payload, int contentFormat) {
    this.code = status;
    this.payload = payload;
    this.contentFormat = contentFormat;
  }

  /**
   * Constructor to create response object, from given HTTP voucher response information.
   *
   * @param httpStatus
   * @param payload
   * @param contentType
   */
  public RestfulVoucherResponse(int httpStatus, byte[] payload, String contentType) {
    this.code = codeFromHttpStatus(httpStatus);
    this.payload = payload;
    if (contentType != null
        && !contentType.toLowerCase().equals(ConstantsBrski.HTTP_APPLICATION_VOUCHER_COSE_CBOR))
      throw new IllegalArgumentException("Unsupported Content-Type " + contentType);
    this.contentFormat = ExtendedMediaTypeRegistry.parse(contentType);
  }

  // internal utility method
  private ResponseCode codeFromHttpStatus(int httpStatus) {
    if (httpStatus == 200) return ResponseCode.CHANGED; // Note: POST-specific, not for GET.
    int nClass = httpStatus / 100;
    int nDetail = httpStatus - nClass * 100;
    ResponseCode c = ResponseCode.valueOf((nClass << 5) + nDetail);
    return c;
  }

  /**
   * Constructor for new successful RESTful voucher response including the given voucher.
   *
   * @param voucher
   */
  public RestfulVoucherResponse(Voucher voucher) {
    this.code = ResponseCode.CHANGED;
    this.voucher = voucher;
  }

  /**
   * Check if this response object represents a success response, or not.
   *
   * @return True if response code indicates success and a Voucher is included in this response.
   *     False otherwise.
   */
  public boolean isSuccess() {
    return (code != null
        && (voucher != null || payload != null)
        && code.equals(ResponseCode.CHANGED));
  }

  public int getHttpCode() {
    if (code == null) return 0;
    return code.codeClass * 100 + code.codeDetail;
  }

  public ResponseCode getCoapCode() {
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

  /*
  public String toString() {
    return code
        + " "
        + msg
        + " CF="
        + contentFormat
        + ((payload != null) ? (" " + payload.length + "B") : "");
  }*/

}
