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

package com.google.openthread.registrar;

import COSE.CoseException;
import COSE.Message;
import COSE.MessageTag;
import COSE.OneKey;
import COSE.Sign1Message;
import com.google.openthread.BouncyCastleInitializer;
import com.google.openthread.Constants;
import com.google.openthread.Credentials;
import com.google.openthread.DummyHostnameVerifier;
import com.google.openthread.DummyTrustManager;
import com.google.openthread.ExtendedMediaTypeRegistry;
import com.google.openthread.RequestDumper;
import com.google.openthread.SecurityUtils;
import com.google.openthread.brski.CBORSerializer;
import com.google.openthread.brski.JSONSerializer;
import com.google.openthread.brski.RestfulVoucherResponse;
import com.google.openthread.brski.StatusTelemetry;
import com.google.openthread.brski.Voucher;
import com.google.openthread.brski.VoucherRequest;
import com.google.openthread.domainca.DomainCA;
import com.google.openthread.pledge.Pledge;
import com.google.openthread.tools.CredentialGenerator;
import com.upokecenter.cbor.CBORObject;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.bouncycastle.asn1.est.CsrAttrs;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The registrar implements BRSKI-EST over CoAPs
 *
 * @author wgtdkp
 */
public class Registrar extends CoapServer {
  // EST resources___________EST EST-CoAPS
  // /cacerts________________/crts
  // /simpleenroll___________/sen
  // /simplereenroll_________/sren
  // /fullcmc________________(N/A)
  // /serverkeygen___________/skg
  // /csrattrs_______________/att
  //
  // Voucher related
  // BRSKI___________________BRSKI-EST-coaps
  // /requestvoucher_________/rv
  // /voucher-status_________/vs
  // /enrollstatus___________/es

  static {
    BouncyCastleInitializer.init();
  }

  /**
   * Constructing registrar with specified settings, credentials and listening port.
   *
   * @param privateKey the private key used for DTLS connection from Pledge
   * @param certificateChain the certificate chain leading up to domain CA and including domain CA
   *     certificate, used for DTLS connection from Pledge.
   * @param masaTrustAnchors pre-installed MASA trust anchors that are trusted only when given. If
   *     null, ALL MASAs will be trusted (for interop testing).
   * @param masaClientCreds credentials to use towards MASA client in Credentials format
   * @param port the CoAP port to listen on
   * @param forcedVoucherRequestFormat by default <= 0 meaning no request format to MASA is forced
   *     but rather the Pledge's request format is copied. When a content-format value from
   *     ExtendedMediaTypeRegistry is given here, that format will be forced in the request.
   * @param isHttpToMasa whether to use HTTP requests to MASA (true, default) or CoAP (false)
   * @param setForcedMasaUri if null, no MASA-URI is forced, while if a non-null string, the
   *     Registrar is forced to use this MASA-URI always.
   * @throws RegistrarException
   */
  Registrar(
      PrivateKey privateKey,
      X509Certificate[] certificateChain,
      X509Certificate[] masaTrustAnchors,
      Credentials masaClientCreds,
      int port,
      int forcedVoucherRequestFormat,
      boolean isHttpToMasa,
      String setForcedMasaUri)
      throws RegistrarException {
    if (certificateChain.length < 2) {
      throw new RegistrarException("bad certificate chain");
    }

    this.listenPort = port;
    this.privateKey = privateKey;
    this.certificateChain = certificateChain;
    this.masaTrustAnchors = masaTrustAnchors;
    this.masaClientCredentials = masaClientCreds;
    this.forcedVoucherRequestFormat = forcedVoucherRequestFormat;
    this.setForcedMasaUri = setForcedMasaUri;
    this.isHttpToMasa = isHttpToMasa;
    try {
      this.csrAttributes = new CSRAttributes(CSRAttributes.DEFAULT_FILE);
    } catch (Exception e) {
      throw new RegistrarException(e.getMessage());
    }

    initResources();

    initEndpoint();
  }

  @Override
  public void start() {
    logger.info("Registrar starting - Number of trusted MASA servers: " + 
          (this.masaTrustAnchors.length == 0 ? "ALL MASAs" : this.masaTrustAnchors.length) );
    if (this.setForcedMasaUri != null)
      logger.info("                   - MASA URI forced to: " + this.setForcedMasaUri + " (-masa parameter)");
    super.start();
  }

  public void setDomainCA(DomainCA domainCA) {
    this.domainCA = domainCA;
  }

  public int getListenPort() {
    return listenPort;
  }

  public String getDomainName() {
    // It is the caller's responsibility to check if domainCA is null.
    return domainCA.getDomainName();
  }

  public final class VoucherStatusResource extends CoapResource {

    public VoucherStatusResource() {
      super(Constants.VOUCHER_STATUS);
    }

    @Override
    public void handlePOST(CoapExchange exchange) {
      StatusTelemetry voucherStatus = null;
      
      try {
        int contentFormat = exchange.getRequestOptions().getContentFormat();
        RequestDumper.dump(logger, getURI(), exchange.getRequestPayload());

        Principal clientId = exchange.advanced().getRequest().getSourceContext().getPeerIdentity();
        voucherStatusLog.put(clientId, StatusTelemetry.UNDEFINED); // log the access by client

        // TODO: check latest draft to see if JSON support is mandatory here.
        if (contentFormat != ExtendedMediaTypeRegistry.APPLICATION_CBOR) {
          logger.warn(
              "unsupported content-format for voucher status report: content-format="
                  + contentFormat);
          exchange.respond(ResponseCode.UNSUPPORTED_CONTENT_FORMAT, "Only Content Format "+ExtendedMediaTypeRegistry.APPLICATION_CBOR+" supported.");
          return;
        }

        voucherStatus = StatusTelemetry.deserialize(exchange.getRequestPayload());
        if (voucherStatus.cbor == null) {
          logger.warn("decoding CBOR payload failed for voucher status report: " + voucherStatus.parseResultStatus);
          exchange.respond(ResponseCode.BAD_REQUEST, "decoding CBOR payload failed for voucher status report: " + voucherStatus.parseResultStatus);
          return;
        }

        logger.info(
            "received voucher status report; status="
                + voucherStatus.status
                + ": "
                + voucherStatus.toString());

        // log the result for this Pledge
        voucherStatusLog.put(clientId, voucherStatus);

      } catch (Exception e) {
        logger.warn("handle voucher status report failed with exception: " + e.getMessage(), e);
        exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR, "Exception: " + e.getMessage() );
        return;
      }

      if (voucherStatus.isValidFormat) {        //success response
        exchange.respond(ResponseCode.CHANGED);
      }else {
        exchange.respond(ResponseCode.BAD_REQUEST, "payload error: " + voucherStatus.parseResultStatus ); // client submitted wrong format.
      } 
            
    }
  }

  public final class EnrollStatusResource extends CoapResource {

    public EnrollStatusResource() {
      super(Constants.ENROLL_STATUS);
    }

    @Override
    public void handlePOST(CoapExchange exchange) {
      StatusTelemetry enrollStatus = null;
      try {
        int contentFormat = exchange.getRequestOptions().getContentFormat();
        RequestDumper.dump(logger, getURI(), exchange.getRequestPayload());

        Principal clientId = exchange.advanced().getRequest().getSourceContext().getPeerIdentity();
        enrollStatusLog.put(clientId, StatusTelemetry.UNDEFINED); // log the access by client

        // TODO: check latest draft if JSON mandatory here too.
        if (contentFormat != ExtendedMediaTypeRegistry.APPLICATION_CBOR) {
          logger.warn(
              "unexpected content format for enroll status report: content-format="
                  + contentFormat);
          exchange.respond(ResponseCode.UNSUPPORTED_CONTENT_FORMAT, "Only Content Format "+ExtendedMediaTypeRegistry.APPLICATION_CBOR+" supported.");
          return;
        }

        enrollStatus = StatusTelemetry.deserialize(exchange.getRequestPayload());
        if (enrollStatus.cbor == null) {
          logger.warn("status telemetry report message decoding error: " + enrollStatus.parseResultStatus);
          exchange.respond(ResponseCode.BAD_REQUEST, "payload error: " + enrollStatus.parseResultStatus);
          return;
        }

        logger.info(
            "received enroll status report; status="
                + enrollStatus.status
                + ": "
                + enrollStatus.toString());

        // log the result for this Pledge
        enrollStatusLog.put(clientId, enrollStatus);

      } catch (Exception e) {
        logger.warn("handle enroll status report failed with exception: " + e.getMessage(), e);
        exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR, "Exception: " + e.getMessage() );
        return;
      }

      if (enrollStatus.isValidFormat) {        //success response
        exchange.respond(ResponseCode.CHANGED);
      }else {
        exchange.respond(ResponseCode.BAD_REQUEST, "payload error: " + enrollStatus.parseResultStatus); // client submitted wrong format.
      }
      
    }
  }

  public final class VoucherRequestResource extends CoapResource {

    public VoucherRequestResource() {
      super(Constants.REQUEST_VOUCHER);
    }

    @Override
    public void handlePOST(CoapExchange exchange) {

      try {
        int contentFormat = exchange.getRequestOptions().getContentFormat();
        RequestDumper.dump(logger, getURI(), exchange.getRequestPayload());

        // Get client certificate, it is pledge's idevid for voucher request
        Principal clientId = exchange.advanced().getRequest().getSourceContext().getPeerIdentity();
        if (!(clientId instanceof X509CertPath)) {
          logger.error("unsupported client identity type");
          exchange.respond(ResponseCode.UNAUTHORIZED, "Unsupported client identity type.");
          return;
        }
        X509Certificate idevid = ((X509CertPath) clientId).getTarget();
        voucherLog.put(clientId, Voucher.UNDEFINED); // log access by this client
        logger.debug("Public key of current client: " + Hex.toHexString(idevid.getPublicKey().getEncoded()));

        VoucherRequest pledgeReq = null;

        if (contentFormat == ExtendedMediaTypeRegistry.APPLICATION_COSE_SIGN1
            || contentFormat == ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_COSE_CBOR) {
          // Verify signature of COSE_Sign1 message
          Sign1Message sign1Msg =
              (Sign1Message)
                  Message.DecodeFromBytes(exchange.getRequestPayload(), MessageTag.Sign1);
          if (!sign1Msg.validate(new OneKey(idevid.getPublicKey(), null))) {
            logger.error("COSE-sign1 voucher-request validation failed");
            exchange.respond(ResponseCode.NOT_FOUND, "COSE-Sign1 validation failed");
            return;
          }

          // 2.1 verify the voucher
          pledgeReq = (VoucherRequest) new CBORSerializer().deserialize(sign1Msg.GetContent());
        } else if (contentFormat == ExtendedMediaTypeRegistry.APPLICATION_CBOR) {
          pledgeReq =
              (VoucherRequest)
                  new CBORSerializer().deserialize(exchange.getRequestPayload());
        } else {
          logger.error("unsupported voucher request format: " + contentFormat);
          exchange.respond(ResponseCode.UNSUPPORTED_CONTENT_FORMAT, "unsupported voucher request Content Format: " + contentFormat);
          return;
        }

        // Validate pledge's voucher request
        if (!pledgeReq.validate()) {
          final String msg = "voucher request did not validate";
          logger.error(msg);
          exchange.respond(ResponseCode.FORBIDDEN, msg);
          return;
        }

        // Constructing new voucher request for MASA
        // ref: section 5.5 BRSKI RFC8995
        VoucherRequest req = new VoucherRequest();
        req.assertion = pledgeReq.assertion; // assertion is copied from Pledge. Section 3.3 example.
        // Note, section 5.5: assertion MAY be omitted.

        // OPTIONAL (RFC 8995), but mandatory for Thread 1.2
        req.nonce = pledgeReq.nonce;

        // Optionally present in Pledge's Voucher Request.
        if (pledgeReq.proximityRegistrarSPKI != null) {
          if (!Arrays.equals(
              pledgeReq.proximityRegistrarSPKI, getCertificate().getPublicKey().getEncoded())) {
            logger.error("unmatched proximity registrar SPKI in Pledge's Voucher Request");
            exchange.respond(ResponseCode.BAD_REQUEST, "proximityRegistrarSPKI error");
            return;
          }
        }

        // MUST NOT include (RFC 8995)
        req.proximityRegistrarSPKI = null;

        // SHOULD include (RFC 8995)
        req.createdOn = new Date();

        // serialNumber provided by pledge's voucher request MUST match (RFC 8995) the
        // one
        // extracted from pledge's idevid.
        req.serialNumber = Pledge.getSerialNumber(idevid);
        if (req.serialNumber == null || !req.serialNumber.equals(pledgeReq.serialNumber)) {
          logger.error(
              String.format(
                  "bad serial number in voucher request: [%s] != [%s]",
                  pledgeReq.serialNumber, req.serialNumber));
          exchange.respond(ResponseCode.BAD_REQUEST, "serial number check failure");
          return;
        }

        // Optional, could be null, but MUST be included for nonceful Voucher Request
        // (RFC 8995).
        // Settting idevid-issuer as authority key identifier of pledge certificate.
        // Mandatory for Thread 1.2. Note: this currently uses a working assumption
        // that the right format is complete AKI SEQUENCE. (Not just KeyIdentifier OCTET STRING).
        req.idevidIssuer = SecurityUtils.getAuthorityKeyIdentifier(idevid);
        if (req.idevidIssuer != null) {
          logger.info(
              String.format(
                  "idevid-issuer inserted in Registrar voucher request [len=%d, %s]",
                  req.idevidIssuer.length, Hex.toHexString(req.idevidIssuer)));
        } else {
          String msg = "missing AKI in Pledge IDevID certificate";
          logger.error(msg);
          exchange.respond(ResponseCode.BAD_REQUEST, msg);
          return;
        }

        // SHOULD include prior-signed-voucher-request (RFC 8995) with Pledge's
        // COSE-signed voucher
        // request
        // Mandatory for Thread 1.2.
        req.priorSignedVoucherRequest = exchange.getRequestPayload();

        // Create voucher request to MASA. Uses HTTPS or CoAPS as protocol.
        // Uses CMS or COSE signing.
        String requestMediaType;
        int requestContentFormat;
        byte[] content = null;

        // Uses CBOR or JSON voucher request format.
        boolean isJsonVR =
            (forcedVoucherRequestFormat == ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_CMS_JSON
                || forcedVoucherRequestFormat
                    == ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_COSE_JSON);
        if (isJsonVR) content = new JSONSerializer().serialize(req);
        else content = new CBORSerializer().serialize(req);

        // use CMS or COSE signing of the voucher request.
        byte[] payload;
        boolean isCms =
            (forcedVoucherRequestFormat == ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_CMS_CBOR
                || forcedVoucherRequestFormat
                    == ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_CMS_JSON);
        if (isCms) {
          // CMS signing.
          requestMediaType =
              isJsonVR
                  ? Constants.HTTP_APPLICATION_VOUCHER_CMS_JSON
                  : Constants.HTTP_APPLICATION_VOUCHER_CMS_CBOR;
          requestContentFormat =
              isJsonVR
                  ? ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_CMS_JSON
                  : ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_CMS_CBOR;
          try {
            payload =
                SecurityUtils.genCMSSignedMessage(
                    privateKey,
                    getCertificate(),
                    SecurityUtils.SIGNATURE_ALGORITHM,
                    certificateChain,
                    content);
          } catch (Exception e) {
            logger.warn("CMS signing voucher request failed: " + e.getMessage(), e);
            exchange.respond(ResponseCode.SERVICE_UNAVAILABLE);
            return;
          }
        } else {
          // COSE signing.
          requestMediaType = Constants.HTTP_APPLICATION_VOUCHER_COSE_CBOR;
          requestContentFormat = ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_COSE_CBOR;
          try {
            payload =
                SecurityUtils.genCoseSign1Message(
                    privateKey, SecurityUtils.COSE_SIGNATURE_ALGORITHM, content, certificateChain);
          } catch (Exception e) {
            logger.warn("COSE signing voucher request failed: " + e.getMessage(), e);
            exchange.respond(ResponseCode.SERVICE_UNAVAILABLE);
            return;
          }
        }

        // Request voucher from MASA server indicated in IDevID cert, or else the
        // default one.
        String uri = SecurityUtils.getMasaUri(idevid);
        if ((uri == null || uri.length() == 0) && setForcedMasaUri == null) {
          uri = Constants.DEFAULT_MASA_URI;
          logger.warn(
              "pledge certificate does not include MASA uri, using default masa uri: " + uri);
        } else if (uri != null && setForcedMasaUri == null) {
          logger.info("Constructing Registrar Voucher Req to MASA: " + uri);
        } else {
          uri = setForcedMasaUri;
          logger.info("Using forced MASA URI to send Registrar Voucher Req: " + uri);
        }

        RestfulVoucherResponse response = null;
        if (isHttpToMasa) {
          MASAConnectorHttp masaClient = new MASAConnectorHttp(masaTrustAnchors);
          response = masaClient.requestVoucher(requestMediaType, payload, uri);
        } else {
          MASAConnector masaClient = new MASAConnector(masaTrustAnchors);
          response = masaClient.requestVoucher(requestContentFormat, payload, uri);
        }

        if (response == null) {
          logger.warn("request voucher from MASA failed with response null");
          exchange.respond(ResponseCode.SERVICE_UNAVAILABLE);
          return;
        }

        if (!response.isSuccess()) {
          logger.warn(
              "request voucher from MASA failed with response code " + response.getCoapCode());
          // mirror the MASA's response code, so the Pledge can distinguish errors from
          // MASA. Get also MASA's diagnostic error message if any.
          exchange.respond(response.getCoapCode(), response.getMessage());
          return;
        }

        if (response.getContentFormat()
            != ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_COSE_CBOR) {
          // TODO(wgtdkp): we can support more formats
          logger.error("Not-supported content format from MASA: " + response.getContentFormat());
          exchange.respond(ResponseCode.SERVICE_UNAVAILABLE);
          return;
        }

        // Note: payload null check must be last.
        if (response.getPayload() == null) {
          logger.warn("unexpected null payload from MASA server");
          exchange.respond(ResponseCode.SERVICE_UNAVAILABLE);
          return;
        }

        // verify CBOR/COSE voucher
        Sign1Message sign1Msg =
            (Sign1Message) Message.DecodeFromBytes(response.getPayload(), MessageTag.Sign1);
        Voucher v = new CBORSerializer().deserialize(sign1Msg.GetContent());

        // voucher is ok, log it
        voucherLog.put(clientId, v);

        // Registrar forwards MASA's success response without modification
        exchange.respond(
            response.getCoapCode(),
            response.getPayload(),
            ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_COSE_CBOR);
        return;

      } catch (Exception e) {
        logger.warn("handle voucher request failed: " + e.getMessage(), e);
        exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR);
        return;
      }
    }
  }

  /** CoAP-based MASA connector, acts as client towards MASA. */
  public final class MASAConnector extends CoapClient {

    MASAConnector(X509Certificate[] trustAnchors) {
      initEndPoint(trustAnchors);
    }

    /**
     * Send new Voucher Request to MASA. Note that the present format used is not standardized, but
     * custom to OT-Registrar and OT-Masa.
     *
     * @param requestContentFormat the CoAP content-format of the request
     * @param payload the Voucher Request in application/voucher-cms+cbor format
     * @param masaURI the MASA URI (without URI path, without coaps:// scheme) to send it to
     * @return null if a timeout error happens
     */
    public RestfulVoucherResponse requestVoucher(
        int requestContentFormat, byte[] payload, String masaURI)
        throws IOException, ConnectorException {
      setURI("coaps://" + masaURI + Constants.BRSKI_PATH + "/" + Constants.REQUEST_VOUCHER);
      // send request as CMS signed CBOR, accept only COSE-signed CBOR back.
      CoapResponse resp =
          post(
              payload,
              requestContentFormat,
              ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_COSE_CBOR);
      if (resp == null) return null;
      return new RestfulVoucherResponse(
          resp.getCode(), resp.getPayload(), resp.getOptions().getContentFormat());
    }

    private void initEndPoint(X509Certificate[] trustAnchors) {
      CoapEndpoint endpoint =
          SecurityUtils.genCoapClientEndPoint(
              trustAnchors, privateKey, certificateChain, null, true);
      setEndpoint(endpoint);
    }
  }

  /** HTTPS-based MASA connector, acts as client towards MASA. */
  public final class MASAConnectorHttp {

    protected SSLContext sc;

    MASAConnectorHttp(X509Certificate[] trustAnchors) throws Exception {
      initEndPoint(trustAnchors);
    }

    /**
     * Send new Voucher Request to MASA.
     *
     * @param the media type string of the body
     * @param body the Voucher Request in bytes
     * @param masaURI the MASA URI (without URI path, without https:// scheme) to send it to
     * @return null if any error happens
     */
    public RestfulVoucherResponse requestVoucher(
        String requestMediaType, byte[] body, String masaURI)
        throws IOException, ConnectorException, NoSuchAlgorithmException, KeyManagementException {
      URL url =
          new URL(
              "https://" + masaURI + Constants.BRSKI_PATH + "/" + Constants.REQUEST_VOUCHER_HTTP);
      // send request as CMS signed JSON, accept only COSE-signed CBOR back.
      HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
      con.setUseCaches(false);
      con.setHostnameVerifier(new DummyHostnameVerifier());
      con.setSSLSocketFactory(sc.getSocketFactory());
      con.setRequestMethod("POST");
      con.setDoOutput(true);
      con.setRequestProperty("Content-Type", requestMediaType);
      con.setRequestProperty("Accept", Constants.HTTP_APPLICATION_VOUCHER_COSE_CBOR);
      con.setInstanceFollowRedirects(true);
      con.connect();
      DataOutputStream out = new DataOutputStream(con.getOutputStream());
      out.write(body);
      out.flush();
      out.close();
      byte[] respPayload = null;
      try {
        respPayload = con.getInputStream().readAllBytes();
      } catch (IOException ex) { // in case no data is sent by MASA.
        ;
      }
      // TODO below assumes the Content-Type of the response, because Accept header was used. May
      // need to be checked though.
      return new RestfulVoucherResponse(
          con.getResponseCode(), respPayload, Constants.HTTP_APPLICATION_VOUCHER_COSE_CBOR);
    }

    private void initEndPoint(X509Certificate[] trustAnchors) throws Exception {
      sc = SSLContext.getInstance("TLS");
      KeyManagerFactory kmf =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(masaClientCredentials.getKeyStore(), CredentialGenerator.PASSWORD.toCharArray());
      sc.init(kmf.getKeyManagers(), new TrustManager[] {new DummyTrustManager()}, null);
    }
  }

  public class EnrollResource extends CoapResource {
    public EnrollResource() {
      this(Constants.SIMPLE_ENROLL);
    }

    protected EnrollResource(String name) {
      super(name);
    }

    @Override
    public void handlePOST(CoapExchange exchange) {

      try {
        int contentFormat = exchange.getRequestOptions().getContentFormat();
        RequestDumper.dump(logger, getURI(), exchange.getRequestPayload());

        if (contentFormat != ExtendedMediaTypeRegistry.APPLICATION_PKCS10) {
          exchange.respond(ResponseCode.UNSUPPORTED_CONTENT_FORMAT, "Only Content Format "+ExtendedMediaTypeRegistry.APPLICATION_PKCS10+" supported.");
          return;
        }

        byte[] payload = exchange.getRequestPayload();

        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(payload);
        X509Certificate cert = domainCA.signCertificate(csr);

        exchange.respond(
            ResponseCode.CHANGED,
            cert.getEncoded(),
            ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT);
      } catch (Exception e) {
        logger.warn("sign certificate failed: " + e.getMessage(), e);
        // TODO(wgtdkp):
        exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR);
        return;
      }
    }
  }

  public final class ReenrollResource extends EnrollResource {
    public ReenrollResource() {
      super(Constants.SIMPLE_REENROLL);
    }
  }

  public final class CsrAttrsResource extends CoapResource {
    public CsrAttrsResource() {
      super(Constants.CSR_ATTRIBUTES);
    }

    @Override
    public void handleGET(CoapExchange exchange) {
      try {
        RequestDumper.dump(logger, getURI(), exchange.getRequestPayload());

        CsrAttrs csrAttrs = getCsrAttrs();

        // No base64 encoding
        exchange.respond(
            ResponseCode.CONTENT,
            csrAttrs.getEncoded(),
            ExtendedMediaTypeRegistry.APPLICATION_CSRATTRS);
      } catch (IOException e) {
        logger.warn("CSR attribute request failed: " + e.getMessage());
        exchange.respond(ResponseCode.BAD_REQUEST);
      }
    }

    private CsrAttrs getCsrAttrs() {
      return new CsrAttrs(csrAttributes.getAttrAndOids());
    }
  }

  public final class CrtsResource extends CoapResource {
    public CrtsResource() {
      super(Constants.CA_CERTIFICATES);
    }

    @Override
    public void handleGET(CoapExchange exchange) {
      try {
        RequestDumper.dump(logger, getURI(), exchange.getRequestPayload());

        exchange.respond(
            ResponseCode.CONTENT,
            domainCA.getCertificate().getEncoded(),
            ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT);
      } catch (Exception e) {
        logger.warn("CA Certificates request failed: " + e.getMessage());
        exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR);
      }
    }
  }

  public final class CommissionerTokenResource extends CoapResource {
    public CommissionerTokenResource() {
      super(Constants.COM_TOK);
    }

    @Override
    public void handlePOST(CoapExchange exchange) {
      try {
        int contentFormat = exchange.getRequestOptions().getContentFormat();
        RequestDumper.dump(logger, getURI(), exchange.getRequestPayload());

        if (contentFormat != ExtendedMediaTypeRegistry.APPLICATION_CWT) {
          exchange.respond(ResponseCode.UNSUPPORTED_CONTENT_FORMAT,  "Only Content Format "+ExtendedMediaTypeRegistry.APPLICATION_CWT+" supported.");
          return;
        }

        // TODO(wgtdkp): verify the COM_TOK.req
        CBORObject req = CBORObject.DecodeFromBytes(exchange.getRequestPayload());
        validateComTokenReq(req);

        CBORObject signedToken = domainCA.signCommissionerToken(req);
        byte[] encodedToken = signedToken.EncodeToBytes();
        logger.info(
            "response token[len={}] : {}", encodedToken.length, Hex.toHexString(encodedToken));

        exchange.respond(
            ResponseCode.CHANGED, encodedToken, ExtendedMediaTypeRegistry.APPLICATION_COSE_SIGN1);
      } catch (Exception e) {
        logger.warn("commissioner token request failed: " + e.getMessage(), e);
        exchange.respond(ResponseCode.BAD_REQUEST, e.getMessage());
      }
    }
  }

  public final class WellknownCoreResource extends CoapResource {
    public WellknownCoreResource() {
      super(Constants.CORE);
    }

    @Override
    public void handleGET(CoapExchange exchange) {
      String wellknownCoreLinkFormat =
          "</hello>;ct=0,</.well-known/brski>;rt=brski,</.well-known/est>;rt=ace.est";
      exchange.respond(
          ResponseCode.CONTENT, wellknownCoreLinkFormat, MediaTypeRegistry.APPLICATION_LINK_FORMAT);
    }
  }

  public static void validateComTokenReq(CBORObject req) throws RegistrarException {
    CBORObject grantType = req.get(CBORObject.FromObject(se.sics.ace.Constants.GRANT_TYPE));
    if (grantType == null) {
      throw new RegistrarException("missing grant-type");
    } else if (grantType.AsInt32() != se.sics.ace.Constants.GT_CLI_CRED) {
      throw new RegistrarException("COM_TOK.req grant-type is wrong: " + grantType.AsInt32());
    }

    CBORObject clientId = req.get(CBORObject.FromObject(se.sics.ace.Constants.CLIENT_ID));
    if (clientId == null) {
      throw new RegistrarException("missing client-id");
    }

    CBORObject reqAud = req.get(CBORObject.FromObject(se.sics.ace.Constants.AUD));
    if (reqAud == null) {
      throw new RegistrarException("missing req-aud");
    }

    CBORObject reqCnf = req.get(CBORObject.FromObject(se.sics.ace.Constants.REQ_CNF));
    if (reqCnf == null) {
      throw new RegistrarException("missing req-cnf");
    }

    CBORObject coseKey = reqCnf.get(CBORObject.FromObject(se.sics.ace.Constants.COSE_KEY));
    if (coseKey == null) {
      throw new RegistrarException("missing cose-key in req-cnf");
    }
  }

  /**
   * return a List of all clients that ever used this Registrar.
   *
   * @return
   */
  public Principal[] getKnownClients() {
    HashSet<Principal> l = new HashSet<Principal>();
    l.addAll(voucherLog.keySet());
    l.addAll(voucherStatusLog.keySet());
    l.addAll(enrollStatusLog.keySet());
    return l.toArray(new Principal[] {});
  }

  /**
   * get the last voucher-status telemetry that was sent by a specific client.
   *
   * @param client the secure client identifier
   * @returns If available, the last voucher-status telemetry. If client did not send any
   *     voucher-status telemetry, it returns null. If client did send voucher-status telemetry, but
   *     in an unrecognized format, it returns StatusTelemetry.UNDEFINED.
   */
  public StatusTelemetry getVoucherStatusLogEntry(Principal client) {
    if (voucherStatusLog.containsKey(client)) return voucherStatusLog.get(client);
    return null;
  }

  /**
   * get the last enroll-status telemetry that was sent by a specific client.
   *
   * @param client the secure client identifier
   * @returns If available, the last enroll-status telemetry. If client did not send any
   *     enroll-status telemetry, it returns null. If client did send enroll-status telemetry, but
   *     in an unrecognized format, it returns StatusTelemetry.UNDEFINED.
   */
  public StatusTelemetry getEnrollStatusLogEntry(Principal client) {
    if (enrollStatusLog.containsKey(client)) return enrollStatusLog.get(client);
    return null;
  }

  /**
   * get the Registrar's EE certificate
   *
   * @return
   */
  X509Certificate getCertificate() {
    return certificateChain[0];
  }

  /**
   * get the Registrar's Domain (CA) certificate, i.e. the top-level certificate in the chain.
   *
   * @return
   */
  X509Certificate getDomainCertificate() {
    return certificateChain[certificateChain.length - 1];
  }

  private void initResources() {
    CoapResource wellKnown = new CoapResource(Constants.WELL_KNOWN);
    CoapResource est = new CoapResource(Constants.EST);
    CoapResource brski = new CoapResource(Constants.BRSKI);

    VoucherRequestResource rv = new VoucherRequestResource();
    VoucherStatusResource vs = new VoucherStatusResource();
    EnrollStatusResource es = new EnrollStatusResource();
    CsrAttrsResource att = new CsrAttrsResource();
    CrtsResource crts = new CrtsResource();
    EnrollResource enroll = new EnrollResource();
    ReenrollResource reenroll = new ReenrollResource();
    WellknownCoreResource core = new WellknownCoreResource();

    // EST and BRSKI and CoRE well-known resources
    est.add(enroll);
    est.add(reenroll);
    est.add(att);
    est.add(crts);
    brski.add(rv);
    brski.add(vs);
    brski.add(es);
    wellKnown.add(core);
    wellKnown.add(est);
    wellKnown.add(brski);
    // Commissioning FIXME ccm not defined in IANA well-known space, can place it in
    // /.well-known/thread/ccm/tokenrequest
    wellKnown.add(new CommissionerTokenResource());
    this.add(wellKnown);

    // 'hello' test resource
    this.add(
        new CoapResource(Constants.HELLO) {
          @Override
          public void handleGET(CoapExchange exchange) {
            exchange.respond(ResponseCode.CONTENT, "hello CoAP");
          }
        });
  }

  private void initEndpoint() {
    List<X509Certificate> trustAnchors = new ArrayList<>(Arrays.asList(masaTrustAnchors));
    trustAnchors.add(getDomainCertificate());

    CoapEndpoint endpoint =
        SecurityUtils.genCoapServerEndPoint(
            listenPort,
            null,
            privateKey,
            certificateChain,
            new RegistrarCertificateVerifier(null) // trust ALL - default for a testing Registrar.
            // new RegistrarCertificateVerifier(trustAnchors.toArray(new
            // X509Certificate[trustAnchors.size()])) // trust only my known MASA - for stricter
            // testing.
            );
    addEndpoint(endpoint);
  }

  private final int listenPort;

  private DomainCA domainCA;

  private PrivateKey privateKey;
  private X509Certificate[] certificateChain;

  private X509Certificate[] masaTrustAnchors;

  // credentials used as a HTTP/CoAP client towards MASA.
  private Credentials masaClientCredentials;

  private CSRAttributes csrAttributes;

  protected int forcedVoucherRequestFormat = -1;

  protected boolean isHttpToMasa = true;

  protected String setForcedMasaUri = null;

  protected Map<Principal, StatusTelemetry> enrollStatusLog =
      new HashMap<Principal, StatusTelemetry>();

  protected Map<Principal, StatusTelemetry> voucherStatusLog =
      new HashMap<Principal, StatusTelemetry>();

  protected Map<Principal, Voucher> voucherLog = new HashMap<Principal, Voucher>();

  private static Logger logger = LoggerFactory.getLogger(Registrar.class);
}
