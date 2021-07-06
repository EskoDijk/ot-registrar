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

package com.google.openthread.masa;

import COSE.CoseException;
import COSE.Message;
import COSE.MessageTag;
import COSE.OneKey;
import COSE.Sign1Message;
import com.google.openthread.BouncyCastleInitializer;
import com.google.openthread.Constants;
import com.google.openthread.Credentials;
import com.google.openthread.DummyTrustManager;
import com.google.openthread.ExtendedMediaTypeRegistry;
import com.google.openthread.RequestDumper;
import com.google.openthread.SecurityUtils;
import com.google.openthread.brski.CBORSerializer;
import com.google.openthread.brski.ConstrainedVoucher;
import com.google.openthread.brski.ConstrainedVoucherRequest;
import com.google.openthread.brski.JSONSerializer;
import com.google.openthread.brski.RestfulVoucherResponse;
import com.google.openthread.brski.Voucher;
import com.google.openthread.brski.VoucherRequest;
import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.BlockingHandler;
import io.undertow.server.handlers.PathHandler;
import io.undertow.util.HttpString;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MASA {

  static {
    BouncyCastleInitializer.init();
  }

  protected CoapServer coapServer;

  protected Undertow httpServer;

  public MASA(PrivateKey privateKey, X509Certificate certificate, Credentials credentials, int port)
      throws Exception {
    this.privateKey = privateKey;
    this.certificate = certificate;

    this.listenPort = port;
    coapServer = new CoapServer();

    // http
    KeyManager[] keyManagers;
    KeyManagerFactory keyManagerFactory =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(credentials.getKeyStore(), credentials.getPassword().toCharArray());
    keyManagers = keyManagerFactory.getKeyManagers();

    TrustManager[] trustManagers;
    trustManagers = new X509TrustManager[] {new DummyTrustManager()};

    SSLContext httpSsl = SSLContext.getInstance("TLS");
    httpSsl.init(keyManagers, trustManagers, null);
    PathHandler voucherRequestPathHandler =
        new PathHandler()
            .addExactPath(
                "/.well-known/brski/requestvoucher",
                new BlockingHandler(new VoucherRequestHttpHandler()));
    httpServer =
        Undertow.builder()
            .addHttpsListener(
                Constants.DEFAULT_MASA_URI_PORT, Constants.DEFAULT_MASA_URI_AUTHORITY, httpSsl)
            .setHandler(voucherRequestPathHandler)
            .build();
    initResources();
    initEndPoint();
  }

  public int getListenPort() {
    return listenPort;
  }

  public void start() {
    // coapServer.start();
    httpServer.start();
  }

  public void stop() {
    // coapServer.stop();
    httpServer.stop();
  }

  X509Certificate getCertificate() {
    return certificate;
  }

  final class VoucherRequestHttpHandler implements HttpHandler {

    public VoucherRequestHttpHandler() {}

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
      final byte[] body = exchange.getInputStream().readAllBytes();
      RequestDumper.dump(logger, exchange.getRequestURI(), body);

      if (!exchange.getRequestMethod().equals(HttpString.tryFromString("POST"))) {
        exchange.setStatusCode(405);
        return;
      }

      if (!exchange.getRequestHeaders().contains("Content-Type")) {
        exchange.setStatusCode(400);
        exchange.setReasonPhrase("Missing Content-Type header");
        return;
      }

      final String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
      List<X509Certificate> reqCerts = new ArrayList<>();
      byte[] reqContent = null;
      VoucherRequest req = null;
      Sign1Message sign1Msg = null;

      switch (contentType) {
        case Constants.HTTP_APPLICATION_VOUCHER_CMS_JSON:
          try {
            reqContent =
                SecurityUtils.decodeCMSSignedMessage(
                    body, reqCerts); // decode CMS and get the embedded reqCerts back.
          } catch (Exception e) {
            logger.error("CMS signed voucher request error: " + e.getMessage(), e);
            exchange.setStatusCode(403);
            exchange.setReasonPhrase(
                "CMS signing/decoding error in voucher request: " + e.getMessage());
            return;
          }
          break;

        case Constants.HTTP_APPLICATION_VOUCHER_COSE_CBOR:
          try {
            // Verify signature
            sign1Msg = (Sign1Message) Message.DecodeFromBytes(body, MessageTag.Sign1);
            // look for set of x509 certificates in header parameters, per draft-ietf-cose-x509-08
            reqCerts = SecurityUtils.getX5BagCertificates(sign1Msg);
            if (reqCerts == null || reqCerts.size() < 1)
              throw new CoseException(
                  "Registrar signing cert chain not found in X5Bag field of voucher request");
            if (sign1Msg == null
                || !sign1Msg.validate(new OneKey(reqCerts.get(0).getPublicKey(), null))) {
              throw new CoseException("COSE-sign1 voucher validation failed");
            }

          } catch (Exception e) {
            logger.error("CBOR signed voucher request error: " + e.getMessage(), e);
            exchange.setStatusCode(403);
            exchange.setReasonPhrase(
                "COSE signing/decoding error in voucher request: " + e.getMessage());
            return;
          }
          break;

        default:
          exchange.setStatusCode(400);
          exchange.setReasonPhrase("Unsupported voucher request format: " + contentType);
          return;
      }

      switch (contentType) {
        case Constants.HTTP_APPLICATION_VOUCHER_CMS_JSON:
          try {
            req = (VoucherRequest) new JSONSerializer().deserialize(reqContent);
          } catch (Exception e) {
            logger.error("JSON deserialization error: " + e.getMessage(), e);
            exchange.setStatusCode(400);
            exchange.setReasonPhrase("JSON deserialization error: " + e.getMessage());
          }
          break;

        case Constants.HTTP_APPLICATION_VOUCHER_COSE_CBOR:
          try {
            req = (VoucherRequest) new CBORSerializer().deserialize(sign1Msg.GetContent());
          } catch (Exception e) {
            logger.error("CBOR deserialization error: " + e.getMessage(), e);
            exchange.setStatusCode(400);
            exchange.setReasonPhrase("CBOR deserialization error: " + e.getMessage());
          }
          break;

        default:
          throw new RuntimeException("Internal MASA error");
      }

      final RestfulVoucherResponse resp =
          processVoucherRequest(req, new ConstrainedVoucher(), reqCerts);

      // Generate and send response
      if (resp.isSuccess()) {
        exchange.setStatusCode(200);
        exchange
            .getResponseHeaders()
            .put(
                HttpString.tryFromString("Content-Type"),
                Constants.HTTP_APPLICATION_VOUCHER_COSE_CBOR);
        byte[] content = new CBORSerializer().serialize(resp.getVoucher());
        byte[] payload =
            SecurityUtils.genCoseSign1Message(
                privateKey, SecurityUtils.COSE_SIGNATURE_ALGORITHM, content);
        exchange.getOutputStream().write(payload);
        exchange.getOutputStream().flush();
        exchange.getOutputStream().close();
      } else {
        // send the error response and diagnostic msg.
        exchange.setStatusCode(resp.getHttpCode());
        exchange.setReasonPhrase(resp.getMessage());
      }
    }
  }

  final class VoucherRequestResource extends CoapResource {
    VoucherRequestResource() {
      super(Constants.REQUEST_VOUCHER);
    }

    @Override
    public void handlePOST(CoapExchange exchange) {

      RequestDumper.dump(logger, getURI(), exchange.getRequestPayload());

      int contentFormat = exchange.getRequestOptions().getContentFormat();
      if (contentFormat != ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_CMS_CBOR) {
        // TODO(wgtdkp): support more formats
        // TODO(EskoDijk): support long URI resource names in case other formats
        // (CMS-over-HTTP)
        // supported
        exchange.respond(ResponseCode.UNSUPPORTED_CONTENT_FORMAT);
        return;
      }

      byte[] reqContent;
      List<X509Certificate> reqCerts = new ArrayList<>();
      try {
        reqContent = SecurityUtils.decodeCMSSignedMessage(exchange.getRequestPayload(), reqCerts);
      } catch (Exception e) {
        logger.error("CMS signed voucher request error: " + e.getMessage(), e);
        exchange.respond(ResponseCode.FORBIDDEN, "CMS signature could not be decoded.");
        return;
      }

      ConstrainedVoucherRequest req =
          (ConstrainedVoucherRequest) new CBORSerializer().deserialize(reqContent);
      RestfulVoucherResponse resp = processVoucherRequest(req, new ConstrainedVoucher(), reqCerts);

      // Generate and send response
      if (resp.isSuccess()) {
        try {
          byte[] content = new CBORSerializer().serialize(resp.getVoucher());
          byte[] payload =
              SecurityUtils.genCoseSign1Message(
                  privateKey, SecurityUtils.COSE_SIGNATURE_ALGORITHM, content);
          exchange.respond(
              ResponseCode.CHANGED,
              payload,
              ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_COSE_CBOR);
        } catch (CoseException e) {
          logger.error("COSE signing voucher request failed: " + e.getMessage(), e);
          exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR);
        }
      } else {
        // send the error response and diagnostic msg.
        exchange.respond(resp.getCoapCode(), resp.getMessage());
      }
    }
  }

  /**
   * Process incoming Voucher Request (and accompanying certificates of Registrar) and evaluate into
   * a generic RESTful response. This response can be an error, or success, and can then be served
   * by the respective CoAP or HTTP (or other) protocol server back to the client.
   *
   * @param req received Voucher Request object
   * @param voucher a new Voucher object of the right type, to be returned upon success in
   *     RestfulResponse.
   * @param reqCerts accompanying certificates of the Registrar to verify against
   * @return a RESTful response that is either error (with diagnostic message) or success (with
   *     Voucher)
   */
  protected RestfulVoucherResponse processVoucherRequest(
      Voucher req, Voucher voucher, List<X509Certificate> reqCerts) {

    if (!req.validate() || reqCerts.isEmpty()) {
      logger.error("invalid voucher request");
      return new RestfulVoucherResponse(
          ResponseCode.BAD_REQUEST, "Voucher Request validation error.");
    }

    // TODO(wgtdkp):
    // Section 5.5.1 BRSKI: MASA renewal of expired vouchers

    // TODO(wgtdkp):
    // Section 5.5.2 BRSKI: MASA verification of voucher-request signature
    // consistency

    // TODO(wgtdkp):
    // Section 5.5.3 BRSKI: MASA authentication of registrar (certificate)
    // do a first check on RA flag of Registrar cert. BHC-651
    boolean isRA = false;
    try {
      X509Certificate registrarCert = reqCerts.get(0);
      if (registrarCert.getExtendedKeyUsage() != null) {
        for (String eku : registrarCert.getExtendedKeyUsage()) {
          if (eku.equals(Constants.CMC_RA_PKIX_KEY_PURPOSE)) {
            isRA = true;
            break;
          }
        }
      }
    } catch (Exception ex) {
      final String msg = "Couldn't parse extended key usage in Registrar certificate.";
      logger.error(msg, ex);
      return new RestfulVoucherResponse(ResponseCode.BAD_REQUEST, msg);
    }
    if (!isRA) {
      final String msg = "Registrar certificate did not have RA set in Extended Key Usage.";
      logger.error(msg);
      return new RestfulVoucherResponse(ResponseCode.FORBIDDEN, msg); // per RFC 8995 5.6
    }

    // TODO(wgtdkp):
    // Section 5.5.4 BRSKI: MASA revocation checking of registrar (certificate)

    // TODO(wgtdkp):
    // Section 5.5.5 BRSKI: MASA verification of pledge prior-signed-voucher-request
    // Note: RFC 8995 suggests HTTP 415 for this case.
    if (req.priorSignedVoucherRequest == null) {
      final String msg = "missing priorSignedVoucherRequest";
      logger.error(msg);
      return new RestfulVoucherResponse(ResponseCode.BAD_REQUEST, msg);
    }

    // TODO(wgtdkp):
    // Section 5.5.6 BRSKI: MASA pinning of registrar

    // TODO(wgtdkp):
    // Section 5.5.7 BRSKI: MASA nonce handling

    // Section 5.6 BRSKI: MASA and Registrar Voucher Response

    voucher.createdOn = new Date();

    voucher.nonce = req.nonce;

    // TODO(wgtdkp): MASA should check the priorSignedVoucherRequest, see if the
    // assertion there
    // is PROXIMITY, and if the proximity relation is deemed correct only then issue
    // a Voucher
    // with below 'PROXIMITY' assertion.
    voucher.assertion = Voucher.Assertion.PROXIMITY;

    voucher.idevidIssuer = req.idevidIssuer;
    voucher.serialNumber = req.serialNumber;
    voucher.domainCertRevocationChecks = false;

    try {
      X509Certificate domainCert = reqCerts.get(reqCerts.size() - 1);
      // SubjectPublicKeyInfo spki =
      // SubjectPublicKeyInfo.getInstance(domainCert.getPublicKey().getEncoded());
      // voucher.pinnedDomainSPKI = spki.getEncoded();

      // According to BHC-405: use Domain CA Certificate in voucher response
      voucher.pinnedDomainCert = domainCert.getEncoded();
    } catch (Exception e) {
      // logger.error("get encoded subject-public-key-info failed: " +
      // e.getMessage());
      logger.error("get encoded domain-ca-cert failed: " + e.getMessage(), e);
      return new RestfulVoucherResponse(
          ResponseCode.BAD_REQUEST, "Get encoded domain-ca-cert failed.");
    }

    if (voucher.nonce == null) {
      // The voucher is going to expire in 10 minutes
      voucher.expiresOn = new Date(System.currentTimeMillis() + 1000 * 60 * 10);
    }

    // TODO(wgtdkp): update audit log

    // Generate and send response
    return new RestfulVoucherResponse(voucher);
  }

  private void initResources() {
    CoapResource wellknown = new CoapResource(Constants.WELL_KNOWN);
    CoapResource brski = new CoapResource(Constants.BRSKI);
    VoucherRequestResource rv = new VoucherRequestResource();

    brski.add(rv);
    wellknown.add(brski);
    coapServer.add(wellknown);
  }

  private void initEndPoint() {
    X509Certificate[] certificateChain = new X509Certificate[] {certificate};

    // We currently don't authenticate a client
    CertificateVerifier verifier = new SecurityUtils.DoNothingVerifier(certificateChain);
    CoapEndpoint endpoint =
        SecurityUtils.genCoapServerEndPoint(
            listenPort,
            null /* with verifier, no trust store can be given */,
            privateKey,
            certificateChain,
            verifier);
    coapServer.addEndpoint(endpoint);
  }

  private final int listenPort;

  private final PrivateKey privateKey;

  private final X509Certificate certificate;

  private static final Logger logger = LoggerFactory.getLogger(MASA.class);
}
