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
import com.google.openthread.brski.ConstantsBrski;
import com.google.openthread.Credentials;
import com.google.openthread.InsecureTrustManager;
import com.google.openthread.RequestDumper;
import com.google.openthread.SecurityUtils;
import com.google.openthread.brski.CBORSerializer;
import com.google.openthread.brski.JSONSerializer;
import com.google.openthread.brski.VoucherSerializationException;
import com.google.openthread.brski.RestfulVoucherResponse;
import com.google.openthread.brski.Voucher;
import com.google.openthread.brski.VoucherRequest;
import com.upokecenter.cbor.CBORObject;
import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.BlockingHandler;
import io.undertow.server.handlers.PathHandler;
import io.undertow.util.HttpString;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.util.encoders.Hex;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class MASA {

  private static final Logger logger = LoggerFactory.getLogger(MASA.class);

  static {
    BouncyCastleInitializer.init();
  }

  /** Expiry for vouchers that do not carry a Pledge nonce (BRSKI §5.3 — see MASA policy). */
  private static final Duration NONCELESS_VOUCHER_LIFETIME = Duration.ofMinutes(10);

  private static final String HTTP_WELCOME_PAGE =
      "<html><head><title>Test MASA server</title></head><body><h1>Test MASA server</h1><p>Use /.well-known/brski/requestvoucher for Voucher Requests. Formats application/voucher-cms+json and application/voucher-cose+cbor are supported for the request.</p></body></html>";

  private final int listenPort;
  private final Credentials credentials; // MASA server credentials
  private final Credentials credentialsCa; // MASA CA credentials (for signing)
  private Undertow httpServer;

  public MASA(Credentials credentials, Credentials credentialsCa, int port) throws MASAException {
    this.credentials = credentials;
    this.credentialsCa = credentialsCa;
    this.listenPort = port;
    try {
      initHttpServer();
    } catch (Exception ex) {
      throw new MASAException("HTTP server init failed: " + ex.getMessage(), ex);
    }
  }

  public int getListenPort() {
    return listenPort;
  }

  public void start() {
    if (httpServer != null) {
      httpServer.start();
    }
  }

  public void stop() {
    if (httpServer != null) {
      httpServer.stop();
    }
  }

  /**
   * Logs every received HTTP request - including ones for unknown paths or with an unsupported
   * method - before delegating to the actual resource handlers. For interop testing.
   */
  final class RequestLoggingHttpHandler implements HttpHandler {
    private final HttpHandler next;

    RequestLoggingHttpHandler(HttpHandler next) {
      this.next = next;
    }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
      logger.info(
          "received HTTP request: {} {} from {}",
          exchange.getRequestMethod(),
          exchange.getRequestURI(),
          exchange.getSourceAddress());
      next.handleRequest(exchange);
    }
  }

  final class RootResourceHttpHandler implements HttpHandler {
    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
      if (!exchange.getRequestMethod().equals(HttpString.tryFromString("GET"))) {
        exchange.setStatusCode(405);
        return;
      }

      exchange.setStatusCode(200);
      exchange.getOutputStream().write(HTTP_WELCOME_PAGE.getBytes());
    }
  }

  final class VoucherRequestHttpHandler implements HttpHandler {
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
        case ConstantsBrski.MEDIA_TYPE_VOUCHER_CMS_JSON:
          try {
            reqContent = SecurityUtils.decodeCMSSignedMessage(body, reqCerts); // decode CMS, get embedded reqCerts back.
          } catch (Exception e) {
            logger.error("CMS signed voucher request error: {}", e.getMessage());
            logger.debug("details:", e);
            exchange.setStatusCode(403);
            exchange.setReasonPhrase("CMS signing/decoding error in voucher request: " + e.getMessage());
            return;
          }
          break;

        case ConstantsBrski.MEDIA_TYPE_VOUCHER_COSE_CBOR:
        case ConstantsBrski.MEDIA_TYPE_COSE_SIGN1:
        case ConstantsBrski.MEDIA_TYPE_COSE:
          try {
            // Verify signature
            sign1Msg = (Sign1Message) Message.DecodeFromBytes(body, MessageTag.Sign1);
            // look for set of x509 certificates in x5bag header parameter, per cBRSKI
            reqCerts = SecurityUtils.getX5BagCertificates(sign1Msg);
            if (reqCerts == null || reqCerts.isEmpty()) {
              throw new CoseException("Registrar signing cert chain not found in X5Bag field of voucher request");
            }
            // The RVR is signed by the Registrar, whose signing certificate is the one carrying
            // the CMC-RA EKU. Find it explicitly rather than assuming it is first in the x5bag:
            // the x5bag (RFC 9360) is unordered, and also carries the Pledge's IDevID chain.
            X509Certificate rvrSignerCert = SecurityUtils.findCmcRaCert(reqCerts);
            if (rvrSignerCert == null) {
              throw new CoseException(
                  "Registrar (CMC-RA) signing certificate not found in x5bag of voucher request");
            }
            if (!sign1Msg.validate(new OneKey(rvrSignerCert.getPublicKey(), null))) {
              logger.debug(
                  "RVR signature validation failed against selected CMC-RA cert (subject={}):\n{}",
                  rvrSignerCert.getSubjectX500Principal(),
                  rvrSignerCert);
              throw new CoseException("COSE-sign1 voucher validation against CMC-RA cert failed");
            }

          } catch (Exception e) {
            logger.error("CBOR signed voucher request error: {}", e.getMessage());
            logger.debug("detail:", e);
            exchange.setStatusCode(403);
            exchange.setReasonPhrase("COSE signing/decoding error in voucher request: " + e.getMessage());
            return;
          }
          break;

        default:
          exchange.setStatusCode(400);
          exchange.setReasonPhrase("Unsupported voucher request format: " + contentType);
          return;
      }

      switch (contentType) {
        case ConstantsBrski.MEDIA_TYPE_VOUCHER_CMS_JSON:
          try {
            req = (VoucherRequest) new JSONSerializer().deserialize(reqContent);
          } catch (Exception e) {
            logger.error("JSON deserialization error: {}", e.getMessage(), e);
            exchange.setStatusCode(400);
            exchange.setReasonPhrase("JSON deserialization error: " + e.getMessage());
            return;
          }
          break;

        case ConstantsBrski.MEDIA_TYPE_VOUCHER_COSE_CBOR:
        case ConstantsBrski.MEDIA_TYPE_COSE_SIGN1:
        case ConstantsBrski.MEDIA_TYPE_COSE:
          try {
            req = (VoucherRequest) new CBORSerializer().deserialize(sign1Msg.GetContent());
          } catch (Exception e) {
            logger.error("CBOR deserialization error: {}", e.getMessage(), e);
            exchange.setStatusCode(400);
            exchange.setReasonPhrase("CBOR deserialization error: " + e.getMessage());
            return;
          }
          break;

        default:
          throw new MASAException("Internal MASA error");
      }

      Voucher voucher = new Voucher();
      voucher.setConstrained(true);
      final RestfulVoucherResponse resp = processVoucherRequest(req, voucher, reqCerts);

      // Generate and send response
      if (resp.isSuccess()) {
        exchange.setStatusCode(200);
        exchange
            .getResponseHeaders()
            .put(HttpString.tryFromString("Content-Type"),
                ConstantsBrski.MEDIA_TYPE_VOUCHER_COSE_CBOR);
        byte[] content = new CBORSerializer().serialize(resp.getVoucher());
        byte[] payload =
            SecurityUtils.genCoseSign1Message(credentialsCa.getPrivateKey(), SecurityUtils.COSE_SIGNATURE_ALGORITHM, content);
        logger.info("returning 200 OK with Voucher: {}", Hex.toHexString(payload));
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

  /**
   * Process incoming Voucher Request (and accompanying certificates of Registrar) and evaluate into a generic RESTful response. This response can be an error, or success, and can then be served by
   * the respective CoAP or HTTP (or other) protocol server back to the client.
   *
   * @param req      received Voucher Request object
   * @param voucher  a new Voucher object of the right type, to be returned upon success in RestfulResponse.
   * @param reqCerts accompanying certificates of the Registrar to verify against
   * @return a RESTful response that is either error (with diagnostic message) or success (with Voucher)
   */
  private RestfulVoucherResponse processVoucherRequest(
      Voucher req, Voucher voucher, List<X509Certificate> reqCerts) {

    if (!req.validate() || reqCerts.isEmpty()) {
      logger.warn("invalid fields in the voucher request");
      return new RestfulVoucherResponse(ResponseCode.BAD_REQUEST, "invalid fields in the voucher request");
    }

    // TODO:
    // Section 5.5.1 BRSKI: MASA renewal of expired vouchers

    // TODO:
    // Section 5.5.2 BRSKI: MASA verification of voucher-request signature
    // consistency

    // The RVR x5bag (cBRSKI section 9.2.1) holds both the Registrar's own signing chain and the
    // Pledge's IDevID chain, in no guaranteed order. Identify each participant's certificate by
    // its properties rather than by position: the Pledge-side (IDevID) certificates are those that
    // chain to this MASA's own CA, the Registrar-side certificates are the rest.
    final X509Certificate masaCaCert;
    try {
      masaCaCert = credentialsCa.getCertificate();
    } catch (Exception ex) {
      logger.error("cannot access MASA CA certificate: {}", ex.getMessage(), ex);
      return new RestfulVoucherResponse(
          ResponseCode.INTERNAL_SERVER_ERROR, "MASA CA certificate unavailable");
    }

    List<X509Certificate> registrarChain = new ArrayList<>();
    for (X509Certificate c : reqCerts) {
      if (!SecurityUtils.chainsTo(c, Collections.singletonList(masaCaCert), reqCerts)) {
        registrarChain.add(c);
      }
    }

    // Section 5.5.2 / 9.2.1: the Registrar must have copied the Pledge's IDevID chain into the RVR
    // x5bag. This MASA does not store the IDevIDs it issued, so it recognises the IDevID
    // structurally — an end-entity (non-CA) certificate carrying a MASA URI (RFC 8995 2.3) — and
    // requires it to chain to this MASA's own CA.
    X509Certificate idevid = SecurityUtils.findPledgeIdevid(reqCerts);
    if (idevid == null) {
      final String msg =
          "no Pledge IDevID (end-entity certificate with MASA URI) in voucher request x5bag";
      logger.warn(msg);
      return new RestfulVoucherResponse(ResponseCode.FORBIDDEN, msg);
    }
    if (!SecurityUtils.chainsTo(idevid, Collections.singletonList(masaCaCert), reqCerts)) {
      final String msg = "Pledge IDevID certificate does not chain to the MASA CA";
      logger.warn(msg);
      return new RestfulVoucherResponse(ResponseCode.FORBIDDEN, msg);
    }

    // Section 5.5.3 / RFC 8995 5.6: the Registrar must present a certificate with the CMC-RA EKU.
    X509Certificate registrarCert = SecurityUtils.findCmcRaCert(registrarChain);
    if (registrarCert == null) {
      final String msg = "Registrar certificate did not have RA set in Extended Key Usage.";
      logger.warn(msg);
      return new RestfulVoucherResponse(ResponseCode.FORBIDDEN, msg); // per RFC 8995 5.6
    }

    // TODO:
    // Section 5.5.4 BRSKI: MASA revocation checking of registrar (certificate)

    // TODO:
    // Section 5.5.5 BRSKI: MASA verification of pledge prior-signed-voucher-request
    if (req.getPriorSignedVoucherRequest() == null) {
      final String msg = "missing priorSignedVoucherRequest";
      logger.warn(msg);
      return new RestfulVoucherResponse(ResponseCode.BAD_REQUEST, msg);
    }

    // recreate it
    Sign1Message sign1Msg = null;
    try {
      sign1Msg = (Sign1Message) Message.DecodeFromBytes(req.getPriorSignedVoucherRequest(), MessageTag.Sign1);
      // validate it TODO
    } catch (Exception ex) {
      final String msg = "Couldn't parse priorSignedVoucherRequest COSE.";
      logger.warn(msg, ex);
      return new RestfulVoucherResponse(ResponseCode.BAD_REQUEST, msg);
    }
    VoucherRequest pledgeReq;
    try {
      pledgeReq = (VoucherRequest) new CBORSerializer().fromCBOR(CBORObject.DecodeFromBytes(sign1Msg.GetContent()));
    } catch (VoucherSerializationException ex) {
      final String msg = "invalid priorSignedVoucherRequest contents: " + ex.getMessage();
      logger.warn(msg);
      return new RestfulVoucherResponse(ResponseCode.BAD_REQUEST, msg);
    }

    // check prox assertion
    if (pledgeReq.getAssertion() != Voucher.Assertion.PROXIMITY) {
      final String msg = "priorSignedVoucherRequest: Assertion != PROXIMITY";
      logger.warn(msg);
      return new RestfulVoucherResponse(ResponseCode.BAD_REQUEST, msg);
    }

    // check serial is equal
    if (!req.getSerialNumber().equals(pledgeReq.getSerialNumber())) {
      final String msg = "priorSignedVoucherRequest.getSerialNumber() != RegistrarRequest.getSerialNumber()";
      logger.warn(msg);
      return new RestfulVoucherResponse(ResponseCode.BAD_REQUEST, msg);
    }

    // TODO:
    // Section 5.5.6 BRSKI: MASA pinning of registrar

    // TODO:
    // Section 5.5.7 BRSKI: MASA nonce handling

    // Section 5.6 BRSKI: MASA and Registrar Voucher Response

    voucher.setCreatedOn(new Date());
    voucher.setNonce(req.getNonce());
    voucher.setAssertion(Voucher.Assertion.PROXIMITY);

    // don't include idevidIssuer - optional field and only needed in case of serial number clashes.
    // TODO make idevidissuer configurable! During tests it is needed.
    voucher.setSerialNumber(req.getSerialNumber());
    voucher.setDomainCertRevocationChecks(false);

    try {
      // Pin the highest-level CA of the Registrar-signing-chain (its Domain CA).
      X509Certificate domainCert = SecurityUtils.topOfChain(registrarChain);
      // According to BHC-405: use Domain CA Certificate in voucher response
      voucher.setPinnedDomainCert(domainCert.getEncoded());
    } catch (Exception e) {
      logger.error("get encoded domain-ca-cert failed: " + e.getMessage(), e);
      return new RestfulVoucherResponse(ResponseCode.INTERNAL_SERVER_ERROR, "Get encoded domain-ca-cert failed.");
    }

    if (voucher.getNonce() == null) {
      voucher.setExpiresOn(Date.from(Instant.now().plus(NONCELESS_VOUCHER_LIFETIME)));
    }

    // TODO: update audit log

    // Generate and send response
    return new RestfulVoucherResponse(voucher);
  }

  private void initHttpServer()
      throws GeneralSecurityException, UnknownHostException, SocketException {
    KeyManager[] keyManagers;
    KeyManagerFactory keyManagerFactory =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(credentials.getKeyStore(), credentials.getPassword().toCharArray());
    keyManagers = keyManagerFactory.getKeyManagers();

    TrustManager[] trustManagers;
    trustManagers = new X509TrustManager[]{new InsecureTrustManager()};

    SSLContext httpSsl = SSLContext.getInstance("TLS");
    httpSsl.init(keyManagers, trustManagers, null);
    PathHandler masaPathHandler =
        new PathHandler()
            .addExactPath("/", new BlockingHandler(new RootResourceHttpHandler()))
            .addExactPath(ConstantsBrski.BRSKI_PATH + "/" + ConstantsBrski.REQUEST_VOUCHER_HTTP,
                new BlockingHandler(new VoucherRequestHttpHandler()));
    // "::" binds to all available IPv4 and IPv6 addresses on a dual-stack JVM.
    httpServer =
        Undertow.builder()
            .addHttpsListener(listenPort, "::", httpSsl)
            .setHandler(new RequestLoggingHttpHandler(masaPathHandler))
            .build();
  }
}
