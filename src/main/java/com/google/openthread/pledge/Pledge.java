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

package com.google.openthread.pledge;

import COSE.CoseException;
import COSE.Message;
import COSE.MessageTag;
import COSE.OneKey;
import COSE.Sign1Message;
import com.google.openthread.BouncyCastleInitializer;
import com.google.openthread.Constants;
import com.google.openthread.brski.ConstantsBrski;
import com.google.openthread.Credentials;
import com.google.openthread.brski.ExtendedMediaTypeRegistry;
import com.google.openthread.SecurityUtils;
import com.google.openthread.brski.CBORSerializer;
import com.google.openthread.brski.StatusTelemetry;
import com.google.openthread.brski.Voucher;
import com.google.openthread.brski.VoucherRequest;
import com.google.openthread.brski.VoucherSerializationException;
import com.google.openthread.thread.ConstantsThread;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Pledge (i.e., CCM Joiner) is the new device which is to securely bootstrap into the network domain using the Constrained BRSKI protocol.
 */
public final class Pledge extends CoapClient {

  private static final Logger logger = LoggerFactory.getLogger(Pledge.class);

  protected static final ASN1ObjectIdentifier THREAD_DOMAIN_NAME_OID_ASN1 =
      new ASN1ObjectIdentifier(ConstantsThread.THREAD_DOMAIN_NAME_OID);

  private static final SecureRandom NONCE_RNG = new SecureRandom();

  static {
    BouncyCastleInitializer.init();
  }

  public enum CertState {
    NO_CONTACT,
    PROVISIONALLY_ACCEPT,
    ACCEPT
  }

  private String hostURI;
  private Credentials credentials;
  private PrivateKey privateKey;
  private X509Certificate[] certificateChain;
  private boolean isLightweightClientCerts = false;

  private Set<TrustAnchor> trustAnchors;
  private PledgeCertificateVerifier certVerifier;

  private CertPath registrarCertPath;

  /** the Content Format to use for a CSR request */
  private int csrContentFormat = ExtendedMediaTypeRegistry.APPLICATION_PKCS10;

  /**
   * the Content Format to use for a CAcerts request */
  private int caCertsAcceptContentFormat = ExtendedMediaTypeRegistry.APPLICATION_MULTIPART_CORE;

  private PublicKey domainPublicKey;

  /**
   * The pinned domain CA certificate from the voucher, if the voucher pinned a full certificate
   * rather than only a public key (SPKI). Null in the latter case.
   */
  private X509Certificate pinnedDomainCert;

  /**
   * The Explicit TA database: domain CA certificates obtained from the Registrar via a CA
   * certificates request.
   */
  private List<X509Certificate> caCertificates = new ArrayList<>();

  private KeyPair operationalKeyPair;
  private X509Certificate operationalCertificate;

  private CertState certState = CertState.NO_CONTACT;

  private VoucherRequest lastPvr = null;
  private byte[] lastPvrCoseSigned = null;
  private byte[] lastVoucherCoseSigned = null;

  /**
   * Constructing pledge with credentials and uri of the registrar
   *
   * @param privateKey       the manufacturer private key
   * @param certificateChain the manufacturer certificate chain leading to the masa and including masa certificate
   * @param hostURI          uri of host (registrar)
   * @throws PledgeException
   */
  public Pledge(Credentials creds, String hostURI) throws PledgeException {
    super(hostURI);
    init(creds, hostURI, this.isLightweightClientCerts);
    this.credentials = creds;
  }

  public String getHostURI() {
    return hostURI;
  }

  public Pledge(Credentials creds, String host, int port) throws PledgeException {
    this(creds, host + ":" + port);
  }

  public static String getSerialNumber(X509Certificate idevid) {
    try {
      String serialNumber = SecurityUtils.getSerialNumber(idevid);
      if (serialNumber != null) {
        return serialNumber;
      }

      // FIXME check in specs which serial nr is required.
      logger.info("extracting Serial-Number from certificate failed, trying HW-Serial-Number");

      // Base64 encoded to convert it to printable string
      return Base64.toBase64String(SecurityUtils.getHWModuleName(idevid).getSerialNumber().getOctets());
    } catch (CertificateEncodingException e) {
      logger.warn("bad certificate: {}", e.getMessage());
      logger.debug("details:", e);
      return null;
    }
  }

  public X509Certificate getOperationalCert() {
    return operationalCertificate;
  }

  /**
   * Get the Thread Domain Name as encoded in the operational certificate of the Pledge.
   *
   * @return the Thread Domain Name, encoded per Thread spec in an X509v3 extension. Or, "DefaultDomain" if name is not encoded in cert.
   *         Null if no operational cert is present or if the extension couldn't be parsed.
   */
  public String getDomainName() {
    if (operationalCertificate == null) {
      return null;
    }

    try {
      byte[] derThreadDomainNameExt = operationalCertificate.getExtensionValue(ConstantsThread.THREAD_DOMAIN_NAME_OID);
      if (derThreadDomainNameExt == null) {
        // if cert correct but not encoded in there, infer it's the domain name - as defined by Thread spec.
        return ConstantsThread.THREAD_DOMAIN_NAME_DEFAULT;
      }
      // MUST be stored as IA5String wrapped inside an OctetString
      Object obj;
      try (ASN1InputStream outer = new ASN1InputStream(new ByteArrayInputStream(derThreadDomainNameExt))) {
        obj = outer.readObject();
      }
      if (obj instanceof DEROctetString) {
        byte[] derIa5String = ((DEROctetString) obj).getOctets();
        try (ASN1InputStream inner = new ASN1InputStream(new ByteArrayInputStream(derIa5String))) {
          obj = inner.readObject();
        }
        if (obj instanceof DERIA5String) {
          return ((DERIA5String) obj).getString();
        }
      }
    } catch (Exception ex) {
      logger.error("getDomainName(): couldn't parse Thread Domain Name extension in LDevID", ex);
    }

    return null;
  }

  // BRSKI protocol

  /**
   * Request constrained voucher from registrar.
   *
   * @return the constrained voucher
   * @throws IllegalStateException
   * @throws PledgeException
   */
  public Voucher requestVoucher()
      throws PledgeException, ConnectorException, IOException, CoseException,
      VoucherSerializationException {
    if (certState == CertState.ACCEPT) {
      throw new IllegalStateException("registrar certificate already accepted");
    }

    connect();
    if (!certVerifier.isPeerAccepted()) {
      throw new PledgeException("provisional DTLS connection failed");
    }
    certState = CertState.PROVISIONALLY_ACCEPT;
    registrarCertPath = certVerifier.getPeerCertPath();

    // 0. Build constrained voucher request
    VoucherRequest voucherRequest = new VoucherRequest();
    voucherRequest.setConstrained(true);
    voucherRequest.setAssertion(Voucher.Assertion.PROXIMITY);
    voucherRequest.setSerialNumber(getSerialNumber(getIdevidCertificate()));
    voucherRequest.setNonce(generateNonce());

    // X509Certificate.getPublicKey().getEncoded() returns the SubjectPublicKeyInfo DER bytes,
    // which is exactly what proximityRegistrarSPKI expects.
    voucherRequest.setProximityRegistrarSPKI(getRegistrarCertificate().getPublicKey().getEncoded());
    if (!voucherRequest.validate()) {
      throw new PledgeException("validate voucher request failed");
    }

    return requestVoucher(voucherRequest);
  }

  /**
   * Request constrained voucher from registrar using the supplied request 'req'.
   *
   * @param req the voucher request to send to registrar
   * @return the constrained voucher response from the registrar
   * @throws IllegalStateException
   * @throws PledgeException
   */
  public Voucher requestVoucher(VoucherRequest req)
      throws PledgeException, ConnectorException, IOException, CoseException,
      VoucherSerializationException {
    // 0. Send to registrar
    CoapResponse response = sendRequestVoucher(req);

    // 1. Verify response
    if (response == null) {
      throw new PledgeException("voucher request failed: null response");
    }
    if (response.getCode() != ResponseCode.CHANGED) {
      throw new PledgeException("voucher request failed", response);
    }
    if (response.getOptions().getContentFormat()
        != ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_COSE_CBOR) {
      throw new PledgeException(
          String.format(
              "expect voucher in format[%d], but got [%d]",
              ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_COSE_CBOR,
              response.getOptions().getContentFormat()));
    }

    byte[] payload = response.getPayload();
    if (payload == null) {
      throw new PledgeException("unexpected null payload");
    }
    this.lastVoucherCoseSigned = payload;

    // 2. Receive voucher signed by MASA CA
    try {
      // 2.0 verify signature
      Sign1Message msg = (Sign1Message) Message.DecodeFromBytes(payload, MessageTag.Sign1);
      if (!msg.validate(new OneKey(getMASACaCertificate().getPublicKey(), null))) {
        throw new CoseException("COSE-sign1 voucher validation against MASA CA failed");
      }

      // 2.1 verify the voucher
      Voucher voucher = (Voucher) new CBORSerializer().deserialize(msg.GetContent());
      if (!voucher.validate()) {
        throw new PledgeException("unexpected combination of fields in the Voucher");
      }

      if (!voucher.getSerialNumber().equals(req.getSerialNumber())
          || (voucher.getIdevidIssuer() != null
          && !Arrays.equals(
          voucher.getIdevidIssuer(),
          SecurityUtils.getAuthorityKeyIdentifier(getIdevidCertificate())))) {
        throw new PledgeException("serial number or idevid-issuer not matched");
      }
      if (req.getNonce() != null
          && (voucher.getNonce() == null || !Arrays.equals(req.getNonce(), voucher.getNonce()))) {
        throw new PledgeException("nonce not matched");
      }
      // TODO(wgtdkp): if nonce is not presented, make sure that the voucher is not expired

      if (voucher.getPinnedDomainSPKI() != null) {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(voucher.getPinnedDomainSPKI());
        X509EncodedKeySpec xspec = new X509EncodedKeySpec(spki.getEncoded());
        AlgorithmIdentifier keyAlg = spki.getAlgorithm();
        domainPublicKey =
            KeyFactory.getInstance(keyAlg.getAlgorithm().getId()).generatePublic(xspec);
      } else {
        pinnedDomainCert =
            (X509Certificate) SecurityUtils.getCertFactory().generateCertificate(
                new ByteArrayInputStream(voucher.getPinnedDomainCert()));
        domainPublicKey = pinnedDomainCert.getPublicKey();
      }
      if (!validateRegistrar(domainPublicKey)) {
        throw new PledgeException("validate registrar with pinned domain public key failed");
      }

      certState = CertState.ACCEPT;
      certVerifier.setDoVerification(true);

      // Add domain public key to trust anchors
      X500Principal issuer = getRegistrarCertificate().getIssuerX500Principal();
      certVerifier.addTrustAnchor(new TrustAnchor(issuer, domainPublicKey, null));

      return voucher;
    } catch (Exception e) {
      logger.error("voucher processing error: " + e.getMessage(), e);
      throw new PledgeException("voucher processing error: " + e.getMessage(), e);
    }
  }

  // EST protocol

  /**
   * Perform an EST-coaps "CA certificates request" (/crts) to the Registrar, to obtain the set of
   * domain CA certificates (trust anchors). See cBRSKI section 6.7.5 and RFC 9148 section 5.2.
   *
   * <p>The request carries a CoAP Accept Option with {@link #getCaCertsAcceptContentFormat()}.
   * For test purposes, the response is parsed according to the Content-Format the server
   * actually used, so a server that
   * answers in a different (supported) format than requested is still handled.
   *
   * @return the CA certificates returned by the Registrar, in the order sent, which per the spec is
   *         the CA hierarchy order starting at the issuer of the client's LDevID. Never empty.
   * @throws PledgeException if the request failed, or the response was empty or not parseable
   */
  public List<X509Certificate> requestCACertificates()
      throws PledgeException, ConnectorException, IOException {
    setURI(getESTPath() + "/" + ConstantsBrski.CA_CERTIFICATES);
    logger.debug("CA certificates request: CoAP GET {}", getURI());

    int cf = getCaCertsAcceptContentFormat();
    CoapResponse response = get(cf);

    if (response == null) {
      throw new PledgeException("CA certificates request failed: null response");
    }
    if (response.getCode() != ResponseCode.CONTENT) {
      throw new PledgeException("CA certificates request failed", response);
    }

    int contentFormat = response.getOptions().getContentFormat();
    if (contentFormat != cf) {
      logger.warn(
          "CA certificates request: asked for format[{}] but got format[{}]",
              cf,
          contentFormat);
    }

    byte[] payload = response.getPayload();
    if (payload == null || payload.length == 0) {
      throw new PledgeException("CA certificates request: unexpected empty payload");
    }

    List<X509Certificate> certs = parseCACertificates(payload, contentFormat);
    if (certs.isEmpty()) {
      throw new PledgeException("CA certificates request: response contained no CA certificate");
    }
    logger.info("CA certificates request: received {} CA certificate(s)", certs.size());
    return certs;
  }

  /**
   * Parse the payload of a /crts response into the CA certificates it carries.
   *
   * @param payload       the response payload
   * @param contentFormat the CoAP Content-Format of the response
   * @return the CA certificates found, in payload order
   * @throws PledgeException if the Content-Format is not supported, or the payload is malformed
   */
  protected static List<X509Certificate> parseCACertificates(byte[] payload, int contentFormat)
      throws PledgeException {
    List<X509Certificate> certs = new ArrayList<>();
    try {
      switch (contentFormat) {
        case ExtendedMediaTypeRegistry.APPLICATION_MULTIPART_CORE:
          // cBRSKI 6.7.5: a CBOR array alternating content-format and the representation's bytes,
          // e.g. [ 287, h'3082...', 287, h'3082...' ].
          CBORObject container = CBORObject.DecodeFromBytes(payload);
          if (container.getType() != CBORType.Array || container.size() % 2 != 0) {
            throw new PledgeException(
                "multipart-core /crts response is not a CBOR array of (content-format, bytes) pairs");
          }
          for (int i = 0; i < container.size(); i += 2) {
            int partFormat = container.get(i).AsInt32();
            if (partFormat != ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT) {
              // Future documents may define other certificate formats in this container.
              logger.warn("ignoring /crts multipart element with unsupported format[{}]", partFormat);
              continue;
            }
            certs.add(toCertificate(container.get(i + 1).GetByteString()));
          }
          break;

        case ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT:
          // A single DER-encoded certificate.
          certs.add(toCertificate(payload));
          break;

        case ExtendedMediaTypeRegistry.APPLICATION_PKCS7_MIME_CERTS_ONLY:
          // The RFC 9148 container format; a degenerate PKCS#7 SignedData holding only certs.
          for (Certificate cert :
              SecurityUtils.getCertFactory().generateCertificates(
                  new ByteArrayInputStream(payload))) {
            certs.add((X509Certificate) cert);
          }
          break;

        default:
          throw new PledgeException(
              String.format("unsupported Content-Format[%d] in /crts response", contentFormat));
      }
    } catch (PledgeException e) {
      throw e;
    } catch (Exception e) {
      throw new PledgeException("could not parse /crts response: " + e.getMessage(), e);
    }
    return certs;
  }

  private static X509Certificate toCertificate(byte[] der) throws CertificateException {
    return (X509Certificate) SecurityUtils.getCertFactory()
        .generateCertificate(new ByteArrayInputStream(der));
  }

  /**
   * Send Voucher Status telemetry message
   *
   * @param isSuccess     true if success voucher-status is to be reported, false if error is to be reported.
   * @param failureReason human-readable failure reason string to be reported, usually only if isSuccess==false.
   * @throws Exception
   */
  public ResponseCode sendVoucherStatusTelemetry(boolean isSuccess, String failureReason)
      throws Exception {
    // create CBOR data structure
    StatusTelemetry st = StatusTelemetry.create(isSuccess, failureReason);
    setURI(getBRSKIPath() + "/" + ConstantsBrski.VOUCHER_STATUS);
    CoapResponse resp = post(st.serializeToBytes(), ExtendedMediaTypeRegistry.APPLICATION_CBOR);
    return resp.getCode();
  }

  /**
   * Send Enroll Status telemetry message
   *
   * @param isSuccess     true if success enroll-status is to be reported, false if error is to be reported.
   * @param failureReason human-readable failure reason string to be reported, usually only if isSuccess==false.
   * @throws Exception
   */
  public ResponseCode sendEnrollStatusTelemetry(boolean isSuccess, String failureReason)
      throws Exception {
    // create CBOR data structure
    StatusTelemetry st = StatusTelemetry.create(isSuccess, failureReason);
    setURI(getBRSKIPath() + "/" + ConstantsBrski.ENROLL_STATUS);
    CoapResponse resp = post(st.serializeToBytes(), ExtendedMediaTypeRegistry.APPLICATION_CBOR);
    return resp.getCode();
  }

  /**
   * Send generic status telemetry message - for testing.
   *
   * @param resource
   * @param payload
   * @return
   * @throws Exception
   */
  public ResponseCode sendStatusTelemetry(String resource, byte[] payload, int contentFormat)
      throws Exception {
    setURI(getBRSKIPath() + "/" + resource);
    CoapResponse resp = post(payload, contentFormat);
    return resp.getCode();
  }

  /**
   * The EST simpleEnrollment process.
   *
   * @throws Exception
   */
  public void enroll() throws Exception {
    if (certState != CertState.ACCEPT) {
      throw new IllegalStateException("should successfully get voucher first");
    }

    // TODO(wgtdkp): we should enable the certificate verifier now

    // 0. Generate operational keypair
    operationalKeyPair =
        SecurityUtils.genKeyPair(SecurityUtils.KEY_ALGORITHM, SecurityUtils.KEY_SIZE);

    // generate CSR
    String subjectName = this.getIdevidCertificate().getSubjectX500Principal().toString();
    PKCS10CertificationRequest csr =
        genCertificateRequest(
            subjectName,
            operationalKeyPair.getPublic(),
            SecurityUtils.SIGNATURE_ALGORITHM,
            operationalKeyPair.getPrivate());

    X509Certificate cert = requestSigning(csr, ConstantsBrski.SIMPLE_ENROLL);
    if (cert == null) {
      throw new PledgeException("CSR response includes no certificate");
    }

    // Decide whether this LDevID may be accepted, per cBRSKI 6.7.1 steps 3-5. This may involve a
    // CA certificates request (/crts) to establish the domain's trust anchors.
    acceptEnrolledCertificate(cert);

    subjectName = cert.getSubjectX500Principal().getName();
    logger.info("enrolled with operational certificate, subject: {}", subjectName);

    operationalCertificate = cert;

    logger.info("operational certificate (PEM): \n{}", SecurityUtils.toPEMFormat(operationalCertificate));
    logger.info("operational private key (PEM): \n{}", SecurityUtils.toPEMFormat(operationalKeyPair));
  }

  /**
   * Decide whether a freshly enrolled LDevID certificate may be accepted, following steps 3 to 5 of
   * the optimized Pledge enrollment procedure of cBRSKI section 6.7.1.
   *
   * <p>Step 3 is the shortcut: if the pinned domain CA is both a root CA and the direct signer of
   * the LDevID, it is accepted as the domain's trust anchor and no /crts request is needed. The
   * shortcut is unavailable when the voucher pinned only a domain public key (SPKI) instead of a
   * certificate, because whether that key belongs to a root CA cannot then be determined.
   *
   * <p>Otherwise (step 4) the full set of CA certificates is fetched with a /crts request and the
   * LDevID must chain to one of them. If the set cannot be obtained, or no chain can be built, the
   * enrollment is aborted and reported via enrollment status telemetry (step 5).
   *
   * @param ldevid the newly issued LDevID certificate
   * @throws PledgeException if the certificate could not be accepted; enrollment status telemetry
   *                         reporting the failure has then been attempted
   */
  private void acceptEnrolledCertificate(X509Certificate ldevid) throws PledgeException {
    if (pinnedDomainCert != null
        && SecurityUtils.isRootCaCertificate(pinnedDomainCert)
        && SecurityUtils.isSignedBy(ldevid, pinnedDomainCert)) {
      logger.info(
          "pinned domain CA is a root CA and the signer of the LDevID: skipping /crts request");
      caCertificates = Collections.singletonList(pinnedDomainCert);
      return;
    }

    logger.info("optimized enrollment shortcut does not apply: performing /crts request");
    List<X509Certificate> caCerts;
    try {
      caCerts = requestCACertificates();
    } catch (PledgeException | ConnectorException | IOException e) {
      throw abortEnrollment("could not obtain the domain CA certificates: " + e.getMessage(), e);
    }

    if (!SecurityUtils.chainsTo(ldevid, caCerts)) {
      throw abortEnrollment(
          "LDevID certificate does not chain to any of the "
              + caCerts.size()
              + " CA certificate(s) obtained from /crts",
          null);
    }

    // Accept the retrieved CA certificates as the domain trust anchors (Explicit TA database).
    caCertificates = caCerts;
    for (X509Certificate ca : caCerts) {
      certVerifier.addTrustAnchor(new TrustAnchor(ca, null));
    }
    logger.info("LDevID certificate chains to the CA certificate(s) obtained from /crts");
  }

  /**
   * Abort the enrollment process and attempt to report the failure to the Registrar using
   * enrollment status telemetry (/es), per cBRSKI section 6.7.1 step 5.
   *
   * @param reason the human-readable failure reason, reported to the Registrar
   * @param cause  the underlying cause, may be null
   * @return the exception to throw, so callers can write {@code throw abortEnrollment(...)}
   */
  private PledgeException abortEnrollment(String reason, Throwable cause) {
    logger.error("aborting enrollment: {}", reason);
    try {
      sendEnrollStatusTelemetry(false, reason);
    } catch (Exception e) {
      // Reporting is a best effort: the enrollment failure itself is what must be propagated.
      logger.warn("could not report enrollment failure to Registrar: {}", e.getMessage());
      logger.debug("details:", e);
    }
    return new PledgeException("enrollment aborted: " + reason, cause);
  }

  /**
   * The EST simpleReenrollment.
   *
   * @throws Exception
   */
  public void reenroll() throws Exception {
    if (certState != CertState.ACCEPT) {
      throw new IllegalStateException("should successfully get voucher first");
    }

    if (operationalCertificate == null || domainPublicKey == null) {
      throw new IllegalStateException("should enroll first");
    }

    // Reset the endpoint, so the pledge will rehandshake
    initEndpoint(privateKey, certificateChain, certVerifier);

    // generate CSR
    String subjectName = getOperationalCert().getSubjectX500Principal().toString();
    PKCS10CertificationRequest csr =
        genCertificateRequest(
            subjectName,
            operationalKeyPair.getPublic(),
            SecurityUtils.SIGNATURE_ALGORITHM,
            operationalKeyPair.getPrivate());

    X509Certificate cert = requestSigning(csr, ConstantsBrski.SIMPLE_REENROLL);
    if (cert == null) {
      throw new PledgeException("CSR response includes no certificate");
    }

    cert.verify(domainPublicKey);

    subjectName = cert.getSubjectX500Principal().getName();
    logger.info("renewed operational certificate, subject: " + subjectName);

    operationalCertificate = cert;
  }

  public CoapResponse sayHello() throws IOException, ConnectorException {
    setURI(hostURI + "/" + Constants.HELLO_PATH);
    return get();
  }

  public CoapResponse discoverResources() throws IOException, ConnectorException {
    setURI(hostURI + ConstantsBrski.CORE_PATH);
    return get();
  }

  public void reset() throws PledgeException {
    shutdown();
    init(credentials, hostURI, this.isLightweightClientCerts);
  }

  public CertState getState() {
    return certState;
  }

  public X509Certificate getIdevidCertificate() {
    return certificateChain[0];
  }

  public X509Certificate getMASACaCertificate() {
    return certificateChain[certificateChain.length - 1];
  }

  /**
   * Set the checking of the CMC-RA (Registration Authority) flag in the Registrar's certificate to on (true) or off (false).
   *
   * @param doCheckCmcRa
   */
  public void setCmcRaCheck(boolean doCheckCmcRa) {
    this.certVerifier.setCmcRaCheck(doCheckCmcRa);
  }

  /**
   * Set the use of 'lightweight' client certificates in the DTLS handshake for this Pledge. If 'lightweight', then the MASA CA root certificate will be omitted from the client's Certificate message
   * in the DTLS handshake to reduce network load. The Registrar will anyhow have means to obtain MASA CA certificates (e.g. by contacting the MASA via the MASA URI, or a sales integration process,
   * etc.
   *
   * @param isSetLightweight whether to use 'lightweight' (true) client certificates or not (false)
   * @throws PledgeException in case reconfiguration of the Pledge failed for some reason
   */
  public void setLightweightClientCertificates(boolean isSetLightweight) throws PledgeException {
    if (isSetLightweight != this.isLightweightClientCerts) {
      this.isLightweightClientCerts = isSetLightweight;
      this.init(credentials, hostURI, this.isLightweightClientCerts);
    }
  }

  /** Generate a fresh 64-bit cryptographically strong nonce. */
  public static byte[] generateNonce() {
    byte[] nonce = new byte[8];
    NONCE_RNG.nextBytes(nonce);
    return nonce;
  }

  public VoucherRequest getLastPvr() {
    return this.lastPvr;
  }

  public byte[] getLastPvrCoseSigned() {
    return this.lastPvrCoseSigned;
  }

  public byte[] getLastVoucherCoseSigned() {
    return this.lastVoucherCoseSigned;
  }

  private void init(Credentials creds, String hostURI, boolean isLightweightClientCerts)
      throws PledgeException {

    // remove trailing slash from hostURI - avoid host//path situations leading to a leading, empty
    // CoAP Uri-Path Option. (=bug)
    while (hostURI.endsWith("/")) {
      hostURI = hostURI.substring(0, hostURI.length() - 1);
    }
    this.hostURI = hostURI;

    try {
      this.privateKey = creds.getPrivateKey();
      this.certificateChain = creds.getCertificateChain();
    } catch (GeneralSecurityException ex) {
      throw new PledgeException("Exception accessing credentials: " + ex.getMessage(), ex);
    }
    if (certificateChain.length < 2) {
      throw new PledgeException(
          "error in Pledge certificate chain (MASA CA and/or IDevID cert missing?)");
    }

    this.trustAnchors = new HashSet<>();
    this.trustAnchors.add(new TrustAnchor(getMASACaCertificate(), null));

    this.certVerifier = new PledgeCertificateVerifier(this.trustAnchors);

    registrarCertPath = null;
    domainPublicKey = null;
    pinnedDomainCert = null;
    caCertificates = new ArrayList<>();
    operationalKeyPair = null;
    operationalCertificate = null;
    certState = CertState.NO_CONTACT;

    X509Certificate[] clientCertChain = this.certificateChain;
    if (isLightweightClientCerts) {
      clientCertChain = new X509Certificate[]{this.certificateChain[0]};
    }
    initEndpoint(this.privateKey, clientCertChain, this.certVerifier);
  }

  private CoapResponse sendRequestVoucher(VoucherRequest voucherRequest)
      throws IOException, ConnectorException, CoseException, VoucherSerializationException {
    setURI(getBRSKIPath() + "/" + ConstantsBrski.REQUEST_VOUCHER);
    byte[] vrEncoded = new CBORSerializer().serialize(voucherRequest);

    // COSE_Sign1 signing of the CBOR
    byte[] payload = SecurityUtils.genCoseSign1Message(privateKey, SecurityUtils.COSE_SIGNATURE_ALGORITHM, vrEncoded);
    // store the transmitted PVR
    this.lastPvr = voucherRequest;
    this.lastPvrCoseSigned = payload;
    logger.debug("Voucher request: CoAP POST {} ", getURI());
    return post(payload, ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_COSE_CBOR);
  }

  private CoapResponse sendCSR(PKCS10CertificationRequest csr, String resource)
      throws IOException, ConnectorException {
    setURI(getESTPath() + "/" + resource);
    return post(csr.getEncoded(), getCsrContentFormat());
  }

  private X509Certificate requestSigning(PKCS10CertificationRequest csr, String resource)
      throws Exception {
    // 0. Send CSR request and get response
    CoapResponse response = sendCSR(csr, resource);
    if (response == null) {
      throw new PledgeException("CSR request failed: null response");
    }
    if (response.getCode() != ResponseCode.CHANGED) {
      throw new PledgeException("CSR request failed", response);
    }

    if (response.getOptions().getContentFormat()
        != ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT) {
      throw new PledgeException(
          String.format(
              "expect CSR response in format[%d], but got [%d]",
              ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT,
              response.getOptions().getContentFormat()));
    }

    byte[] payload = response.getPayload();
    if (payload == null) {
      throw new PledgeException("unexpected null payload");
    }

    // 1. Decode PKCS7 message in CBOR byte string
    return (X509Certificate) SecurityUtils.getCertFactory()
        .generateCertificate(new ByteArrayInputStream(payload));
  }

  private PKCS10CertificationRequest genCertificateRequest(
      String name, PublicKey publicKey, String signatureAlgorithm, PrivateKey signingPrivateKey)
      throws OperatorCreationException, PKCSException, GeneralSecurityException {
    X500Name subject = new X500Name(name);
    ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).build(signingPrivateKey);
    PKCS10CertificationRequest csr =
        new JcaPKCS10CertificationRequestBuilder(subject, publicKey).build(signer);
    ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().build(publicKey);
    if (!csr.isSignatureValid(verifier)) {
      throw new GeneralSecurityException("signature verification failed");
    }
    return csr;
  }

  private void initEndpoint(
      PrivateKey privateKey,
      X509Certificate[] certificateChain,
      NewAdvancedCertificateVerifier verifier) {
    CoapEndpoint endpoint =
        SecurityUtils.genCoapClientEndPoint(
            new X509Certificate[]{}, privateKey, certificateChain, verifier, false);
    setEndpoint(endpoint);
    // Californium's CoapClient pins the destination EndpointContext from the previous response
    // to keep follow-up requests on the same DTLS session. When we swap the endpoint (e.g. for
    // re-enrollment or reset) that pinned context refers to a session that no longer exists, and
    // the strict context matcher would drop the next request. Clear it so the freshly created
    // endpoint performs a new handshake.
    setDestinationContext(null);
  }

  // We need a provisional DTLS session before requesting
  // voucher since we need registrar certificate. But there
  // is no 'connect' API to build this session ahead. We
  // here send a 'CoAP ping' to registrar to have this session built.
  private void connect() {
    setURI(getBRSKIPath());
    logger.debug("DTLS session establishment and sending CoAP ping...");
    ping();
  }

  private boolean validateRegistrar(PublicKey domainPublicKey) {
    try {
      List<? extends Certificate> certs = registrarCertPath.getCertificates();
      X509Certificate lastCert = (X509Certificate) certs.get(certs.size() - 1);

      Set<TrustAnchor> trustAnchors = new HashSet<>();

      // Build trust anchor with the last certificate's issuer name and public key of
      // Domain CA.
      trustAnchors.add(new TrustAnchor(lastCert.getIssuerX500Principal(), domainPublicKey, null));
      PKIXParameters params = new PKIXParameters(trustAnchors);

      params.setRevocationEnabled(false);
      CertPathValidator validator = CertPathValidator.getInstance("PKIX");
      validator.validate(registrarCertPath, params);
      return true;
    } catch (GeneralSecurityException e) {
      logger.error("Certificate validation failed: " + e.getMessage());
      return false;
    }
  }

  private X509Certificate getRegistrarCertificate() {
    return (X509Certificate) registrarCertPath.getCertificates().get(0);
  }

  private String getESTPath() {
    return hostURI + ConstantsBrski.EST_PATH;
  }

  private String getBRSKIPath() {
    return hostURI + ConstantsBrski.BRSKI_PATH;
  }

  public int getCsrContentFormat() {
    return csrContentFormat;
  }

  public void setCsrContentFormat(int csrContentFormat) {
    this.csrContentFormat = csrContentFormat;
  }

  public int getCaCertsAcceptContentFormat() {
    return caCertsAcceptContentFormat;
  }

  public void setCaCertsAcceptContentFormat(int caCertsAcceptContentFormat) {
    this.caCertsAcceptContentFormat = caCertsAcceptContentFormat;
  }

  /**
   * Get the domain CA certificates that this Pledge currently trusts (its Explicit TA database),
   * as established during enrollment.
   *
   * @return the trusted domain CA certificates; empty if the Pledge has not enrolled yet
   */
  public List<X509Certificate> getCaCertificates() {
    return Collections.unmodifiableList(caCertificates);
  }
}
