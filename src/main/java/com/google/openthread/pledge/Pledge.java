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
import com.google.openthread.thread.ConstantsThread;
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
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Pledge (i.e., CCM Joiner) is the new device which is to securely bootstrap into the network domain using the Constrained BRSKI protocol.
 */
public class Pledge extends CoapClient {

  protected static final ASN1ObjectIdentifier THREAD_DOMAIN_NAME_OID_ASN1 =
      new ASN1ObjectIdentifier(ConstantsThread.THREAD_DOMAIN_NAME_OID); // per Thread 1.2 spec

  static {
    BouncyCastleInitializer.init();
  }

  public enum CertState {
    NO_CONTACT,
    PROVISIONALLY_ACCEPT,
    ACCEPT
  }

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
      ASN1InputStream asn1Input = new ASN1InputStream(new ByteArrayInputStream(derThreadDomainNameExt));
      Object obj = asn1Input.readObject();
      if (obj instanceof DEROctetString) {
        byte[] derIa5String = ((DEROctetString) obj).getOctets();
        asn1Input = new ASN1InputStream(new ByteArrayInputStream(derIa5String));
        obj = asn1Input.readObject();
        if (obj instanceof DERIA5String) {
          return ((DERIA5String)obj).toString();
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
  public Voucher requestVoucher() throws Exception {
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
    voucherRequest.assertion = Voucher.Assertion.PROXIMITY;
    voucherRequest.serialNumber = getSerialNumber(getIdevidCertificate());
    voucherRequest.nonce = generateNonce();

    // FIXME(wgtdkp): should use 'subjectPublicKeyInfo' -> note, seems to already use this properly.
    voucherRequest.proximityRegistrarSPKI = getRegistrarCertificate().getPublicKey().getEncoded();
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
      throws PledgeException, ConnectorException, IOException, CoseException {
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

      if (!voucher.serialNumber.equals(req.serialNumber)
          || (voucher.idevidIssuer != null
          && !Arrays.equals(
          voucher.idevidIssuer,
          SecurityUtils.getAuthorityKeyIdentifier(getIdevidCertificate())))) {
        throw new PledgeException("serial number or idevid-issuer not matched");
      }
      if (req.nonce != null
          && (voucher.nonce == null || !Arrays.equals(req.nonce, voucher.nonce))) {
        throw new PledgeException("nonce not matched");
      }
      // TODO(wgtdkp): if nonce is not presented, make sure that the voucher is not expired

      if (voucher.pinnedDomainSPKI != null) {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(voucher.pinnedDomainSPKI);
        X509EncodedKeySpec xspec = new X509EncodedKeySpec(spki.getEncoded());
        AlgorithmIdentifier keyAlg = spki.getAlgorithm();
        domainPublicKey =
            KeyFactory.getInstance(keyAlg.getAlgorithm().getId()).generatePublic(xspec);
      } else {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Certificate domainCert =
            certFactory.generateCertificate(new ByteArrayInputStream(voucher.pinnedDomainCert));
        domainPublicKey = domainCert.getPublicKey();
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
      throw new PledgeException("voucher processing error: " + e.getMessage());
    }
  }

  // EST protocol

  // /.well-known/est/cacerts
  public void requestCACertificate() {
    // TODO(wgtdkp):
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

    cert.verify(domainPublicKey);

    subjectName = cert.getSubjectX500Principal().getName();
    logger.info("enrolled with operational certificate, subject: {}", subjectName);

    operationalCertificate = cert;

    logger.info("operational certificate (PEM): \n{}", SecurityUtils.toPEMFormat(operationalCertificate));
    logger.info("operational private key (PEM): \n{}", SecurityUtils.toPEMFormat(operationalKeyPair));
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
    setURI(hostURI + "/" + Constants.HELLO);
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

  // Generate 64-bit cryptographically strong random/pseudo-random number
  public static byte[] generateNonce() {
    SecureRandom random = new SecureRandom();

    // FIXME(wgtdkp): generateSeed() will hang on GCE VM.
    random = new SecureRandom(random.generateSeed(20));
    byte[] nonce = new byte[8];
    random.nextBytes(nonce);
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
      logger.error("Exception accessing credentials", ex);
      throw new PledgeException("Exception accessing credentials: " + ex.getMessage());
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
      throws IOException, ConnectorException, CoseException {
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
    return post(csr.getEncoded(), csrContentFormat);
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
    // CBORObject cbor = CBORObject.DecodeFromBytes(payload);
    // CMSSignedData data = new CMSSignedData(cbor.GetByteString());
    // return extractCertFromCMSSignedData(data);
    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(payload));
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

  private X509Certificate extractCertFromCMSSignedData(CMSSignedData signedData)
      throws CertificateException {
    Store<X509CertificateHolder> certStore = signedData.getCertificates();
    for (X509CertificateHolder holder : certStore.getMatches(null)) {
      return new JcaX509CertificateConverter().getCertificate(holder);
    }
    return null;
  }

  private void initEndpoint(
      PrivateKey privateKey, X509Certificate[] certificateChain, CertificateVerifier verifier) {
    CoapEndpoint endpoint =
        SecurityUtils.genCoapClientEndPoint(
            new X509Certificate[]{}, privateKey, certificateChain, verifier, false);
    setEndpoint(endpoint);
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

  private String hostURI;
  private Credentials credentials;
  private PrivateKey privateKey;
  private X509Certificate[] certificateChain;
  private boolean isLightweightClientCerts = false;

  private Set<TrustAnchor> trustAnchors;
  PledgeCertificateVerifier certVerifier;

  private CertPath registrarCertPath;

  /**
   * the Content Format to use for a CSR request
   */
  public int csrContentFormat = ExtendedMediaTypeRegistry.APPLICATION_PKCS10;

  private PublicKey domainPublicKey;

  private KeyPair operationalKeyPair;
  private X509Certificate operationalCertificate;

  private CertState certState = CertState.NO_CONTACT;

  private VoucherRequest lastPvr = null;
  private byte[] lastPvrCoseSigned = null;
  private byte[] lastVoucherCoseSigned = null;

  private static Logger logger = LoggerFactory.getLogger(Pledge.class);
}
