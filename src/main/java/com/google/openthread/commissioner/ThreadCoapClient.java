package com.google.openthread.commissioner;

import java.io.IOException;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.openthread.Constants;
import com.google.openthread.commissioner.tlv.*;
import COSE.CoseException;
import se.sics.ace.cwt.CWT;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

/*** 
 * A Commissioner Coap client that can send Thread-specific management commands to a Border Agent (BA), 
 * for CCM or non-CCM networks. It can generate signed messages, by using a Token.
 */
public class ThreadCoapClient extends CoapClient {

  protected boolean doIncludeCOM_TOK = true;
  protected boolean doIncludeCOM_TOK_SIG = true;
  protected boolean doUDP_TX_Encapsulation = false;
  protected String server;
  protected CWT comTok = null;
  
  private static Logger logger = LoggerFactory.getLogger(ThreadCoapClient.class);
  private static int signingSequenceNumber = 0;
  
  public ThreadCoapClient(String serverEndPoint) {
    doIncludeCOM_TOK = false;
    doIncludeCOM_TOK_SIG = false;
    server = serverEndPoint;
  }
  
  public ThreadCoapClient(String serverEndPoint, CWT token) {
    comTok = token;
    server = serverEndPoint;
  }
  
  public void setIncludeCOM_TOK(boolean isInclude) {
    this.doIncludeCOM_TOK = isInclude;
  }
  
  public void setIncludeCOM_TOK_SIG(boolean isInclude) {
    this.doIncludeCOM_TOK_SIG = isInclude;
  }
  
  public void setUDP_TX_Encapsulation(boolean doEncapsulate) {
    throw new NotImplementedException();
  }
  
  /**
   * send a TMF request with TLV payload to the server endpoint.
   * 
   * @param uri            the CoAP request Uri-Path
   * @param tlvs           the TLVs payload
   * 
   * @throws IOException
   * @throws CoseException
   * @throws ConnectorException
   */
  public CoapResponse sendTMFRequest(final String uri, TLVset tlvs) throws IOException, CoseException, ConnectorException {
      logger.trace("sendTMFRequest(Uri={},TLVs={},COM_TOK={},COM_TOK_SIG={},udpTx={},seq={})", uri, tlvs, doIncludeCOM_TOK, doIncludeCOM_TOK_SIG, 
              doUDP_TX_Encapsulation, signingSequenceNumber);

      // sign URIs and TLVs with COM_TOK_SIG
      if (doIncludeCOM_TOK_SIG)
          signCoap(uri, tlvs);

      if (doIncludeCOM_TOK) {
          // NOTE: for commands in /n,/a,/b namespace the "TLVA_COMMISSIONER_TOKEN" would
          // need to be added.
          // its value is equal to TLVC_COMMISSIONER_TOKEN so we don't check for that
          // here.
          tlvs.put(TLV.C_COMMISSIONER_TOKEN, comTok.encode().EncodeToBytes() );
      }
      
      // create the coap request
      this.setURI(server + "/" + uri);
      return this.post(tlvs.serialize(), MediaTypeRegistry.APPLICATION_OCTET_STREAM);

  }
  
  /**
   * send COMM_PET.req message
   * @param commissionerId
   * @return
   */
  public CoapResponse sendCOMM_PET_req(String commissionerId) throws IOException, CoseException, ConnectorException {
    TLVset tlvs = new TLVset();
    tlvs.put(new CommissionerIdTlv(commissionerId));
    return sendTMFRequest(Constants.COMM_PET_REQ_PATH, tlvs);
  }
  
  /**
   * Sign the set of TLVs by adding a COM_TOK_SIG TLV to it.
   * @param uri
   * @param tlvs
   */
  protected void signCoap(String uri, TLVset tlvs) {
    // TODO
  }
  
}
