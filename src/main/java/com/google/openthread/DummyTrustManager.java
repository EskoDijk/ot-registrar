package com.google.openthread;

import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

public class DummyTrustManager implements X509TrustManager {

  public X509Certificate[] getAcceptedIssuers() {
    return new X509Certificate[] {};
  }

  public void checkClientTrusted(X509Certificate[] certs, String authType) {}

  public void checkServerTrusted(X509Certificate[] certs, String authType) {}
}
