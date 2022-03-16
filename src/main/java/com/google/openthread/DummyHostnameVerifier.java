package com.google.openthread;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class DummyHostnameVerifier implements HostnameVerifier {

  @Override
  public boolean verify(String arg0, SSLSession arg1) {
    return true;
  }
}
