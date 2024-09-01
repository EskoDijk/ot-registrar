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

package com.google.openthread;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;

public class NetworkUtils {

  /**
   * Returns the IPv6-specific host string for a global address of the current host. For example,
   * "[2a01:7e01::ca98]". If no global IPv6 available it returns "[::1]". It will try to find an address
   * over all interfaces. It will avoid the example IPv6 addresses "[2001:db8:...]" which may be used
   * by Docker.
   *
   * @return IPv6-specific host string or "[::1]" if no global address available.
   */
  public static String getIPv6Host() throws UnknownHostException, SocketException {
    NetworkInterface nif;
    Enumeration<NetworkInterface> nifs;
    InetAddress addr;
    String retVal = "[::1]";
    String addrStr;
    nifs = NetworkInterface.getNetworkInterfaces();

    // look for addresses per NIF
    while (nifs.hasMoreElements()) {
      nif = nifs.nextElement();
      Enumeration<InetAddress> nifAddrs = nif.getInetAddresses();
      while (nifAddrs.hasMoreElements()) {
        addr = nifAddrs.nextElement();
        addrStr = addr.getHostAddress();
        if (addr instanceof Inet6Address
            && !addr.isLinkLocalAddress()
            && !addr.isLoopbackAddress()
            && !addr.isSiteLocalAddress()
            && !addrStr.startsWith("2001:db8")) {
          // ((Inet6Address) addr).getScopeId() // could check for scope id
          retVal = "[" + addr.getHostAddress() + "]";
        }
      }
    }
    return retVal;
  }

  public static String getIPv4Host() throws UnknownHostException, SocketException {
    NetworkInterface nif;
    Enumeration<NetworkInterface> nifs;
    InetAddress addr;
    String retVal = null;
    nifs = NetworkInterface.getNetworkInterfaces();

    // look for addresses per NIF
    while (nifs.hasMoreElements()) {
      nif = nifs.nextElement();
      Enumeration<InetAddress> nifAddrs = nif.getInetAddresses();
      while (nifAddrs.hasMoreElements()) {
        addr = nifAddrs.nextElement();
        if (!(addr instanceof Inet6Address)
            && !addr.isLinkLocalAddress()
            && !addr.isLoopbackAddress()) {
          retVal = addr.getHostAddress();
        }
      }
    }
    return retVal;
  }
}
