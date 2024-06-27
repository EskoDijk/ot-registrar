/*
 *    Copyright (c) 2021, The OpenThread Registrar Authors.
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

package com.google.openthread.thread;

/**
 * Utilities for dealing with an OpenThread CLI dongle/device. Used when testing an OpenThread CLI
 * Pledge against the Registrar.
 */
public class OpenThreadUtils {

  /**
   * From a set of OT CLI output lines, filter out all lines containing info/debug log messages, all
   * empty lines, and prompt ("> ") chars/lines.
   *
   * @param log string of log lines or multiple lines, separated by CRLF or CR.
   * @return filtered log lines
   */
  public static String filterOutLogLines(String logLines) {
    StringBuilder res = new StringBuilder();
    String[] aLogLines = logLines.split("\n");
    for (String l : aLogLines) {
      l = l.trim();
      if (l.startsWith("> ")) l = l.substring(2);
      if (l.length() == 0) continue;
      if (l.startsWith("[INFO]")) continue;
      if (l.startsWith("[CRIT]")) continue;
      if (l.startsWith("[WARN]")) continue;
      if (l.startsWith("[[WARN]")) continue;
      res.append(l);
    }
    return res.toString();
  }

  public static boolean detectEnrollSuccess(String log) {
    if (log.length() == 0) return false;
    String[] aL = log.split("\n");
    for (String l : aL) {
      if (l.trim().startsWith("Join success")) return true;
    }
    return false;
  }

  public static boolean detectEnrollFailure(String log) {
    if (log.length() == 0) return false;
    String[] aL = log.split("\n");
    for (String l : aL) {
      if (l.trim().startsWith("Join failed [")) return true;
      if (l.trim().startsWith("Error ")) return true;
    }
    return false;
  }

  public static boolean detectNkpFailure(String log) {
    if (log.length() == 0) return false;
    String[] aL = log.split("\n");
    for (String l : aL) {
      if (l.trim().startsWith("Error ")) return true;
    }
    return false;
  }
}
