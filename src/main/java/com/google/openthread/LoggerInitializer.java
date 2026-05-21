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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import org.slf4j.LoggerFactory;

public final class LoggerInitializer {

  public static final int MAX_VERBOSITY = 4;

  private static final String OPENTHREAD = "com.google.openthread";
  private static final String CALIFORNIUM = "org.eclipse.californium";
  private static final String XNIO = "org.xnio";
  private static final String JBOSS = "org.jboss";
  private static final String UNDERTOW = "io.undertow";

  private LoggerInitializer() {}

  public static void init(int verbosity) {
    Level level, levelLibrary;

    switch (verbosity) {
      case 0:
        level = Level.WARN;
        levelLibrary = Level.ERROR;
        break;
      case 1:
        level = Level.INFO;
        levelLibrary = Level.WARN;
        break;
      case 2:
        level = Level.DEBUG;
        levelLibrary = Level.INFO;
        break;
      case 3:
        level = Level.DEBUG;
        levelLibrary = Level.DEBUG;
        break;
      case 4:
        level = Level.TRACE;
        levelLibrary = Level.DEBUG;
        break;
      default:
        throw new IllegalArgumentException(
            "verbosity must be in 0.." + MAX_VERBOSITY);
    }

    // Logback level inheritance propagates each parent-package level to its descendants.
    LoggerContext ctx = (LoggerContext) LoggerFactory.getILoggerFactory();
    ctx.getLogger(OPENTHREAD).setLevel(level);
    ctx.getLogger(CALIFORNIUM).setLevel(levelLibrary);
    ctx.getLogger(XNIO).setLevel(levelLibrary);
    ctx.getLogger(JBOSS).setLevel(levelLibrary);
    ctx.getLogger(UNDERTOW).setLevel(levelLibrary);
  }
}
