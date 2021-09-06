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

package com.google.openthread.pledge;

import com.fazecast.jSerialComm.*;
import com.google.openthread.OpenThreadUtils;
import com.google.openthread.brski.StatusTelemetry;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.Principal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Java proxy object connecting to a hardware Pledge (CCM OpenThread CLI Joiner) over a serial
 * interface on the local computer.
 */
public class PledgeHardware {

  /** default wait time in ms after sending a serial command, to allow time for command execution */
  public static final int DEFAULT_SERIAL_CMD_WAIT_MS = 20;
  
  /** COM port baud rate */
  public static final int COM_BAUD_RATE = 115200;
  
  /** Expected Thread version of DUT Pledge */
  public static final String THREAD_VERSION_PLEDGE = "1.2";
  
  protected SerialPort serPort = null;
  protected PrintWriter serialWriter = null;
  protected InputStreamReader serialReader = null;
  protected StringBuilder pledgeLog = null;
  protected boolean statusIsEnrolled = false;

  private static Logger logger = LoggerFactory.getLogger(PledgeHardware.class);

  public PledgeHardware() throws IOException {
    init();
    if (!execCommandDone("ifconfig up"))
      throw new IOException("Pledge initialization with 'ifconfig up' failed.");
  }

  /** select COM port to Pledge and open it */
  protected void init() throws IOException {
    SerialPort[] comPorts = SerialPort.getCommPorts();
    if (comPorts.length == 0)
      throw new IOException("No serial ports found to connect to hardware Pledge");
    for (int i = 0; i < comPorts.length; i++) {
      SerialPort p = comPorts[i];
      if (p.getPortDescription().contains("OpenThread")) {
        serPort = p;
        break;
      }
    }

    if (serPort == null)
      throw new IOException(
          "Serial ports were found, but no compatible port to connect to hardware Pledge");

    serPort.setComPortParameters(COM_BAUD_RATE, 8, SerialPort.ONE_STOP_BIT, SerialPort.NO_PARITY);
    serPort.setFlowControl(SerialPort.FLOW_CONTROL_DISABLED);
    serPort.setComPortTimeouts(SerialPort.TIMEOUT_READ_SEMI_BLOCKING, 2500, 2500);

    boolean isOpen = serPort.openPort();
    if (!isOpen) throw new IOException("Serial port " + serPort + " couldn't be opened.");

    pledgeLog = new StringBuilder();
    serialWriter = new PrintWriter(serPort.getOutputStream());
    serialReader = new InputStreamReader(serPort.getInputStream());
    readSerialLines();
    // reset the CLI to known state (of receiving input)
    serialWriter.write("\n\n");
    serialWriter.flush();
    try { Thread.sleep(10); } catch (InterruptedException ex) {;}
    readSerialLines();
  }

  /** shutdown the Pledge, stopping the radio and closing the serial connection. */
  public void shutdown() {
    if (serPort == null) return;
    try {
      execCommand("thread stop");
      execCommand("ifconfig down");
      waitForMessage(10);
    } catch (IOException ex) {
      logger.warn("shutdown() had an exception", ex);
    }
    finally{
      serPort.closePort();
      serPort = null;
    }    
  }

  /**
   * execute an OpenThread CLI command and check result for the 'Done' response.
   *
   * @param consoleCmd command to execute in OpenThread CLI e.g. 'ifconfig up'
   * @return true if 'Done' was responsed by the OT CLI, false otherwise.
   * @throws IOException
   */
  public boolean execCommandDone(String consoleCmd) throws IOException {
    if (execCommand(consoleCmd).equals("Done")) return true;
    return false;
  }

  /**
   * execute an OpenThread CLI command and return only a single-line response with result of the
   * command.
   *
   * @param consoleCmd command to execute in OpenThread CLI e.g. 'thread version'
   * @return result of command, only first line is used.
   * @throws IOException if no response was returned by Pledge, or another IO error occurred.
   */
  public String execCommand(String consoleCmd) throws IOException {
    String[] aRes = execCommand(consoleCmd, DEFAULT_SERIAL_CMD_WAIT_MS, true);
    if (aRes.length == 0) throw new IOException("No result returned");
    return aRes[0];
  }

  /**
   * Execute a command (sent over serial to the hw Pledge) and return the response line(s) if any.
   *
   * @param consoleCmd the command
   * @param msWait milliseconds to wait after sending command, to try reading result over serial.
   * @param filterOutLogLines if true, filters out any log/empty/prompt lines from result.
   * @return result of command as lines, or empty array if nothing was returned after the wait time.
   * @throws IOException
   */
  public String[] execCommand(String consoleCmd, int msWait, boolean filterOutLogLines)
      throws IOException {
    if (serPort == null || !serPort.isOpen())
      throw new IOException("error in serial port state: not open");
    if (consoleCmd.length() > 0) serialWriter.print("\n" + consoleCmd);
    serialWriter.flush();
    try {
      Thread.sleep(1 + consoleCmd.length() * 8 * 1000 / COM_BAUD_RATE);
    } catch (InterruptedException ex) {;
    }
    readSerialLines();
    // send CR to execute the command in CLI
    if (consoleCmd.length() > 0) serialWriter.print('\n');
    serialWriter.flush();
    // wait for processing to happen
    try {
      Thread.sleep(msWait);
    } catch (InterruptedException ex) {;
    }

    // if nothing outputed, return empty string
    if (!serialReader.ready()) return new String[] {};

    // create result string.
    StringBuilder s = new StringBuilder();
    while (serialReader.ready()) {
      s.append((char) serialReader.read());
    }
    String res = s.toString();
    addToPledgeLog(res);
    String[] aRes = res.split("\n");

    if (filterOutLogLines && res.length() > 0) {
      String[] aF = OpenThreadUtils.filterOutLogLines(aRes);
      return aF;
    }
    return aRes;
  }

  /**
   * Factory-reset the Pledge and verify that it responds afterwards.
   *
   * @return true if factory reset was successfully done and Pledge responds after it.
   */
  public boolean factoryReset() throws IOException {
    execCommand("factoryreset", 250, false);
    String v = execCommand("thread version");
    if (v.equals(THREAD_VERSION_PLEDGE)) return true;
    else return false;
  }

  /**
   * Wait for any (non-Log) message or response from the Pledge. It blocks for at most maxWaitTimeMs
   * to get a first message i.e. set of line(s), but does not block to get additional lines.
   *
   * @param maxWaitTimeMs milliseconds time to wait, at most.
   * @return lines of the response message received, or null if nothing received within
   *     maxWaitTimeMs.
   * @throws IOException
   */
  public String[] waitForMessage(int maxWaitTimeMs) throws IOException {
    long t0 = System.currentTimeMillis();
    do {
      String[] aR = execCommand("", 100, true);
      if (aR.length > 0 && aR[0].length() > 0) {
        return aR;
      }
    } while (System.currentTimeMillis() < t0 + maxWaitTimeMs);
    return null;
  }

  /** check whether this Pledge is enrolled (true), or not (false). Based on log analysis. */
  public boolean isEnrolled() {
    try {
      while (waitForMessage(0) != null) ;
    } catch (IOException ex) {;
    }
    return statusIsEnrolled;
  }

  public void enroll() throws IOException {
    execCommandDone("joiner startae");
    waitForMessage(20000);

    // verify same on pledge side.
    if(!isEnrolled())
      throw new IOException("enroll() failed");

  }
  
  /**
   * returns the Pledge log, built during the session of using this Pledge.
   *
   * @return complete Pledge log output
   */
  public String getLog() {
    return pledgeLog.toString();
  }

  /**
   * helper method to read all available serial input from OT device, and store it in the log without further
   * processing.
   *
   * @throws IOException
   */
  protected void readSerialLines() throws IOException {
    StringBuilder s = new StringBuilder();
    while (serialReader.ready()) {
      s.append((char) serialReader.read());
    }
    if (s.length() > 0) {
      // add new data to the Pledge log
      addToPledgeLog(s.toString());
    }
  }

  /** helper method to add string 'log' to the Pledge log. It will perform log analysis functions on the input. */
  protected void addToPledgeLog(String log) {
    pledgeLog.append(log);
    statusIsEnrolled =
        OpenThreadUtils.detectEnrollSuccess(log) && !OpenThreadUtils.detectEnrollFailure(log);
  }
  
}
