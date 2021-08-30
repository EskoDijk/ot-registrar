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
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Java proxy object connecting to a hardware Pledge (CCM OpenThread CLI Joiner) over a serial
 * interface on the local computer.
 */
public class PledgeHardware {

  protected static final int DEFAULT_SERIAL_CMD_WAIT_MS = 20;
  protected static final int COM_BAUD_RATE = 115200;

  protected SerialPort serPort = null;
  protected PrintWriter serialWriter = null;
  protected InputStreamReader serialReader = null;

  private static Logger logger = LoggerFactory.getLogger(PledgeHardware.class);

  public PledgeHardware() throws IOException {
    init();
  }

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

    // serPort.setBaudRate(115200);
    serPort.setComPortParameters(COM_BAUD_RATE, 8, SerialPort.ONE_STOP_BIT, SerialPort.NO_PARITY);
    serPort.setFlowControl(SerialPort.FLOW_CONTROL_DISABLED);
    serPort.setComPortTimeouts(SerialPort.TIMEOUT_READ_SEMI_BLOCKING, 2500, 2500);

    boolean isOpen = serPort.openPort();
    if (!isOpen) throw new IOException("Serial port " + serPort + " couldn't be opened.");

    serialWriter = new PrintWriter(serPort.getOutputStream());
    serialReader = new InputStreamReader(serPort.getInputStream());
    // flush the reader. (Old console chars may come in)
    while (serialReader.ready()) serialReader.read();
    // reset the CLI to known state (of receiving input)
    serialWriter.write("\n\n");
    serialWriter.flush();
  }

  /**
   * shutdown the Pledge, stopping the radio and closing the serial connection.
   */
  public void shutdown() {
    if (serPort == null) return;
    try {
      execCommand("thread stop");
      execCommand("ifconfig down");
    } catch (IOException ex) {
      logger.warn("shutdown() had an exception", ex);
    }
    serPort.closePort();
    serPort = null;
  }

  /**
   * execute an OpenThread CLI command and return only a single-line response with
   * result of the command.
   * 
   * @param consoleCmd command to execute in OpenThread CLI e.g. 'thread version'
   * @return result of command
   * @throws IOException
   */
  public String execCommand(String consoleCmd) throws IOException {
    return execCommand(consoleCmd, DEFAULT_SERIAL_CMD_WAIT_MS, true);
  }

  /**
   * Execute a command (sent over serial to the hw Pledge) and return the response line(s).
   *
   * @param consoleCmd the command
   * @param msWait milliseconds to wait after sending command, to try reading result over serial.
   * @param keepFirstResponseLine if true, keeps only the first-line response of the command result. If false, keeps all.
   * @return result of command, or empty string "" if nothing was returned after the wait time.
   * @throws IOException
   */
  public String execCommand(String consoleCmd, int msWait, boolean keepFirstResponseLine)
      throws IOException {
    if (serPort == null || !serPort.isOpen())
      throw new IOException("error in serial port state: not open");
    serialWriter.print("\n" + consoleCmd);
    serialWriter.flush();
    try {
      Thread.sleep(1 + consoleCmd.length() * 8 / COM_BAUD_RATE);
    } catch (InterruptedException ex) {;
    }
    while (serialReader.ready()) // flush the CLI command mirroring.
    serialReader.read();
    // send CR
    serialWriter.print('\n');
    serialWriter.flush();
    // wait for processing to happen
    try {
      Thread.sleep(msWait);
    } catch (InterruptedException ex) {;
    }

    // if nothing outputed, return empty string
    if (!serialReader.ready()) return "";

    // create result string.
    String s = "";
    while (serialReader.ready()) s += Character.toString((char) serialReader.read());
    s = s.trim();

    if (keepFirstResponseLine && s.length() > 0) s = s.split("\n")[0].trim();
    logger.trace("Serial-read: " + s);
    return s;
  }
}
