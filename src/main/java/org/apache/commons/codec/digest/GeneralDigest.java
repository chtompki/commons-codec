/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.codec.digest;

/**
 * base implementation of MD4 family style digest as outlined in
 * "Handbook of Applied Cryptography", pages 344 - 347.
 */
public abstract class GeneralDigest implements Digest, Memoable {
  private static final int BYTE_LENGTH = 64;

  private final byte[] xBuf = new byte[4];
  private int xBufOff;

  private long byteCount;

  /**
   * Return an encoded byte array for the digest's internal state
   *
   * @return an encoding of the digests internal state.
   */
  public abstract byte[] getEncodedState();

  /**
   * Standard constructor
   */
  protected GeneralDigest() {
    xBufOff = 0;
  }

  /**
   * Copy constructor.  We are using copy constructors in place
   * of the Object.clone() interface as this interface is not
   * supported by J2ME.
   */
  protected GeneralDigest(GeneralDigest t) {
    copyIn(t);
  }

  protected GeneralDigest(byte[] encodedState) {
    System.arraycopy(encodedState, 0, xBuf, 0, xBuf.length);
    xBufOff = Pack.bigEndianToInt(encodedState, 4);
    byteCount = Pack.bigEndianToLong(encodedState, 8);
  }

  protected void copyIn(GeneralDigest t) {
    System.arraycopy(t.xBuf, 0, xBuf, 0, t.xBuf.length);

    xBufOff = t.xBufOff;
    byteCount = t.byteCount;
  }

  public void update(
      byte in) {
    xBuf[xBufOff++] = in;

    if (xBufOff == xBuf.length) {
      processWord(xBuf, 0);
      xBufOff = 0;
    }

    byteCount++;
  }

  public void update(
      byte[] in,
      int inOff,
      int len) {
    len = Math.max(0, len);

    //
    // fill the current word
    //
    int i = 0;
    if (xBufOff != 0) {
      while (i < len) {
        xBuf[xBufOff++] = in[inOff + i++];
        if (xBufOff == 4) {
          processWord(xBuf, 0);
          xBufOff = 0;
          break;
        }
      }
    }

    //
    // process whole words.
    //
    int limit = ((len - i) & ~3) + i;
    for (; i < limit; i += 4) {
      processWord(in, inOff + i);
    }

    //
    // load in the remainder.
    //
    while (i < len) {
      xBuf[xBufOff++] = in[inOff + i++];
    }

    byteCount += len;
  }

  public void finish() {
    long bitLength = (byteCount << 3);

    //
    // add the pad bytes.
    //
    update((byte) 128);

    while (xBufOff != 0) {
      update((byte) 0);
    }

    processLength(bitLength);

    processBlock();
  }

  public void reset() {
    byteCount = 0;

    xBufOff = 0;
    for (int i = 0; i < xBuf.length; i++) {
      xBuf[i] = 0;
    }
  }

  protected void populateState(byte[] state) {
    System.arraycopy(xBuf, 0, state, 0, xBufOff);
    Pack.intToBigEndian(xBufOff, state, 4);
    Pack.longToBigEndian(byteCount, state, 8);
  }

  public int getByteLength() {
    return BYTE_LENGTH;
  }

  protected abstract void processWord(byte[] in, int inOff);

  protected abstract void processLength(long bitLength);

  protected abstract void processBlock();
}
