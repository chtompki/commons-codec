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

import org.apache.commons.codec.binary.Hex;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;

/**
 * Unit tests for {@link SHA1Digest}.
 */
public class SHA1DigestTest {

  private static String[] messages =
      {
          "",
          "a",
          "abc",
          "abcdefghijklmnopqrstuvwxyz"
      };

  private static String[] digests =
      {
          "da39a3ee5e6b4b0d3255bfef95601890afd80709",
          "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
          "a9993e364706816aba3e25717850c26c9cd0d89d",
          "32d10c7b8cf96570ca04ce37f2a19d84240d3a89"
      };

  private GeneralDigest digest;
  private String[] input;
  private String[] results;

  @Before
  public void before() {
    digest = new SHA1Digest();
    input = messages;
    results = digests;
  }


  public String getName() {
    return digest.getAlgorithmName();
  }

  @Test
  public void performTest() throws Exception {
    byte[] resBuf = new byte[digest.getDigestSize()];

    for (int i = 0; i < input.length - 1; i++) {
      byte[] m = toByteArray(input[i]);

      vectorTest(digest, i, resBuf, m, Hex.decodeHex(results[i]));
    }

    offsetTest(digest, 0, toByteArray(input[0]), Hex.decodeHex(results[0]));

    byte[] lastV = toByteArray(input[input.length - 1]);
    byte[] lastDigest = Hex.decodeHex(results[input.length - 1]);


    testClone(resBuf, lastV, lastDigest);
    testMemo(resBuf, lastV, lastDigest);
    testEncodedState(resBuf, lastV, lastDigest);

  }

  private void testEncodedState(byte[] resBuf, byte[] input, byte[] expected) {
    // test state encoding;
    digest.update(input, 0, input.length / 2);

    // copy the GeneralDigest
    GeneralDigest copy1 = cloneDigest(digest.getEncodedState());
    GeneralDigest copy2 = cloneDigest(copy1.getEncodedState());

    digest.update(input, input.length / 2, input.length - input.length / 2);

    digest.doFinal(resBuf, 0);

    assertEquals(new String(resBuf), new String(expected));

    copy1.update(input, input.length / 2, input.length - input.length / 2);
    copy1.doFinal(resBuf, 0);

    assertEquals(new String(resBuf), new String(expected));

    copy2.update(input, input.length / 2, input.length - input.length / 2);
    copy2.doFinal(resBuf, 0);

    assertEquals(new String(resBuf), new String(expected));
  }

  private void testMemo(byte[] resBuf, byte[] input, byte[] expected) {
    Memoable m = (Memoable) digest;

    digest.update(input, 0, input.length / 2);

    // copy the GeneralDigest
    Memoable copy1 = m.copy();
    Memoable copy2 = copy1.copy();

    digest.update(input, input.length / 2, input.length - input.length / 2);
    digest.doFinal(resBuf, 0);

    assertEquals(new String(resBuf), new String(expected));

    m.reset(copy1);

    digest.update(input, input.length / 2, input.length - input.length / 2);
    digest.doFinal(resBuf, 0);

    assertEquals(new String(resBuf), new String(expected));

    GeneralDigest md = (GeneralDigest) copy2;

    md.update(input, input.length / 2, input.length - input.length / 2);
    md.doFinal(resBuf, 0);

    assertEquals(new String(resBuf), new String(expected));
  }

  private void testClone(byte[] resBuf, byte[] input, byte[] expected) {
    digest.update(input, 0, input.length / 2);

    // clone the GeneralDigest
    GeneralDigest d = cloneDigest(digest);

    digest.update(input, input.length / 2, input.length - input.length / 2);
    digest.doFinal(resBuf, 0);

    assertEquals(new String(resBuf), new String(expected));

    d.update(input, input.length / 2, input.length - input.length / 2);
    d.doFinal(resBuf, 0);

    assertEquals(new String(resBuf), new String(expected));
  }

  protected byte[] toByteArray(String input) {
    byte[] bytes = new byte[input.length()];

    for (int i = 0; i != bytes.length; i++) {
      bytes[i] = (byte) input.charAt(i);
    }

    return bytes;
  }

  private void vectorTest(
      GeneralDigest digest,
      int count,
      byte[] resBuf,
      byte[] input,
      byte[] expected) {
    digest.update(input, 0, input.length);
    digest.doFinal(resBuf, 0);

    assertEquals(new String(resBuf), new String(expected));
  }

  private void offsetTest(
      Digest digest,
      int count,
      byte[] input,
      byte[] expected) {
    byte[] resBuf = new byte[expected.length + 11];

    digest.update(input, 0, input.length);
    digest.doFinal(resBuf, 11);

    assertEquals(new String(Arrays.copyOfRange(resBuf, 11, resBuf.length)), new String(expected));
  }

  protected GeneralDigest cloneDigest(Digest digest) {
    return new SHA1Digest((SHA1Digest) digest);
  }

  protected GeneralDigest cloneDigest(byte[] encodedState) {
    return new SHA1Digest(encodedState);
  }
}
