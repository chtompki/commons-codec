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
 * Unit Tests for {@link SHA256Digest}.
 */
public class SHA256DigestTest {

  private static String[] messages =
      {
          "",
          "a",
          "abc",
          "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
      };

  private static String[] digests =
      {
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
      };

  private GeneralDigest digest;
  private String[] input;
  private String[] results;

  @Before
  public void before() {
    digest = new SHA256Digest();
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
    return new SHA256Digest((SHA256Digest) digest);
  }

  protected GeneralDigest cloneDigest(byte[] encodedState) {
    return new SHA256Digest(encodedState);
  }

}
