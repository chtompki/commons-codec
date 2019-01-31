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
 * Interface for Memoable objects. Memoable objects allow the taking of a snapshot of their internal state
 * via the copy() method and then reseting the object back to that state later using the reset() method.
 */
public interface Memoable {
  /**
   * Produce a copy of this object with its configuration and in its current state.
   * <p>
   * The returned object may be used simply to store the state, or may be used as a similar object
   * starting from the copied state.
   */
  Memoable copy();

  /**
   * Restore a copied object state into this object.
   * <p>
   * Implementations of this method <em>should</em> try to avoid or minimise memory allocation to perform the reset.
   *
   * @param other an object originally {@link #copy() copied} from an object of the same type as this instance.
   * @throws ClassCastException if the provided object is not of the correct type.
   */
  void reset(Memoable other);
}