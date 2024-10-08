/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.druid.segment.data;

import org.apache.druid.segment.serde.Serializer;

import java.io.IOException;

/**
 * Serializer that produces {@link ColumnarDoubles}.
 */
public interface ColumnarDoublesSerializer extends Serializer
{
  void open() throws IOException;

  int size();

  void add(double value) throws IOException;

  default void addAll(double[] values, int start, int end) throws IOException
  {
    for (int i = start; i < end; ++i) {
      add(values[i]);
    }
  }
}
