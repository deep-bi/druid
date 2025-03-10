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

package org.apache.druid.query.extraction;

import com.fasterxml.jackson.annotation.JsonCreator;

import javax.annotation.Nullable;

public class StrlenExtractionFn extends DimExtractionFn
{
  private static final StrlenExtractionFn INSTANCE = new StrlenExtractionFn();

  private StrlenExtractionFn()
  {
  }

  @JsonCreator
  public static StrlenExtractionFn instance()
  {
    return INSTANCE;
  }

  @Override
  @Nullable
  public String apply(@Nullable String value)
  {
    if (value == null) {
      return null;
    }
    return String.valueOf(value.length());
  }

  @Override
  public boolean preservesOrdering()
  {
    return false;
  }

  @Override
  public ExtractionType getExtractionType()
  {
    return ExtractionType.MANY_TO_ONE;
  }

  @Override
  public byte[] getCacheKey()
  {
    return new byte[]{ExtractionCacheHelper.CACHE_TYPE_ID_STRLEN};
  }

  @Override
  public final int hashCode()
  {
    return StrlenExtractionFn.class.hashCode();
  }

  @Override
  public final boolean equals(Object obj)
  {
    return obj instanceof StrlenExtractionFn;
  }
}
