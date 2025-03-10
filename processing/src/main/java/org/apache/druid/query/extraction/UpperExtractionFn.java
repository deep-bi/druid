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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import org.apache.druid.java.util.common.StringUtils;

import javax.annotation.Nullable;
import java.nio.ByteBuffer;
import java.util.Locale;
import java.util.Objects;

@JsonTypeName("upper")
public class UpperExtractionFn extends DimExtractionFn
{
  private final Locale locale;

  @JsonProperty
  private final String localeString;

  public UpperExtractionFn(@JsonProperty("locale") String localeString)
  {
    this.localeString = localeString;
    this.locale = localeString == null ? Locale.getDefault() : Locale.forLanguageTag(localeString);
  }

  /**
   * @param key string input of extraction function
   *
   * @return new string with all of the characters in {@code key} as an upper case  or <tt>null</tt> if {@code key} is empty or null
   */
  @Nullable
  @Override
  public String apply(@Nullable String key)
  {
    if (key == null) {
      return null;
    }
    return key.toUpperCase(locale);
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
    byte[] localeBytes = StringUtils.toUtf8(StringUtils.nullToEmptyNonDruidDataString(localeString));
    return ByteBuffer.allocate(2 + localeBytes.length)
                     .put(ExtractionCacheHelper.CACHE_TYPE_ID_UPPER)
                     .put((byte) 0XFF)
                     .put(localeBytes)
                     .array();
  }

  @Override
  public boolean equals(Object o)
  {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    UpperExtractionFn that = (UpperExtractionFn) o;
    return Objects.equals(locale, that.locale) &&
           Objects.equals(localeString, that.localeString);
  }

  @Override
  public int hashCode()
  {
    return Objects.hash(locale, localeString);
  }
}
