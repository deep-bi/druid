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

package org.apache.druid.data.input.impl;

import com.fasterxml.jackson.databind.InjectableValues;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.google.common.collect.ImmutableList;
import org.apache.druid.data.input.InputEntityReader;
import org.apache.druid.data.input.InputFormat;
import org.apache.druid.java.util.common.StringUtils;
import org.apache.druid.java.util.common.parsers.CloseableIterator;
import org.apache.druid.java.util.common.parsers.ParseException;
import org.apache.druid.regex.RegexConfig;
import org.apache.druid.regex.RegexEngineType;
import org.apache.druid.utils.CompressionUtils;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Map;

@RunWith(Parameterized.class)
public class RegexInputFormatTest
{
  private final ObjectMapper mapper;
  private final RegexConfig regexConfig;

  @Parameterized.Parameters(name = "{0}")
  public static Collection<Object[]> constructorFeeder()
  {
    return ImmutableList.of(
      new Object[]{RegexConfig.with(RegexEngineType.JAVA)},
      new Object[]{RegexConfig.with(RegexEngineType.RE2J)}
    );
  }

  public RegexInputFormatTest(RegexConfig regexConfig)
  {
    this.regexConfig = regexConfig;
    mapper = new ObjectMapper();
    mapper.registerSubtypes(new NamedType(RegexInputFormat.class, "regex"));
  }

  @Test
  public void testSerde() throws IOException
  {
    mapper.setInjectableValues(new InjectableValues.Std().addValue(RegexConfig.class, regexConfig));

    final RegexInputFormat expected = new RegexInputFormat(
        regexConfig,
        "//[^\\r\\n]*[\\r\\n]",
        "|",
        ImmutableList.of("col1", "col2", "col3")
    );

    final byte[] json = mapper.writeValueAsBytes(expected);
    final RegexInputFormat fromJson = (RegexInputFormat) mapper.readValue(json, InputFormat.class);

    Assert.assertEquals(expected.getPattern(), fromJson.getPattern());
    Assert.assertEquals(expected.getListDelimiter(), fromJson.getListDelimiter());
    Assert.assertEquals(expected.getColumns(), fromJson.getColumns());
  }

  @Test
  public void testIgnoreCompiledPatternInJson() throws IOException
  {
    final RegexInputFormat expected = new RegexInputFormat(
        regexConfig,
        "//[^\\r\\n]*[\\r\\n]",
        "|",
        ImmutableList.of("col1", "col2", "col3")
    );

    final byte[] json = mapper.writeValueAsBytes(expected);
    final Map<String, Object> map = mapper.readValue(json, Map.class);
    Assert.assertFalse(map.containsKey("compiledPattern"));
  }

  @Test
  public void test_getWeightedSize_withoutCompression()
  {
    final RegexInputFormat format = new RegexInputFormat(
        regexConfig,
        "//[^\\r\\n]*[\\r\\n]",
        "|",
        ImmutableList.of("col1", "col2", "col3")
    );
    final long unweightedSize = 100L;
    Assert.assertEquals(unweightedSize, format.getWeightedSize("file.txt", unweightedSize));
  }
  @Test
  public void test_getWeightedSize_withGzCompression()
  {
    final RegexInputFormat format = new RegexInputFormat(
        regexConfig,
        "//[^\\r\\n]*[\\r\\n]",
        "|",
        ImmutableList.of("col1", "col2", "col3")
    );
    final long unweightedSize = 100L;
    Assert.assertEquals(
        unweightedSize * CompressionUtils.COMPRESSED_TEXT_WEIGHT_FACTOR,
        format.getWeightedSize("file.txt.gz", unweightedSize)
    );
  }

  @Test(timeout = 10000)
  public void test_backtracking() throws IOException
  {
    Assume.assumeTrue(regexConfig.getEngine() == RegexEngineType.RE2J);

    final RegexInputFormat inputFormat = new RegexInputFormat(
        regexConfig,
        "^(.*a){20}$",
        null,
        ImmutableList.of("value")
    );

    String maliciousInput = StringUtils.repeat("a", 50) + "X";
    InputEntityReader reader = inputFormat.createReader(
        null,
        new ByteEntity(maliciousInput.getBytes(StandardCharsets.UTF_8)),
        null
    );

    try (CloseableIterator<?> iterator = reader.read()) {
      while (iterator.hasNext()) {
        iterator.next();
      }
    }

    catch (ParseException ignored) {
      // expected for non-matching input
    }
  }
}
